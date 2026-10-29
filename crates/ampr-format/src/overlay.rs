//! Directory overlay and packed-path logic:
//! ASCII-folded path ordering, overlay path normalization, packed directory
//! ranges, service-name hiding and synthetic `struct dirent` records.
//! Uses caller-owned buffers; no alloc.
use core::cmp::Ordering;


/// `SCE_KERNEL_PATH_MAX`.
pub const PATH_MAX: usize = 1024;
/// `AMPR_EMU_PACK_LOGICAL_ROOT_PATH`.
pub const LOGICAL_ROOT: &[u8] = b"/app0";
/// `AMPR_EMU_PACK_INDEX_PATH`.
pub const INDEX_PATH: &[u8] = b"/app0/ampr_assets.index";
pub const DT_DIR: u8 = 4;
pub const DT_REG: u8 = 8;
/// `offsetof(struct dirent, d_name)` on the PS5 (FreeBSD 11 layout).
pub const DIRENT_NAME_AT: usize = 8;

// ASCII A-Z only; unlike `crate::folded`, a backslash stays a backslash.
fn fold(b: u8) -> u8 {
    b.to_ascii_lowercase()
}

/// Byte-wise on folded bytes, shorter prefix first.
pub fn folded_compare(a: &[u8], b: &[u8]) -> Ordering {
    a.iter().map(|&x| fold(x)).cmp(b.iter().map(|&x| fold(x)))
}

pub fn folded_equal(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.eq_ignore_ascii_case(b)
}

/// FNV-1a over folded bytes, low bit forced on.
pub fn folded_hash(value: &[u8]) -> u64 {
    let mut hash = 1_469_598_103_934_665_603u64;
    for &b in value {
        hash = (hash ^ u64::from(fold(b))).wrapping_mul(1_099_511_628_211);
    }
    hash | 1
}

/// Normalizes an overlay path. `input` yields the bytes before the NUL;
/// it is consumed lazily, so reading stops once `out` overflows. On success
/// `out` holds the NUL-terminated path and the length is returned.
pub fn normalize_path(input: impl Iterator<Item = u8>, out: &mut [u8]) -> Option<u16> {
    if out.len() < 6 {
        return None;
    }
    let mut n = 0usize;
    let mut previous_slash = false;
    for ch in input {
        let ch = if ch == b'\\' { b'/' } else { ch };
        if ch == b'/' {
            if previous_slash {
                continue;
            }
            previous_slash = true;
        } else {
            previous_slash = false;
        }
        if n + 1 >= out.len() {
            return None;
        }
        out[n] = ch;
        n += 1;
    }
    while n > 5 && out[n - 1] == b'/' {
        n -= 1;
    }
    out[n] = 0;
    let r = LOGICAL_ROOT.len();
    if n < r || !folded_equal(&out[..r], LOGICAL_ROOT) || (n != r && out[r] != b'/') {
        return None;
    }
    u16::try_from(n).ok()
}

/// Whether `directory + "/" + name` folds to `target`.
pub fn joined_matches(directory: &[u8], name: &[u8], target: &[u8]) -> bool {
    let slash = directory.last() != Some(&b'/');
    if directory.len() + usize::from(slash) + name.len() != target.len()
        || !folded_equal(directory, &target[..directory.len()])
    {
        return false;
    }
    let mut at = directory.len();
    if slash {
        if target[at] != b'/' {
            return false;
        }
        at += 1;
    }
    folded_equal(name, &target[at..])
}

/// Writes NUL-terminated `directory/name`.
pub fn join_child(directory: &[u8], name: &[u8], out: &mut [u8]) -> bool {
    let slash = directory.last() != Some(&b'/');
    let needed = directory.len() + usize::from(slash) + name.len() + 1;
    if needed > out.len() {
        return false;
    }
    out[..directory.len()].copy_from_slice(directory);
    let mut at = directory.len();
    if slash {
        out[at] = b'/';
        at += 1;
    }
    out[at..at + name.len()].copy_from_slice(name);
    out[at + name.len()] = 0;
    true
}

/// One `next_virtual_child` result: `name[..len]` plus NUL in the caller's
/// buffer, its dirent type and the cursor after its group.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Child {
    pub len: u8,
    pub kind: u8,
    pub next: u32,
}

// The directory-order helpers below are shared by AMPRPAK4 and zstd: `order`
// holds record ids sorted by folded path, and `path` maps an id to its path
// (None for a malformed record).

/// First position in `order` whose path does not sort before `key`;
/// an id without a path never sorts before it.
pub fn lower_bound<'a>(order: &[u32], key: &[u8], path: impl Fn(u32) -> Option<&'a [u8]>) -> usize {
    order.partition_point(|&id| path(id).is_some_and(|p| folded_compare(p, key).is_lt()))
}

/// The `[begin, end)` span of `order` whose paths lie strictly below
/// `prefix`, a directory path ending in `/`; None when none does.
/// `prefix` is scratch: its last byte is overwritten.
pub fn prefix_range<'a>(
    order: &[u32],
    prefix: &mut [u8],
    path: impl Fn(u32) -> Option<&'a [u8]>,
) -> Option<(u32, u32)> {
    let n = prefix.len();
    let begin = lower_bound(order, prefix, &path);
    let first = path(*order.get(begin)?)?;
    if first.len() <= n || !folded_equal(&first[..n], prefix) {
        return None;
    }
    // '0' follows '/': [dir/, dir0) is exactly the paths below dir.
    *prefix.last_mut()? = b'0';
    let end = lower_bound(order, prefix, &path);
    Some((begin as u32, end as u32))
}

// Span of the first component below a `dir_len`-byte directory prefix.
fn child_span(path: &[u8], dir_len: usize) -> Option<(usize, usize)> {
    if path.len() <= dir_len {
        return None;
    }
    let rel = dir_len + usize::from(path[dir_len] == b'/');
    let end = path[rel..]
        .iter()
        .position(|&b| b == b'/')
        .map_or(path.len(), |i| rel + i);
    Some((rel, end))
}

/// `next_virtual_child`: the child at `order[cursor]` of a directory whose
/// path, as `path` spells it, is `dir_len` bytes, merged with the following
/// entries of the same folded name (a directory if any of them has
/// descendants). `name` gets the NUL-terminated child name.
pub fn next_child<'a>(
    order: &[u32],
    range_end: u32,
    dir_len: usize,
    cursor: u32,
    name: &mut [u8],
    path: impl Fn(u32) -> Option<&'a [u8]>,
) -> Option<Child> {
    if cursor >= range_end {
        return None;
    }
    let first = path(*order.get(cursor as usize)?)?;
    let (rel, end) = child_span(first, dir_len)?;
    if rel >= first.len() {
        return None;
    }
    let child = &first[rel..end];
    if child.is_empty() || child.len() > 255 || child.len() >= name.len() {
        return None;
    }
    name[..child.len()].copy_from_slice(child);
    name[child.len()] = 0;
    let mut kind = if end < first.len() { DT_DIR } else { DT_REG };
    let mut next = cursor + 1;
    while next < range_end {
        let Some(other) = order.get(next as usize).and_then(|&i| path(i)) else {
            break;
        };
        let Some((orel, oend)) = child_span(other, dir_len) else {
            break;
        };
        if !folded_equal(child, &other[orel..oend]) {
            break;
        }
        if oend < other.len() {
            kind = DT_DIR;
        }
        next += 1;
    }
    Some(Child {
        len: child.len() as u8,
        kind,
        next,
    })
}

/// Size of a synthetic dirent for a `name_len`-byte name; `usize::MAX` on overflow.
pub fn dirent_size(name_len: usize) -> usize {
    (DIRENT_NAME_AT + 1)
        .checked_add(name_len)
        .and_then(|v| v.checked_add(3))
        .map_or(usize::MAX, |v| v & !3)
}

/// Writes one zero-padded FreeBSD 11 `struct dirent`
/// (`u32 d_fileno, u16 d_reclen, u8 d_type, u8 d_namlen, d_name[]`).
/// Returns the record size, or `None` when it does not fit.
pub fn emit_dirent(out: &mut [u8], name: &[u8], kind: u8, inode_seed: u64) -> Option<usize> {
    let size = dirent_size(name.len());
    if name.len() > 255 || size > out.len() || size > usize::from(u16::MAX) {
        return None;
    }
    let record = &mut out[..size];
    record.fill(0);
    let fileno = ((inode_seed & 0x7fff_ffff) | 1) as u32;
    record[0..4].copy_from_slice(&fileno.to_le_bytes());
    record[4..6].copy_from_slice(&(size as u16).to_le_bytes());
    record[6] = kind;
    record[7] = name.len() as u8;
    record[DIRENT_NAME_AT..DIRENT_NAME_AT + name.len()].copy_from_slice(name);
    Some(size)
}

/// Directory offset after a read: saturating `base + bytes` for `bytes > 0`.
pub fn advance_offset(base: i64, bytes: i32) -> i64 {
    if bytes <= 0 {
        base
    } else {
        base.saturating_add(i64::from(bytes))
    }
}

