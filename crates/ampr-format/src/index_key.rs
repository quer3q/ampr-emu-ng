//! Game path to AMPRIDX3 lookup key. Keys are lowercase ASCII with `/`
//! separators.
use crate::folded;
use core::cmp::Ordering;

/// SCE_KERNEL_PATH_MAX: the input must be NUL-terminated within this many bytes.
pub const PATH_MAX: usize = 1024;
/// SCE_KERNEL_NAME_MAX: longest accepted path component.
pub const NAME_MAX: usize = 255;
/// Runtime key buffer size used by lookups (PATH_MAX + 1).
pub const RUNTIME_KEY_CAPACITY: usize = PATH_MAX + 1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyError {
    /// EINVAL: empty, relative, or `..` above the root.
    Invalid,
    /// ENAMETOOLONG: input, component, or output buffer too long.
    NameTooLong,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Key {
    pub len: usize,
    pub had_trailing_separator: bool,
}

fn is_sep(b: u8) -> bool {
    b == b'/' || b == b'\\'
}

/// Appends one key byte, keeping room for the terminating NUL.
fn push(out: &mut [u8], len: &mut usize, b: u8) -> Result<(), KeyError> {
    if *len + 1 >= out.len() {
        return Err(KeyError::NameTooLong);
    }
    out[*len] = b;
    *len += 1;
    out[*len] = 0;
    Ok(())
}

/// Normalizes an `/app0` path into a lookup key. `path` is the input without its NUL
/// terminator. Collapses separators, drops `.`, resolves `..`, lowercases
/// ASCII and writes a NUL-terminated key to `out`.
pub fn normalize(path: &[u8], out: &mut [u8]) -> Result<Key, KeyError> {
    if let Some(first) = out.first_mut() {
        *first = 0;
    }
    let path = &path[..path.iter().position(|&b| b == 0).unwrap_or(path.len())];
    match path.first() {
        Some(&b) if is_sep(b) => {}
        _ => return Err(KeyError::Invalid),
    }
    if path.len() >= PATH_MAX {
        return Err(KeyError::NameTooLong);
    }
    let had_trailing_separator = path.last().is_some_and(|&b| is_sep(b));
    let mut len = 0usize;
    push(out, &mut len, b'/')?;
    for component in path.split(|&b| is_sep(b)) {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component.len() > NAME_MAX {
            return Err(KeyError::NameTooLong);
        }
        if component == b".." {
            if len <= 1 {
                return Err(KeyError::Invalid);
            }
            while len > 1 && out[len - 1] != b'/' {
                len -= 1;
            }
            if len > 1 {
                len -= 1;
            }
            out[len] = 0;
            continue;
        }
        if len > 1 {
            push(out, &mut len, b'/')?;
        }
        for &b in component {
            push(out, &mut len, b.to_ascii_lowercase())?;
        }
    }
    Ok(Key {
        len,
        had_trailing_separator,
    })
}

/// Whether `key` is the `/app0` root or a file below it.
pub fn is_app0_key(key: &[u8]) -> bool {
    key == b"/app0" || (key.len() > 6 && key.starts_with(b"/app0/"))
}

/// Fast check for an `/app0` root prefix. `byte(i)` reads byte `i` of a
/// NUL-terminated string; reads stop at the first mismatch, so no byte past
/// the terminator is requested.
pub fn has_app0_root(byte: impl Fn(usize) -> u8) -> bool {
    is_sep(byte(0))
        && byte(1).to_ascii_lowercase() == b'a'
        && byte(2).to_ascii_lowercase() == b'p'
        && byte(3).to_ascii_lowercase() == b'p'
        && byte(4) == b'0'
        && matches!(byte(5), 0 | b'/' | b'\\')
}

/// Index key order over NUL-free slices: case and separator
/// folded byte order, a proper prefix sorting first.
pub fn compare(a: &[u8], b: &[u8]) -> Ordering {
    a.iter()
        .copied()
        .map(folded)
        .cmp(b.iter().copied().map(folded))
}

/// `compare(path, dir ++ "/")` without building the prefix.
pub(crate) fn compare_dir_prefix(path: &[u8], dir: &[u8]) -> Ordering {
    path.iter()
        .copied()
        .map(folded)
        .cmp(dir.iter().chain(b"/").copied().map(folded))
}

/// Whether `path` lies below `dir`; `dir` is a normalized key.
pub fn is_descendant(path: &[u8], dir: &[u8]) -> bool {
    path.len() > dir.len()
        && path.iter().zip(dir).all(|(&p, &d)| folded(p) == d)
        && is_sep(path[dir.len()])
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;

    fn key(path: &[u8]) -> Result<(std::vec::Vec<u8>, bool), KeyError> {
        let mut out = [0xffu8; RUNTIME_KEY_CAPACITY];
        let k = normalize(path, &mut out)?;
        assert_eq!(out[k.len], 0);
        Ok((out[..k.len].to_vec(), k.had_trailing_separator))
    }

    #[test]
    fn normalize_matches_reference_cases() {
        let ok = |p: &[u8], k: &[u8], t: bool| assert_eq!(key(p), Ok((k.to_vec(), t)), "{p:?}");
        ok(b"/app0/Data/File.BIN", b"/app0/data/file.bin", false);
        ok(b"\\APP0\\\\a\\.\\b\\", b"/app0/a/b", true);
        ok(b"/app0/x/../y", b"/app0/y", false);
        ok(b"/app0/..", b"/", false);
        ok(b"/", b"/", true);
        ok(b"/app0/\xc3\x84", b"/app0/\xc3\x84", false);
        assert_eq!(key(b""), Err(KeyError::Invalid));
        assert_eq!(key(b"app0/x"), Err(KeyError::Invalid));
        assert_eq!(key(b"/.."), Err(KeyError::Invalid));
        assert_eq!(key(b"/a/../.."), Err(KeyError::Invalid));
        let mut long = std::vec![b'/'];
        long.extend([b'a'; 256]);
        assert_eq!(key(&long), Err(KeyError::NameTooLong));
        long.truncate(256);
        assert!(key(&long).is_ok());
        let mut deep = std::vec::Vec::new();
        while deep.len() < PATH_MAX {
            deep.extend_from_slice(b"/a");
        }
        assert_eq!(key(&deep[..PATH_MAX]), Err(KeyError::NameTooLong));
        assert!(key(&deep[..PATH_MAX - 2]).is_ok());
        let mut small = [0u8; 6];
        assert_eq!(normalize(b"/abcde", &mut small), Err(KeyError::NameTooLong));
        assert!(is_app0_key(b"/app0") && is_app0_key(b"/app0/x"));
        assert!(!is_app0_key(b"/app0/") && !is_app0_key(b"/app01"));
        assert_eq!(compare(b"/app0/A", b"/app0/a/"), Ordering::Less);
        assert_eq!(compare(b"/app0\\B", b"/APP0/b"), Ordering::Equal);
        assert!(is_descendant(b"/app0/Dir\\f", b"/app0/dir"));
        assert!(!is_descendant(b"/app0/dirx", b"/app0/dir"));
        let root = |s: &'static [u8]| has_app0_root(|i| s.get(i).copied().unwrap_or(0));
        assert!(root(b"\\APP0") && root(b"/app0/x") && !root(b"/app01") && !root(b"/ap"));
    }
}
