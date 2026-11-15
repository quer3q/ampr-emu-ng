//! The compiled index view: per-file columns, two hash slot arrays (files,
//! then directories) and one record per folded directory key, built once
//! from an AMPRIDX3 index into caller slices and read-only afterwards.
//!
//! Crate accessors for `view_join` and `view_list`: `View::next_file` (the
//! packed chain of a directory), `View::dirs`, `View::path_at`,
//! `View::hash`, `View::files_by_hash` and `View::dirs_by_hash` (slot probes
//! yielding ids of that hash) and `View::collides`.
use crate::index::Index;
use crate::source::{Source, PATH_BUF};
use crate::{folded, idx_path_hash, pak_path_hash, Error, Result};

/// Ids are one-based; 0 is no file or directory.
pub const NONE: u32 = 0;
/// Bit of `Dir::flags`: the directory has a packed file below it.
pub const DIR_PACKED: u16 = 1;
/// `chunk` of a loose file, and of every file of a title that is not zstd.
pub const NO_CHUNK: u32 = u32::MAX;
/// `next` of a file `link_packed` did not link (a chain ends with `NONE`).
const UNLINKED: u32 = u32::MAX;
/// Key length of `/app0`, the root directory.
const ROOT_LEN: usize = 5;

/// One folded directory key.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Dir {
    /// `idx_path_hash` of the folded key.
    pub hash: u64,
    /// Parent directory id, `NONE` for `/app0`.
    pub parent: u32,
    pub first_dir: u32,
    pub next_sibling: u32,
    /// First packed file; the chain goes on through `next`.
    pub first_file: u32,
    /// A file below it whose path cut to `key_len` spells the directory.
    pub rep_file: u32,
    pub key_len: u16,
    pub flags: u16,
}

const _: () = assert!(core::mem::size_of::<Dir>() == 32);

/// Which pack columns a view carries. `Lz4` also covers pkg.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Packs {
    None,
    Lz4,
    Zstd,
}

/// Element counts of every `Buffers` slice for a file count and a
/// directory capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sizes {
    pub files: u32,
    pub file_slots: u32,
    pub dir_cap: u32,
    pub dir_slots: u32,
}

impl Sizes {
    /// (`next`, `chunk`, `lz4_hash`) lengths for `packs`.
    pub fn pack_columns(&self, packs: Packs) -> (usize, usize, usize) {
        let n = self.files as usize;
        match packs {
            Packs::None => (0, 0, 0),
            Packs::Lz4 => (n, 0, n),
            Packs::Zstd => (n, n, 0),
        }
    }
}

/// Slot count: the power of two at or above 1.5 times `n`, at least 2.
fn slot_count(n: u32) -> Option<u32> {
    let wanted = u64::from(n) * 3 / 2 + u64::from(n & 1);
    u32::try_from(wanted.max(2).next_power_of_two()).ok()
}

/// `None` when either count is zero or the slots would not fit a `u32`.
pub fn sizes(files: u32, dir_cap: u32) -> Option<Sizes> {
    if files == 0 || dir_cap == 0 || files >= 1 << 31 || dir_cap >= 1 << 31 {
        return None;
    }
    Some(Sizes {
        files,
        file_slots: slot_count(files)?,
        dir_cap,
        dir_slots: slot_count(dir_cap)?,
    })
}

/// Caller memory for a view; lengths as `sizes` and `Sizes::pack_columns`
/// give them, `dirs.len()` being the directory capacity.
pub struct Buffers<'a> {
    pub hash: &'a mut [u64],
    pub size: &'a mut [u64],
    pub mtime: &'a mut [i64],
    /// Absolute offset of the path in the index file.
    pub path_at: &'a mut [u32],
    pub next: &'a mut [u32],
    pub chunk: &'a mut [u32],
    pub slots: &'a mut [u32],
    pub dirs: &'a mut [Dir],
    pub dir_slots: &'a mut [u32],
    pub collide: &'a mut [u32],
    /// Transient: each file's directory id, until `finish`.
    pub dir_of: &'a mut [u32],
    /// Transient: `pak_path_hash` of each path, until the LZ4 join.
    pub lz4_hash: &'a mut [u64],
}

/// What a lookup key names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hit {
    File(u32),
    Dir(u32),
    Miss,
}

// ---- build ----

/// Ids in the probe chain of `hash` whose hash (`hash_of`) is `hash`.
fn probe<'s>(
    slots: &'s [u32],
    hash: u64,
    hash_of: impl Fn(u32) -> u64 + 's,
) -> impl Iterator<Item = u32> + 's {
    let mask = slots.len().wrapping_sub(1);
    let (mut pos, mut left) = (hash as usize & mask, slots.len());
    core::iter::from_fn(move || {
        while left > 0 {
            let id = slots[pos];
            if id == NONE {
                return None;
            }
            pos = (pos + 1) & mask;
            left -= 1;
            if hash_of(id) == hash {
                return Some(id);
            }
        }
        None
    })
}

/// Puts `id` in the first empty slot of `hash`'s chain.
fn insert(slots: &mut [u32], hash: u64, id: u32) -> Result<()> {
    let mask = slots.len() - 1;
    let mut pos = hash as usize & mask;
    for _ in 0..slots.len() {
        if slots[pos] == NONE {
            slots[pos] = id;
            return Ok(());
        }
        pos = (pos + 1) & mask;
    }
    Err(Error::OutOfRange)
}

fn folded_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| folded(x) == folded(y))
}

/// Adds `id` to the collision list once; `Invalid` when the list is full.
fn push_collide(collide: &mut [u32], len: &mut usize, id: u32) -> Result<()> {
    if collide[..*len].contains(&id) {
        return Ok(());
    }
    *collide.get_mut(*len).ok_or(Error::Invalid)? = id;
    *len += 1;
    Ok(())
}

/// Builds the view from `idx` in one pass over its records in id order,
/// checking each path as `Index::check` does. Two files of one folded path
/// are `Invalid`; more directories than `bufs.dirs` holds is `OutOfRange`
/// (the caller grows it and builds again).
pub fn build<'a, S: Source + ?Sized>(idx: &Index<'_, S>, bufs: Buffers<'a>) -> Result<Builder<'a>> {
    let files = idx.len();
    let dir_cap = u32::try_from(bufs.dirs.len()).map_err(|_| Error::Invalid)?;
    let sz = sizes(files, dir_cap).ok_or(Error::Invalid)?;
    let n = files as usize;
    let (next, chunk, lz4) = (bufs.next.len(), bufs.chunk.len(), bufs.lz4_hash.len());
    let packs = [Packs::None, Packs::Lz4, Packs::Zstd]
        .into_iter()
        .any(|p| sz.pack_columns(p) == (next, chunk, lz4));
    if !packs
        || [
            bufs.hash.len(),
            bufs.size.len(),
            bufs.mtime.len(),
            bufs.path_at.len(),
            bufs.dir_of.len(),
        ]
        .iter()
        .any(|&l| l != n)
        || bufs.slots.len() != sz.file_slots as usize
        || bufs.dir_slots.len() != sz.dir_slots as usize
    {
        return Err(Error::Invalid);
    }
    let mut b = Builder {
        hash: bufs.hash,
        size: bufs.size,
        mtime: bufs.mtime,
        path_at: bufs.path_at,
        next: bufs.next,
        chunk: bufs.chunk,
        slots: bufs.slots,
        dirs: bufs.dirs,
        dir_slots: bufs.dir_slots,
        collide: bufs.collide,
        dir_of: bufs.dir_of,
        lz4_hash: bufs.lz4_hash,
        dir_count: 0,
        collide_len: 0,
    };
    b.slots.fill(NONE);
    b.dir_slots.fill(NONE);
    b.next.fill(UNLINKED);
    b.chunk.fill(NO_CHUNK);
    let mut bufs = [[0u8; PATH_BUF]; 3];
    let (mut prev_len, mut prev_dir) = (None, NONE);
    for id in 1..=files {
        let [a, z, scratch] = &mut bufs;
        let (cur, prev) = if id & 1 == 0 { (a, &*z) } else { (z, &*a) };
        let rec = idx.record(id)?;
        let path = idx.checked_path(&rec, cur)?;
        let i = (id - 1) as usize;
        let h = idx_path_hash(path);
        b.hash[i] = h;
        b.size[i] = rec.size;
        b.mtime[i] = rec.mtime;
        b.path_at[i] = u32::try_from(rec.path_at).map_err(|_| Error::OutOfRange)?;
        if let Some(l) = b.lz4_hash.get_mut(i) {
            *l = pak_path_hash(path);
        }
        b.add_file(idx, id, h, path, scratch)?;
        let prev = prev_len.map(|l: usize| &prev[..l]);
        let d = b.add_dirs(idx, id, path, prev, prev_dir, scratch)?;
        b.dir_of[i] = d;
        prev_dir = d;
        prev_len = Some(path.len());
    }
    b.collide[..b.collide_len].sort_unstable();
    Ok(b)
}

// ---- builder ----

/// A view being built: `build` filled the AMPRIDX3 columns, a pack join
/// sets chunks and links packed files, `finish` makes it read-only.
pub struct Builder<'a> {
    hash: &'a mut [u64],
    size: &'a mut [u64],
    mtime: &'a mut [i64],
    path_at: &'a mut [u32],
    next: &'a mut [u32],
    chunk: &'a mut [u32],
    slots: &'a mut [u32],
    dirs: &'a mut [Dir],
    dir_slots: &'a mut [u32],
    collide: &'a mut [u32],
    dir_of: &'a mut [u32],
    lz4_hash: &'a mut [u64],
    dir_count: u32,
    collide_len: usize,
}

impl<'a> Builder<'a> {
    /// Inserts file `id`'s slot. A file of the same hash and folded path is
    /// `Invalid`; one of the same hash only puts both on the collision list.
    fn add_file<S: Source + ?Sized>(
        &mut self,
        idx: &Index<'_, S>,
        id: u32,
        hash: u64,
        path: &[u8],
        scratch: &mut [u8; PATH_BUF],
    ) -> Result<()> {
        let hashes = &*self.hash;
        for other in probe(self.slots, hash, |v| hashes[v as usize - 1]) {
            let other_path = idx.path(&idx.record(other)?, scratch)?;
            if folded_eq(other_path, path) {
                return Err(Error::Invalid);
            }
            push_collide(self.collide, &mut self.collide_len, other)?;
            push_collide(self.collide, &mut self.collide_len, id)?;
        }
        insert(self.slots, hash, id)
    }

    /// The directory of `path` (its key up to the last `/`), adding it and
    /// any missing ancestor. The part of the key `path` shares with `prev`
    /// is `prev_dir`'s chain, found by walking up from it with no probe.
    fn add_dirs<S: Source + ?Sized>(
        &mut self,
        idx: &Index<'_, S>,
        id: u32,
        path: &[u8],
        prev: Option<&[u8]>,
        prev_dir: u32,
        scratch: &mut [u8; PATH_BUF],
    ) -> Result<u32> {
        let dir_len = path
            .iter()
            .rposition(|&c| c == b'/')
            .ok_or(Error::Invalid)?;
        let (mut d, known) = match prev {
            Some(prev) if prev_dir != NONE => {
                let common = path
                    .iter()
                    .zip(prev)
                    .take_while(|(&x, &y)| folded(x) == folded(y))
                    .count();
                let shared = (ROOT_LEN..=dir_len)
                    .rev()
                    .find(|&c| {
                        path[c] == b'/'
                            && (c < common || (c == common && prev.get(c) == Some(&b'/')))
                    })
                    .ok_or(Error::Invalid)?;
                let mut d = prev_dir;
                while d != NONE && usize::from(self.dirs[d as usize - 1].key_len) > shared {
                    d = self.dirs[d as usize - 1].parent;
                }
                (d, shared)
            }
            _ => (
                self.find_or_add(idx, id, path, ROOT_LEN, NONE, scratch)?,
                ROOT_LEN,
            ),
        };
        if d == NONE {
            return Err(Error::Invalid);
        }
        for k in known + 1..=dir_len {
            if path[k] == b'/' {
                d = self.find_or_add(idx, id, path, k, d, scratch)?;
            }
        }
        Ok(d)
    }

    /// Directory `path[..k]` under `parent`; a hash match is confirmed
    /// against its representative file's path.
    fn find_or_add<S: Source + ?Sized>(
        &mut self,
        idx: &Index<'_, S>,
        id: u32,
        path: &[u8],
        k: usize,
        parent: u32,
        scratch: &mut [u8; PATH_BUF],
    ) -> Result<u32> {
        let key = &path[..k];
        let hash = idx_path_hash(key);
        let dirs = &*self.dirs;
        for d in probe(self.dir_slots, hash, |v| dirs[v as usize - 1].hash) {
            let dir = dirs[d as usize - 1];
            if usize::from(dir.key_len) == k {
                let rep = idx.path(&idx.record(dir.rep_file)?, scratch)?;
                if rep.len() > k && folded_eq(&rep[..k], key) {
                    return Ok(d);
                }
            }
        }
        if self.dir_count as usize == self.dirs.len() {
            return Err(Error::OutOfRange);
        }
        self.dir_count += 1;
        let d = self.dir_count;
        let sibling = match parent {
            NONE => NONE,
            p => core::mem::replace(&mut self.dirs[p as usize - 1].first_dir, d),
        };
        self.dirs[d as usize - 1] = Dir {
            hash,
            parent,
            next_sibling: sibling,
            rep_file: id,
            key_len: k as u16,
            ..Dir::default()
        };
        insert(self.dir_slots, hash, d).map(|()| d)
    }

    pub fn files(&self) -> u32 {
        self.hash.len() as u32
    }

    pub fn size(&self, id: u32) -> u64 {
        at(self.size, id).unwrap_or(0)
    }

    /// The file id of `hash`, `None` for no file or a hash on the collision
    /// list (the join then has no row for it).
    pub fn find_hash(&self, hash: u64) -> Option<u32> {
        let hashes = &*self.hash;
        let id = probe(self.slots, hash, |v| hashes[v as usize - 1]).next()?;
        (self.collide[..self.collide_len].binary_search(&id).is_err()).then_some(id)
    }

    /// Sets file `id`'s first zstd chunk; ignored without a chunk column.
    pub fn set_chunk(&mut self, id: u32, first: u32) {
        if let Some(c) = index_of(id).and_then(|i| self.chunk.get_mut(i)) {
            *c = first;
        }
    }

    /// Puts file `id` on its directory's packed chain and flags the
    /// directory and its ancestors `DIR_PACKED`. Once per file: a second
    /// call, or one without a `next` column, does nothing and answers
    /// false, so a join counts each row once.
    pub fn link_packed(&mut self, id: u32) -> bool {
        let Some(i) = index_of(id).filter(|&i| i < self.next.len()) else {
            return false;
        };
        let d = self.dir_of[i];
        if self.next[i] != UNLINKED || d == NONE {
            return false;
        }
        self.next[i] = core::mem::replace(&mut self.dirs[d as usize - 1].first_file, id);
        let mut d = d;
        while d != NONE && self.dirs[d as usize - 1].flags & DIR_PACKED == 0 {
            self.dirs[d as usize - 1].flags |= DIR_PACKED;
            d = self.dirs[d as usize - 1].parent;
        }
        true
    }

    /// `pak_path_hash` of file `id`'s path; 0 without the LZ4 column.
    pub fn lz4_hash(&self, id: u32) -> u64 {
        at(self.lz4_hash, id).unwrap_or(0)
    }

    /// File `id`'s directory id, for tests.
    #[cfg(test)]
    pub(crate) fn dir_of(&self, id: u32) -> u32 {
        at(self.dir_of, id).unwrap_or(NONE)
    }

    /// Undoes every `link_packed` and `set_chunk`: all files loose, no
    /// directory `DIR_PACKED`. For a pack mount that failed after linking
    /// some rows.
    pub fn unlink_all(&mut self) {
        self.next.fill(UNLINKED);
        self.chunk.fill(NO_CHUNK);
        for d in self.dirs[..self.dir_count as usize].iter_mut() {
            d.first_file = NONE;
            d.flags &= !DIR_PACKED;
        }
    }

    /// The read-only view; the transient columns are no longer used.
    pub fn finish(self) -> View<'a> {
        let (dirs, collide): (&'a [Dir], &'a [u32]) = (self.dirs, self.collide);
        View {
            hash: self.hash,
            size: self.size,
            mtime: self.mtime,
            path_at: self.path_at,
            next: self.next,
            chunk: self.chunk,
            slots: self.slots,
            dirs: &dirs[..self.dir_count as usize],
            dir_slots: self.dir_slots,
            collide: &collide[..self.collide_len],
        }
    }
}

fn index_of(id: u32) -> Option<usize> {
    (id as usize).checked_sub(1)
}

fn at<T: Copy>(column: &[T], id: u32) -> Option<T> {
    column.get(index_of(id)?).copied()
}

// ---- view ----

/// The built view, read-only. Accessors answer 0, `NO_CHUNK`, false or a
/// default `Dir` for an id out of range.
#[derive(Clone, Copy)]
pub struct View<'a> {
    hash: &'a [u64],
    size: &'a [u64],
    mtime: &'a [i64],
    path_at: &'a [u32],
    next: &'a [u32],
    chunk: &'a [u32],
    slots: &'a [u32],
    dirs: &'a [Dir],
    dir_slots: &'a [u32],
    collide: &'a [u32],
}

impl<'a> View<'a> {
    pub fn files(&self) -> u32 {
        self.hash.len() as u32
    }

    pub fn dir_count(&self) -> u32 {
        self.dirs.len() as u32
    }

    pub fn size(&self, id: u32) -> u64 {
        at(self.size, id).unwrap_or(0)
    }

    pub fn mtime(&self, id: u32) -> i64 {
        at(self.mtime, id).unwrap_or(0)
    }

    /// First zstd chunk of file `id`; `NO_CHUNK` when loose or not zstd.
    pub fn chunk(&self, id: u32) -> u32 {
        at(self.chunk, id).unwrap_or(NO_CHUNK)
    }

    /// Whether a join linked file `id` with `Builder::link_packed`.
    pub fn packed(&self, id: u32) -> bool {
        at(self.next, id).is_some_and(|n| n != UNLINKED)
    }

    pub fn dir(&self, id: u32) -> Dir {
        at(self.dirs, id).unwrap_or_default()
    }

    /// The next packed file of file `id`'s directory, `NONE` at the end.
    pub(crate) fn next_file(&self, id: u32) -> u32 {
        at(self.next, id).filter(|&n| n != UNLINKED).unwrap_or(NONE)
    }

    /// Every directory record, id `i + 1` at `i`.
    pub(crate) fn dirs(&self) -> &'a [Dir] {
        self.dirs
    }

    /// Absolute offset of file `id`'s path in the index file.
    pub(crate) fn path_at(&self, id: u32) -> Option<u32> {
        at(self.path_at, id)
    }

    /// File `id`'s path hash, 0 for no file.
    pub(crate) fn hash(&self, id: u32) -> u64 {
        at(self.hash, id).unwrap_or(0)
    }

    /// File ids whose path hash is `hash`, in probe order.
    pub(crate) fn files_by_hash(&self, hash: u64) -> impl Iterator<Item = u32> + 'a {
        let hashes = self.hash;
        probe(self.slots, hash, move |v| hashes[v as usize - 1])
    }

    /// Directory ids whose key hash is `hash`, in probe order.
    pub(crate) fn dirs_by_hash(&self, hash: u64) -> impl Iterator<Item = u32> + 'a {
        let dirs = self.dirs;
        probe(self.dir_slots, hash, move |v| dirs[v as usize - 1].hash)
    }

    /// Whether another file shares file `id`'s hash (its path must be read).
    pub(crate) fn collides(&self, id: u32) -> bool {
        self.collide.binary_search(&id).is_ok()
    }

    /// Sorted ids whose hash another file shares, for tests.
    #[cfg(test)]
    pub(crate) fn collide_list(&self) -> &'a [u32] {
        self.collide
    }

    /// What the normalized `key` names: files are probed first, then
    /// directories, as `Index::find` before `Index::find_directory`. The
    /// source is read only for a file on the collision list, or when two
    /// directories of the key's length share its hash; any other hash
    /// match is the answer.
    pub fn lookup<S: Source + ?Sized>(&self, src: &S, key: &[u8]) -> Result<Hit> {
        let hash = idx_path_hash(key);
        let mut buf = [0u8; PATH_BUF];
        for id in self.files_by_hash(hash) {
            if !self.collides(id) || folded_eq(self.path(src, id, &mut buf)?, key) {
                return Ok(Hit::File(id));
            }
        }
        Ok(self.lookup_dir(src, key)?.map_or(Hit::Miss, Hit::Dir))
    }

    /// The directory the normalized `key` names, files not probed: a file
    /// and a directory can share one folded key (file `a` beside directory
    /// `A/`), and `lookup` answers the file there. The source is read only
    /// when two directories of the key's length share its hash.
    pub fn lookup_dir<S: Source + ?Sized>(&self, src: &S, key: &[u8]) -> Result<Option<u32>> {
        let hash = idx_path_hash(key);
        let len_ok = |d: &u32| usize::from(self.dir(*d).key_len) == key.len();
        let mut dirs = self.dirs_by_hash(hash).filter(len_ok);
        let Some(first) = dirs.next() else {
            return Ok(None);
        };
        if dirs.next().is_none() {
            return Ok(Some(first));
        }
        let mut buf = [0u8; PATH_BUF];
        for d in self.dirs_by_hash(hash).filter(len_ok) {
            if folded_eq(self.dir_path(src, d, &mut buf)?, key) {
                return Ok(Some(d));
            }
        }
        Ok(None)
    }

    /// File `id`'s stored path, read at `path_at` up to its NUL in one
    /// read. `build` checked the path is shorter than `PATH_BUF`, so path
    /// and NUL fit; no NUL in the read is `Invalid`, as is an id out of
    /// range.
    pub fn path<'b, S: Source + ?Sized>(
        &self,
        src: &S,
        id: u32,
        buf: &'b mut [u8; PATH_BUF],
    ) -> Result<&'b [u8]> {
        let at = u64::from(self.path_at(id).ok_or(Error::Invalid)?);
        let left = src.len().checked_sub(at).ok_or(Error::Invalid)?;
        let n = usize::try_from(left).map_or(PATH_BUF, |l| l.min(PATH_BUF));
        src.read_at(at, &mut buf[..n])?;
        let len = buf[..n]
            .iter()
            .position(|&c| c == 0)
            .ok_or(Error::Invalid)?;
        Ok(&buf[..len])
    }

    /// Directory `dir`'s stored spelling: its representative file's path
    /// cut to the key length, so the case is the one that file was stored
    /// with.
    pub fn dir_path<'b, S: Source + ?Sized>(
        &self,
        src: &S,
        dir: u32,
        buf: &'b mut [u8; PATH_BUF],
    ) -> Result<&'b [u8]> {
        let d = at(self.dirs, dir).ok_or(Error::Invalid)?;
        let path = self.path(src, d.rep_file, buf)?;
        path.get(..usize::from(d.key_len)).ok_or(Error::Invalid)
    }

    /// File `id`'s stored path when it folds to `key`, else `None`: a hash
    /// hit becomes exact before a loose file's real call.
    pub fn confirm<'b, S: Source + ?Sized>(
        &self,
        src: &S,
        id: u32,
        key: &[u8],
        buf: &'b mut [u8; PATH_BUF],
    ) -> Result<Option<&'b [u8]>> {
        let path = self.path(src, id, buf)?;
        Ok(folded_eq(path, key).then_some(path))
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use crate::idx_path_hash_parts;
    use crate::index::{
        read_layout,
        tests::{image, Counting},
    };
    use core::cell::Cell;
    use std::collections::HashSet;
    use std::vec::Vec;
    use std::{format, vec};

    /// Owned memory for every `Buffers` slice.
    struct Mem {
        hash: Vec<u64>,
        size: Vec<u64>,
        mtime: Vec<i64>,
        path_at: Vec<u32>,
        next: Vec<u32>,
        chunk: Vec<u32>,
        slots: Vec<u32>,
        dirs: Vec<Dir>,
        dir_slots: Vec<u32>,
        collide: Vec<u32>,
        dir_of: Vec<u32>,
        lz4_hash: Vec<u64>,
    }

    impl Mem {
        fn new(files: u32, dir_cap: u32, packs: Packs) -> Self {
            let sz = sizes(files, dir_cap).unwrap();
            let n = files as usize;
            let (next, chunk, lz4) = sz.pack_columns(packs);
            Mem {
                hash: vec![0; n],
                size: vec![0; n],
                mtime: vec![0; n],
                path_at: vec![0; n],
                next: vec![0; next],
                chunk: vec![0; chunk],
                slots: vec![7; sz.file_slots as usize],
                dirs: vec![Dir::default(); dir_cap as usize],
                dir_slots: vec![7; sz.dir_slots as usize],
                collide: vec![0; 256],
                dir_of: vec![0; n],
                lz4_hash: vec![0; lz4],
            }
        }

        fn bufs(&mut self) -> Buffers<'_> {
            Buffers {
                hash: &mut self.hash,
                size: &mut self.size,
                mtime: &mut self.mtime,
                path_at: &mut self.path_at,
                next: &mut self.next,
                chunk: &mut self.chunk,
                slots: &mut self.slots,
                dirs: &mut self.dirs,
                dir_slots: &mut self.dir_slots,
                collide: &mut self.collide,
                dir_of: &mut self.dir_of,
                lz4_hash: &mut self.lz4_hash,
            }
        }
    }

    /// An index view over `img` that skips `Index::check`, so `build`'s own
    /// checks are what refuses a bad image.
    fn unchecked(img: &[u8]) -> Index<'_, [u8]> {
        Index::view_validated(img, &read_layout(img).unwrap()).unwrap()
    }

    /// Byte offsets of every `/` from `/app0`'s on, up to the last one.
    fn dir_lens(path: &[u8]) -> Vec<usize> {
        let last = path.iter().rposition(|&c| c == b'/').unwrap();
        (ROOT_LEN..=last).filter(|&k| path[k] == b'/').collect()
    }

    #[test]
    fn parts_hash_equals_the_joined_hash() {
        let path: &[u8] = b"/app0/Data/Sub\\File.BIN";
        for cut in 0..=path.len() {
            let (a, b) = path.split_at(cut);
            assert_eq!(idx_path_hash_parts(&[a, b]), idx_path_hash(path));
        }
        assert_eq!(
            idx_path_hash_parts(&[b"/app0/", b"x/", b"", b"y.bin"]),
            idx_path_hash(b"/app0/x/y.bin")
        );
        assert_eq!(idx_path_hash_parts(&[]), idx_path_hash(b""));
    }

    /// 500 paths in mixed case under nested directories, out of order.
    fn unsorted_paths() -> Vec<Vec<u8>> {
        mixed_paths(500)
    }

    /// `n` paths in mixed case under nested directories, out of order
    /// (7919 is prime, so the order is a permutation for these `n`).
    fn mixed_paths(n: u32) -> Vec<Vec<u8>> {
        (0..n)
            .map(|i| (i * 7919) % n)
            .map(|i| {
                let top = if i % 2 == 0 { "Data" } else { "data" };
                let path = match i % 5 {
                    0 => format!("/app0/F{i}.bin"),
                    1 => format!("/app0/{top}/f{i}.bin"),
                    _ => format!("/app0/{top}/S{}/d{}/x{i}.bin", i % 7, i % 3),
                };
                path.into_bytes()
            })
            .collect()
    }

    #[test]
    fn build_fills_columns_and_directory_chains() {
        let paths = unsorted_paths();
        let refs: Vec<&[u8]> = paths.iter().map(|p| &p[..]).collect();
        let img = image(&refs);
        let idx = Index::open(&img[..]).unwrap();
        assert!(!idx.check().unwrap());
        let files = idx.len();
        let mut mem = Mem::new(files, files / 8 + 1024, Packs::Zstd);
        let b = build(&idx, mem.bufs()).unwrap();
        assert_eq!(b.files(), 500);
        let dir_of: Vec<u32> = (1..=files).map(|id| b.dir_of(id)).collect();
        assert_eq!(b.find_hash(idx_path_hash(b"/APP0/f0.BIN")), Some(1));
        let v = b.finish();
        assert_eq!(v.files(), 500);
        let mut keys = HashSet::new();
        for id in 1..=files {
            let rec = idx.record(id).unwrap();
            assert_eq!((v.size(id), v.mtime(id)), (rec.size, rec.mtime));
            assert_eq!(v.path_at(id), Some(rec.path_at as u32));
            assert_eq!(v.chunk(id), NO_CHUNK);
            assert!(!v.packed(id));
            let path = &paths[id as usize - 1];
            let mut d = dir_of[id as usize - 1];
            for &k in dir_lens(path).iter().rev() {
                let dir = v.dir(d);
                assert_eq!(usize::from(dir.key_len), k);
                assert_eq!(dir.hash, idx_path_hash(&path[..k]));
                let rep = &paths[dir.rep_file as usize - 1];
                assert!(folded_eq(&rep[..k], &path[..k]));
                keys.insert(path[..k].to_ascii_lowercase());
                d = dir.parent;
            }
            assert_eq!(d, NONE);
        }
        assert_eq!(v.dir_count() as usize, keys.len());
        assert!(v.collide_list().is_empty());
        let root = v.dirs_by_hash(idx_path_hash(b"/app0")).next().unwrap();
        let mut children = 0;
        let mut c = v.dir(root).first_dir;
        while c != NONE {
            assert_eq!(v.dir(c).parent, root);
            children += 1;
            c = v.dir(c).next_sibling;
        }
        assert_eq!(children, 1);
    }

    #[test]
    fn build_refuses_a_duplicate_folded_path() {
        let img = image(&[b"/app0/A/x.bin", b"/app0/b.bin", b"/app0/a/X.BIN"]);
        let idx = unchecked(&img);
        let mut mem = Mem::new(3, 16, Packs::None);
        assert_eq!(build(&idx, mem.bufs()).err(), Some(Error::Invalid));
    }

    #[test]
    fn build_refuses_more_directories_than_its_capacity() {
        let img = image(&[b"/app0/a/x.bin", b"/app0/b/y.bin", b"/app0/c/z.bin"]);
        let idx = Index::open(&img[..]).unwrap();
        let mut mem = Mem::new(3, 3, Packs::None);
        assert_eq!(build(&idx, mem.bufs()).err(), Some(Error::OutOfRange));
        let mut mem = Mem::new(3, 4, Packs::None);
        assert_eq!(build(&idx, mem.bufs()).unwrap().finish().dir_count(), 4);
    }

    #[test]
    fn link_packed_flags_every_ancestor_once() {
        let img = image(&[b"/app0/a/b/c/x.bin", b"/app0/a/y.bin", b"/app0/q/z.bin"]);
        let idx = Index::open(&img[..]).unwrap();
        let mut mem = Mem::new(3, 8, Packs::Lz4);
        let mut b = build(&idx, mem.bufs()).unwrap();
        assert_eq!(b.lz4_hash(2), pak_path_hash(b"/app0/a/y.bin"));
        b.set_chunk(1, 9);
        b.link_packed(1);
        b.link_packed(1);
        let deep = b.dir_of(1);
        let v = b.finish();
        assert_eq!(v.chunk(1), NO_CHUNK);
        assert!(v.packed(1) && !v.packed(2) && !v.packed(3));
        assert_eq!((v.dir(deep).first_file, v.next_file(1)), (1, NONE));
        let mut d = deep;
        while d != NONE {
            assert_eq!(v.dir(d).flags & DIR_PACKED, DIR_PACKED);
            d = v.dir(d).parent;
        }
        let q = v.dirs_by_hash(idx_path_hash(b"/app0/q")).next().unwrap();
        assert_eq!(v.dir(q).flags, 0);
        assert_eq!(v.dir(q).first_file, NONE);
    }

    #[test]
    fn unlink_all_leaves_every_file_loose() {
        let img = image(&[b"/app0/a/b/x.bin", b"/app0/a/y.bin", b"/app0/q/z.bin"]);
        let idx = Index::open(&img[..]).unwrap();
        let mut mem = Mem::new(3, 8, Packs::Zstd);
        let mut b = build(&idx, mem.bufs()).unwrap();
        for id in 1..=2 {
            b.set_chunk(id, id * 10);
            assert!(b.link_packed(id));
        }
        b.unlink_all();
        // A relink after the reset works, as for a fresh builder.
        assert!(b.link_packed(3));
        let v = b.finish();
        for id in 1..=2 {
            assert!(!v.packed(id));
            assert_eq!(v.chunk(id), NO_CHUNK);
        }
        assert!(v.packed(3));
        let a = v.dirs_by_hash(idx_path_hash(b"/app0/a")).next().unwrap();
        assert_eq!((v.dir(a).flags, v.dir(a).first_file), (0, NONE));
    }

    // ---- lookups ----

    /// A `Counting` source over `img` with no reads yet.
    fn counting(img: &[u8]) -> Counting {
        Counting {
            bytes: img.to_vec(),
            reads: Cell::new(0),
            fail: Cell::new(false),
        }
    }

    /// Gives file `to` file `from`'s hash, as a real collision would, by
    /// rewriting the hash column, the file slots and the collision list.
    fn share_hash(b: &mut Builder<'_>, from: u32, to: u32) {
        b.hash[to as usize - 1] = b.hash[from as usize - 1];
        b.slots.fill(NONE);
        for id in 1..=b.files() {
            insert(b.slots, b.hash[id as usize - 1], id).unwrap();
        }
        push_collide(b.collide, &mut b.collide_len, from).unwrap();
        push_collide(b.collide, &mut b.collide_len, to).unwrap();
        b.collide[..b.collide_len].sort_unstable();
    }

    #[test]
    fn lookup_agrees_with_find_and_find_directory() {
        let paths = mixed_paths(2000);
        let refs: Vec<&[u8]> = paths.iter().map(|p| &p[..]).collect();
        let img = image(&refs);
        let idx = Index::open(&img[..]).unwrap();
        assert!(!idx.check().unwrap());
        let files = idx.len();
        let mut mem = Mem::new(files, files / 8 + 1024, Packs::None);
        let v = build(&idx, mem.bufs()).unwrap().finish();
        let src = counting(&img);
        let mut buf = [0u8; PATH_BUF];
        let mut dir_keys = HashSet::new();
        for p in &paths {
            let id = idx.find(p).unwrap().unwrap();
            assert_eq!(v.lookup(&src, p).unwrap(), Hit::File(id));
            let upper = p.to_ascii_uppercase();
            assert_eq!(v.lookup(&src, &upper).unwrap(), Hit::File(id));
            for k in dir_lens(p) {
                dir_keys.insert(p[..k].to_ascii_lowercase());
            }
        }
        assert_eq!(src.reads.get(), 0);
        assert_eq!(dir_keys.len(), v.dir_count() as usize);
        for key in &dir_keys {
            // `find` refuses `/app0` itself, which is no logical file path.
            assert!(!matches!(idx.find(key), Ok(Some(_))));
            assert!(idx.find_directory(key, false).unwrap().is_some());
            let Hit::Dir(d) = v.lookup(&src, key).unwrap() else {
                panic!(
                    "no directory for {:?}",
                    std::string::String::from_utf8_lossy(key)
                );
            };
            assert!(folded_eq(v.dir_path(&src, d, &mut buf).unwrap(), key));
        }
        let misses: [&[u8]; 6] = [
            b"/app0/nothing.bin",
            b"/app0/data/s9",
            b"/app0/data/f1.bin/x",
            b"/app0/dat",
            b"/app0/data/s1/d1/x2.bin",
            b"/app0/zz/yy",
        ];
        for key in misses {
            assert_eq!(idx.find(key).unwrap(), None);
            assert_eq!(idx.find_directory(key, false).unwrap(), None);
            assert_eq!(v.lookup(&src, key).unwrap(), Hit::Miss);
        }
    }

    #[test]
    fn lookup_reads_paths_only_for_a_collision() {
        let names: [&[u8]; 3] = [b"/app0/a/One.bin", b"/app0/a/two.bin", b"/app0/b.bin"];
        let img = image(&names);
        let idx = Index::open(&img[..]).unwrap();
        let src = counting(&img);
        // File 2 takes file 1's hash: a key of either path probes both.
        for (from, to) in [(1, 2), (2, 1)] {
            let mut mem = Mem::new(3, 8, Packs::None);
            let mut b = build(&idx, mem.bufs()).unwrap();
            share_hash(&mut b, from, to);
            let v = b.finish();
            assert_eq!(v.collide_list(), &[1, 2]);
            src.reads.set(0);
            let key = names[from as usize - 1].to_ascii_lowercase();
            assert_eq!(v.lookup(&src, &key).unwrap(), Hit::File(from));
            assert!(src.reads.get() > 0);
            src.reads.set(0);
            assert_eq!(v.lookup(&src, b"/app0/B.BIN").unwrap(), Hit::File(3));
            assert_eq!(
                v.lookup(&src, b"/app0/a").unwrap(),
                Hit::Dir(v.dir(1).first_dir)
            );
            assert_eq!(src.reads.get(), 0);
            src.fail.set(true);
            assert_eq!(v.lookup(&src, &key).err(), Some(Error::Io));
            src.fail.set(false);
        }
    }

    #[test]
    fn lookup_dir_finds_a_directory_beside_a_file_of_its_key() {
        let names: [&[u8]; 3] = [b"/app0/a", b"/app0/A/x", b"/app0/b.bin"];
        let img = image(&names);
        let idx = Index::open(&img[..]).unwrap();
        let mut mem = Mem::new(3, 8, Packs::None);
        let v = build(&idx, mem.bufs()).unwrap().finish();
        let src = counting(&img);
        let mut buf = [0u8; PATH_BUF];
        assert_eq!(v.lookup(&src, b"/app0/a").unwrap(), Hit::File(1));
        let d = v.lookup_dir(&src, b"/app0/a").unwrap().unwrap();
        assert_eq!(v.dir_path(&src, d, &mut buf).unwrap(), b"/app0/A");
        assert_eq!(v.lookup_dir(&src, b"/APP0/A").unwrap(), Some(d));
        assert_eq!(v.lookup_dir(&src, b"/app0/b.bin").unwrap(), None);
        assert_eq!(v.lookup_dir(&src, b"/app0/A/x").unwrap(), None);
        let Hit::Dir(root) = v.lookup(&src, b"/app0").unwrap() else {
            panic!("no root");
        };
        assert_eq!(v.lookup_dir(&src, b"/app0").unwrap(), Some(root));
    }

    #[test]
    fn dir_path_and_confirm_keep_the_stored_case() {
        let names: [&[u8]; 3] = [
            b"/app0/Some/Dir/X.bin",
            b"/app0/some/DIR/y.bin",
            b"/app0/z.bin",
        ];
        let img = image(&names);
        let idx = Index::open(&img[..]).unwrap();
        let mut mem = Mem::new(3, 8, Packs::None);
        let v = build(&idx, mem.bufs()).unwrap().finish();
        let src = &img[..];
        let mut buf = [0u8; PATH_BUF];
        let Hit::Dir(d) = v.lookup(src, b"/app0/some/dir").unwrap() else {
            panic!("no directory");
        };
        assert_eq!(v.dir_path(src, d, &mut buf).unwrap(), b"/app0/Some/Dir");
        let Hit::Dir(root) = v.lookup(src, b"/app0").unwrap() else {
            panic!("no root");
        };
        assert_eq!(v.dir_path(src, root, &mut buf).unwrap(), b"/app0");
        assert_eq!(v.path(src, 2, &mut buf).unwrap(), names[1]);
        let hit = v
            .confirm(src, 2, b"/app0/some/dir/y.bin", &mut buf)
            .unwrap();
        assert_eq!(hit, Some(names[1]));
        assert_eq!(
            v.confirm(src, 2, b"/app0/some/dir/x.bin", &mut buf)
                .unwrap(),
            None
        );
        assert_eq!(
            v.confirm(src, 2, b"/app0/some/dir/y.bi", &mut buf).unwrap(),
            None
        );
        assert_eq!(v.path(src, 4, &mut buf).err(), Some(Error::Invalid));
        assert_eq!(v.dir_path(src, 99, &mut buf).err(), Some(Error::Invalid));
    }
}
