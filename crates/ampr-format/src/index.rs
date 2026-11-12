//! AMPRIDX3 fixed records, path blob, and open-addressed hash slots.
use crate::index_key::{
    compare, compare_dir_prefix, is_descendant, NAME_MAX, PATH_MAX, RUNTIME_KEY_CAPACITY,
};
use crate::source::{src_bytes, Source, PATH_BUF};
use crate::{
    folded, i64_at, idx_path_hash, logical_path, u32_at, u64_at, Error, Result, IDX_HEADER,
    IDX_MAGIC, IDX_RECORD, IDX_SLOT,
};
use core::cmp::Ordering;

const MAX_RECORDS: u64 = 2_000_000;
const MAX_PATH_BYTES: u64 = 256 << 20;

/// A record by value: the path stays in the source at `path_at` (absolute
/// offset, NUL-terminated) and is copied out with `Index::path`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Record {
    pub path_at: u64,
    pub path_len: u32,
    pub size: u64,
    pub mtime: i64,
}

/// File geometry declared by a checked AMPRIDX3 header. Offsets are from the
/// start of the file; `payload_len` spans records through the hash slots.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Layout {
    pub count: u64,
    pub records_len: u64,
    pub paths_at: u64,
    pub path_bytes: u64,
    pub slots_at: u64,
    pub slot_count: u32,
    pub slots_len: u64,
    pub file_len: u64,
}

impl Layout {
    /// Every header check `Index::open` relies on, before any section is read.
    pub fn parse(header: &[u8]) -> Result<Self> {
        if header.len() != IDX_HEADER || header.get(..8) != Some(IDX_MAGIC) {
            return Err(Error::Invalid);
        }
        if u32_at(header, 8)? != 3
            || u32_at(header, 12)? != IDX_RECORD as u32
            || u32_at(header, 40)? != IDX_SLOT as u32
        {
            return Err(Error::Invalid);
        }
        let count = u64_at(header, 16)?;
        let path_bytes = u64_at(header, 24)?;
        let slots_at = u64_at(header, 32)?;
        let slot_count = u32_at(header, 44)?;
        if !(1..=MAX_RECORDS).contains(&count)
            || !(1..=MAX_PATH_BYTES).contains(&path_bytes)
            || slot_count < 2
            || !slot_count.is_power_of_two()
            || u64::from(slot_count) < count
        {
            return Err(Error::Invalid);
        }
        let records_len = count * IDX_RECORD as u64;
        let paths_at = IDX_HEADER as u64 + records_len;
        if slots_at < paths_at + path_bytes || slots_at % 8 != 0 {
            return Err(Error::Invalid);
        }
        let slots_len = u64::from(slot_count) * IDX_SLOT as u64;
        let file_len = slots_at.checked_add(slots_len).ok_or(Error::Invalid)?;
        Ok(Self {
            count,
            records_len,
            paths_at,
            path_bytes,
            slots_at,
            slot_count,
            slots_len,
            file_len,
        })
    }
}

/// Applies the limits of key normalization, which rejects inputs of
/// PATH_MAX bytes or components over NAME_MAX.
fn kernel_path_limits(path: &[u8]) -> bool {
    path.len() < PATH_MAX && path.split(|&b| b == b'/').all(|c| c.len() <= NAME_MAX)
}

/// Hash slot count: next power of two >= 2 * entries.
pub fn slot_count_for(entries: usize) -> Option<usize> {
    if entries == 0 || entries >= u32::MAX as usize {
        return None;
    }
    entries.checked_mul(2)?.max(2).checked_next_power_of_two()
}

fn put_u32(b: &mut [u8], at: usize, v: u32) -> Result<()> {
    b.get_mut(at..at + 4)
        .ok_or(Error::Truncated)?
        .copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// Inserts every record into the hash slots, for the runtime
/// builder. `slots` must be zeroed. Returns (total probe steps, max probe).
pub fn fill_slots(records: &[u8], paths: &[u8], slots: &mut [u8]) -> Result<(u64, u64)> {
    let slot_count = slots.len() / IDX_SLOT;
    if records.len() % IDX_RECORD != 0
        || slots.len() % IDX_SLOT != 0
        || slot_count < 2
        || !slot_count.is_power_of_two()
        || records.len() / IDX_RECORD >= u32::MAX as usize
    {
        return Err(Error::Invalid);
    }
    let mask = slot_count - 1;
    let (mut steps, mut max) = (0u64, 0u64);
    for i in 0..records.len() / IDX_RECORD {
        let off = u32_at(records, i * IDX_RECORD)? as usize;
        let len = u32_at(records, i * IDX_RECORD + 4)? as usize;
        let end = off.checked_add(len).ok_or(Error::Invalid)?;
        if paths.get(end) != Some(&0) {
            return Err(Error::Invalid);
        }
        let hash = idx_path_hash(paths.get(off..end).ok_or(Error::Invalid)?);
        let mut pos = hash as usize & mask;
        let mut duplicate = false;
        let mut probe = 0u64;
        while u32_at(slots, pos * IDX_SLOT + 8)? != 0 {
            if u64_at(slots, pos * IDX_SLOT)? == hash {
                let flags = u32_at(slots, pos * IDX_SLOT + 12)?;
                put_u32(slots, pos * IDX_SLOT + 12, flags | 1)?;
                duplicate = true;
            }
            pos = (pos + 1) & mask;
            probe += 1;
            if probe > mask as u64 {
                return Err(Error::Invalid);
            }
        }
        let at = pos * IDX_SLOT;
        slots[at..at + 8].copy_from_slice(&hash.to_le_bytes());
        put_u32(slots, at + 8, i as u32 + 1)?;
        put_u32(slots, at + 12, u32::from(duplicate))?;
        steps += probe;
        max = max.max(probe);
    }
    Ok((steps, max))
}

/// One fast table entry: a record's path hash and its one-based id, 12 B
/// (three `u32`, so a table of them packs with no padding).
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FastEntry {
    hash_lo: u32,
    hash_hi: u32,
    id: u32,
}

impl FastEntry {
    pub fn hash(&self) -> u64 {
        u64::from(self.hash_lo) | u64::from(self.hash_hi) << 32
    }
    pub fn id(&self) -> u32 {
        self.id
    }
}

/// The checked header of `src`, read once: `Truncated` for an AMPRIDX3
/// shorter than its header, `Invalid` for anything else that is not one.
/// A loader calls it before it commits memory to the file.
pub fn read_layout<S: Source + ?Sized>(src: &S) -> Result<Layout> {
    if src.len() < IDX_HEADER as u64 {
        let mut magic = [0u8; 8];
        src.read_at(0, &mut magic).map_err(|_| Error::Invalid)?;
        return Err(if &magic == IDX_MAGIC {
            Error::Truncated
        } else {
            Error::Invalid
        });
    }
    let mut header = [0u8; IDX_HEADER];
    src.read_at(0, &mut header)?;
    Layout::parse(&header)
}

/// Reads records, paths and slots through `src` at absolute offsets of the
/// file layout, so the same reader serves a resident image and the
/// runtime's index page cache.
pub struct Index<'s, S: Source + ?Sized = [u8]> {
    src: &'s S,
    /// The fast table (`fill_fast`): every (hash, id) sorted by hash then
    /// id. With it `find` reads the source only to confirm a path whose
    /// hash matches, instead of probing the on-disk slots.
    fast: Option<&'s [FastEntry]>,
    layout: Layout,
    paths_at: u64,
    path_bytes: u64,
    slots_at: u64,
    count: u32,
    slot_count: u32,
}

impl<'s, S: Source + ?Sized> Index<'s, S> {
    /// Checks the header and every record and slot through the source.
    pub fn open(src: &'s S) -> Result<Self> {
        let layout = read_layout(src)?;
        let index = Self::view_validated(src, &layout)?;
        index.check()?;
        Ok(index)
    }

    /// A lookup view over a source whose content `open` (or an equivalent
    /// loader) already checked with this `layout`. O(1): it checks that the
    /// layout fits the source, not every record and slot.
    pub fn view_validated(src: &'s S, layout: &Layout) -> Result<Self> {
        if src.len() < layout.file_len
            || layout.count == 0
            || layout.count > MAX_RECORDS
            || layout.slot_count < 2
            || !layout.slot_count.is_power_of_two()
            || u64::from(layout.slot_count) < layout.count
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            src,
            fast: None,
            layout: *layout,
            paths_at: layout.paths_at,
            path_bytes: layout.path_bytes,
            slots_at: layout.slots_at,
            count: layout.count as u32,
            slot_count: layout.slot_count,
        })
    }

    pub fn len(&self) -> u32 {
        self.count
    }

    pub fn source(&self) -> &'s S {
        self.src
    }

    /// The checked header geometry (`open` parsed it once).
    pub fn layout(&self) -> Layout {
        self.layout
    }

    // ---- fast table ----

    /// Entries of the fast table: one per record.
    pub fn fast_len(&self) -> usize {
        self.count as usize
    }

    /// Fills the fast table from one sequential pass over the hash slots,
    /// 4 KiB per source read (no_std threads have small stacks), then sorts
    /// it. The slots already hold each record's hash, so no path is read.
    /// `Invalid` when `out` is not `fast_len` long, a slot is malformed
    /// (as `check` without a fast table refuses it) or the occupied slots
    /// do not number the records. `check` then ties each entry to its
    /// record's path.
    pub fn fill_fast(&self, out: &mut [FastEntry]) -> Result<()> {
        if out.len() != self.fast_len() {
            return Err(Error::Invalid);
        }
        let mut buf = [0u8; 4096];
        let per = buf.len() / IDX_SLOT;
        let total = u64::from(self.slot_count);
        let (mut n, mut pos) = (0usize, 0u64);
        while pos < total {
            let take = (total - pos).min(per as u64) as usize;
            let block = &mut buf[..take * IDX_SLOT];
            self.src
                .read_at(self.slots_at + pos * IDX_SLOT as u64, block)?;
            for slot in block.chunks_exact(IDX_SLOT) {
                let (hash, id, flags) = (u64_at(slot, 0)?, u32_at(slot, 8)?, u32_at(slot, 12)?);
                if id == 0 {
                    if hash != 0 || flags != 0 {
                        return Err(Error::Invalid);
                    }
                    continue;
                }
                if id > self.count || flags & !1 != 0 {
                    return Err(Error::Invalid);
                }
                *out.get_mut(n).ok_or(Error::Invalid)? = FastEntry {
                    hash_lo: hash as u32,
                    hash_hi: (hash >> 32) as u32,
                    id,
                };
                n += 1;
            }
            pos += take as u64;
        }
        if n != out.len() {
            return Err(Error::Invalid);
        }
        out.sort_unstable_by_key(|e| (e.hash(), e.id));
        Ok(())
    }

    /// Makes `find` use `fast` (filled by `fill_fast` from this index).
    /// O(1), as the runtime takes a view per lookup; `Invalid` when its
    /// length does not match.
    pub fn with_fast(mut self, fast: &'s [FastEntry]) -> Result<Self> {
        if fast.len() != self.fast_len() {
            return Err(Error::Invalid);
        }
        self.fast = Some(fast);
        Ok(self)
    }

    /// Whether `find` searches the resident fast table.
    pub fn has_fast(&self) -> bool {
        self.fast.is_some()
    }

    /// One-based record `id`. Bounds are checked (the path and its NUL fit
    /// the path blob, the path is shorter than `PATH_BUF`); the path bytes
    /// are not read, `open` checked them.
    pub fn record(&self, id: u32) -> Result<Record> {
        if id == 0 || id > self.count {
            return Err(Error::OutOfRange);
        }
        let at = IDX_HEADER as u64 + u64::from(id - 1) * IDX_RECORD as u64;
        let mut r = [0u8; IDX_RECORD];
        self.src.read_at(at, &mut r)?;
        let off = u32_at(&r, 0)?;
        let len = u32_at(&r, 4)?;
        if len as usize >= PATH_BUF || u64::from(off) + u64::from(len) >= self.path_bytes {
            return Err(Error::Invalid);
        }
        Ok(Record {
            path_at: self.paths_at + u64::from(off),
            path_len: len,
            size: u64_at(&r, 8)?,
            mtime: i64_at(&r, 16)?,
        })
    }

    /// Copies `rec`'s path (without its NUL) into `buf`; `Invalid` when it
    /// does not fit.
    pub fn path<'b>(&self, rec: &Record, buf: &'b mut [u8]) -> Result<&'b [u8]> {
        src_bytes(self.src, rec.path_at, rec.path_len as usize, buf)
    }

    /// The slot at `pos`: (hash, id plus one, flags).
    fn slot(&self, pos: u32) -> Result<(u64, u32, u32)> {
        let mut s = [0u8; IDX_SLOT];
        self.src
            .read_at(self.slots_at + u64::from(pos) * IDX_SLOT as u64, &mut s)?;
        Ok((u64_at(&s, 0)?, u32_at(&s, 8)?, u32_at(&s, 12)?))
    }
}

impl<S: Source + ?Sized> Index<'_, S> {
    /// The record's path with its NUL checked, no NUL inside, logical and
    /// within the kernel path limits.
    fn checked_path<'b>(&self, rec: &Record, buf: &'b mut [u8; PATH_BUF]) -> Result<&'b [u8]> {
        let mut nul = [1u8];
        self.src
            .read_at(rec.path_at + u64::from(rec.path_len), &mut nul)?;
        let path = self.path(rec, buf)?;
        if nul[0] != 0 || path.contains(&0) || !logical_path(path) || !kernel_path_limits(path) {
            return Err(Error::Invalid);
        }
        Ok(path)
    }

    /// Checks every record path and that each record is the lookup's
    /// answer for its path, and returns whether the records are in folded
    /// order (ties allowed), from the same pass over the paths. With a fast
    /// table (`with_fast`, filled by `fill_fast`, which checked the slots'
    /// form) the slots are not read again: each path's hash must be in the
    /// table under its id, and records whose hashes collide must not fold
    /// to one path, so a paged index is checked in one sequential pass.
    /// Without one, every slot is checked and every record is found
    /// through its probe chain.
    pub fn check(&self) -> Result<bool> {
        let mut bufs = [[0u8; PATH_BUF]; 2];
        let (mut sorted, mut previous) = (true, None);
        for id in 1..=self.count {
            let [a, b] = &mut bufs;
            let (cur, prev) = if id & 1 == 0 { (a, &*b) } else { (b, &*a) };
            let path = self.checked_path(&self.record(id)?, cur)?;
            if previous.is_some_and(|n: usize| compare(&prev[..n], path) == Ordering::Greater) {
                sorted = false;
            }
            previous = Some(path.len());
            if let Some(fast) = self.fast {
                let key = (idx_path_hash(path), id);
                if fast
                    .binary_search_by_key(&key, |e| (e.hash(), e.id))
                    .is_err()
                {
                    return Err(Error::Invalid);
                }
            }
        }
        let [buf, key] = &mut bufs;
        match self.fast {
            Some(fast) => self.check_collisions(fast, buf, key)?,
            None => self.check_slots(buf, key)?,
        }
        Ok(sorted)
    }

    /// No two records of one hash in the fast table fold to one path (the
    /// first would hide the second). Reads paths only for colliding hashes.
    fn check_collisions(
        &self,
        fast: &[FastEntry],
        buf: &mut [u8; PATH_BUF],
        key: &mut [u8; PATH_BUF],
    ) -> Result<()> {
        for (i, e) in fast.iter().enumerate() {
            let run = fast[i + 1..].iter().take_while(|o| o.hash() == e.hash());
            if run.clone().next().is_none() {
                continue;
            }
            let path = self.path(&self.record(e.id)?, key)?;
            for o in run {
                if folded_eq(self.path(&self.record(o.id)?, buf)?, path) {
                    return Err(Error::Invalid);
                }
            }
        }
        Ok(())
    }

    /// Every slot, and every record reachable through its probe chain with
    /// no duplicate folded path claiming the lookup.
    fn check_slots(&self, buf: &mut [u8; PATH_BUF], key: &mut [u8; PATH_BUF]) -> Result<()> {
        let mut occupied = 0u32;
        for pos in 0..self.slot_count {
            let (hash, id, flags) = self.slot(pos)?;
            if id == 0 {
                if hash != 0 || flags != 0 {
                    return Err(Error::Invalid);
                }
                continue;
            }
            if id > self.count || flags & !1 != 0 {
                return Err(Error::Invalid);
            }
            if hash != idx_path_hash(self.path(&self.record(id)?, buf)?) {
                return Err(Error::Invalid);
            }
            occupied += 1;
        }
        if occupied != self.count {
            return Err(Error::Invalid);
        }
        for id in 1..=self.count {
            let path = self.path(&self.record(id)?, key)?;
            if self.find_with(path, buf)? != Some(id) {
                return Err(Error::Invalid);
            }
        }
        Ok(())
    }

    /// Whether records are in folded order, ties allowed; false on a read
    /// error (`try_records_sorted` returns it).
    pub fn records_sorted(&self) -> bool {
        self.try_records_sorted().unwrap_or(false)
    }

    /// `records_sorted` with a read error returned.
    pub fn try_records_sorted(&self) -> Result<bool> {
        let mut bufs = [[0u8; PATH_BUF]; 2];
        let mut previous = None;
        for id in 1..=self.count {
            let [a, b] = &mut bufs;
            let (cur, prev) = if id & 1 == 0 { (a, &*b) } else { (b, &*a) };
            let path = self.path(&self.record(id)?, cur)?;
            if previous.is_some_and(|n: usize| compare(&prev[..n], path) == Ordering::Greater) {
                return Ok(false);
            }
            previous = Some(path.len());
        }
        Ok(true)
    }

    /// Finds a record below the normalized directory `key`. Sorted indexes
    /// probe only the lower bound of `key/`; unsorted runtime images fall
    /// back to a linear scan. A read error is returned, not a miss: the
    /// caller must not answer ENOENT for it.
    pub fn find_directory(&self, key: &[u8], sorted: bool) -> Result<Option<u32>> {
        let mut buf = [0u8; PATH_BUF];
        let (first, end) = if sorted {
            if key.len() > RUNTIME_KEY_CAPACITY - 2 {
                return Ok(None);
            }
            let (mut first, mut last) = (0u32, self.count);
            while first < last {
                let middle = first + (last - first) / 2;
                let rec = self.record(middle + 1)?;
                if compare_dir_prefix(self.path(&rec, &mut buf)?, key) == Ordering::Less {
                    first = middle + 1;
                } else {
                    last = middle;
                }
            }
            (first, (first + 1).min(self.count))
        } else {
            (0, self.count)
        };
        for id in first + 1..=end {
            if is_descendant(self.path(&self.record(id)?, &mut buf)?, key) {
                return Ok(Some(id));
            }
        }
        Ok(None)
    }

    /// Runtime-style lookup. The bounded probe also rejects a broken chain.
    pub fn find(&self, path: &[u8]) -> Result<Option<u32>> {
        self.find_with(path, &mut [0u8; PATH_BUF])
    }

    /// `find` with a caller path buffer. A record's path is read only on a
    /// slot whose hash matches.
    fn find_with(&self, path: &[u8], buf: &mut [u8; PATH_BUF]) -> Result<Option<u32>> {
        if !logical_path(path) {
            return Err(Error::Invalid);
        }
        let hash = idx_path_hash(path);
        if let Some(fast) = self.fast {
            // `open` refused two records of one folded path, so the first
            // match of the equal-hash run is the slot probe's answer.
            let mut at = fast.partition_point(|e| e.hash() < hash);
            while let Some(e) = fast.get(at).filter(|e| e.hash() == hash) {
                let rec = self.record(e.id)?;
                if rec.path_len as usize == path.len() && folded_eq(self.path(&rec, buf)?, path) {
                    return Ok(Some(e.id));
                }
                at += 1;
            }
            return Ok(None);
        }
        let mask = self.slot_count - 1;
        let mut pos = hash as u32 & mask;
        for _ in 0..self.slot_count {
            let (slot_hash, id, _) = self.slot(pos)?;
            if id == 0 {
                return Ok(None);
            }
            if slot_hash == hash {
                let rec = self.record(id)?;
                if rec.path_len as usize == path.len() && folded_eq(self.path(&rec, buf)?, path) {
                    return Ok(Some(id));
                }
            }
            pos = (pos + 1) & mask;
        }
        Ok(None)
    }
}

fn folded_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(&x, &y)| folded(x) == folded(y))
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use core::cell::Cell;
    use std::vec::Vec;

    /// An AMPRIDX3 image of `paths` (sizes 10, 20, ...), slots by `fill_slots`.
    fn image(paths: &[&[u8]]) -> Vec<u8> {
        let (mut records, mut blob) = (Vec::new(), Vec::new());
        for (i, p) in paths.iter().enumerate() {
            records.extend_from_slice(&(blob.len() as u32).to_le_bytes());
            records.extend_from_slice(&(p.len() as u32).to_le_bytes());
            records.extend_from_slice(&(10 * (i as u64 + 1)).to_le_bytes());
            records.extend_from_slice(&(-(i as i64)).to_le_bytes());
            blob.extend_from_slice(p);
            blob.push(0);
        }
        let slot_count = slot_count_for(paths.len()).unwrap();
        let mut slots = std::vec![0u8; slot_count * IDX_SLOT];
        fill_slots(&records, &blob, &mut slots).unwrap();
        let slots_at = (IDX_HEADER + records.len() + blob.len()).next_multiple_of(8);
        let mut out = std::vec![0u8; IDX_HEADER];
        out[..8].copy_from_slice(IDX_MAGIC);
        out[8..12].copy_from_slice(&3u32.to_le_bytes());
        out[12..16].copy_from_slice(&(IDX_RECORD as u32).to_le_bytes());
        out[16..24].copy_from_slice(&(paths.len() as u64).to_le_bytes());
        out[24..32].copy_from_slice(&(blob.len() as u64).to_le_bytes());
        out[32..40].copy_from_slice(&(slots_at as u64).to_le_bytes());
        out[40..44].copy_from_slice(&(IDX_SLOT as u32).to_le_bytes());
        out[44..48].copy_from_slice(&(slot_count as u32).to_le_bytes());
        out.extend_from_slice(&records);
        out.extend_from_slice(&blob);
        out.resize(slots_at, 0);
        out.extend_from_slice(&slots);
        out
    }

    /// A source that is not a slice: counts reads and can fail like a file.
    struct Counting {
        bytes: Vec<u8>,
        reads: Cell<usize>,
        fail: Cell<bool>,
    }

    impl Source for Counting {
        fn len(&self) -> u64 {
            self.bytes.len() as u64
        }
        fn read_at(&self, at: u64, out: &mut [u8]) -> Result<()> {
            self.reads.set(self.reads.get() + 1);
            if self.fail.get() {
                return Err(Error::Io);
            }
            self.bytes[..].read_at(at, out)
        }
    }

    #[test]
    fn index_reads_through_a_non_slice_source() {
        let names: [&[u8]; 3] = [b"/app0/a/One.bin", b"/app0/a/two.bin", b"/app0/b.bin"];
        let bytes = image(&names);
        let src = Counting {
            bytes: bytes.clone(),
            reads: Cell::new(0),
            fail: Cell::new(false),
        };
        let (paged, plain) = (Index::open(&src).unwrap(), Index::open(&bytes[..]).unwrap());
        assert!(src.reads.get() > 0);
        let (mut x, mut y) = ([0u8; PATH_BUF], [0u8; PATH_BUF]);
        for id in 1..=3 {
            let (a, b) = (paged.record(id).unwrap(), plain.record(id).unwrap());
            assert_eq!(a, b);
            assert_eq!(paged.path(&a, &mut x), plain.path(&b, &mut y));
            assert_eq!(paged.path(&a, &mut x).unwrap(), names[id as usize - 1]);
            assert_eq!(paged.find(names[id as usize - 1]), Ok(Some(id)));
        }
        assert_eq!(paged.record(2).unwrap().size, 20);
        assert_eq!(
            paged.find(b"/APP0/A/one.BIN"),
            plain.find(b"/APP0/A/one.BIN")
        );
        assert_eq!(paged.find(b"/app0/missing"), Ok(None));
        assert!(paged.records_sorted());
        assert_eq!(paged.find_directory(b"/app0/a", true), Ok(Some(1)));
        assert_eq!(paged.find_directory(b"/app0/c", false), Ok(None));
        let rec = paged.record(1).unwrap();
        assert_eq!(paged.path(&rec, &mut [0u8; 4]).err(), Some(Error::Invalid));
        assert_eq!(paged.record(4).err(), Some(Error::OutOfRange));
        src.fail.set(true);
        assert_eq!(paged.record(1).err(), Some(Error::Io));
        assert_eq!(Index::open(&src).err(), Some(Error::Io));
    }

    /// `check` with a fast table refuses what the probe check refuses: two
    /// records of one folded path, and slots that name a record under
    /// another record's hash; it finds a sorted image sorted.
    #[test]
    fn check_with_the_fast_table_refuses_what_the_probe_refuses() {
        let checked = |bytes: &[u8]| {
            let index = Index::view_validated(bytes, &read_layout(bytes)?)?;
            let mut fast = std::vec![FastEntry::default(); index.fast_len()];
            index.fill_fast(&mut fast)?;
            index.with_fast(&fast)?.check()
        };
        let good = image(&[b"/app0/a.bin", b"/app0/b.bin", b"/app0/c.bin"]);
        assert_eq!(checked(&good), Ok(true));
        let dup = image(&[b"/app0/a.bin", b"/app0/A.BIN"]);
        assert!(Index::open(&dup[..]).is_err());
        assert_eq!(checked(&dup), Err(Error::Invalid));
        // Swap the ids of two occupied slots: each hash names the wrong record.
        let mut swapped = good.clone();
        let l = read_layout(&good[..]).unwrap();
        let ids: Vec<usize> = (0..l.slot_count as usize)
            .map(|i| l.slots_at as usize + i * IDX_SLOT + 8)
            .filter(|&at| good[at..at + 4] != [0; 4])
            .collect();
        swapped[ids[0]..ids[0] + 4].copy_from_slice(&good[ids[1]..ids[1] + 4]);
        swapped[ids[1]..ids[1] + 4].copy_from_slice(&good[ids[0]..ids[0] + 4]);
        assert!(Index::open(&swapped[..]).is_err());
        assert_eq!(checked(&swapped), Err(Error::Invalid));
        assert_eq!(read_layout(&good[..20]), Err(Error::Truncated));
    }

    #[test]
    fn fast_table_gives_the_same_answers_without_slot_reads() {
        // 600 files, 2048 slots: the pass crosses 4 KiB blocks of slots.
        let names: Vec<Vec<u8>> = (0..600)
            .map(|i| std::format!("/app0/d{}/F{i}.bin", i % 7).into_bytes())
            .collect();
        let refs: Vec<&[u8]> = names.iter().map(|n| &n[..]).collect();
        let bytes = image(&refs);
        let src = Counting {
            bytes: bytes.clone(),
            reads: Cell::new(0),
            fail: Cell::new(false),
        };
        let plain = Index::open(&bytes[..]).unwrap();
        let index = Index::open(&src).unwrap();
        assert_eq!(index.layout(), plain.layout());
        let mut fast = std::vec![FastEntry::default(); index.fast_len()];
        assert_eq!(index.fill_fast(&mut fast[1..]), Err(Error::Invalid));
        index.fill_fast(&mut fast).unwrap();
        assert!(fast
            .windows(2)
            .all(|w| (w[0].hash(), w[0].id) < (w[1].hash(), w[1].id)));
        assert!(Index::open(&src).unwrap().with_fast(&fast[1..]).is_err());
        let index = index.with_fast(&fast).unwrap();
        assert!(index.has_fast() && !plain.has_fast());
        // A path whose hash no record has: answered from memory.
        src.reads.set(0);
        assert_eq!(index.find(b"/app0/none.bin"), Ok(None));
        assert_eq!(src.reads.get(), 0);
        for (i, name) in names.iter().enumerate() {
            let folded: Vec<u8> = name.iter().map(|&b| folded(b)).collect();
            src.reads.set(0);
            assert_eq!(index.find(name), Ok(Some(i as u32 + 1)));
            // The record and the path that confirm it, no slot.
            assert_eq!(src.reads.get(), 2);
            assert_eq!(index.find(&folded), plain.find(&folded));
        }
        assert_eq!(
            index.find_directory(b"/app0/d3", true),
            plain.find_directory(b"/app0/d3", true)
        );
        // `check` with the table reads records and paths once, no slot,
        // and finds the names unsorted (`d{i % 7}`).
        src.reads.set(0);
        assert_eq!(index.check(), Ok(false));
        assert_eq!(src.reads.get(), 2 * 600 + 600);
        src.fail.set(true);
        assert_eq!(index.find(&names[0]), Err(Error::Io));
        assert_eq!(index.find_directory(b"/app0/d3", false), Err(Error::Io));
        assert_eq!(index.try_records_sorted(), Err(Error::Io));
    }

    #[test]
    fn open_refuses_a_path_of_path_buf_bytes() {
        let mut long = std::vec![b'a'; PATH_BUF];
        long[..6].copy_from_slice(b"/app0/");
        // Components stay within NAME_MAX.
        for i in (206..PATH_BUF).step_by(200) {
            long[i] = b'/';
        }
        let ok = image(&[&long[..PATH_BUF - 1]]);
        assert!(Index::open(&ok[..]).is_ok());
        let too_long = image(&[&long[..]]);
        assert_eq!(Index::open(&too_long[..]).err(), Some(Error::Invalid));
    }
}
