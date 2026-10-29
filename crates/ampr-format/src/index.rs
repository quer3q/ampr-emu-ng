//! AMPRIDX3 fixed records, path blob, and open-addressed hash slots.
use crate::index_key::{
    compare, compare_dir_prefix, is_descendant, NAME_MAX, PATH_MAX, RUNTIME_KEY_CAPACITY,
};
use crate::{
    i64_at, idx_path_hash, logical_path, section, terminated_slice, u32_at, u64_at, Error, Result,
    IDX_HEADER, IDX_MAGIC, IDX_RECORD, IDX_SLOT,
};
use core::cmp::Ordering;

const MAX_RECORDS: u64 = 2_000_000;
const MAX_PATH_BYTES: u64 = 256 << 20;

#[derive(Clone, Copy, Debug)]
pub struct Record<'a> {
    pub path: &'a [u8],
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
    /// Every header check `open_parts` relies on, before any section is read.
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
        if paths.get(off + len) != Some(&0) {
            return Err(Error::Invalid);
        }
        let hash = idx_path_hash(&paths[off..off + len]);
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

pub struct Index<'a> {
    records: &'a [u8],
    paths: &'a [u8],
    slots: &'a [u8],
    count: u32,
    slot_count: u32,
}

impl<'a> Index<'a> {
    pub fn open(bytes: &'a [u8]) -> Result<Self> {
        if bytes.get(..8) != Some(IDX_MAGIC) {
            return Err(Error::Invalid);
        }
        let header = bytes.get(..IDX_HEADER).ok_or(Error::Truncated)?;
        let l = Layout::parse(header)?;
        let records = section(bytes, IDX_HEADER as u64, l.records_len)?;
        let paths = section(bytes, l.paths_at, l.path_bytes)?;
        let slots = section(bytes, l.slots_at, l.slots_len)?;
        Self::open_parts(header, records, paths, slots)
    }

    /// Validates separately initialized sections, including a 48-byte header.
    /// The gap before the slots need not be mapped or initialized. The header
    /// need not remain resident after this call.
    pub fn open_parts(
        header: &[u8],
        records: &'a [u8],
        paths: &'a [u8],
        slots: &'a [u8],
    ) -> Result<Self> {
        let layout = Layout::parse(header)?;
        if records.len() as u64 != layout.records_len
            || paths.len() as u64 != layout.path_bytes
            || slots.len() as u64 != layout.slots_len
        {
            return Err(Error::Invalid);
        }
        let slot_count = layout.slot_count;
        let index = Self::view_validated_sections(records, paths, slots)?;
        for id in 1..=index.count {
            if !kernel_path_limits(index.record(id)?.path) {
                return Err(Error::Invalid);
            }
        }
        let mut occupied = 0u32;
        for pos in 0..slot_count {
            let at = pos as usize * IDX_SLOT;
            let hash = u64_at(slots, at)?;
            let id = u32_at(slots, at + 8)?;
            let flags = u32_at(slots, at + 12)?;
            if id == 0 {
                if hash != 0 || flags != 0 {
                    return Err(Error::Invalid);
                }
            } else {
                if id > index.count
                    || flags & !1 != 0
                    || hash != idx_path_hash(index.record(id)?.path)
                {
                    return Err(Error::Invalid);
                }
                occupied += 1;
            }
        }
        if occupied != index.count {
            return Err(Error::Invalid);
        }
        // Every record must be reachable through its probe chain, with no
        // duplicate folded path claiming the same lookup.
        for id in 1..=index.count {
            if index.find(index.record(id)?.path)? != Some(id) {
                return Err(Error::Invalid);
            }
        }
        Ok(index)
    }

    /// Constructs a bounded lookup view over sections already validated by
    /// `open_parts` or an equivalent loader. This checks section geometry in
    /// O(1); it does not rescan every record and slot before each lookup.
    pub fn view_validated_sections(
        records: &'a [u8],
        paths: &'a [u8],
        slots: &'a [u8],
    ) -> Result<Self> {
        if records.len() % IDX_RECORD != 0 || slots.len() % IDX_SLOT != 0 {
            return Err(Error::Invalid);
        }
        let count = records.len() / IDX_RECORD;
        let slot_count = slots.len() / IDX_SLOT;
        if count == 0
            || count as u64 > MAX_RECORDS
            || paths.is_empty()
            || paths.len() as u64 > MAX_PATH_BYTES
            || slot_count < 2
            || !slot_count.is_power_of_two()
            || slot_count < count
            || slot_count > u32::MAX as usize
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            records,
            paths,
            slots,
            count: count as u32,
            slot_count: slot_count as u32,
        })
    }

    pub fn len(&self) -> u32 {
        self.count
    }

    /// On-disk ids start at one. Paths retain their original spelling.
    pub fn record(&self, id: u32) -> Result<Record<'a>> {
        let record = self.record_trusted(id)?;
        if record.path.contains(&0) || !logical_path(record.path) {
            return Err(Error::Invalid);
        }
        Ok(record)
    }

    /// Lookup-path `record` for an image `open_parts` already validated:
    /// bounds and the NUL terminator are checked, the path content is not.
    /// Never panics; on an unvalidated view the path may be non-logical.
    pub fn record_trusted(&self, id: u32) -> Result<Record<'a>> {
        if id == 0 || id > self.count {
            return Err(Error::OutOfRange);
        }
        let at = (id as usize - 1) * IDX_RECORD;
        let off = u32_at(self.records, at)?;
        let len = u32_at(self.records, at + 4)?;
        Ok(Record {
            path: terminated_slice(self.paths, off, len)?,
            size: u64_at(self.records, at + 8)?,
            mtime: i64_at(self.records, at + 16)?,
        })
    }

    /// Whether records are in folded order, ties allowed.
    pub fn records_sorted(&self) -> bool {
        (2..=self.count).all(|id| match (self.record(id - 1), self.record(id)) {
            (Ok(a), Ok(b)) => compare(a.path, b.path) != Ordering::Greater,
            _ => false,
        })
    }

    /// Finds a record below the
    /// normalized directory `key`. Sorted indexes probe only the lower bound
    /// of `key/`; unsorted runtime images fall back to a linear scan.
    pub fn find_directory(&self, key: &[u8], sorted: bool) -> Option<u32> {
        let (first, end) = if sorted {
            if key.len() > RUNTIME_KEY_CAPACITY - 2 {
                return None;
            }
            let (mut first, mut last) = (0u32, self.count);
            while first < last {
                let middle = first + (last - first) / 2;
                let less = self
                    .record_trusted(middle + 1)
                    .is_ok_and(|r| compare_dir_prefix(r.path, key) == Ordering::Less);
                if less {
                    first = middle + 1;
                } else {
                    last = middle;
                }
            }
            (first, (first + 1).min(self.count))
        } else {
            (0, self.count)
        };
        (first + 1..=end).find(|&id| {
            self.record_trusted(id)
                .is_ok_and(|r| is_descendant(r.path, key))
        })
    }

    /// Runtime-style lookup. The bounded probe also rejects a broken chain.
    pub fn find(&self, path: &[u8]) -> Result<Option<u32>> {
        if !logical_path(path) {
            return Err(Error::Invalid);
        }
        let hash = idx_path_hash(path);
        let mask = self.slot_count - 1;
        let mut pos = hash as u32 & mask;
        for _ in 0..self.slot_count {
            let at = pos as usize * IDX_SLOT;
            let id = u32_at(self.slots, at + 8)?;
            if id == 0 {
                return Ok(None);
            }
            if u64_at(self.slots, at)? == hash && folded_eq(self.record_trusted(id)?.path, path) {
                return Ok(Some(id));
            }
            pos = (pos + 1) & mask;
        }
        Ok(None)
    }
}

fn folded_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && a.iter().zip(b).all(|(&x, &y)| {
            let fold = |v| match v {
                b'\\' => b'/',
                b'A'..=b'Z' => v + 32,
                _ => v,
            };
            fold(x) == fold(y)
        })
}
