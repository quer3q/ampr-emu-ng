//! `FileSource`: the `Source` the index build reads an index file through,
//! in one pass at module_start. Records and paths are
//! two sequential streams, so two 64 KiB windows, one per stream, cost one
//! pread per 64 KiB block of each; an index whose paths are not in record
//! order is still correct, with one pread per window miss. The windows
//! are the caller's, taken from the Index ledger (rt/index_memory.rs), not
//! a static pool site. The build runs on one thread: the type is !Sync.
//!
//! After the build the view reads paths through a `Sync` source:
//! `PathSource` on the index fd kept open, or `BlobSource` over the path
//! blob of an index the walk built in memory.

use ampr_format::source::Source;
use ampr_format::{Error, Result};
use core::cell::{Cell, UnsafeCell};
use core::ffi::c_int;

/// Bytes per window; windows hold blocks aligned to it.
pub(crate) const WINDOW: usize = 64 * 1024;

/// Base of a window that holds no block.
const EMPTY: u64 = u64::MAX;

/// An index file read at offsets through `read`, a pread that fills the
/// whole slice at the offset (false on an error or a short file).
pub(crate) struct FileSource<'w, R>
where
    R: Fn(u64, &mut [u8]) -> bool,
{
    len: u64,
    read: R,
    windows: UnsafeCell<[&'w mut [u8; WINDOW]; 2]>,
    /// File offset of each window's block, `EMPTY` when it holds none.
    base: [Cell<u64>; 2],
    /// Valid bytes of each window: `WINDOW`, less for the last block.
    filled: [Cell<usize>; 2],
    /// The window to refill next: the one used least recently.
    lru: Cell<usize>,
}

impl<'w, R> FileSource<'w, R>
where
    R: Fn(u64, &mut [u8]) -> bool,
{
    pub(crate) fn new(len: u64, read: R, a: &'w mut [u8; WINDOW], b: &'w mut [u8; WINDOW]) -> Self {
        Self {
            len,
            read,
            windows: UnsafeCell::new([a, b]),
            base: [Cell::new(EMPTY), Cell::new(EMPTY)],
            filled: [Cell::new(0), Cell::new(0)],
            lru: Cell::new(0),
        }
    }

    /// The window holding `[at, end)`, if any.
    fn holding(&self, at: u64, end: u64) -> Option<usize> {
        (0..2).find(|&w| {
            let base = self.base[w].get();
            base != EMPTY && base <= at && end <= base + self.filled[w].get() as u64
        })
    }

    /// Copies `out.len()` bytes at `at` from window `w`, which holds them,
    /// and marks the other window as the next to refill.
    fn copy_from(&self, w: usize, at: u64, out: &mut [u8]) {
        let off = (at - self.base[w].get()) as usize;
        // SAFETY: `windows` is only borrowed inside one `read_at` call on
        // one thread (the type is !Sync), and no borrow outlives it.
        let win: &[u8; WINDOW] = unsafe { &(*self.windows.get())[w] };
        out.copy_from_slice(&win[off..off + out.len()]);
        self.lru.set(1 - w);
    }

    /// Reads the aligned block at `at` into a window; its index, or `Io`.
    /// The window holding the block just before goes first: that is a
    /// stream moving on, and a stream that read several times in a row
    /// would otherwise evict the other stream's window. Else the least
    /// recently used one.
    fn refill(&self, at: u64) -> Result<usize> {
        let base = at - at % WINDOW as u64;
        let prev = base.wrapping_sub(WINDOW as u64);
        let w = (0..2)
            .find(|&w| base != 0 && self.base[w].get() == prev)
            .unwrap_or(self.lru.get());
        let n = (self.len - base).min(WINDOW as u64) as usize;
        self.base[w].set(EMPTY);
        // SAFETY: as in `copy_from`.
        let win: &mut [u8; WINDOW] = unsafe { &mut (*self.windows.get())[w] };
        if !(self.read)(base, &mut win[..n]) {
            return Err(Error::Io);
        }
        self.base[w].set(base);
        self.filled[w].set(n);
        Ok(w)
    }
}

impl<R> Source for FileSource<'_, R>
where
    R: Fn(u64, &mut [u8]) -> bool,
{
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, at: u64, out: &mut [u8]) -> Result<()> {
        let end = at.checked_add(out.len() as u64).ok_or(Error::Truncated)?;
        if end > self.len {
            return Err(Error::Truncated);
        }
        if out.is_empty() {
            return Ok(());
        }
        if let Some(w) = self.holding(at, end) {
            self.copy_from(w, at, out);
            return Ok(());
        }
        // A read that crosses a block boundary (or is longer than one)
        // would fit no window: read it straight from the file.
        if at / WINDOW as u64 != (end - 1) / WINDOW as u64 {
            return if (self.read)(at, out) {
                Ok(())
            } else {
                Err(Error::Io)
            };
        }
        let w = self.refill(at)?;
        self.copy_from(w, at, out);
        Ok(())
    }
}

// ---- run-time path sources ----

/// Longest single pread `pread_fd` asks for: a path read is at most
/// `PATH_BUF`, so one request covers it; longer reads loop.
#[cfg(not(test))]
const PREAD_MAX: usize = WINDOW;

/// The raw pre-detour pread the index loader uses:
/// short reads continue, EINTR retries, EOF fails. Never a hooked call:
/// the hooks themselves look paths up in the index.
#[cfg(not(test))]
pub(crate) fn pread_fd(fd: c_int, at: u64, out: &mut [u8]) -> bool {
    let dst = out.as_mut_ptr();
    super::pack::pread_loop(
        out.len(),
        at,
        PREAD_MAX,
        |done, want, off| unsafe {
            super::sys::real_physical_pread(fd, dst.add(done).cast(), want, off)
        },
        super::sys::errno,
    )
}

/// Host tests link no libkernel; they pass their own read to
/// `PathSource::with_read`.
#[cfg(test)]
pub(crate) fn pread_fd(_fd: c_int, _at: u64, _out: &mut [u8]) -> bool {
    false
}

/// The paths of an index file after the build, read with one pread per
/// path on an fd kept open for the life of the module. No cache: a path
/// is read only to confirm a hash match or to list a directory, and the
/// view keeps everything else resident. The source holds only the fd and
/// a plain fn, so it is `Sync` and any hook thread reads through it. It
/// does not close the fd: the fd outlives every view that reads it.
pub(crate) struct PathSource {
    fd: c_int,
    len: u64,
    read: fn(c_int, u64, &mut [u8]) -> bool,
}

impl PathSource {
    /// `len` bytes of the index file open on `fd`, read with `pread_fd`.
    pub(crate) fn new(fd: c_int, len: u64) -> Self {
        Self::with_read(fd, len, pread_fd)
    }

    /// As `new`, reading through `read` (false on an error or EOF).
    pub(crate) fn with_read(fd: c_int, len: u64, read: fn(c_int, u64, &mut [u8]) -> bool) -> Self {
        Self { fd, len, read }
    }

    pub(crate) fn fd(&self) -> c_int {
        self.fd
    }
}

impl Source for PathSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, at: u64, out: &mut [u8]) -> Result<()> {
        let end = at.checked_add(out.len() as u64).ok_or(Error::Truncated)?;
        if end > self.len {
            return Err(Error::Truncated);
        }
        if out.is_empty() || (self.read)(self.fd, at, out) {
            Ok(())
        } else {
            Err(Error::Io)
        }
    }
}

/// The path blob of an index the walk built, kept resident after the
/// image is freed. A record's `path_at` is an absolute offset in the
/// image, and the blob starts at the image's `paths_at`, so reads
/// subtract `base`; `len` is `base` plus the blob, so the view's
/// `path_at` bounds checks hold unchanged. An offset before `base` is
/// outside the source: `Truncated`, like one past the end.
pub(crate) struct BlobSource<'a> {
    pub(crate) blob: &'a [u8],
    pub(crate) base: u64,
}

impl Source for BlobSource<'_> {
    fn len(&self) -> u64 {
        self.base + self.blob.len() as u64
    }

    fn read_at(&self, at: u64, out: &mut [u8]) -> Result<()> {
        let rel = at.checked_sub(self.base).ok_or(Error::Truncated)?;
        self.blob.read_at(rel, out)
    }
}

// ---- resident AMPRPAK4 source ----

/// `len` bytes of an index file kept at file offset `at`, stored from
/// byte `off` of the resident names.
#[derive(Clone, Copy, Default, Debug, PartialEq, Eq)]
#[repr(C)]
pub(crate) struct Span {
    pub(crate) at: u64,
    pub(crate) off: u32,
    pub(crate) len: u32,
}

/// Sorts `spans` by file offset and merges the ones that overlap or
/// touch, in place, then numbers their bytes back to back. The merged
/// count and their total bytes.
pub(crate) fn merge_spans(spans: &mut [Span]) -> (usize, u32) {
    spans.sort_unstable_by_key(|s| s.at);
    let mut n = 0usize;
    for i in 0..spans.len() {
        let s = spans[i];
        match n.checked_sub(1).map(|k| &mut spans[k]) {
            Some(last) if s.at <= last.at + u64::from(last.len) => {
                let end = (s.at + u64::from(s.len)).max(last.at + u64::from(last.len));
                last.len = (end - last.at) as u32;
            }
            _ => {
                spans[n] = s;
                n += 1;
            }
        }
    }
    let mut total = 0u32;
    for s in &mut spans[..n] {
        s.off = total;
        total += s.len;
    }
    (n, total)
}

/// The parts of an AMPRPAK4 index file the mounted manifest reads, at
/// their file offsets: `head` is the file from offset 0 (the header and
/// the record sections), `spans` the pack names with their NULs, sorted
/// and disjoint (`merge_spans`), their bytes in `names`. A pack name is
/// read for every listed directory entry, so it stays in memory. Any
/// other read, a file path among them, is `Io`: after the view join
/// nothing reads a path, and its bytes are not resident.
#[derive(Clone, Copy)]
pub(crate) struct ResidentSource<'a> {
    head: &'a [u8],
    spans: &'a [Span],
    names: &'a [u8],
    len: u64,
}

impl<'a> ResidentSource<'a> {
    pub(crate) const EMPTY: ResidentSource<'static> = ResidentSource {
        head: &[],
        spans: &[],
        names: &[],
        len: 0,
    };

    /// A file of `len` bytes; each span must lie in `names` and past `head`.
    pub(crate) fn new(head: &'a [u8], spans: &'a [Span], names: &'a [u8], len: u64) -> Self {
        Self {
            head,
            spans,
            names,
            len,
        }
    }

    pub(crate) fn head(&self) -> &'a [u8] {
        self.head
    }

    /// The resident bytes `[at, end)`, if any.
    fn resident(&self, at: u64, end: u64) -> Option<&'a [u8]> {
        if end <= self.head.len() as u64 {
            return self.head.get(at as usize..end as usize);
        }
        let s = self.spans[..self.spans.partition_point(|s| s.at <= at)].last()?;
        if end > s.at + u64::from(s.len) {
            return None;
        }
        let from = s.off as usize + (at - s.at) as usize;
        self.names.get(from..from + (end - at) as usize)
    }
}

impl Source for ResidentSource<'_> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, at: u64, out: &mut [u8]) -> Result<()> {
        let end = at.checked_add(out.len() as u64).ok_or(Error::Truncated)?;
        if end > self.len {
            return Err(Error::Truncated);
        }
        if out.is_empty() {
            return Ok(());
        }
        let bytes = self.resident(at, end).ok_or(Error::Io)?;
        out.copy_from_slice(bytes);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    use std::vec::Vec;

    fn file(len: usize) -> Vec<u8> {
        (0..len).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    fn windows() -> (Box<[u8; WINDOW]>, Box<[u8; WINDOW]>) {
        (Box::new([0; WINDOW]), Box::new([0; WINDOW]))
    }

    /// A pread over `data` that counts its calls and fails when `fail` is set.
    fn reader<'a>(
        data: &'a [u8],
        calls: &'a Cell<usize>,
        fail: &'a Cell<bool>,
    ) -> impl Fn(u64, &mut [u8]) -> bool + 'a {
        move |at, out| {
            calls.set(calls.get() + 1);
            let at = at as usize;
            match data.get(at..at + out.len()) {
                Some(src) if !fail.get() => {
                    out.copy_from_slice(src);
                    true
                }
                _ => false,
            }
        }
    }

    #[test]
    fn two_streams_cost_one_read_per_block_each() {
        let data = file(8 * WINDOW + 100);
        let (calls, fail) = (Cell::new(0), Cell::new(false));
        let (mut a, mut b) = windows();
        let src = FileSource::new(
            data.len() as u64,
            reader(&data, &calls, &fail),
            &mut a,
            &mut b,
        );
        // Records 48 B from 0, paths 30 B from 4 blocks in, with an extra
        // record read now and then so one stream reads twice in a row.
        let (mut rec, mut path) = (0u64, 4 * WINDOW as u64);
        let (mut r, mut p) = ([0u8; 48], [0u8; 30]);
        let mut i = 0;
        while rec + 48 <= 4 * WINDOW as u64 && path + 30 <= data.len() as u64 {
            let at = rec - rec % WINDOW as u64;
            if (rec + 48) as usize <= at as usize + WINDOW {
                src.read_at(rec, &mut r).unwrap();
                assert_eq!(&r[..], &data[rec as usize..rec as usize + 48]);
            }
            rec += 48;
            if i % 5 != 0 {
                let at = path - path % WINDOW as u64;
                if (path + 30) as usize <= at as usize + WINDOW {
                    src.read_at(path, &mut p).unwrap();
                    assert_eq!(&p[..], &data[path as usize..path as usize + 30]);
                }
                path += 30;
            }
            i += 1;
        }
        let blocks = |from: u64, to: u64| (to - 1) / WINDOW as u64 - from / WINDOW as u64 + 1;
        assert_eq!(
            calls.get() as u64,
            blocks(0, rec) + blocks(4 * WINDOW as u64, path)
        );
    }

    #[test]
    fn random_reads_match_slice_source() {
        let data = file(3 * WINDOW + 777);
        let (calls, fail) = (Cell::new(0), Cell::new(false));
        let (mut a, mut b) = windows();
        let src = FileSource::new(
            data.len() as u64,
            reader(&data, &calls, &fail),
            &mut a,
            &mut b,
        );
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        for _ in 0..5000 {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            let at = x % data.len() as u64;
            let n = ((x >> 32) % 300) as usize;
            let (mut got, mut want) = (std::vec![0u8; n], std::vec![0u8; n]);
            assert_eq!(src.read_at(at, &mut got), data[..].read_at(at, &mut want));
            assert_eq!(got, want);
        }
    }

    #[test]
    fn straddling_and_long_reads_go_to_the_file() {
        let data = file(3 * WINDOW + 10);
        let (calls, fail) = (Cell::new(0), Cell::new(false));
        let (mut a, mut b) = windows();
        let src = FileSource::new(
            data.len() as u64,
            reader(&data, &calls, &fail),
            &mut a,
            &mut b,
        );
        let mut out = [0u8; 16];
        let at = WINDOW as u64 - 8;
        src.read_at(at, &mut out).unwrap();
        assert_eq!(&out[..], &data[at as usize..at as usize + 16]);
        assert_eq!(calls.get(), 1);
        let mut long = std::vec![0u8; WINDOW + 5];
        src.read_at(3, &mut long).unwrap();
        assert_eq!(&long[..], &data[3..3 + WINDOW + 5]);
        assert_eq!(calls.get(), 2);
        // The short last block fills a window and serves its tail.
        let mut tail = [0u8; 10];
        src.read_at(3 * WINDOW as u64, &mut tail).unwrap();
        assert_eq!(&tail[..], &data[3 * WINDOW..]);
        src.read_at(3 * WINDOW as u64 + 2, &mut tail[..8]).unwrap();
        assert_eq!(calls.get(), 3);
    }

    #[test]
    fn errors_map_to_truncated_and_io() {
        let data = file(WINDOW + 10);
        let (calls, fail) = (Cell::new(0), Cell::new(false));
        let (mut a, mut b) = windows();
        let src = FileSource::new(
            data.len() as u64,
            reader(&data, &calls, &fail),
            &mut a,
            &mut b,
        );
        let mut out = [0u8; 8];
        let len = data.len() as u64;
        assert_eq!(src.read_at(len - 4, &mut out), Err(Error::Truncated));
        assert_eq!(src.read_at(u64::MAX - 2, &mut out), Err(Error::Truncated));
        assert_eq!(src.read_at(len, &mut out[..0]), Ok(()));
        assert_eq!(calls.get(), 0);
        fail.set(true);
        assert_eq!(src.read_at(0, &mut out), Err(Error::Io));
        assert_eq!(src.read_at(WINDOW as u64 - 4, &mut out), Err(Error::Io));
        // A failed refill leaves no window claiming the block.
        fail.set(false);
        src.read_at(0, &mut out).unwrap();
        assert_eq!(&out[..], &data[..8]);
    }

    // ---- run-time path sources ----

    /// An index file: 40 B of header and records, then the path blob.
    const PATHS_AT: usize = 40;
    const IMAGE: &[u8] = b"AMPRIDX3 header and records 40 bytes....a/b.bin\0c/dd.txt\0";

    /// A pread over `IMAGE` on fd 7; any other fd fails.
    fn image_read(fd: c_int, at: u64, out: &mut [u8]) -> bool {
        let at = at as usize;
        match IMAGE.get(at..at + out.len()) {
            Some(src) if fd == 7 => {
                out.copy_from_slice(src);
                true
            }
            _ => false,
        }
    }

    /// The path at `path_at`, read like `View::path`: up to `PATH_BUF`
    /// bytes or the end, cut at the NUL.
    fn path_at<S: Source>(src: &S, path_at: u64) -> Result<Vec<u8>> {
        let n = (src.len() - path_at).min(ampr_format::source::PATH_BUF as u64) as usize;
        let mut buf = std::vec![0u8; n];
        src.read_at(path_at, &mut buf)?;
        let len = buf.iter().position(|&c| c == 0).ok_or(Error::Invalid)?;
        buf.truncate(len);
        Ok(buf)
    }

    fn assert_sync<T: Sync>() {}

    #[test]
    fn path_source_reads_paths_at_file_offsets() {
        assert_sync::<PathSource>();
        let src = PathSource::with_read(7, IMAGE.len() as u64, image_read);
        assert_eq!(src.fd(), 7);
        assert_eq!(path_at(&src, PATHS_AT as u64).unwrap(), b"a/b.bin");
        assert_eq!(path_at(&src, PATHS_AT as u64 + 8).unwrap(), b"c/dd.txt");
        let mut out = [0u8; 4];
        let len = IMAGE.len() as u64;
        assert_eq!(src.read_at(len - 2, &mut out), Err(Error::Truncated));
        assert_eq!(src.read_at(u64::MAX - 1, &mut out), Err(Error::Truncated));
        assert_eq!(src.read_at(len, &mut out[..0]), Ok(()));
        let bad = PathSource::with_read(8, len, image_read);
        assert_eq!(bad.read_at(PATHS_AT as u64, &mut out), Err(Error::Io));
        // Host tests link no libkernel: the default pread fails.
        let host = PathSource::new(7, len);
        assert_eq!(host.read_at(0, &mut out), Err(Error::Io));
    }

    #[test]
    fn blob_source_subtracts_the_paths_offset() {
        assert_sync::<BlobSource<'static>>();
        let blob = &IMAGE[PATHS_AT..];
        let src = BlobSource {
            blob,
            base: PATHS_AT as u64,
        };
        assert_eq!(src.len(), IMAGE.len() as u64);
        assert_eq!(path_at(&src, PATHS_AT as u64).unwrap(), b"a/b.bin");
        assert_eq!(path_at(&src, PATHS_AT as u64 + 8).unwrap(), b"c/dd.txt");
        let mut out = [0u8; 4];
        assert_eq!(
            src.read_at(PATHS_AT as u64 - 1, &mut out),
            Err(Error::Truncated)
        );
        assert_eq!(src.read_at(0, &mut out[..0]), Err(Error::Truncated));
        assert_eq!(src.read_at(src.len() - 2, &mut out), Err(Error::Truncated));
        assert_eq!(src.read_at(u64::MAX - 1, &mut out), Err(Error::Truncated));
    }

    /// Overlapping and touching spans merge into one run, kept once in
    /// file order; a read answers from the head or from one run, and `Io`
    /// for any byte that is not kept, a read that crosses a run's end or
    /// the head's end included.
    #[test]
    fn resident_source_answers_only_its_parts() {
        let span = |at, len| Span { at, off: 0, len };
        let mut spans = [
            span(120, 7),
            span(100, 7),
            span(104, 7),
            span(200, 3),
            span(111, 2),
        ];
        let (n, total) = merge_spans(&mut spans);
        assert_eq!((n, total), (3, 23));
        let want = [
            Span {
                at: 100,
                off: 0,
                len: 13,
            },
            Span {
                at: 120,
                off: 13,
                len: 7,
            },
            Span {
                at: 200,
                off: 20,
                len: 3,
            },
        ];
        assert_eq!(spans[..n], want);
        let data = file(256);
        let names = [&data[100..113], &data[120..127], &data[200..203]].concat();
        let src = ResidentSource::new(&data[..64], &spans[..n], &names, 256);
        let mut out = [0u8; 8];
        for (at, len) in [(0, 8), (56, 8), (100, 8), (105, 8), (120, 7), (200, 3)] {
            src.read_at(at, &mut out[..len]).unwrap();
            assert_eq!(out[..len], data[at as usize..at as usize + len], "{at}");
        }
        for (at, len) in [(60, 8), (64, 1), (108, 6), (113, 1), (126, 2), (150, 1)] {
            assert_eq!(src.read_at(at, &mut out[..len]), Err(Error::Io), "{at}");
        }
        assert_eq!(src.read_at(150, &mut out[..0]), Ok(()));
        assert_eq!(src.read_at(250, &mut out), Err(Error::Truncated));
    }
}
