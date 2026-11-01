//! Tuning knobs of the debug build (`make AMPR_MEM_REPORT=1`). Startup knobs
//! (cache sizes, workers, pipelines, cache reserve) are read from TUNE_PATH
//! when the pack state is created (pack/state.rs); live knobs (read-ahead, read
//! extension and their disk gates, pread pool on/off for pack and loose reads,
//! the reactor's per-pass and per-read issue limits, lane EOP overlap) take
//! effect on the next read or reactor pass.
//! `GET /set?k=v&...` on the metrics port changes both and rewrites TUNE_PATH,
//! so startup knobs apply on the next game launch; `profile=low|medium|high`
//! sets all startup knobs. Release builds use the compile-time constants:
//! `ON` is false and the atomics are never read.

use super::pack::{
    AMPR_EMU_PACK_DECODED_CACHE_BYTES, AMPR_EMU_PACK_MEMORY_RESERVE_BYTES,
    AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES, AMPR_EMU_PACK_PIPELINE_SLOTS,
    AMPR_EMU_PACK_READAHEAD_CHUNKS, AMPR_EMU_PACK_READAHEAD_MAX_DISK_INFLIGHT,
    AMPR_EMU_PACK_READ_EXTEND_BYTES, AMPR_EMU_PACK_READ_EXTEND_MAX_DISK_INFLIGHT,
    AMPR_EMU_PACK_WORKERS, AMPR_EMU_PACK_WORKER_CAPACITY,
};
use super::reactor::{
    kSoftwareReadChunkMax, AMPR_EMU_APR_LANE_EOP_OVERLAP, AMPR_EMU_APR_LOOSE_PREAD,
    AMPR_EMU_APR_LOOSE_PREAD_PART_KIB, AMPR_EMU_APR_PER_READ_ACTIVE_BYTES,
    AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS, AMPR_EMU_APR_READ_CHUNK_QUANTUM,
    AMPR_EMU_APR_READ_PASS_MAX_BYTES, AMPR_EMU_PACK_PREAD_WORKERS,
};
use super::sys::*;
use core::ffi::{c_int, CStr};
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

pub(crate) const ON: bool = cfg!(feature = "mem_report");
pub(crate) const TUNE_PATH: &CStr = c"/data/ampr_emu_tune.txt";
/// Pipelines a release build has; the debug build has room for 32.
pub(crate) const RELEASE_PIPELINES: u32 = 16;
/// Pread pool threads a release build starts: 32, more than the 16
/// pipelines, because split loose reads (reactor/loose_pread.rs) use them too.
/// A game, loose files, internal SSD, debug /metrics (2026-11-01): 16 threads split
/// 73% of loose reads at 1.35 ms per read, 32 threads split 98% at 1.10 ms.
pub(crate) const RELEASE_PREAD_THREADS: u32 = 32;
/// Upper bound of `ra` (one u64 bitmask per read-ahead job, pack/readahead.rs).
pub(crate) const RA_MAX: u32 = 64;

pub(crate) struct Knob {
    pub name: &'static str,
    #[cfg(feature = "mem_report")]
    pub live: bool,
    pub min: u32,
    pub max: u32,
    v: AtomicU32,
}

const fn knob(name: &'static str, live: bool, min: u32, max: u32, default: u32) -> Knob {
    #[cfg(not(feature = "mem_report"))]
    let _ = live;
    Knob {
        name,
        #[cfg(feature = "mem_report")]
        live,
        min,
        max,
        v: AtomicU32::new(default),
    }
}

const MIB: u64 = 1024 * 1024;
const DECODED_MIB: usize = 0;
const PHYSICAL_MIB: usize = 1;
const WORKERS: usize = 2;
const PIPELINES: usize = 3;
const RESERVE_MIB: usize = 4;
const RA: usize = 5;
const RA_GATE: usize = 6;
const EXT_KIB: usize = 7;
const EXT_GATE: usize = 8;
const PREAD: usize = 9;
const PREAD_THREADS: usize = 10;
const LOOSE_PREAD: usize = 11;
const LOOSE_PREAD_PART_KIB: usize = 12;
const READ_PASS_KIB: usize = 13;
const READ_CHUNK_QUANTUM: usize = 14;
const PER_READ_ACTIVE_KIB: usize = 15;
const PER_READ_ACTIVE_CHUNKS: usize = 16;
const LANE_EOP_OVERLAP: usize = 17;

/// Smallest pass budget and per-read active window, in KiB: one full read
/// slice (kSoftwareReadChunkMax, 512 KiB). A smaller value would leave a full
/// slice unissuable forever (flush.rs submit_read_chain_slice), so the job
/// would never finish.
const READ_SLICE_KIB: u32 = (kSoftwareReadChunkMax / 1024) as u32;
/// Largest pass budget and per-read active window, in KiB (16 MiB).
const READ_LIMIT_MAX_KIB: u32 = 16 * 1024;

/// Cache sizes: 0 turns a cache off (reads bypass it); otherwise the cache
/// allocators' minimums apply (decoded 16, physical 8 MiB, pack/manifest.rs).
pub(crate) static KNOBS: [Knob; 18] = [
    knob(
        "decoded_mib",
        false,
        0,
        512,
        (AMPR_EMU_PACK_DECODED_CACHE_BYTES / MIB) as u32,
    ),
    knob(
        "physical_mib",
        false,
        0,
        128,
        (AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES / MIB) as u32,
    ),
    knob(
        "workers",
        false,
        1,
        AMPR_EMU_PACK_WORKER_CAPACITY as u32,
        AMPR_EMU_PACK_WORKERS,
    ),
    knob(
        "pipelines",
        false,
        1,
        AMPR_EMU_PACK_PIPELINE_SLOTS as u32,
        RELEASE_PIPELINES,
    ),
    knob(
        "reserve_mib",
        false,
        0,
        256,
        (AMPR_EMU_PACK_MEMORY_RESERVE_BYTES / MIB) as u32,
    ),
    knob("ra", true, 0, RA_MAX, AMPR_EMU_PACK_READAHEAD_CHUNKS),
    knob(
        "ra_gate",
        true,
        0,
        64,
        AMPR_EMU_PACK_READAHEAD_MAX_DISK_INFLIGHT,
    ),
    knob(
        "ext_kib",
        true,
        0,
        2048,
        (AMPR_EMU_PACK_READ_EXTEND_BYTES / 1024) as u32,
    ),
    knob(
        "ext_gate",
        true,
        0,
        64,
        AMPR_EMU_PACK_READ_EXTEND_MAX_DISK_INFLIGHT,
    ),
    knob("pread", true, 0, 1, 1),
    knob(
        "pread_threads",
        false,
        1,
        AMPR_EMU_PACK_PREAD_WORKERS as u32,
        RELEASE_PREAD_THREADS,
    ),
    knob("loose_pread", true, 0, 1, AMPR_EMU_APR_LOOSE_PREAD as u32),
    knob(
        "loose_pread_part_kib",
        true,
        0,
        4096,
        AMPR_EMU_APR_LOOSE_PREAD_PART_KIB,
    ),
    knob(
        "read_pass_kib",
        true,
        READ_SLICE_KIB,
        READ_LIMIT_MAX_KIB,
        (AMPR_EMU_APR_READ_PASS_MAX_BYTES / 1024) as u32,
    ),
    knob(
        "read_chunk_quantum",
        true,
        1,
        64,
        AMPR_EMU_APR_READ_CHUNK_QUANTUM,
    ),
    knob(
        "per_read_active_kib",
        true,
        READ_SLICE_KIB,
        READ_LIMIT_MAX_KIB,
        (AMPR_EMU_APR_PER_READ_ACTIVE_BYTES / 1024) as u32,
    ),
    knob(
        "per_read_active_chunks",
        true,
        1,
        32,
        AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS,
    ),
    knob(
        "lane_eop_overlap",
        true,
        0,
        1,
        AMPR_EMU_APR_LANE_EOP_OVERLAP as u32,
    ),
];

/// (name, [decoded_mib, physical_mib, workers, pipelines, reserve_mib]).
/// Expected pool need (caches + workers x 1 MiB + pipelines x 2 MiB + ~30 MiB
/// index/SDK): low ~74, medium ~150, high ~262 MiB.
const PROFILES: [(&str, [u32; 5]); 3] = [
    ("low", [16, 8, 4, 8, 8]),
    ("medium", [64, 16, 8, 16, 16]),
    ("high", [128, 32, 8, 32, 32]),
];

fn get(i: usize) -> u32 {
    KNOBS[i].v.load(Relaxed)
}

pub(crate) fn decoded_bytes() -> usize {
    if ON {
        get(DECODED_MIB) as usize * MIB as usize
    } else {
        AMPR_EMU_PACK_DECODED_CACHE_BYTES as usize
    }
}
pub(crate) fn physical_bytes() -> usize {
    if ON {
        get(PHYSICAL_MIB) as usize * MIB as usize
    } else {
        AMPR_EMU_PACK_PHYSICAL_CACHE_BYTES as usize
    }
}
pub(crate) fn workers() -> u32 {
    if ON {
        get(WORKERS)
    } else {
        AMPR_EMU_PACK_WORKERS
    }
}
pub(crate) fn pipelines() -> usize {
    if ON {
        get(PIPELINES) as usize
    } else {
        AMPR_EMU_PACK_PIPELINE_SLOTS
    }
}
pub(crate) fn reserve_bytes() -> usize {
    if ON {
        get(RESERVE_MIB) as usize * MIB as usize
    } else {
        AMPR_EMU_PACK_MEMORY_RESERVE_BYTES as usize
    }
}
pub(crate) fn ra() -> u32 {
    if ON {
        get(RA)
    } else {
        AMPR_EMU_PACK_READAHEAD_CHUNKS
    }
}
pub(crate) fn ra_gate() -> u32 {
    if ON {
        get(RA_GATE)
    } else {
        AMPR_EMU_PACK_READAHEAD_MAX_DISK_INFLIGHT
    }
}
pub(crate) fn ext_bytes() -> usize {
    if ON {
        get(EXT_KIB) as usize * 1024
    } else {
        AMPR_EMU_PACK_READ_EXTEND_BYTES
    }
}
/// 1: pack physical reads go to the pread pool (reactor/pread_pool.rs); 0: kernel AIO.
pub(crate) fn pread() -> bool {
    if ON {
        get(PREAD) != 0
    } else {
        true
    }
}
/// 1: the game's loose (real-fd) APR reads go to the pread pool first
/// (reactor/loose_pread.rs); 0: kernel AIO only.
pub(crate) fn loose_pread() -> bool {
    if ON {
        get(LOOSE_PREAD) != 0
    } else {
        AMPR_EMU_APR_LOOSE_PREAD
    }
}
/// Part size of split loose reads in KiB (reactor/loose_pread.rs rounds it
/// to a 4 KiB multiple, at least 16); 0: one pool task per read.
pub(crate) fn loose_pread_part_kib() -> u32 {
    if ON {
        get(LOOSE_PREAD_PART_KIB)
    } else {
        AMPR_EMU_APR_LOOSE_PREAD_PART_KIB
    }
}
pub(crate) fn pread_threads() -> usize {
    if ON {
        get(PREAD_THREADS) as usize
    } else {
        AMPR_EMU_PACK_PREAD_WORKERS
    }
}
// ---- reactor issue limits (reactor/progress.rs, reactor/read_window.rs) ----
// Sized for kernel AIO, which serves 1-2 requests at a time on BFS
// (reactor/mod.rs); the debug build makes them live to A/B them against the
// pread pool. Release returns the constants.

/// Read bytes one priority lane may issue per reactor pass
/// (ReadIssueBudget.bytesLeft), at least one 512 KiB slice.
pub(crate) fn read_pass_bytes() -> u64 {
    if ON {
        get(READ_PASS_KIB) as u64 * 1024
    } else {
        AMPR_EMU_APR_READ_PASS_MAX_BYTES
    }
}
/// Read requests one priority lane may issue per reactor pass
/// (ReadIssueBudget.requestsLeft), at least 1.
pub(crate) fn read_chunk_quantum() -> u32 {
    if ON {
        get(READ_CHUNK_QUANTUM)
    } else {
        AMPR_EMU_APR_READ_CHUNK_QUANTUM
    }
}
/// Credit bytes one read (chain) may have in flight, at least one 512 KiB slice.
pub(crate) fn per_read_active_bytes() -> u64 {
    if ON {
        get(PER_READ_ACTIVE_KIB) as u64 * 1024
    } else {
        AMPR_EMU_APR_PER_READ_ACTIVE_BYTES
    }
}
/// Chunks one read (chain) may have in flight in the exclusive bulk window,
/// at least 1; contended windows still use 1 or 2 (ampr_loose_chain_chunk_limit).
pub(crate) fn per_read_active_chunks() -> u32 {
    if ON {
        get(PER_READ_ACTIVE_CHUNKS)
    } else {
        AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS
    }
}
/// 1: a priority lane's next job may parse while the head job has only
/// completion commands left (reactor/lane_overlap.rs); 0: one parsing job per
/// lane, as in release.
pub(crate) fn lane_eop_overlap() -> bool {
    if ON {
        get(LANE_EOP_OVERLAP) != 0
    } else {
        AMPR_EMU_APR_LANE_EOP_OVERLAP
    }
}

#[cfg(any(test, feature = "mem_report"))]
fn hex(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Percent-decodes `src` into `out` and NUL-terminates it. '+' stays
/// literal: it is a valid path byte. None on a bad escape, %00, or when
/// the result plus NUL does not fit. Used by /bench (rt/exports.rs).
#[cfg(any(test, feature = "mem_report"))]
pub(crate) fn url_decode(src: &[u8], out: &mut [u8]) -> Option<usize> {
    let (mut i, mut n) = (0, 0);
    while i < src.len() {
        let c = if src[i] == b'%' {
            let v = hex(*src.get(i + 1)?)? << 4 | hex(*src.get(i + 2)?)?;
            i += 3;
            v
        } else {
            i += 1;
            src[i - 1]
        };
        if c == 0 || n + 1 >= out.len() {
            return None;
        }
        out[n] = c;
        n += 1;
    }
    *out.get_mut(n)? = 0;
    Some(n)
}

pub(crate) fn ext_gate() -> u32 {
    if ON {
        get(EXT_GATE)
    } else {
        AMPR_EMU_PACK_READ_EXTEND_MAX_DISK_INFLIGHT
    }
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [b' ' | b'\t', rest @ ..] = s {
        s = rest;
    }
    while let [rest @ .., b' ' | b'\t'] = s {
        s = rest;
    }
    s
}

fn parse_u32(s: &[u8]) -> Option<u32> {
    if s.is_empty() || s.len() > 9 || !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(s.iter().fold(0u32, |v, d| v * 10 + (d - b'0') as u32))
}

/// Applies `k=v` pairs separated by '&' or newlines ('#' starts a comment
/// line). Pairs before the first bad one stay applied; returns the bad one.
pub(crate) fn apply(s: &[u8]) -> Result<(), &[u8]> {
    for pair in s.split(|&c| c == b'&' || c == b'\n' || c == b'\r') {
        let pair = trim(pair);
        if pair.is_empty() || pair[0] == b'#' {
            continue;
        }
        let Some(eq) = pair.iter().position(|&c| c == b'=') else {
            return Err(pair);
        };
        let (k, v) = (trim(&pair[..eq]), trim(&pair[eq + 1..]));
        if k == b"profile" {
            let Some((_, values)) = PROFILES.iter().find(|(name, _)| name.as_bytes() == v) else {
                return Err(pair);
            };
            for (i, &value) in values.iter().enumerate() {
                KNOBS[i].v.store(value, Relaxed);
            }
            continue;
        }
        let Some(knob) = KNOBS.iter().find(|n| n.name.as_bytes() == k) else {
            return Err(pair);
        };
        match parse_u32(v) {
            Some(value) if (knob.min..=knob.max).contains(&value) => knob.v.store(value, Relaxed),
            _ => return Err(pair),
        }
    }
    Ok(())
}

const O_RDONLY: c_int = 0x0;
#[cfg(feature = "mem_report")]
const O_WRONLY: c_int = 0x1;
#[cfg(feature = "mem_report")]
const O_CREAT: c_int = 0x200;
#[cfg(feature = "mem_report")]
const O_TRUNC: c_int = 0x400;

/// Reads TUNE_PATH into the knobs; a missing or bad file keeps the defaults
/// of the pairs it does not set. Called once, before the pack state is built.
pub(crate) unsafe fn load() {
    if !ON {
        return;
    }
    let fd = unsafe { real_posix_open(TUNE_PATH.as_ptr(), O_RDONLY, 0) };
    if fd < 0 {
        return;
    }
    let mut buf = [0u8; 1024];
    let n = unsafe { real_physical_pread(fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
    let _ = unsafe { real_physical_close(fd) };
    if n > 0 {
        apply_file(&buf[..n as usize]);
    }
}

/// Applies a tune file line by line. A bad or unknown line (e.g. the
/// `app0_direct=` and `app0_backing=` lines older builds wrote) is skipped,
/// so it does not drop the knobs on the lines after it.
fn apply_file(s: &[u8]) {
    for line in s.split(|&c| c == b'\n') {
        let _ = apply(line);
    }
}

/// Writes every knob as `name=value` lines to TUNE_PATH; false on failure.
#[cfg(feature = "mem_report")]
pub(crate) unsafe fn save() -> bool {
    let mut buf = [0u8; 512];
    let mut len = 0;
    for knob in KNOBS.iter() {
        let mut digits = [0u8; 10];
        let (mut v, mut n) = (knob.v.load(Relaxed), 0);
        loop {
            digits[n] = b'0' + (v % 10) as u8;
            n += 1;
            v /= 10;
            if v == 0 {
                break;
            }
        }
        digits[..n].reverse();
        for part in [knob.name.as_bytes(), b"=", &digits[..n], b"\n"] {
            buf[len..len + part.len()].copy_from_slice(part);
            len += part.len();
        }
    }
    let fd = unsafe { real_posix_open(TUNE_PATH.as_ptr(), O_WRONLY | O_CREAT | O_TRUNC, 0o666) };
    if fd < 0 {
        return false;
    }
    let ok = unsafe { super::index::write_all(fd, &buf[..len]) };
    let closed = unsafe { real_physical_close(fd) } == 0;
    closed && ok
}

/// Current value of `knob` (for listings).
#[cfg(feature = "mem_report")]
pub(crate) fn value(knob: &Knob) -> u32 {
    knob.v.load(Relaxed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn knob_value(i: usize) -> u32 {
        KNOBS[i].v.load(Relaxed)
    }

    /// KNOBS is global and tests run in parallel: tests that set knobs or
    /// expect their defaults hold this lock.
    static KNOB_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn knob_lock() -> std::sync::MutexGuard<'static, ()> {
        KNOB_LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    #[test]
    fn issue_limit_knobs_default_to_release_constants() {
        let _lock = knob_lock();
        assert_eq!(
            knob_value(READ_PASS_KIB) as u64 * 1024,
            AMPR_EMU_APR_READ_PASS_MAX_BYTES
        );
        assert_eq!(
            knob_value(READ_CHUNK_QUANTUM),
            AMPR_EMU_APR_READ_CHUNK_QUANTUM
        );
        assert_eq!(
            knob_value(PER_READ_ACTIVE_KIB) as u64 * 1024,
            AMPR_EMU_APR_PER_READ_ACTIVE_BYTES
        );
        assert_eq!(
            knob_value(PER_READ_ACTIVE_CHUNKS),
            AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS
        );
        assert_eq!(KNOBS[READ_PASS_KIB].name, "read_pass_kib");
        assert_eq!(KNOBS[READ_CHUNK_QUANTUM].name, "read_chunk_quantum");
        assert_eq!(KNOBS[PER_READ_ACTIVE_KIB].name, "per_read_active_kib");
        assert_eq!(KNOBS[PER_READ_ACTIVE_CHUNKS].name, "per_read_active_chunks");
    }

    #[test]
    fn issue_limit_knob_ranges_keep_a_full_slice_issuable() {
        // A budget or window below one 512 KiB slice would never admit it.
        assert_eq!(READ_SLICE_KIB, 512);
        for i in [READ_PASS_KIB, PER_READ_ACTIVE_KIB] {
            assert_eq!(KNOBS[i].min, READ_SLICE_KIB);
            assert_eq!(KNOBS[i].max, 16 * 1024);
        }
        assert_eq!(
            (KNOBS[READ_CHUNK_QUANTUM].min, KNOBS[READ_CHUNK_QUANTUM].max),
            (1, 64)
        );
        assert_eq!(
            (
                KNOBS[PER_READ_ACTIVE_CHUNKS].min,
                KNOBS[PER_READ_ACTIVE_CHUNKS].max
            ),
            (1, 32)
        );
    }

    #[test]
    fn apply_rejects_issue_limits_out_of_range() {
        let _lock = knob_lock();
        for bad in [
            &b"read_pass_kib=511"[..],
            b"read_pass_kib=16385",
            b"read_chunk_quantum=0",
            b"read_chunk_quantum=65",
            b"per_read_active_kib=0",
            b"per_read_active_kib=16385",
            b"per_read_active_chunks=0",
            b"per_read_active_chunks=33",
        ] {
            assert_eq!(
                apply(bad),
                Err(bad),
                "{}",
                core::str::from_utf8(bad).unwrap()
            );
        }
        // Rejected pairs leave the defaults in place.
        assert_eq!(
            knob_value(READ_CHUNK_QUANTUM),
            AMPR_EMU_APR_READ_CHUNK_QUANTUM
        );
    }

    #[test]
    fn apply_sets_issue_limits_in_range_then_restores() {
        let _lock = knob_lock();
        assert_eq!(
            apply(b"read_pass_kib=4096&read_chunk_quantum=32&per_read_active_kib=8192&per_read_active_chunks=16"),
            Ok(())
        );
        assert_eq!(knob_value(READ_PASS_KIB), 4096);
        assert_eq!(knob_value(READ_CHUNK_QUANTUM), 32);
        assert_eq!(knob_value(PER_READ_ACTIVE_KIB), 8192);
        assert_eq!(knob_value(PER_READ_ACTIVE_CHUNKS), 16);
        assert_eq!(
            apply(b"read_pass_kib=512\nread_chunk_quantum=8\nper_read_active_kib=2048\nper_read_active_chunks=4"),
            Ok(())
        );
        assert_eq!(knob_value(READ_PASS_KIB), 512);
        assert_eq!(knob_value(PER_READ_ACTIVE_CHUNKS), 4);
    }

    #[test]
    fn release_getters_return_constants() {
        if ON {
            return;
        }
        assert_eq!(read_pass_bytes(), AMPR_EMU_APR_READ_PASS_MAX_BYTES);
        assert_eq!(read_chunk_quantum(), AMPR_EMU_APR_READ_CHUNK_QUANTUM);
        assert_eq!(per_read_active_bytes(), AMPR_EMU_APR_PER_READ_ACTIVE_BYTES);
        assert_eq!(
            per_read_active_chunks(),
            AMPR_EMU_APR_PER_READ_ACTIVE_CHUNKS
        );
        assert_eq!(pread_threads(), RELEASE_PREAD_THREADS as usize);
    }

    #[test]
    fn pread_threads_range_reaches_the_debug_ceiling() {
        let _lock = knob_lock();
        let knob = &KNOBS[PREAD_THREADS];
        assert_eq!(knob.max as usize, AMPR_EMU_PACK_PREAD_WORKERS);
        assert_eq!(knob_value(PREAD_THREADS), RELEASE_PREAD_THREADS);
        if ON {
            assert_eq!(AMPR_EMU_PACK_PREAD_WORKERS, 64);
        } else {
            assert_eq!(AMPR_EMU_PACK_PREAD_WORKERS, 32);
        }
    }

    #[test]
    fn lane_eop_overlap_defaults_off_and_applies() {
        let _lock = knob_lock();
        assert_eq!(KNOBS[LANE_EOP_OVERLAP].name, "lane_eop_overlap");
        assert_eq!(knob_value(LANE_EOP_OVERLAP), 0);
        assert!(!AMPR_EMU_APR_LANE_EOP_OVERLAP);
        assert_eq!(
            apply(b"lane_eop_overlap=2"),
            Err(&b"lane_eop_overlap=2"[..])
        );
        assert_eq!(knob_value(LANE_EOP_OVERLAP), 0);
        assert_eq!(apply(b"lane_eop_overlap=1"), Ok(()));
        assert_eq!(knob_value(LANE_EOP_OVERLAP), 1);
        // Release builds ignore the knob and use the constant (off).
        assert_eq!(lane_eop_overlap(), ON);
        assert_eq!(apply(b"lane_eop_overlap=0"), Ok(()));
        assert!(!lane_eop_overlap());
    }

    #[test]
    fn tune_file_skips_unknown_lines_and_applies_the_rest() {
        let _lock = knob_lock();
        // The console's /data/ampr_emu_tune.txt still has the removed
        // app0_direct knob and app0_backing folder between known knobs.
        let file = b"ra=8\napp0_direct=1\napp0_backing=/data/homebrew/%5BX%5D\r\n\
            # comment\nnot a pair\nread_chunk_quantum=32\nlane_eop_overlap=0\n";
        apply_file(file);
        assert_eq!(knob_value(RA), 8);
        assert_eq!(knob_value(READ_CHUNK_QUANTUM), 32);
        assert_eq!(knob_value(LANE_EOP_OVERLAP), 0);
        // /set queries still report the first bad pair.
        assert_eq!(apply(b"app0_direct=1"), Err(&b"app0_direct=1"[..]));
        KNOBS[RA].v.store(AMPR_EMU_PACK_READAHEAD_CHUNKS, Relaxed);
        KNOBS[READ_CHUNK_QUANTUM]
            .v
            .store(AMPR_EMU_APR_READ_CHUNK_QUANTUM, Relaxed);
        KNOBS[LANE_EOP_OVERLAP]
            .v
            .store(AMPR_EMU_APR_LANE_EOP_OVERLAP as u32, Relaxed);
    }

    #[test]
    fn save_buffer_fits_every_knob_at_its_widest() {
        // save() writes `name=value\n` per knob into 512 bytes.
        let widest: usize = KNOBS
            .iter()
            .map(|k| k.name.len() + 2 + k.max.to_string().len())
            .sum();
        assert!(widest <= 512, "{widest}");
    }
}
