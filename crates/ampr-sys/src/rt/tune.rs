//! Tuning knobs of the debug build (`make AMPR_MEM_REPORT=1`). Startup knobs
//! (cache sizes, workers, pipelines, cache reserve) are read from TUNE_PATH
//! when the pack state is created (pack/state.rs); live knobs (read-ahead, read
//! extension and their disk gates, pread pool on/off) take effect on the next
//! read.
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
use super::reactor::AMPR_EMU_PACK_PREAD_WORKERS;
use super::sys::*;
use core::ffi::{c_int, CStr};
use core::sync::atomic::{AtomicU32, Ordering::Relaxed};

pub(crate) const ON: bool = cfg!(feature = "mem_report");
pub(crate) const TUNE_PATH: &CStr = c"/data/ampr_emu_tune.txt";
/// Pipelines a release build has; the debug build has room for 32.
pub(crate) const RELEASE_PIPELINES: u32 = 16;
/// Pread pool threads a release build starts: one per pipeline, so a
/// pipeline's disk read never waits for a thread.
pub(crate) const RELEASE_PREAD_THREADS: u32 = RELEASE_PIPELINES;
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

/// Cache sizes: 0 turns a cache off (reads bypass it); otherwise the cache
/// allocators' minimums apply (decoded 16, physical 8 MiB, pack/manifest.rs).
pub(crate) static KNOBS: [Knob; 11] = [
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
pub(crate) fn pread_threads() -> usize {
    if ON {
        get(PREAD_THREADS) as usize
    } else {
        AMPR_EMU_PACK_PREAD_WORKERS
    }
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
        let _ = apply(&buf[..n as usize]);
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
