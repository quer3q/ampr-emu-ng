//! Tuning knobs of the debug build (`make AMPR_MEM_REPORT=1`). All knobs are
//! read from TUNE_PATH once, in module_start before the hooks install
//! (rt/exports.rs). Startup knobs (cache sizes, workers, pipelines, pread
//! threads, zstd_verify, equeue_local, pack worker stack) are used once at
//! startup; live knobs
//! (read-ahead and its disk gate, pread pool on/off for pack and loose reads,
//! the reactor's per-pass and per-read issue limits, lane EOP overlap, the
//! thread budget and runtime thread spin and regrow times)
//! take effect on the next read, reactor pass or thread idle check.
//! `GET /set?k=v&...` on the metrics port changes both and rewrites TUNE_PATH,
//! so startup knobs apply on the next game launch; `profile=low|medium|high`
//! sets all startup knobs. Release builds use the compile-time constants:
//! `ON` is false and the atomics are never read.

use super::pack::{
    AMPR_EMU_PACK_DECODED_CACHE_BYTES, AMPR_EMU_PACK_PIPELINE_SLOTS,
    AMPR_EMU_PACK_READAHEAD_CHUNKS, AMPR_EMU_PACK_READAHEAD_MAX_DISK_INFLIGHT,
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
/// Pipelines a build starts, from the Makefile's `AMPR_PACK_PIPELINES`
/// (default 12, also when built outside the Makefile); it is the release
/// build's slot count too (pack/mod.rs). A zstd title used at most 9-10 at
/// once, and 12 against 16 gave the same game wait per read, 312 vs 315 us
/// (debug /metrics).
pub(crate) const RELEASE_PIPELINES: u32 = match option_env!("AMPR_PACK_PIPELINES") {
    Some(s) => super::runtime_memory::parse_size(s.as_bytes()) as u32,
    None => 12,
};
/// Most pread pool threads, both builds (the pool starts at 1 and grows on
/// demand within the thread budget, rt/thread_hooks.rs). At 32 a game's own
/// thread creation failed once the pool had grown to 24, with never more
/// than 4 reads in flight; a zstd title peaked at 5-6 threads and its game
/// wait per read did not change between 8 and 32, and two titles peaked at
/// 4-5 disk threads (debug /metrics), so 6.
pub(crate) const RELEASE_PREAD_THREADS: u32 = 6;
/// Most worker threads the runtime grows, all groups together, both builds
/// (rt/thread_hooks.rs budget); the debug knob `thread_budget` lowers it.
pub(crate) const THREAD_BUDGET: u32 = 16;
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
const WORKERS: usize = 1;
const PIPELINES: usize = 2;
const RA: usize = 3;
const RA_GATE: usize = 4;
const PREAD: usize = 5;
const PREAD_THREADS: usize = 6;
const LOOSE_PREAD: usize = 7;
const LOOSE_PREAD_PART_KIB: usize = 8;
const READ_PASS_KIB: usize = 9;
const READ_CHUNK_QUANTUM: usize = 10;
const PER_READ_ACTIVE_KIB: usize = 11;
const PER_READ_ACTIVE_CHUNKS: usize = 12;
const LANE_EOP_OVERLAP: usize = 13;
const PREAD_WAKE_ALL: usize = 14;
const ZSTD_VERIFY: usize = 15;
const EQUEUE_LOCAL: usize = 16;
const THREAD_BUDGET_KNOB: usize = 17;
const SPIN_US: usize = 18;
const REGROW_S: usize = 19;
const WORKER_STACK_KIB: usize = 20;

// ---- runtime thread lifetime (rt/thread_hooks.rs) ----
// Release values; the debug knobs of the same names default to them.

/// Microseconds an idle runtime thread spins before it parks; 0 parks at once.
pub(crate) const SPIN_US_DEFAULT: u32 = 0;
/// Quiet seconds after a thread creation failure before the budget regrows
/// by one and pressure mode ends (rt/thread_hooks.rs). Retirement is by load,
/// so the groups shrink by themselves; 10 s gives the budget back sooner
/// than the earlier 30 s.
pub(crate) const REGROW_S_DEFAULT: u32 = 10;
/// Pack worker stack in KiB; 0 keeps the system default.
pub(crate) const WORKER_STACK_KIB_DEFAULT: u32 = 0;

/// Smallest pass budget and per-read active window, in KiB: one full read
/// slice (kSoftwareReadChunkMax, 512 KiB). A smaller value would leave a full
/// slice unissuable forever (flush.rs submit_read_chain_slice), so the job
/// would never finish.
const READ_SLICE_KIB: u32 = (kSoftwareReadChunkMax / 1024) as u32;
/// Largest pass budget and per-read active window, in KiB (16 MiB).
const READ_LIMIT_MAX_KIB: u32 = 16 * 1024;

/// Cache size: 0 turns the decoded cache off (reads bypass it); otherwise
/// its 16 MiB minimum applies (pack/manifest.rs).
pub(crate) static KNOBS: [Knob; 21] = [
    knob(
        "decoded_mib",
        false,
        0,
        512,
        (AMPR_EMU_PACK_DECODED_CACHE_BYTES / MIB) as u32,
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
    knob("ra", true, 0, RA_MAX, AMPR_EMU_PACK_READAHEAD_CHUNKS),
    knob(
        "ra_gate",
        true,
        0,
        64,
        AMPR_EMU_PACK_READAHEAD_MAX_DISK_INFLIGHT,
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
    knob("pread_wake_all", true, 0, 1, 0),
    knob("zstd_verify", false, 0, 1, ON as u32),
    knob("equeue_local", false, 0, 1, 0),
    knob("thread_budget", true, 1, THREAD_BUDGET, THREAD_BUDGET),
    knob("spin_us", true, 0, 200, SPIN_US_DEFAULT),
    knob("regrow_s", true, 1, 60, REGROW_S_DEFAULT),
    knob("worker_stack_kib", false, 0, 1024, WORKER_STACK_KIB_DEFAULT),
];

/// (name, [decoded_mib, workers, pipelines]). The decoded sizes are the
/// earlier two-cache totals. `pipelines` is clamped to the build's slots
/// (`apply`); a cache past the Cache cap is cut to what is left under
/// it, and workers and windows past the Buffer cap are refused
/// (rt/index_memory.rs).
const PROFILES: [(&str, [u32; 3]); 3] = [
    ("low", [24, 4, 8]),
    ("medium", [80, 8, 16]),
    ("high", [160, 8, 32]),
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
pub(crate) fn workers() -> u32 {
    if ON {
        get(WORKERS)
    } else {
        AMPR_EMU_PACK_WORKERS
    }
}
/// At most AMPR_EMU_PACK_PIPELINE_SLOTS, the slots the worker start
/// (worker.rs) has.
pub(crate) fn pipelines() -> usize {
    if ON {
        (get(PIPELINES) as usize).min(AMPR_EMU_PACK_PIPELINE_SLOTS)
    } else {
        AMPR_EMU_PACK_PIPELINE_SLOTS
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
/// 1: a pool submit wakes every pool thread (the old behavior, for A/B);
/// 0: one thread per queued task (reactor/pread_pool.rs).
pub(crate) fn pread_wake_all() -> bool {
    ON && get(PREAD_WAKE_ALL) != 0
}
/// 1 (the debug default): zstd decoders check each chunk's frame checksum,
/// and a mismatch fails the read and logs a 'Z' event. Release never
/// checks. Read when the decoders are created.
pub(crate) fn zstd_verify() -> bool {
    ON && get(ZSTD_VERIFY) != 0
}
/// 1 lets the equeue overlay wait on a queue it classified as AMPR-only in
/// user space (rt/equeue.rs `queue_would_be_exclusive_local_ignoring_amm_health_locked`);
/// 0, the default in both builds, keeps every tracked wait a native kernel
/// wait, which the overlay wakes privately to hand over its own events.
/// The user-space wait missed native events added by paths the overlay
/// does not hook (a game's save mount was never unmounted, kernel log).
/// Queues are tracked either way (rt/hook.rs `refresh`): the kernel merges
/// two events of one id, which hung a save load. The knob is for A/B.
pub(crate) fn equeue_local() -> bool {
    ON && get(EQUEUE_LOCAL) != 0
}
/// `THREAD_BUDGET`; the debug build reads `thread_budget` (1..=16).
pub(crate) fn thread_budget() -> u32 {
    if ON {
        get(THREAD_BUDGET_KNOB)
    } else {
        THREAD_BUDGET
    }
}
/// Spin window, in us, of an idle runtime thread before it parks; the debug
/// build reads `spin_us` (0..=200).
pub(crate) fn spin_us() -> u32 {
    if ON {
        get(SPIN_US)
    } else {
        SPIN_US_DEFAULT
    }
}
/// Quiet time, in ns, after a thread creation failure before the budget
/// regrows by one and pressure mode ends; the debug build reads `regrow_s`
/// (1..=60).
pub(crate) fn regrow_ns() -> u64 {
    let s = if ON { get(REGROW_S) } else { REGROW_S_DEFAULT };
    s as u64 * 1_000_000_000
}
/// Pack worker stack in bytes, 0 for the system default; the debug build
/// reads `worker_stack_kib` (0..=1024) at startup.
pub(crate) fn worker_stack_bytes() -> usize {
    let kib = if ON {
        get(WORKER_STACK_KIB)
    } else {
        WORKER_STACK_KIB_DEFAULT
    };
    kib as usize * 1024
}
pub(crate) fn pread_threads() -> usize {
    if ON {
        get(PREAD_THREADS) as usize
    } else {
        RELEASE_PREAD_THREADS as usize
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

/// `v` for `knob`: a number in its range.
fn parse_value(knob: &Knob, v: &[u8]) -> Option<u32> {
    parse_u32(v).filter(|value| (knob.min..=knob.max).contains(value))
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
            // Clamped to each knob's range: `high` asks for 32 pipelines,
            // more than a build with fewer AMPR_PACK_PIPELINES slots has.
            for (i, &value) in values.iter().enumerate() {
                KNOBS[i].v.store(value.clamp(KNOBS[i].min, KNOBS[i].max), Relaxed);
            }
            continue;
        }
        let Some(knob) = KNOBS.iter().find(|n| n.name.as_bytes() == k) else {
            return Err(pair);
        };
        match parse_value(knob, v) {
            Some(value) => knob.v.store(value, Relaxed),
            None => return Err(pair),
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
/// of the pairs it does not set. Called once, from module_start before the
/// hooks install (rt/exports.rs).
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

/// `v` as save() writes it: decimal digits in `digits`.
#[cfg(any(test, feature = "mem_report"))]
fn value_text(mut v: u32, digits: &mut [u8; 10]) -> &[u8] {
    let mut n = 0;
    loop {
        digits[n] = b'0' + (v % 10) as u8;
        n += 1;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    digits[..n].reverse();
    &digits[..n]
}

/// Every knob as `name=value\n` lines into `buf`; returns the length. Every
/// knob at its widest value fits (test below); load reads 1024.
#[cfg(any(test, feature = "mem_report"))]
fn render(buf: &mut [u8; 1024]) -> usize {
    let mut len = 0;
    for knob in KNOBS.iter() {
        let mut digits = [0u8; 10];
        let text = value_text(knob.v.load(Relaxed), &mut digits);
        for part in [knob.name.as_bytes(), b"=", text, b"\n"] {
            buf[len..len + part.len()].copy_from_slice(part);
            len += part.len();
        }
    }
    len
}

/// Writes every knob as `name=value` lines to TUNE_PATH; false on failure.
#[cfg(feature = "mem_report")]
pub(crate) unsafe fn save() -> bool {
    let mut buf = [0u8; 1024];
    let len = render(&mut buf);
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
pub(crate) mod tests {
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

    /// `apply` rejects out-of-range pairs without storing them and stores
    /// in-range ones; the test restores the defaults it changed.
    #[test]
    fn apply_checks_ranges_then_stores() {
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
            b"lane_eop_overlap=2",
        ] {
            assert_eq!(
                apply(bad),
                Err(bad),
                "{}",
                core::str::from_utf8(bad).unwrap()
            );
        }
        assert_eq!(
            knob_value(READ_CHUNK_QUANTUM),
            AMPR_EMU_APR_READ_CHUNK_QUANTUM
        );
        assert_eq!(knob_value(LANE_EOP_OVERLAP), 0);
        assert_eq!(
            apply(b"read_pass_kib=4096&read_chunk_quantum=32&per_read_active_kib=8192&per_read_active_chunks=16&lane_eop_overlap=1"),
            Ok(())
        );
        assert_eq!(knob_value(READ_PASS_KIB), 4096);
        assert_eq!(knob_value(READ_CHUNK_QUANTUM), 32);
        assert_eq!(knob_value(PER_READ_ACTIVE_KIB), 8192);
        assert_eq!(knob_value(PER_READ_ACTIVE_CHUNKS), 16);
        // Release builds ignore the knob and use the constant (off).
        assert_eq!(lane_eop_overlap(), ON);
        assert_eq!(
            apply(b"read_pass_kib=512\nread_chunk_quantum=8\nper_read_active_kib=2048\nper_read_active_chunks=4\nlane_eop_overlap=0"),
            Ok(())
        );
        assert_eq!(knob_value(READ_PASS_KIB), 512);
        assert_eq!(knob_value(PER_READ_ACTIVE_CHUNKS), 4);
        assert!(!lane_eop_overlap());
    }

    /// The tune file may hold removed knobs and junk lines: they are skipped
    /// and the known pairs still apply. save() writes `name=value\n` per knob
    /// into 1024 bytes, which fits every knob at its widest.
    #[test]
    fn tune_file_skips_unknown_lines_and_save_fits() {
        let _lock = knob_lock();
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
        let widest: usize = KNOBS
            .iter()
            .map(|k| k.name.len() + 2 + k.max.to_string().len())
            .sum();
        assert!(widest <= 1024, "{widest}");
    }

    /// `pipelines` defaults to AMPR_PACK_PIPELINES and never passes the
    /// build's slots: the knob range ends there and a profile is clamped to
    /// it (`high` asks for 32).
    #[test]
    fn pipelines_stay_within_build_slots() {
        let _lock = knob_lock();
        let slots = AMPR_EMU_PACK_PIPELINE_SLOTS as u32;
        let k = &KNOBS[PIPELINES];
        assert_eq!(
            (k.min, k.max, knob_value(PIPELINES)),
            (1, slots, RELEASE_PIPELINES)
        );
        assert_eq!(RELEASE_PIPELINES, 12);
        if ON {
            assert_eq!(pipelines(), RELEASE_PIPELINES as usize);
        }
        let saved: Vec<u32> = (0..3).map(knob_value).collect();
        assert_eq!(apply(b"profile=high"), Ok(()));
        assert_eq!(knob_value(PIPELINES), slots.min(32));
        assert!(pipelines() <= AMPR_EMU_PACK_PIPELINE_SLOTS);
        let over = format!("pipelines={}", slots + 1);
        assert_eq!(apply(over.as_bytes()), Err(over.as_bytes()));
        for (i, v) in saved.into_iter().enumerate() {
            KNOBS[i].v.store(v, Relaxed);
        }
    }

    /// The sizing knobs are plain numbers with the build defaults (workers
    /// 4, pipelines 12, decoded cache 64 MiB); `auto`, junk and the removed
    /// `workers_min`/`pipelines_min` are rejected without storing; 0 turns
    /// the cache off.
    #[test]
    fn sizing_knobs_take_numbers_only() {
        let _lock = knob_lock();
        let defaults = [
            (DECODED_MIB, 64),
            (WORKERS, AMPR_EMU_PACK_WORKERS),
            (PIPELINES, RELEASE_PIPELINES),
        ];
        for (i, v) in defaults {
            assert_eq!(knob_value(i), v, "{}", KNOBS[i].name);
        }
        assert_eq!(AMPR_EMU_PACK_WORKERS, 4);
        assert_eq!(workers(), AMPR_EMU_PACK_WORKERS);
        assert_eq!(decoded_bytes(), AMPR_EMU_PACK_DECODED_CACHE_BYTES as usize);
        for bad in [
            &b"workers=auto"[..],
            b"pipelines=auto",
            b"decoded_mib=auto",
            b"workers=",
            b"workers=-1",
            b"workers=0",
            b"workers=17",
            b"pipelines=4x",
            b"decoded_mib=513",
            b"workers_min=1",
            b"pipelines_min=2",
        ] {
            assert_eq!(apply(bad), Err(bad), "{}", core::str::from_utf8(bad).unwrap());
        }
        assert_eq!(knob_value(WORKERS), AMPR_EMU_PACK_WORKERS);
        assert_eq!(apply(b"workers=3&pipelines=5&decoded_mib=0"), Ok(()));
        assert_eq!(
            (knob_value(WORKERS), knob_value(PIPELINES), knob_value(DECODED_MIB)),
            (3, 5, 0)
        );
        if ON {
            assert_eq!((workers(), pipelines()), (3, 5));
            assert_eq!(decoded_bytes(), 0);
        }
        for (i, v) in defaults {
            KNOBS[i].v.store(v, Relaxed);
        }
    }

    /// The text save() writes (render) parses back to the same values.
    #[test]
    fn saved_values_round_trip() {
        let _lock = knob_lock();
        assert_eq!(apply(b"workers=3&pipelines=7"), Ok(()));
        let saved: Vec<u32> = KNOBS.iter().map(|k| k.v.load(Relaxed)).collect();
        let mut buf = [0u8; 1024];
        let len = render(&mut buf);
        let file = buf[..len].to_vec();
        let text = String::from_utf8(file.clone()).unwrap();
        assert!(text.contains("workers=3\n") && text.contains("pipelines=7\n"), "{text}");
        assert!(text.contains("decoded_mib=64\n"), "{text}");
        assert_eq!(apply(b"workers=2&pipelines=4&decoded_mib=48"), Ok(()));
        assert_eq!(apply(&file), Ok(()));
        let loaded: Vec<u32> = KNOBS.iter().map(|k| k.v.load(Relaxed)).collect();
        assert_eq!(loaded, saved);
        let restore = format!("workers={}&pipelines={}", AMPR_EMU_PACK_WORKERS, RELEASE_PIPELINES);
        assert_eq!(apply(restore.as_bytes()), Ok(()));
    }
}
