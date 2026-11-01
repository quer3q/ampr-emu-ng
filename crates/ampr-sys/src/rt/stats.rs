//! Streaming counters for the debug build (`make AMPR_MEM_REPORT=1`). In normal
//! builds every function here is an empty inline, so call sites cost nothing.
//! The debug metrics endpoint (rt/exports.rs) serves them over TCP.

use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

const ON: bool = cfg!(feature = "mem_report");

macro_rules! stats {
    ($($(#[$doc:meta])* $name:ident = $key:literal,)*) => {
        #[derive(Clone, Copy)]
        #[repr(usize)]
        pub(crate) enum Stat { $($(#[$doc])* $name,)* Count }
        /// Metric names in `Stat` order, as served by the endpoint.
        #[cfg(feature = "mem_report")]
        pub(crate) const NAMES: [&str; Stat::Count as usize] = [$($key,)*];
    };
}

stats! {
    /// Physical pack-volume reads issued (kernel AIO or pread) and their bytes.
    PackDiskReads = "pack_disk_reads",
    PackDiskBytes = "pack_disk_bytes",
    /// Pack virtual reads completed and their submit->complete latency.
    PackJobs = "pack_jobs",
    PackJobNs = "pack_job_ns",
    PackJobNsMax = "pack_job_ns_max",
    /// LZ4/RAW chunk decodes and time spent decoding.
    Decodes = "decodes",
    DecodeNs = "decode_ns",
    DecodedBytes = "decoded_bytes",
    /// Decoded-chunk cache lookups.
    CacheHits = "cache_hits",
    CacheMisses = "cache_misses",
    /// Demand misses split by whether the chunk was read before (demand or
    /// read-ahead) and later evicted: "repeat" misses are what a bigger or
    /// smarter cache could save, "first" misses only earlier prefetch can.
    CacheMissFirst = "cache_miss_first",
    CacheMissRepeat = "cache_miss_repeat",
    /// Reactor active reads (the game's APR read commands): submit->observed
    /// latency, polls per read, and the gap between the last "not done" poll
    /// and the "done" poll (how late a completion was noticed, upper bound).
    AprReads = "apr_reads",
    AprReadBytes = "apr_read_bytes",
    AprReadNs = "apr_read_ns",
    AprReadNsMax = "apr_read_ns_max",
    AprPolls = "apr_polls",
    AprDetectNs = "apr_detect_ns",
    /// Same for the reactor's external AIO reads (pack workers' physical reads).
    ExtReads = "ext_reads",
    ExtReadNs = "ext_read_ns",
    ExtReadNsMax = "ext_read_ns_max",
    ExtPolls = "ext_polls",
    ExtDetectNs = "ext_detect_ns",
    /// Read-ahead: chunks queued for prefetch, and candidates skipped (already
    /// cached, random-access file, no free slot or worker).
    PrefetchChunks = "prefetch_chunks",
    PrefetchSkipped = "prefetch_skipped",
    /// Physical page cache lookups (hits = no disk read needed).
    PhysHits = "phys_hits",
    PhysMisses = "phys_misses",
    /// Reads served by the blocking pread pool (reactor/pread_pool.rs): calls and
    /// bytes, time queued for a pool thread, time in pread, and the peak
    /// number of queued + running reads since the last scrape. Pack reads
    /// and, with `loose_pread` on, loose reads (the loose_pread_* subset).
    PreadReads = "pread_reads",
    PreadBytes = "pread_bytes",
    PreadQueueNs = "pread_queue_ns",
    PreadQueueNsMax = "pread_queue_ns_max",
    PreadReadNs = "pread_read_ns",
    PreadReadNsMax = "pread_read_ns_max",
    PreadPendingMax = "pread_pending_max",
    /// Loose APR reads (real fds) through the pread pool (reactor/loose_pread.rs):
    /// full reads and their bytes; pool reads that got EFAULT and went to
    /// kernel AIO; pool reads that failed otherwise or came back short and went
    /// to kernel AIO; reads sent straight to kernel AIO because their
    /// destination faulted before. apr_reads/apr_read_ns cover loose reads on
    /// either path, so runs with the knob on and off compare.
    LoosePreadReads = "loose_pread_reads",
    LoosePreadBytes = "loose_pread_bytes",
    LoosePreadEfault = "loose_pread_efault",
    LoosePreadRetry = "loose_pread_retry",
    LoosePreadSkipped = "loose_pread_skipped",
    /// Split loose reads (`loose_pread_part_kib`, reactor/loose_pread.rs):
    /// reads queued as more than one part task, and the part tasks they
    /// queued. Unsplit reads count in neither; loose_pread_reads and
    /// apr_reads still count each read once.
    LoosePreadSplitReads = "loose_pread_split_reads",
    LoosePreadParts = "loose_pread_parts",
    /// Highest number of reactor AIO reads in flight since the last scrape.
    AprInflightMax = "apr_inflight_max",
    /// Failures: pack virtual reads completed with an error, chunk decodes that failed.
    PackJobErrors = "pack_job_errors",
    DecodeErrors = "decode_errors",
    /// libc `open` hook (index.rs open_impl) by resident-lookup outcome, and
    /// /app0 opens it routed to a virtual pack fd or to the real open.
    OpenNotApp0 = "open_not_app0",
    OpenIndexNotReady = "open_index_not_ready",
    OpenHit = "open_hit",
    OpenMiss = "open_miss",
    OpenDirectory = "open_directory",
    OpenVirtual = "open_virtual",
    OpenRealFailed = "open_real_failed",
    /// zstd: bytes a mandatory group read through gaps of cached pages
    /// between its cold pages (one request instead of two), then discarded.
    ReadGapBytes = "read_gap_bytes",
    /// Where a pack job's time goes besides disk and decode: submit to the
    /// first worker pick (queue wait), worker time inside its read steps
    /// (planning, decode, copies), and the copies of decoded bytes into the
    /// caller's buffer.
    JobsStarted = "jobs_started",
    QueueFirstNs = "queue_first_ns",
    WorkerStepNs = "worker_step_ns",
    CopyNs = "copy_ns",
    CopyBytes = "copy_bytes",
    /// Time a started job spends parked between worker steps (debug only).
    /// Io: its disk read submitted -> the job requeued by the completion (pread
    /// queue + pread + completion detection + callback). Cache/Fd: parked on a
    /// page another job is loading, or on the volume fd budget -> requeued.
    /// Requeue: requeued -> a worker picks it up again.
    ParkIos = "park_ios",
    ParkIoNs = "park_io_ns",
    ParkCaches = "park_caches",
    ParkCacheNs = "park_cache_ns",
    ParkFds = "park_fds",
    ParkFdNs = "park_fd_ns",
    Requeues = "requeues",
    RequeueNs = "requeue_ns",
    /// zstd: physical pages another job was loading, read privately by this
    /// job (its own disk read into its I/O window) instead of waiting.
    PrivatePageReads = "private_page_reads",
    /// Reactor issue limits (reactor/progress.rs, reactor/flush.rs; live knobs
    /// read_pass_kib, read_chunk_quantum, per_read_active_kib,
    /// per_read_active_chunks in rt/tune.rs). read_budget_held: lane passes
    /// that left a read slice unissued because the pass budget
    /// (ReadIssueBudget) ran out, counted once per lane pass. read_active_held:
    /// slice attempts refused by the per-read active window (chunks or bytes
    /// in flight on one read chain), counted per attempt, so a read waiting
    /// several passes counts several times.
    ReadBudgetHeld = "read_budget_held",
    ReadActiveHeld = "read_active_held",
    /// APR jobs (command buffers) the reactor finished. job_first_issue_*:
    /// submit accepted (AprAioReactor::submit, reactor/submit.rs) -> the job's
    /// first read slice issued to kernel AIO or the pread pool
    /// (account_active_read_accept, reactor/admission.rs), once per job with
    /// such a read; job_first_issues is its count. job_notify_*: the
    /// reactor observing a job's read chain complete (mark_seq_complete,
    /// reactor/backoff.rs) -> the next point that tells the game: a non-read
    /// command reached with the read fence clear (address write, counter,
    /// equeue, native op; reactor/native.rs), a deferred native EOP released
    /// to the kernel, or the job result published on release
    /// (maybe_release_reactor_job, reactor/worker.rs); job_notifies is its count.
    JobCount = "job_count",
    JobFirstIssues = "job_first_issues",
    JobFirstIssueNs = "job_first_issue_ns",
    JobFirstIssueNsMax = "job_first_issue_ns_max",
    JobNotifies = "job_notifies",
    JobNotifyNs = "job_notify_ns",
    JobNotifyNsMax = "job_notify_ns_max",
    /// The part of job_notify_ns spent waiting on an earlier job of the
    /// lane: when a lane head is released (reactor/worker.rs
    /// maybe_release_reactor_job) and its successor's reads are all done with
    /// its cursor on a completion command, its read-done time -> this
    /// release. N before N+1 forces this wait; job_notify_ns minus it is the
    /// reactor's own share (reactor/lane_overlap.rs note_successor_order_wait).
    JobOrderWaits = "job_order_waits",
    JobOrderWaitNs = "job_order_wait_ns",
    /// Lane loop (reactor/progress.rs) stops before a job that has a
    /// successor queued in its priority lane, so the successor does not parse
    /// in this pass. Counted once per stop (per lane pass), by what the head
    /// is parked on (reactor/lane_overlap.rs lane_block_kind):
    /// lane_successor_blocked_fence: a completion command (EOP write, counter,
    /// equeue) waiting on the head's own read fence or deferred native EOP;
    /// lane_successor_blocked_wait: a WaitOnAddress/WaitOnCounter, or a
    /// native batch wait; lane_successor_blocked_other: anything else (a read
    /// held by budget or window, a native/AMM op, a failed head).
    LaneSuccessorBlockedFence = "lane_successor_blocked_fence",
    LaneSuccessorBlockedWait = "lane_successor_blocked_wait",
    LaneSuccessorBlockedOther = "lane_successor_blocked_other",
    /// Completion commands (not nops/markers) in head jobs whose tail the
    /// live knob lane_eop_overlap let the successor run past, counted once
    /// per job when its tail is first verified (reactor/lane_overlap.rs).
    EopDeferred = "eop_deferred",
}

const N: usize = Stat::Count as usize;
static VALUES: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];

/// `*_max` stats reset on every scrape; all others are monotonic counters.
#[cfg(feature = "mem_report")]
fn resets_on_read(s: usize) -> bool {
    s == Stat::PackJobNsMax as usize
        || s == Stat::AprReadNsMax as usize
        || s == Stat::ExtReadNsMax as usize
        || s == Stat::AprInflightMax as usize
        || s == Stat::PreadQueueNsMax as usize
        || s == Stat::PreadReadNsMax as usize
        || s == Stat::PreadPendingMax as usize
        || s == Stat::JobFirstIssueNsMax as usize
        || s == Stat::JobNotifyNsMax as usize
}

/// Chunks read so far (decoded-cache loads), as a 2^23-bit hash set; a false
/// positive (~1% at 100k chunks) counts a first miss as a repeat. Debug only.
#[cfg(feature = "mem_report")]
static SEEN_CHUNKS: [AtomicU64; 1 << 17] = [const { AtomicU64::new(0) }; 1 << 17];

/// Marks the chunk with `key_hash` as read; true if it was marked before.
#[inline(always)]
pub(crate) fn chunk_seen_before(key_hash: u64) -> bool {
    #[cfg(feature = "mem_report")]
    {
        let bit = (key_hash.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 41) as usize; // 23 bits
        let mask = 1u64 << (bit & 63);
        SEEN_CHUNKS[bit >> 6].fetch_or(mask, Relaxed) & mask != 0
    }
    #[cfg(not(feature = "mem_report"))]
    {
        let _ = key_hash;
        false
    }
}

/// Monotonic nanoseconds, or 0 in normal builds (no clock call).
#[inline(always)]
pub(crate) fn now() -> u64 {
    if ON {
        super::sys::monotonic_ns()
    } else {
        0
    }
}

/// Path hook calls (open/stat/reachability), newest last, debug only: op
/// (b'o', b's', b'r'), resident lookup (b'h' hit, b'm' miss, b'd' directory,
/// b'n' index not ready, b'x' not /app0), result, path.
#[cfg(feature = "mem_report")]
pub(crate) struct FsEvents {
    pub next: usize,
    pub op: [u8; FS_EVENTS],
    pub how: [u8; FS_EVENTS],
    pub rc: [i64; FS_EVENTS],
    pub len: [usize; FS_EVENTS],
    pub path: [[u8; 160]; FS_EVENTS],
}
#[cfg(feature = "mem_report")]
pub(crate) const FS_EVENTS: usize = 32;
#[cfg(feature = "mem_report")]
pub(crate) static FS_LOG: super::sync::SyncCell<FsEvents> = super::sync::SyncCell::new(FsEvents {
    next: 0,
    op: [0; FS_EVENTS],
    how: [0; FS_EVENTS],
    rc: [0; FS_EVENTS],
    len: [0; FS_EVENTS],
    path: [[0; 160]; FS_EVENTS],
});

/// Records one path hook call (racy by design: a debug trace).
#[inline(always)]
pub(crate) fn fs_event(op: u8, how: u8, rc: i64, path: *const core::ffi::c_char) {
    #[cfg(feature = "mem_report")]
    unsafe {
        let log = &mut *FS_LOG.get();
        let slot = log.next % FS_EVENTS;
        log.next = log.next.wrapping_add(1);
        let mut n = 0;
        while n < 160 && !path.is_null() && *path.add(n) != 0 {
            log.path[slot][n] = *path.add(n) as u8;
            n += 1;
        }
        (log.op[slot], log.how[slot], log.rc[slot], log.len[slot]) = (op, how, rc, n);
    }
    #[cfg(not(feature = "mem_report"))]
    let _ = (op, how, rc, path);
}

#[inline(always)]
pub(crate) fn add(s: Stat, v: u64) {
    if ON {
        VALUES[s as usize].fetch_add(v, Relaxed);
    }
}

#[inline(always)]
pub(crate) fn max(s: Stat, v: u64) {
    if ON {
        VALUES[s as usize].fetch_max(v, Relaxed);
    }
}

/// Elapsed ns since `start` from `now()`; 0 if the clock was unavailable.
#[inline(always)]
pub(crate) fn since(start: u64) -> u64 {
    if ON && start != 0 {
        now().saturating_sub(start)
    } else {
        0
    }
}

/// Records one span that started at `start` (from `now()`; 0 = no span):
/// +1 to `count`, the elapsed ns to `sum`, and the scrape maximum to `max_ns`.
#[inline(always)]
pub(crate) fn span(start: u64, count: Stat, sum: Stat, max_ns: Stat) {
    if ON && start != 0 {
        let ns = since(start);
        add(count, 1);
        add(sum, ns);
        max(max_ns, ns);
    }
}

/// Current values: counters as totals since load, maxima since the last read.
#[cfg(feature = "mem_report")]
pub(crate) fn read() -> [u64; N] {
    let mut out = [0u64; N];
    for (i, v) in VALUES.iter().enumerate() {
        out[i] = if resets_on_read(i) {
            v.swap(0, Relaxed)
        } else {
            v.load(Relaxed)
        };
    }
    out
}
