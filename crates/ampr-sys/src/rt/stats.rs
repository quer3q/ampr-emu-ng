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
    /// Misses split by whether the chunk was read before and later evicted:
    /// "repeat" misses are what a bigger or smarter cache could save,
    /// "first" misses only earlier prefetch can.
    CacheMissFirst = "cache_miss_first",
    CacheMissRepeat = "cache_miss_repeat",
    /// The protected cache segment (pack/caches.rs): bytes held by protected
    /// entries now (a gauge), entries promoted after `cache_protect_hits`
    /// hits, and protected entries the hand demoted back to probation.
    CacheProtectedBytes = "cache_protected_bytes",
    /// Bytes the decoded cache grew by when the index finished, from the
    /// Index ledger's idle room (rt/pack/manifest.rs `grow_cache_from_index`).
    CacheGrownBytes = "cache_grown_bytes",
    CachePromotions = "cache_promotions",
    CacheDemotions = "cache_demotions",
    /// Evictions a cache miss made only because all 16384 entries
    /// (`AMPR_EMU_PACK_CACHE_ENTRY_CAP`) were taken while a free page run
    /// was there (rt/pack/caches.rs `cache_acquire`): what a bigger entry
    /// cap would save. Nonzero only for a title of small chunks.
    CacheCapEvictions = "cache_cap_evictions",
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
    /// Pool thread wake-ups, and those that found no queued task (a wake-up
    /// that only takes the lock and scans the table).
    PreadWakeups = "pread_wakeups",
    PreadWakeupsIdle = "pread_wakeups_idle",
    /// Pack window reads a worker queued to the pread pool itself, and those
    /// that went through the reactor instead (no free task or no live pool
    /// thread; reactor/pread_pool.rs `queue_pack_pread`).
    PackPreadDirect = "pack_pread_direct",
    PackPreadReactor = "pack_pread_reactor",
    /// Debug: threads created through scePthreadCreate/pthread_create, the
    /// game's and the runtime's, and the creations that failed (each failure
    /// is also a 'P' event; rt/probe.rs).
    ThreadsCreated = "threads_created",
    ThreadCreateFailed = "thread_create_failed",
    /// Failed game creations retried after the pool gave threads back, and
    /// the retries that succeeded (rt/thread_hooks.rs).
    ThreadCreateRetried = "thread_create_retried",
    ThreadCreateRescued = "thread_create_rescued",
    /// The runtime-wide thread budget (rt/thread_hooks.rs): cuts after a
    /// game creation failed, and growths back by one after 5 s quiet.
    ThreadBudgetCuts = "thread_budget_cuts",
    ThreadBudgetRegrows = "thread_budget_regrows",
    /// Runtime threads started on a pool stack (rt/thread_stack.rs) and
    /// those that got libkernel's own stack instead (no symbol, no slot, a
    /// refused attribute), the pool stack bytes in use with their guard
    /// pages, and the most at once.
    ThreadStacksPool = "thread_stacks_pool",
    ThreadStacksLibkernel = "thread_stacks_libkernel",
    ThreadStackBytes = "thread_stack_bytes",
    ThreadStackBytesMax = "thread_stack_bytes_max",
    /// The Rust global allocator (rt/heap.rs, iced-x86 only): bytes live,
    /// the most at once, the pool heap's bump top, and bytes that went to
    /// libc malloc because the pool heap was full or absent.
    HeapBytes = "heap_bytes",
    HeapBytesMax = "heap_bytes_max",
    HeapBumpTop = "heap_bump_top",
    HeapLibcBytes = "heap_libc_bytes",
    /// Packed POSIX reads run on the caller's own thread (rt/pack/fd_read.rs
    /// `note_caller_stack`, one in 16 sampled): the ones whose caller had
    /// under 16 KiB of stack left, and the least stack a sampled caller had
    /// left (0 until libkernel says).
    ReadInlineLowStack = "read_inline_low_stack",
    ReadInlineStackLeft = "read_inline_stack_left",
    /// Packed POSIX reads (read, readv, pread, preadv and libc's `_read`,
    /// `_readv` on a virtual pack fd, rt/pack/fd_read.rs `read_slot_at`)
    /// of one byte or more, and their latency as the caller sees it: the
    /// queue wait, the pack job and the wake-up, all on the caller's thread.
    PosixReads = "posix_reads",
    PosixReadNs = "posix_read_ns",
    PosixReadNsMax = "posix_read_ns_max",
    /// Packed POSIX reads that ran with cancellation still on, because
    /// neither `scePthreadSetcancelstate` nor `pthread_setcancelstate`
    /// resolved or the call failed (rt/pack/fd_read.rs `no_cancel`). A
    /// thread cancelled in such a read leaves workers writing to its stack.
    PosixReadCancelOn = "posix_read_cancel_on",
    /// Calls into the libc entry hooks, by hook id (rt/sys.rs `hook`):
    /// 84 `_open`, 85 `_openat`, 86 `_read`, 87 `_readv`, 88 `_close`,
    /// 89 `_fstat`, 90 `_getdirentries`, 91 `access`, 92 `lstat`, 93 `fcntl`,
    /// 94 `_fcntl`, 95 `sceKernelFcntl`. They install only in a title with
    /// packs; which ones a game reaches decides which can go.
    LibcHits84 = "libc_hits_84",
    LibcHits85 = "libc_hits_85",
    LibcHits86 = "libc_hits_86",
    LibcHits87 = "libc_hits_87",
    LibcHits88 = "libc_hits_88",
    LibcHits89 = "libc_hits_89",
    LibcHits90 = "libc_hits_90",
    LibcHits91 = "libc_hits_91",
    LibcHits92 = "libc_hits_92",
    LibcHits93 = "libc_hits_93",
    LibcHits94 = "libc_hits_94",
    LibcHits95 = "libc_hits_95",
    /// The same calls that the runtime served on a virtual pack fd: the fd
    /// hooks on one (or on a packed directory fd), `_open`/`_openat` that
    /// returned one. `access` (91) and `lstat` (92) take no fd and stay 0.
    LibcPacked84 = "libc_packed_84",
    LibcPacked85 = "libc_packed_85",
    LibcPacked86 = "libc_packed_86",
    LibcPacked87 = "libc_packed_87",
    LibcPacked88 = "libc_packed_88",
    LibcPacked89 = "libc_packed_89",
    LibcPacked90 = "libc_packed_90",
    LibcPacked91 = "libc_packed_91",
    LibcPacked92 = "libc_packed_92",
    LibcPacked93 = "libc_packed_93",
    LibcPacked94 = "libc_packed_94",
    LibcPacked95 = "libc_packed_95",
    /// Save data icon (rt/save.rs): bytes of icons handed over through
    /// sceSaveDataSaveIcon (packed ones, and loose ones whose path the
    /// service refused with 0x809f000e), and such icons the runtime could
    /// not read or the service refused (the call then answers 0: the icon
    /// is cosmetic, the error stalled a save).
    SaveIconBytes = "save_icon_bytes",
    SaveIconSkipped = "save_icon_skipped",
    /// What sceSaveDataSaveIcon answered the last icon handed over as bytes,
    /// before the hook maps a failure to 0, and what the service answered
    /// the last path forwarded (a loose or missing icon). Set, not summed, and printed as
    /// hex on /metrics (`is_code`); 0 there is also "no such call yet".
    SaveIconLastResult = "save_icon_last_result",
    SaveIconPathLastResult = "save_icon_path_last_result",
    /// sceSaveDataMount3 (rt/save.rs): mounts and BUSY answers, passed back
    /// to the game.
    SaveMounts = "save_mounts",
    SaveBusy = "save_busy",
    /// Creating sceSaveDataMount3 calls the library refused (0x809F0000)
    /// that were sent again with systemBlocks 0 (rt/save.rs MOUNT3_BYTES).
    SaveSystemBlocksZeroed = "save_system_blocks_zeroed",
    /// Read pool size (reactor/pread_pool.rs): threads started, the most
    /// live at once, threads given back to the game, and our own creations
    /// that failed (the pool stops growing). Exits under pressure are
    /// pread_retired_pressure (rt/thread_hooks.rs LoadGroup). Joins of an
    /// exited thread that failed (its slot and stack kept, retried later).
    PreadThreadsStarted = "pread_threads_started",
    PreadThreadsMax = "pread_threads_max",
    PreadThreadsYielded = "pread_threads_yielded",
    PreadThreadCreateFailed = "pread_thread_create_failed",
    ThreadJoinFailed = "thread_join_failed",
    /// Pack volume descriptors (rt/pack/leases.rs): opens, time spent in
    /// open, and closes of the least recently used one to make room
    /// (AMPR_EMU_PACK_OPEN_PACK_FD_CAP).
    PackFdOpens = "pack_fd_opens",
    PackFdOpenNs = "pack_fd_open_ns",
    PackFdEvictions = "pack_fd_evictions",
    /// Pack workers (rt/pack/worker.rs): threads started, given back to the
    /// game, own creations that failed. Exits under pressure are
    /// decode_retired_pressure.
    PackWorkersStarted = "pack_workers_started",
    PackWorkersYielded = "pack_workers_yielded",
    PackWorkerCreateFailed = "pack_worker_create_failed",
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
    /// Packed reads split into chunk-aligned child jobs that workers decode
    /// in parallel (rt/pack/pack_split.rs), and the children they made.
    PackSplitReads = "pack_split_reads",
    PackSplitChildren = "pack_split_children",
    /// Highest number of reactor AIO reads in flight since the last scrape.
    AprInflightMax = "apr_inflight_max",
    /// Failures: pack virtual reads completed with an error, chunk decodes that failed.
    PackJobErrors = "pack_job_errors",
    DecodeErrors = "decode_errors",
    /// Pack virtual reads whose game destination was not mapped
    /// CPU-writable when the pass first checked it, so the worker waited for
    /// it (once per read, not once per task), and those still missing at the
    /// job's deadline, failed with EFAULT (pack/virtual_read.rs
    /// ensure_destination). Without the wait the write faulted the worker.
    PackDestWaits = "pack_dest_waits",
    PackDestFaults = "pack_dest_faults",
    /// Destination queries sceKernelQueryMemoryProtection refused (EACCES),
    /// answered by probing the page with a kernel copy out instead
    /// (pack/virtual_read.rs destination_covered). Once a walk gets one
    /// refused answer it probes the rest without asking, so this counts that
    /// first answer per walk; a query refused for the runtime's own memory
    /// skips the walk's queries entirely and does not count here.
    PackDestQueryDenied = "pack_dest_query_denied",
    /// Software WaitOnAddress / WriteAddress commands failed with an APR
    /// error because sceKernelQueryMemoryProtection found the target
    /// unmapped or without CPU read (wait) or write (write) protection
    /// (reactor/software.rs address_target_check). EACCES never counts here:
    /// those targets pass (apr_address_query_denied). Each unmapped one would
    /// otherwise have faulted in the reactor thread.
    AprAddressFaults = "apr_address_faults",
    /// Software WaitOnAddress / WriteAddress target checks the query refused
    /// with EACCES (reactor/software.rs address_query_allows). A write goes
    /// ahead unchecked. A wait goes ahead too: on a zstd title those
    /// targets are mapped (its stores land there) and refusing the waits
    /// froze it. A title that signals a read batch with a
    /// WriteAddress to such a target hung on the loading screen while the
    /// write was refused.
    AprAddressQueryDenied = "apr_address_query_denied",
    /// 1 when sceKernelQueryMemoryProtection also answers EACCES for a known
    /// unmapped address (the null page), so EACCES cannot be told apart from
    /// "not mapped" on this setup; 0 or absent when it can. Asked once, at
    /// the first EACCES target (sys::eacces_is_unmapped).
    AprAddressEaccesUnmapped = "apr_address_eacces_unmapped",
    /// Pack volume fds closed for a reopen after a read failed with EBADF,
    /// EIO or ENXIO (pack/leases.rs PackFdReopen; e.g. a USB image remounted
    /// after rest mode).
    PackFdReopens = "pack_fd_reopens",
    /// libc `open` hook (index.rs open_impl) by resident-lookup outcome, and
    /// /app0 opens it routed to a virtual pack fd or to the real open.
    OpenNotApp0 = "open_not_app0",
    OpenIndexNotReady = "open_index_not_ready",
    OpenHit = "open_hit",
    OpenMiss = "open_miss",
    OpenDirectory = "open_directory",
    OpenVirtual = "open_virtual",
    OpenRealFailed = "open_real_failed",
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
    /// Reactor loop passes (AprAioReactor::worker, reactor/worker.rs), one
    /// per wake or poll deadline; per job or per read it is the fixed pass
    /// cost the reactor pays.
    ReactorPasses = "reactor_passes",
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
    /// reactor's own share (reactor/progress.rs note_successor_order_wait).
    JobOrderWaits = "job_order_waits",
    JobOrderWaitNs = "job_order_wait_ns",
    /// Lane loop (reactor/progress.rs) stops before a job that has a
    /// successor queued in its priority lane, so the successor does not parse
    /// in this pass. Counted once per stop (per lane pass), by what the head
    /// is parked on (reactor/progress.rs lane_block_kind):
    /// lane_successor_blocked_fence: a completion command (EOP write, counter,
    /// equeue) waiting on the head's own read fence or deferred native EOP;
    /// lane_successor_blocked_wait: a WaitOnAddress/WaitOnCounter, or a
    /// native batch wait; lane_successor_blocked_other: anything else (a read
    /// held by budget or window, a native/AMM op, a failed head).
    LaneSuccessorBlockedFence = "lane_successor_blocked_fence",
    LaneSuccessorBlockedWait = "lane_successor_blocked_wait",
    LaneSuccessorBlockedOther = "lane_successor_blocked_other",
    /// Gather/scatter re-resolves from the lane cursor
    /// (`gatherScatterStates[prioIndex]`) after a first resolution of the
    /// same command did not issue, counted per retry (a command parked and
    /// retried n times counts n), and those whose file id or offset differed
    /// from that first resolution (job_state.rs `GsPrepRecord`). A mismatch
    /// means another job advanced the shared lane cursor and the retry would
    /// read another file's bytes. Each is also logged as a 'G'
    /// event in /fsfail (`gs_retry_mismatch`). No path advances another
    /// job's lane cursor today, so a mismatch means a new bug.
    GsRetryChecks = "gs_retry_checks",
    GsRetryMismatches = "gs_retry_mismatches",
    /// Gauges that rise and fall (`enter`/`leave`): game threads blocked
    /// inside the runtime right now. apr_submit_blocked_now: an APR submit
    /// waiting for a free job state, request slot or submit-id slot
    /// (reactor/submit.rs `submit`); apr_wait_blocked_now: an APR wait on a
    /// synthetic id (`wait_synthetic_submit_id`); equeue_wait_now: anywhere
    /// in sceKernelWaitEqueue_emul, native waits included (a render thread
    /// waiting on vblank counts); equeue_private_spin_now: spinning in the
    /// equeue private wake (rt/equeue.rs `wait_for_private_wake`). In a hang
    /// with the reactor idle, a gauge above 0 names where the game waits.
    AprSubmitBlockedNow = "apr_submit_blocked_now",
    AprWaitBlockedNow = "apr_wait_blocked_now",
    EqueueWaitNow = "equeue_wait_now",
    EqueuePrivateSpinNow = "equeue_private_spin_now",
    /// Submits that had to wait for a slot; APR waits (rt/services.rs
    /// `wait`) by outcome: answered from the done ring, waited on a live
    /// synthetic id, not ours (passed to libkernel), and those that returned
    /// an error (each logged as op b'J', first 64 only).
    AprSubmitBlocked = "apr_submit_blocked",
    AprWaits = "apr_waits",
    AprWaitDoneRing = "apr_wait_done_ring",
    AprWaitLive = "apr_wait_live",
    AprWaitNative = "apr_wait_native",
    AprWaitErrors = "apr_wait_errors",
    /// Native APR batch buffers the kernel accepted (reactor/batch_buffer.rs
    /// `submit_native_batch_buffer`); a refused one is logged as op b'J'
    /// lookup b'n'.
    NativeBatchSubmits = "native_batch_submits",
    /// The reactor's own kernel AIO (reactor/flush.rs, progress.rs): request
    /// ids the kernel accepted, ids deleted after they finished, deletes the
    /// kernel refused, and submits deferred (EAGAIN, the AIO table is full)
    /// or refused. submitted minus deleted is what the runtime holds now.
    AioIdsSubmitted = "aio_ids_submitted",
    AioIdsDeleted = "aio_ids_deleted",
    AioDeleteFailed = "aio_delete_failed",
    AioSubmitDeferred = "aio_submit_deferred",
    AioSubmitFailed = "aio_submit_failed",
    /// Completion signals by how they reach the game: packets placed in a
    /// native APR batch by op type (reactor/native.rs
    /// `append_native_apr_batch`; WriteAddressFrom{TimeCounter,Counter,
    /// CounterPair} together), software WriteAddress stores
    /// (reactor/software.rs), and WriteKernelEventQueue commands offered to
    /// the equeue overlay by its answer (rt/equeue.rs
    /// `apr_equeue_try_publish`; a fallback then becomes a native packet,
    /// a backpressure is offered again later).
    NativeWaitOnCounter = "native_wait_on_counter",
    NativeWriteCounter = "native_write_counter",
    NativeWriteEqueue = "native_write_equeue",
    NativeWriteFromCounter = "native_write_from_counter",
    NativeOther = "native_other",
    SoftwareWriteAddress = "software_write_address",
    EqueueLocalPublished = "equeue_local_published",
    EqueueLocalBackpressure = "equeue_local_backpressure",
    EqueueLocalFallback = "equeue_local_fallback",
    /// Debug, both pack formats: mmap/sceKernelMmap of a virtual pack fd
    /// (rt/probe.rs probes, ids 96 and 97). Each fails: a packed file has no
    /// physical copy.
    #[cfg_attr(not(feature = "mem_report"), allow(dead_code))]
    MmapVirtual = "mmap_virtual",
    /// Index memory held for lookups once an index is mounted: the
    /// resident block of the compiled index view (rt/index_view.rs), the
    /// zstd chunk tables (8 B per chunk and volume, rt/pack/zstd.rs) and
    /// the resident AMPRPAK4 parts (header, record sections and pack
    /// names, rt/pack/manifest.rs). Each part is added when it is taken
    /// and taken back when it is freed.
    IndexViewBytes = "index_view_bytes",
    /// Time of the last index load in `ensure_ready_slow` (rt/index.rs):
    /// the index read or walk build into the view plus, in a title with
    /// packs, the pack index mount and its join into the view. A gauge:
    /// each load replaces it.
    IndexMountNs = "index_mount_ns",
    /// File index lookups that could not read the index file: sent to the
    /// real call, never answered ENOENT (rt/index.rs `IndexIo`).
    IndexLookupIo = "index_lookup_io",
    /// Path lookup hooks (rt/index.rs), per hook id: calls and the ns
    /// spent in each, from entry to return (`path_span`). Ids: 0 open,
    /// 1 stat, 2 sceKernelCheckReachability, 3 unlink, 4 rename,
    /// 78 sceKernelOpen, 79 sceKernelStat, 84 _open, 85 _openat,
    /// 91 access, 92 lstat.
    PathCalls0 = "path_calls_0",
    PathNs0 = "path_ns_0",
    PathCalls1 = "path_calls_1",
    PathNs1 = "path_ns_1",
    PathCalls2 = "path_calls_2",
    PathNs2 = "path_ns_2",
    PathCalls3 = "path_calls_3",
    PathNs3 = "path_ns_3",
    PathCalls4 = "path_calls_4",
    PathNs4 = "path_ns_4",
    PathCalls78 = "path_calls_78",
    PathNs78 = "path_ns_78",
    PathCalls79 = "path_calls_79",
    PathNs79 = "path_ns_79",
    PathCalls84 = "path_calls_84",
    PathNs84 = "path_ns_84",
    PathCalls85 = "path_calls_85",
    PathNs85 = "path_ns_85",
    PathCalls91 = "path_calls_91",
    PathNs91 = "path_ns_91",
    PathCalls92 = "path_calls_92",
    PathNs92 = "path_ns_92",
}

const N: usize = Stat::Count as usize;
static VALUES: [AtomicU64; N] = [const { AtomicU64::new(0) }; N];

/// `*_max` stats reset on every scrape; `set` codes (`is_code`) hold the
/// last value; all others are monotonic counters.
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
        || s == Stat::PosixReadNsMax as usize
}

/// Stats that hold a 32-bit SCE return code, printed as hex on /metrics.
#[cfg(feature = "mem_report")]
pub(crate) fn is_code(s: usize) -> bool {
    s == Stat::SaveIconLastResult as usize
        || s == Stat::SaveIconPathLastResult as usize
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

/// Path hook calls, newest last, debug only. Op: b'o' open, b's' stat,
/// b'l' lstat, b'a' access, b'r' reachability, b'O'/b'A' libc _open/_openat;
/// and from the runtime itself b'L' its open of an indexed loose file, b'R'
/// an APR path that did not resolve, b'E' a failed APR job (path = reason),
/// b'K' a module load: lookup b'-' the name the game asked for with the
/// final result; b'h' the index hit's stored path when its load failed with
/// ENOENT and the name, whose bytes differ (case or a normalized spelling),
/// was tried next (rt/hook.rs).
/// b'G' a gather/scatter retry that re-resolved to
/// another file id or offset than its first resolution (path = both pairs,
/// see `gs_retry_mismatch`). b'X' mmap and b'Y' sceKernelMmap of a virtual
/// fd (rt/probe.rs, debug-only pass-through probes; `/fsfail` keeps only the
/// failed ones, which is every map of a packed file): path "<call> <packed
/// file path>", lookup b'v'. b'I' a game's own
/// sceKernelAioSubmitReadCommands(Multiple) with a request on a packed fd,
/// which the runtime's AIO emulation served (rt/pack/aio.rs, logged through
/// rt/probe.rs `note_aio_submit` whatever the result), lookup b'v'.
/// Pass-through probes for fully packed games, LZ4 or zstd packs
/// (rt/probe.rs, logged by `fs_note` whatever the result): b'D' dup, b'W'
/// poll, b'T' openat, b'F' fstatat, b'C' faccessat, b'N' readlink;
/// their path is the packed file's path (or the call name and `<virtual
/// fd>`) and their lookup letter b'p' a packed file, b'd' an indexed
/// directory, b'v' a virtual fd. In debug
/// builds the libc hooks b'O', b'A', b'a', b'l' whose
/// `AMPR_PACK_LIBC_HOOKS` bit is off run as such pass-through observers too (rt/hook.rs `observed_only`), logged with
/// lookup b'p' or b'd' only. Resident lookup: b'h' hit,
/// b'm' miss the index answers, b'M' miss sent to the FS, b'd' directory,
/// b'n' index not ready, b'x' not /app0, b'-' none. Then result and path.
/// b'Z' a pack chunk that failed to decode (rt/pack/virtual_read.rs; with
/// the debug `zstd_verify` knob also a zstd frame checksum mismatch),
/// lookup b'-', path "decode fid=<hex> chunk=<hex> pack=<hex> off=<hex>
/// size=<hex>".
/// b'U' a failed getdents/getdirentries on a virtual directory fd
/// (rt/pack/directories.rs `note_directory_read`), lookup b'd', path
/// "read <directory> rc=0x<8 hex>"; lookup b'x', path "realfail <directory>
/// errno=<n>", the physical listing failed and the packed entries are listed
/// alone. Logged through `fs_note`, so each distinct line is kept once.
/// b'V' a save data icon the runtime handed over from a pack (rt/save.rs),
/// lookup b'-', path "save icon <packed path> rc=0x<result>". Logged through
/// `fs_note`, so `/fsfail` lists each distinct icon path whatever the result.
/// b'P' thread creation (rt/thread_hooks.rs): a game creation that failed,
/// lookup b's' scePthreadCreate (rc the SCE error) or b'p' pthread_create
/// (rc minus its errno), path "<call> <thread name>"; b'r' its retry after
/// the read pool gave threads back, path "<call>-retry <thread name>" (rc
/// -1 when the retry succeeded); b'h'
/// the `GET /threads` limit probe (black box only, rc = threads held, or
/// the failure).
/// b'J' an APR call that returned an error (rt/services.rs): lookup b'w'
/// a wait, path "wait id=<hex> how=<s|n>" (synthetic id, or passed to libkernel);
/// b'u' a submit, path "submit prio=<n>"; b'n' a native batch submit the
/// kernel refused, path "native batch lane=<n>"; b'r' a pack read job that
/// failed, path "pack-read fid=<hex>". First 64 only.
/// b'Q' packed-fd/open failures (rt/pack/slots.rs, rt/index.rs): lookup b'H'
/// a packed open's raw SCE error, b'R' a physical open's errno (ring only,
/// positive), b'S' the 320-slot synthetic packed-fd table full.
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

/// Failed path hook calls (rc < 0), one slot per distinct (op, path), the
/// first FS_FAILS kept: boot-time failures outlive the 32-entry FS_LOG ring.
/// 96 x ~150 B of text fits the 16 KiB response of `GET /fsfail`; the table
/// is ~14 KiB of .bss outside the pool.
#[cfg(feature = "mem_report")]
pub(crate) struct FsFails {
    pub count: usize,
    pub dropped: core::sync::atomic::AtomicU64,
    pub op: [u8; FS_FAILS],
    pub how: [u8; FS_FAILS],
    pub rc: [i64; FS_FAILS],
    pub hits: [u32; FS_FAILS],
    pub len: [usize; FS_FAILS],
    pub path: [[u8; 128]; FS_FAILS],
}
#[cfg(feature = "mem_report")]
pub(crate) const FS_FAILS: usize = 96;
#[cfg(feature = "mem_report")]
pub(crate) static FS_FAIL_LOG: super::sync::SyncCell<FsFails> =
    super::sync::SyncCell::new(FsFails {
        count: 0,
        dropped: core::sync::atomic::AtomicU64::new(0),
        op: [0; FS_FAILS],
        how: [0; FS_FAILS],
        rc: [0; FS_FAILS],
        hits: [0; FS_FAILS],
        len: [0; FS_FAILS],
        path: [[0; 128]; FS_FAILS],
    });

/// Counts a failed call in FS_FAIL_LOG. Paths are kept and deduplicated by
/// their first 128 bytes, so longer paths that differ only past that share
/// an entry. Returns true only when the call added a new (op, path) entry,
/// so `fs_note` writes each distinct probe to the black box once; a repeat,
/// a filtered path, a busy log or a full table returns false.
#[cfg(feature = "mem_report")]
unsafe fn fs_fail(op: u8, how: u8, rc: i64, path: *const core::ffi::c_char) -> bool {
    use core::sync::atomic::{AtomicBool, Ordering};
    // One writer at a time; a hook never waits for it: a busy log drops.
    static BUSY: AtomicBool = AtomicBool::new(false);
    if BUSY.swap(true, Ordering::Acquire) {
        unsafe { (*FS_FAIL_LOG.get()).dropped.fetch_add(1, Ordering::Relaxed) };
        return false;
    }
    let added = unsafe { fs_fail_locked(op, how, rc, path) };
    BUSY.store(false, Ordering::Release);
    added
}

#[cfg(feature = "mem_report")]
unsafe fn fs_fail_locked(op: u8, how: u8, rc: i64, path: *const core::ffi::c_char) -> bool {
    let log = unsafe { &mut *FS_FAIL_LOG.get() };
    let mut name = [0u8; 128];
    let mut n = 0;
    while n < name.len() && !path.is_null() && unsafe { *path.add(n) } != 0 {
        name[n] = unsafe { *path.add(n) } as u8;
        n += 1;
    }
    if !fail_kept(how, rc, &name[..n]) {
        return false;
    }
    for i in 0..log.count.min(FS_FAILS) {
        if log.op[i] == op && log.path[i][..log.len[i]] == name[..n] {
            log.hits[i] = log.hits[i].saturating_add(1);
            return false;
        }
    }
    if log.count >= FS_FAILS {
        log.dropped
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        return false;
    }
    let i = log.count;
    (log.op[i], log.how[i], log.rc[i], log.hits[i], log.len[i]) = (op, how, rc, 1, n);
    log.path[i] = name;
    log.count += 1;
    true
}

/// An authoritative miss: the index answered "no such path" (lookup letter
/// b'm'), which `fs_event` keeps out of `/fsfail` and the black box.
#[cfg_attr(not(any(feature = "mem_report", test)), allow(dead_code))]
pub(crate) const fn index_miss(how: u8, rc: i64) -> bool {
    rc < 0 && how == b'm'
}

/// A failure `/fsfail` and the black box (rt/blackbox.rs) keep: not an
/// authoritative miss (`index_miss`) and not under /download0/, where UE
/// probes many optional user configs that always miss. `path` may be just
/// the first bytes of the path.
#[cfg_attr(not(any(feature = "mem_report", test)), allow(dead_code))]
pub(crate) fn fail_kept(how: u8, rc: i64, path: &[u8]) -> bool {
    !index_miss(how, rc) && !path.starts_with(b"/download0/")
}

/// Records one path hook call (racy by design: a debug trace).
#[inline(always)]
pub(crate) fn fs_event(op: u8, how: u8, rc: i64, path: *const core::ffi::c_char) {
    // Authoritative misses ('m') of the path hooks are answered by the index
    // alone, the same on every filesystem, so they are left out of the
    // failure log and the black box (a game probes many absent paths; a
    // line each would be a file write per miss). 'R' events carry no lookup
    // letter and are always logged.
    #[cfg(feature = "mem_report")]
    if !index_miss(how, rc) {
        super::blackbox::event(op, how, rc, path);
        if rc < 0 {
            unsafe { fs_fail(op, how, rc, path) };
        }
    }
    #[cfg(feature = "mem_report")]
    unsafe {
        fs_ring(op, how, rc, path)
    };
    #[cfg(not(feature = "mem_report"))]
    let _ = (op, how, rc, path);
}

/// Records one probe call (rt/probe.rs) in FS_FAIL_LOG whatever `rc` is, so
/// `/fsfail` lists every distinct (op, path) a game used on packed files,
/// and in the FS_LOG ring. A note that adds a new (op, path) entry is also
/// written to the black box (rt/blackbox.rs) whatever `rc` is, once each:
/// a probe that succeeds is still in the trace when the game dies before
/// :9090 answers, and a repeat costs no file write. Also called by rt/save.rs and
/// rt/pack/directories.rs; a no-op in release builds, like `fs_event`.
#[inline(always)]
#[cfg_attr(not(feature = "mem_report"), allow(dead_code))]
pub(crate) fn fs_note(op: u8, how: u8, rc: i64, path: *const core::ffi::c_char) {
    #[cfg(feature = "mem_report")]
    unsafe {
        let added = fs_fail(op, how, rc, path);
        fs_ring(op, how, rc, path);
        if added {
            super::blackbox::note(op, how, rc, path);
        }
    }
    #[cfg(not(feature = "mem_report"))]
    let _ = (op, how, rc, path);
}

/// Appends one event to the FS_LOG ring.
#[cfg(feature = "mem_report")]
unsafe fn fs_ring(op: u8, how: u8, rc: i64, path: *const core::ffi::c_char) {
    // Hooks can arrive on multiple threads. Keep this log best-effort rather
    // than wait in a callback or race its shared cursor and entries.
    static BUSY: core::sync::atomic::AtomicBool = core::sync::atomic::AtomicBool::new(false);
    use core::sync::atomic::Ordering;
    if BUSY.swap(true, Ordering::Acquire) {
        return;
    }
    let log = unsafe { &mut *FS_LOG.get() };
    let slot = log.next % FS_EVENTS;
    log.next = log.next.wrapping_add(1);
    let mut n = 0;
    while n < 160 && !path.is_null() && unsafe { *path.add(n) } != 0 {
        log.path[slot][n] = unsafe { *path.add(n) } as u8;
        n += 1;
    }
    (log.op[slot], log.how[slot], log.rc[slot], log.len[slot]) = (op, how, rc, n);
    BUSY.store(false, Ordering::Release);
}

#[cfg(feature = "mem_report")]
fn hex(buf: &mut [u8; 128], n: &mut usize, v: u64) {
    let digits = (64 - (v | 1).leading_zeros()).div_ceil(4);
    for i in (0..digits).rev() {
        buf[*n] = b"0123456789abcdef"[((v >> (i * 4)) & 0xf) as usize];
        *n += 1;
    }
}
#[cfg(feature = "mem_report")]
fn text(buf: &mut [u8; 128], n: &mut usize, s: &[u8]) {
    buf[*n..*n + s.len()].copy_from_slice(s);
    *n += s.len();
}

/// Logs a failed APR call as op b'J' (see `FsEvents`), path
/// "<label><hex v><tail>"; the first 64 only, so a game retrying a failed
/// wait in a loop does not flood the black box.
pub(crate) fn apr_call_error(how: u8, rc: i64, label: &[u8], v: u64, tail: &[u8]) {
    #[cfg(feature = "mem_report")]
    {
        static LOGGED: AtomicU64 = AtomicU64::new(0);
        if LOGGED.fetch_add(1, Relaxed) >= 64 {
            return;
        }
        let mut buf = [0u8; 128];
        let mut n = 0;
        text(&mut buf, &mut n, label);
        hex(&mut buf, &mut n, v);
        text(&mut buf, &mut n, tail);
        fs_event(b'J', how, rc, buf.as_ptr().cast());
    }
    #[cfg(not(feature = "mem_report"))]
    let _ = (how, rc, label, v, tail);
}

/// Logs a gather/scatter retry that re-resolved to `got` instead of the
/// `prep` (file id, offset) of its first resolution, as a 'G' event with path
/// "gs-retry fid=<hex> off=<hex> got fid=<hex> off=<hex>" (at most 80 bytes,
/// within FsFails' 128). Debug only; the caller counts GsRetryMismatches.
#[cfg(feature = "mem_report")]
pub(crate) fn gs_retry_mismatch(rc: i64, prep: (u32, u64), got: (u32, u64)) {
    let mut buf = [0u8; 128];
    let mut n = 0;
    text(&mut buf, &mut n, b"gs-retry fid=");
    hex(&mut buf, &mut n, prep.0 as u64);
    text(&mut buf, &mut n, b" off=");
    hex(&mut buf, &mut n, prep.1);
    text(&mut buf, &mut n, b" got fid=");
    hex(&mut buf, &mut n, got.0 as u64);
    text(&mut buf, &mut n, b" off=");
    hex(&mut buf, &mut n, got.1);
    // buf[n] is still 0: the path is NUL-terminated.
    fs_event(b'G', b'-', rc, buf.as_ptr().cast());
}

#[inline(always)]
pub(crate) fn add(s: Stat, v: u64) {
    if ON {
        VALUES[s as usize].fetch_add(v, Relaxed);
    }
}

/// Takes `v` back from a running total (a source given back).
#[inline(always)]
pub(crate) fn sub(s: Stat, v: u64) {
    if ON {
        VALUES[s as usize].fetch_sub(v, Relaxed);
    }
}

/// Gauge up by one (a matching `leave` brings it down).
#[inline(always)]
pub(crate) fn enter(s: Stat) {
    add(s, 1);
}

/// Gauge down by one.
#[inline(always)]
pub(crate) fn leave(s: Stat) {
    if ON {
        VALUES[s as usize].fetch_sub(1, Relaxed);
    }
}

/// Replaces the value (a last-seen code, not a total).
#[inline(always)]
pub(crate) fn set(s: Stat, v: u64) {
    if ON {
        VALUES[s as usize].store(v, Relaxed);
    }
}

#[inline(always)]
pub(crate) fn max(s: Stat, v: u64) {
    if ON {
        VALUES[s as usize].fetch_max(v, Relaxed);
    }
}

/// First libc entry hook id counted by `libc_hit`, and the stats of each
/// id from it on, in id order.
const LIBC_FIRST: usize = super::sys::hook::_open;
const LIBC_HITS: [Stat; 12] = [
    Stat::LibcHits84,
    Stat::LibcHits85,
    Stat::LibcHits86,
    Stat::LibcHits87,
    Stat::LibcHits88,
    Stat::LibcHits89,
    Stat::LibcHits90,
    Stat::LibcHits91,
    Stat::LibcHits92,
    Stat::LibcHits93,
    Stat::LibcHits94,
    Stat::LibcHits95,
];
const LIBC_PACKED: [Stat; 12] = [
    Stat::LibcPacked84,
    Stat::LibcPacked85,
    Stat::LibcPacked86,
    Stat::LibcPacked87,
    Stat::LibcPacked88,
    Stat::LibcPacked89,
    Stat::LibcPacked90,
    Stat::LibcPacked91,
    Stat::LibcPacked92,
    Stat::LibcPacked93,
    Stat::LibcPacked94,
    Stat::LibcPacked95,
];
const _: () = assert!(
    super::sys::hook::sceKernelFcntl - LIBC_FIRST + 1 == LIBC_HITS.len(),
    "one libc_hits and one libc_packed stat per libc entry hook id"
);

/// One call into libc entry hook `id` (84..=95), and with `packed` one the
/// runtime served on a virtual pack fd. Other ids are ignored.
#[inline(always)]
pub(crate) fn libc_hit(id: usize, packed: bool) {
    let Some(i) = id.checked_sub(LIBC_FIRST).filter(|&i| i < LIBC_HITS.len()) else {
        return;
    };
    add(LIBC_HITS[i], 1);
    if packed {
        add(LIBC_PACKED[i], 1);
    }
}

/// The path lookup hook ids `path_span` counts, and their
/// (calls, ns) stats in the same order.
const PATH_HOOKS: [(usize, Stat, Stat); 11] = [
    (0, Stat::PathCalls0, Stat::PathNs0),
    (1, Stat::PathCalls1, Stat::PathNs1),
    (2, Stat::PathCalls2, Stat::PathNs2),
    (3, Stat::PathCalls3, Stat::PathNs3),
    (4, Stat::PathCalls4, Stat::PathNs4),
    (78, Stat::PathCalls78, Stat::PathNs78),
    (79, Stat::PathCalls79, Stat::PathNs79),
    (84, Stat::PathCalls84, Stat::PathNs84),
    (85, Stat::PathCalls85, Stat::PathNs85),
    (91, Stat::PathCalls91, Stat::PathNs91),
    (92, Stat::PathCalls92, Stat::PathNs92),
];

/// One call of path lookup hook `id` that started at `start` (from
/// `now()`; 0 = no span): +1 call and its ns. Other ids are ignored.
/// Release builds compile it to nothing.
#[inline(always)]
pub(crate) fn path_span(id: usize, start: u64) {
    if ON && start != 0 {
        if let Some(&(_, calls, ns)) = PATH_HOOKS.iter().find(|h| h.0 == id) {
            add(calls, 1);
            add(ns, since(start));
        }
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

// ---- tests --------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_failed_index_lookups_are_index_misses() {
        assert!(index_miss(b'm', -2));
        // A miss sent to the FS, a successful 'm' and a module load stay.
        assert!(!index_miss(b'M', -2) && !index_miss(b'm', 0) && !index_miss(b'K', 5));
        assert!(fail_kept(b'h', -2, b"/app0/a.bin") && fail_kept(b'K', 5, b"/app0/x.prx"));
        assert!(!fail_kept(b'm', -2, b"/app0/a.bin"));
        assert!(!fail_kept(b'M', -2, b"/download0/user.ini"));
    }

    #[cfg(feature = "mem_report")]
    #[test]
    fn metrics_name_the_view_not_the_page_cache() {
        // `/metrics` serves `NAMES`: the view and mount gauges are there,
        // and no name of the deleted page cache or fast tables is.
        for name in ["index_view_bytes", "index_mount_ns", "index_lookup_io"] {
            assert!(NAMES.contains(&name), "{name}");
        }
        assert!(!NAMES.iter().any(|n| n.starts_with("index_page_")
            || *n == "index_arena_bytes"
            || *n == "index_fast_bytes"));
    }

    #[cfg(feature = "mem_report")]
    #[test]
    fn a_repeated_note_is_new_once() {
        // `fs_note` writes the black box only when `fs_fail` reports a new
        // (op, path): the same probe twice is one trace line, rc 0 or not.
        let p = c"/app0/cache_ps5/loc/test-repeat.larc";
        assert!(unsafe { fs_fail(b'I', b'v', 0, p.as_ptr()) });
        assert!(!unsafe { fs_fail(b'I', b'v', 0, p.as_ptr()) });
        // Another op on the same path is a distinct entry.
        assert!(unsafe { fs_fail(b'D', b'v', 0, p.as_ptr()) });
        // A path `/fsfail` filters out is never new.
        assert!(!unsafe { fs_fail(b'I', b'v', 0, c"/download0/u.ini".as_ptr()) });
    }
}
