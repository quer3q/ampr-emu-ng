# Debug build

`libSceAmpr-debug.sprx` is the release runtime plus a metrics server, a
tuning file, a failed-call log and a crash trace. Test a game or a change
with it, then ship the release build.

## How it differs from release

`./ps5/build-docker.sh` (`make dist`) builds both files. The debug one is
`make AMPR_MEM_REPORT=1` (Cargo feature `mem_report`) with the pool set to
`AMPR_DEBUG_POOL_SIZE` (`0x8ECC000`, 142.80 MiB); the release pool is
`0x9030000` (144.19 MiB). The smaller pool offsets the larger debug code,
so both PRX files load to 150.89 MiB (within a 16 KiB page) with the same
Index and Buffer caps and thread limits. The decoded cache is the rest of
the pool, so the debug cache is 1.39 MiB (about 4%) smaller: 30.61 vs
32.00 MiB; debug cache numbers are that much conservative. Those are the
sizes carved at the pack mount: once the index is built the cache grows
into the Index ledger's idle room above 2 MiB (`cache_grown_bytes`, 76-80
MiB on two zstd titles and a pkg title, 103-107 MiB in all), and
`cache_mem_cap_bytes` shows the cap after the move.

Only the debug build:

- serves plain text on TCP port 9090 ([Pages](#pages));
- reads knobs from `/data/ampr_emu_tune.txt` at start
  ([Tune file](#tune-file)); release ignores the file;
- records failed file calls for `/fsfail` and writes the black box
  `/data/ampr_emu_trace.txt`;
- in a title with packs, installs pass-through probes (hook ids 112..=119:
  dup, dup2, poll, select, openat, fstatat, faccessat, readlink) that log a
  packed file or virtual fd reaching a call the runtime does not serve. A
  libc hook (`_open`, `_openat`, `access`, `lstat`) whose
  `AMPR_PACK_LIBC_HOOKS` bit is clear still installs and only observes;
- checks each zstd chunk's frame checksum (knob `zstd_verify`, default 1).
  A mismatch fails the read and logs a `Z` event.

The README's performance numbers come from this build. Compare timings only
between runs of the same build.

## Pages

Port 9090 serves one client at a time, in plain text of at most 16 KiB per
answer. The pages are listed in `serve` in `crates/ampr-sys/src/rt/exports.rs`.

| Page | What it returns |
| --- | --- |
| `/metrics` (or any path not listed here) | Counters and gauges, below. |
| `/set`, `/set?k=v&...` | Lists or changes the tune knobs. |
| `/bench` | Raw read speed of pack volume 0. |
| `/bench?path=/app0/<file>[&backing=/abs/file]` | Read speed of a loose file through `/app0` and, with `backing=`, through its backing path. |
| `/fsfail` | Every distinct failed call since load. |
| `/modules` | Loaded modules. |
| `/queues` | Event queue waits in progress and queues with pending events. Only queues with an AMPR registration are tracked (from the first `sceKernelAddAmprEvent`), so a queue that never had one is not listed or counted. The first line, `eqpeak queues=N/1024 regs=N/4096 pending=N/5120 extras=N/1024`, is the overlay tables' live peaks against their caps (`equeue_peaks` in `rt/equeue.rs`); a queue line's `flags=` keeps bits 8, 16, 32 and 64. |
| `/threads` | Thread counts; `?hold=N`, `?release=1`, `?yield=N` and `?yield_workers=N` test the game's thread limit. Then one `thread <owner> prio <p> cpus <mask> <name>` line per thread created since module_start (owner `g` game scePthreadCreate, `p` game pthread_create, `a` runtime, `m` the module_start thread), priority and core mask read now (256 highest, 767 lowest; `err` for an exited thread), up to 256 threads (`census` in `rt/thread_hooks.rs`). |
| `/crash` | Nothing: it crashes the game on purpose (a write to address 0 on the metrics thread), so the system's core dump captures it as it is, e.g. while frozen. |

```sh
curl http://<ps5-ip>:9090/metrics
```

### /metrics

The first line, `build ampr-emu-ng <version> <git rev> debug`, names the PRX
that answered, so a stale build shows. `ps5/build-docker.sh` sets the git rev
(`-dirty` when tracked files changed); a build outside it shows `unknown`.
The second, `pack_format <plain|lz4|zstd|pkg>`, names the title's mode
(`PackFormat::label` in `rt/pack/mod.rs`), as the load notice does. A pkg
title shows `pkg`, never `lz4`, though it shares the LZ4 manifest format.

Then one `name value` pair per line: uptime, pool used, peak and size, the
`rt/stats.rs` counters, the ledgers (`index_mem_*`, `cache_mem_*`,
`buffer_mem_*`, `ledger_alloc_refused`, `pool_alloc_failed`), fd and thread
counts, the last 32 file events as `fs` lines, the knobs as `tune_` lines and
pool use per site as `pool_now:` and `pool_peak:` lines. Counters are totals
since load; `*_max` values reset on each scrape.

Each title has one compiled index view (`rt/index_view.rs`, built by
`crates/ampr-format/src/view.rs`) in the Index ledger (`index_mem_bytes`
against `index_mem_cap_bytes`). It keeps hashes, sizes, mtimes,
directories and the pack links resident; paths stay in the index file and
are read with one pread each (`rt/index_file.rs`), only to confirm a hash
match, to list a directory or to reach a loose file whose spelling the
game did not match. `index_view_bytes` is what the
mounted index holds for lookups: the view's resident block, the zstd chunk
tables (8 B per chunk and volume) and the resident AMPRPAK4 parts (header,
record sections and pack names). Each part is counted when it is taken and
taken back when it is freed; the AMPRPAK4 parts stay held until a reload
or a failed mount, as hooks past the reader gate may still read them. The
build's transient columns are not in it, and the rest of `index_mem_bytes`
is other Index users (a walk build's path blob, the LZ4 mismatch bitmap,
`/bench`). On the host, a 242,409-file zstd index gives 21.74 MiB (columns
8.32, file slots 2.00, directories 1.21 allocated, chunks and volumes
10.22); no console reading of `index_view_bytes` has been taken yet.
`index_mount_ns` is the time of the last index load: the index read, or a
walk build, into the view plus, with packs, the pack index mount and its
join into the view. It is set once per load, so read it once the index
is loaded; no console number is recorded for it yet.

`index_lookup_io` counts lookups that could not read a path from the index
file. Such a lookup is never an authoritative ENOENT: a miss goes to the
real call, and with packs mounted an ENOENT from it is answered EIO, since
the file may be packed with no copy on disk; a hit whose stored path
cannot be read answers EIO. A loose hit (an indexed file that is not
packed) calls the real function with the game's own spelling first,
normalized with its case kept, so a hit reads no path. Only when that call
fails ENOENT or ENOTDIR, or the spelling does not fold to the index key, is
the stored path read and confirmed, then called if it differs. A creating
open reads the stored path first, so it never makes a second file beside
one stored in another case. A stat or access of a hit reads no path. A
game that spells its files as stored reads no path for its loose hits; on
a folder install on the case-sensitive internal SSD, each access spelled in
another case reads and confirms the stored path. `index_lookup_io` counts
only failed reads, so a value above 0 means the index file could not be
read.

Pack chunks are read with exact-size reads, the only read path: one disk
read covers a chunk's stored bytes, adjacent chunks coalesced.
`pack_disk_reads` counts those reads and `pack_disk_bytes` their bytes.
Read bytes are not cached; decoded chunks go to the decoded cache, the
Cache ledger (30.61 MiB in the debug build at the mount).

Most runs compare these numbers:

- command buffer, submit to release: `job_total_ns / job_totals`. Compare
  builds on this one: it includes the wait in the priority lane, which
  game wait per read does not (it starts at the reactor's submit of a
  read). `job_first_issue_ns / job_first_issues` is the part before the
  first read is issued, `job_order_wait_ns / job_totals` the wait for
  earlier jobs of the lane to publish;
- game wait per read: `apr_read_ns / apr_reads`;
- pack job (a packed read from submit to completion):
  `pack_job_ns / pack_jobs`;
- disk read: `pread_read_ns / pread_reads` in the pread pool,
  `ext_read_ns / ext_reads` for the reactor's kernel AIO reads.

A pack worker queues its disk read to the pread pool itself, and the pool
thread that runs it requeues the job, with no reactor hop either way
(rt/reactor/pread_pool.rs `queue_pack_pread`). `pack_pread_direct` counts
those reads; `pack_pread_reactor` counts the ones that went through the
reactor instead (no free pool task, or no live pool thread, which also
covers the first read and kernel AIO when the pool gave every thread back).
`ext_reads` and `ext_read_ns` include the direct reads, timed from queue to
completion. What queueing and hand-offs cost a disk read is
`park_io_ns / park_ios` minus `pread_read_ns / pread_reads` and
`pread_queue_ns / pread_reads`. Pool threads for pack reads and decode
workers are created with no runtime lock held and not on the reactor thread
(except the first decode worker of a mount, under PACK_M, and loose-read
pool growth, on the reactor thread): a pack worker
starts the pool threads its read asked for after it releases PACK_M, and a
decode worker that a queued job asked for is started by a worker after its
step or by a pool thread after it requeued a job (`pread_queue_ns_max`,
`pack_workers_started`). Loose reads still start pool threads on the
reactor thread, the only thread that queues them.

In pkg mode (this title's .pkg named by `/app0/kraken.image`) chunks of the .pkg are
read the same way, one exact-size read of their stored bytes, and count in
the same `pack_disk_reads`, `pack_disk_bytes` and disk read times as other
pack reads; `pack_disk_bytes / pack_disk_reads` is the average read size.

Packed POSIX reads run on the caller's own thread: it queues the pack
jobs and sleeps until they are done (rt/pack/fd_read.rs `read_on_workers`;
the frames down to the queue push are pinned to 4 KiB in
tools/check_stack_frames.py). One read in 16 asks libkernel for the stack
its caller had left: `read_inline_stack_left` is the least seen (0 until
libkernel says) and `read_inline_low_stack` counts those under 16 KiB.

The runtime's own threads run on stacks from a 2 MiB pool block, each with
a no-access 16 KiB guard page below it (rt/thread_stack.rs).
`thread_stacks_pool` counts threads started on one, `thread_stacks_libkernel`
those that got libkernel's stack instead (no `scePthreadAttrSetstack`, block
full, a stack over 128 KiB, or the attribute refused), and
`thread_stack_bytes` / `thread_stack_bytes_max` the block bytes in use,
guards included. Held threads (`/threads?hold=N`) keep libkernel stacks.
The iced-x86 heap (rt/heap.rs) is a 384 KiB pool block: `heap_bytes` and
`heap_bytes_max` are live bytes, `heap_bump_top` how far the block is
used, and `heap_libc_bytes` what went to libc malloc past it (0 expected;
the host measured 246,688 B for the decoder tables). Compare
`flex_free_bytes` with every thread group at its ceiling against v0.4.1 to
see the stacks leave the game's flexible memory.

`posix_reads`, `posix_read_ns` and `posix_read_ns_max` time each packed
POSIX read of one byte or more (read, readv, pread, preadv, and libc's
`_read`/`_readv` on a virtual pack fd; rt/pack/fd_read.rs `read_slot_at`)
as its caller sees it: the queue wait, the pack job and the wake-up.
`posix_read_ns / posix_reads` is the time per read; `posix_read_ns_max`
resets on every scrape. Compare it with `pack_job_ns / pack_jobs`, and with
a v0.4.1 run, whose reads went through a read thread (two more hops).
`posix_read_cancel_on` counts packed POSIX reads that ran with thread
cancellation still on (it could not be turned off); the read proceeds.

`path_calls_<id>` and `path_ns_<id>` count and time the path lookup hooks
by hook id (0 to 4, 78, 79, 84 `_open`, 85 `_openat`, 91 `access`, 92
`lstat`: open, stat, the sceKernel open and stat, reachability, unlink and
rename; `PATH_HOOKS` in `rt/stats.rs`). `path_ns_<id> / path_calls_<id>`
is the time per call.

`reactor_passes` counts reactor loop passes; per job or per read it is
the fixed pass cost. `thread_join_failed` counts a failed `scePthreadJoin`
of an exited pool thread or decode worker: the slot is freed (a retry
could join a reused handle) and its pool stack stays reserved.

`libc_hits_84` to `libc_hits_95` count calls into the libc entry hooks by
hook id: 84 `_open`, 85 `_openat`, 86 `_read`, 87 `_readv`, 88 `_close`,
89 `_fstat`, 90 `_getdirentries`, 91 `access`, 92 `lstat`, 93 `fcntl`,
94 `_fcntl`, 95 `sceKernelFcntl`. `libc_packed_84` to `libc_packed_95`
count the same calls the runtime served on a virtual pack fd or packed
directory fd (for 84 and 85, an open that returned one); 91 and 92 take no
fd and stay 0. These hooks install only in a title with packs; an id that
stays 0 across a title's play is a candidate for removal.

### /bench

`/bench` reads pack volume 0 through the unhooked kernel calls, each test in
its own region so the OS cache does not help later tests. It needs a title
with packs. It blocks only the metrics thread, but its reads compete with the
game's, so run it while the game is idle.

`/bench?path=/app0/<file>` needs a loose file of at least 736 MiB not read
since boot. `&backing=/abs/path` also reads the file at its backing path,
if the sizes match. The bench buffer (8 MiB, halved when short) comes from
the Index ledger.

### /modules

One line per loaded module: name, segment count, first segment size and a
fingerprint that tells a fakelib copy from the system library of the same
name.

### Decoded cache

A chunk hit `cache_protect_hits` times while cached (release 3; 0 turns it
off) turns protected, and the eviction hand skips protected chunks while
they hold at most `cache_protect_pct` percent of the cache (release 50).
Above that share the hand demotes them to probation, one more sweep before
eviction (`rt/pack/caches.rs`). `cache_protected_bytes` is the protected
bytes now, `cache_promotions` and `cache_demotions` count the moves. Judge
it by `cache_miss_repeat` (a chunk cached before and evicted, which it
should lower) against `cache_miss_first` (never read before, which it
cannot change), per 10 minutes of play. A read of part of a chunk is
cached on its first touch; a read of a whole chunk decodes into the game
buffer and is cached on its second touch, so `cache_miss_repeat /
cache_misses` and `pack_disk_bytes` per game byte show the admission
change. `cache_cap_evictions` counts evictions forced by the entry cap
(16384 entries) while free page room was left; a high count says the cap,
not the cache size, limits the hit rate.

## Tune file

The knobs are in `crates/ampr-sys/src/rt/tune.rs`. The debug build reads
`/data/ampr_emu_tune.txt` once, at module start before the hooks install,
so titles without packs read it too.

```sh
curl http://<ps5-ip>:9090/set                       # list knobs, ranges, live or next launch
curl 'http://<ps5-ip>:9090/set?read_chunk_quantum=8&pread_threads=4'
```

`/set` applies the pairs in order and stops at the first bad one, then
rewrites the file and lists every knob, so a knob set in one run stays
set for every later launch of any title until the file is deleted. Live knobs (pread pool switches,
reactor issue limits, thread budget,
`spin_us`, `regrow_s`, `pread_wake_all`, `cache_protect_hits`,
`cache_protect_pct`, `lane_eop_overlap`) apply from the next read or reactor
pass. `spin_us` (0..=200, release 100) is read at each idle wait of a pack
worker and pread pool thread, so `/set?spin_us=50` or `100`
takes effect at once; compare game wait per read and `pread_wakeups_idle`
before and after. Grown runtime threads stay until a failed game thread
creation (pressure mode) gives them back; watch `/fsfail` op `P` and the
pressure counters (`<group>_threads_live`, `_threads_peak`,
`_retired_pressure`; `_target` is written only under pressure, 0 or 1,
and reads 0 before the first pressure check). Startup knobs (`decoded_mib`, workers, pipelines, `pread_threads`,
`zstd_verify`, `worker_stack_kib`) apply at the next launch. The tune file
skips knobs that no longer exist (`ra`, `ra_gate`,
`equeue_local`, `retire_load`, `profile`); `/set` refuses them. A decoded
cache past the Cache ledger (`decoded_mib` default 136, the cap rounded up)
is cut to fit. The I/O windows
are taken at the worker start and the pipelines are the windows the Buffer
ledger grants after the worker buffers; workers are cut until each has a
pipeline (8 workers run with 9 pipelines,
`buffer_split` in `rt/pack/worker.rs`).

The file stores every knob, defaults included, so a file from an older build
keeps that build's values (for example `decoded_mib=0`, decoded cache off).
Delete it to get the current defaults.

## Failed calls and op letters

`/fsfail` keeps the first 96 distinct (op, path) pairs since load, each with
its lookup letter, result and count; `fsfail_dropped` counts the rest. Paths
are compared on their first 128 bytes. Misses the index answers itself and
`/download0/` paths are left out. The same letters appear in the `fs` lines
of `/metrics` and in the black box; the full list is at `FsEvents` in
`crates/ampr-sys/src/rt/stats.rs`.

| Op | Event |
| --- | --- |
| `o s l a r` | Path hooks: open, stat, lstat, access, reachability. |
| `O A` | libc `_open`, `_openat`. |
| `L` | The runtime's own open of an indexed loose file. |
| `R` | An APR path that did not resolve. |
| `E` | A failed APR job; the path is the reason. |
| `J` | An APR call that returned an error (first 64): lookup `w` wait, `u` submit, `n` native batch. |
| `K` | A module load. Lookup `-`: the name the game asked for; `h`: the index path tried first after an ENOENT. |
| `G` | A gather/scatter retry resolved to another file or offset. |
| `D W T F C N` | Probes: dup, poll, openat, fstatat, faccessat, readlink reached a packed file (`p`), indexed directory (`d`) or virtual fd (`v`). |
| `O A a l` with lookup `p` or `d` | A libc hook with its `AMPR_PACK_LIBC_HOOKS` bit clear saw a packed file or directory and did not route it. |
| `I` | The game's own AIO submit on a packed fd, served by the runtime (logged whatever the result). |
| `X Y` | mmap, `sceKernelMmap` of a virtual fd, lookup `v`: the map failed (a packed file has no physical copy to map; the mmap disk cache was removed). Debug only, ids 96 and 97 are probes; `mmap_virtual` counts them. |
| `Z` | A pack chunk failed to decode, or a zstd checksum mismatched. |
| `U` | A failed `getdents` or `getdirentries` on a virtual directory fd, lookup `d`: path `read <directory> rc=0x<8 hex>`. Each distinct result of a directory is kept once, `/fsfail` counts the repeats. Lookup `x`: path `realfail <directory> errno=<n>`, the physical `getdents` behind the directory failed with `n`, so the listing goes on with the packed entries only. A first EINVAL (a caller buffer below the filesystem's block size) is not logged: the directory is read again through the 64 KiB listing window, and only a failure of that read logs `realfail`. |
| `P` | A failed game thread creation: lookup `s` scePthreadCreate, `p` pthread_create, `r` its retry, `h` the `/threads` probe (black box only). |
| `V` | Save data (`rt/save.rs`), lookup `-`: `save icon <path> rc=0x<8 hex>` for an icon handed over as bytes, packed or a loose one whose path the service refused (`-1`: not read; that retry shows `save SaveIconByPath rc=0x809f000e`, the service's answer, before the hook's own); `save <call> in` and `save <call> rc=0x<8 hex>` on entry to and return from each probed save or dialog call, so a call with an `in` and no answer is the one a game is stuck in; `save Mount3 arg` (the request's first 5 words: blocks, systemBlocks and the mode in the low half of the 5th), `dir`, `point` and `save Umount2 point` for the mounts (debug probe), so a point mounted more often than unmounted shows; `save Mount3 systemBlocks 0 rc=0x<8 hex>` for a refused creating mount sent again with systemBlocks 0. Counters: `save_mounts`, `save_busy`, `save_system_blocks_zeroed`, `save_icon_bytes`, `save_icon_skipped`, and the answer codes `save_icon_last_result`, `save_icon_path_last_result` (hex). |
| `Q` | Packed fd and open failures: `H` raw SCE error of a packed open, `R` errno of a physical open (`fs` ring only), `S` the 320-slot packed-fd table full. |

Lookup letters of path hooks: `h` index hit, `m` miss the index answers,
`M` miss sent to the filesystem, `d` directory, `n` index not ready, `x`
not under `/app0`, `-` none. With a writable /app0 every miss is `M`
([writable-app0.md](writable-app0.md)).

## Black box

When the game dies before port 9090 answers, read
`/data/ampr_emu_trace.txt` (`crates/ampr-sys/src/rt/blackbox.rs`). It is
written as events happen, so it survives the crash, and holds:

- the loaded modules with segment addresses, at start and after each module
  load, to map a crash RIP to a module;
- one `pkg <how> <detail> <path or ->` line on how pkg discovery ended
  (`log_discovery` in `rt/pack/pkg.rs`). `how` is `noimage` (no
  kraken.image, other modes as before), `badimage` (unreadable or refused
  path; detail the open errno or 0), `open` (the .pkg failed to open;
  detail the errno), `notregular`, `nomanifest`, `size` (the page-aligned
  .pkg size is not pack 0's; detail the .pkg size) or `ok` (detail the
  .pkg size), detail in hex. The path is `/app0/` plus the kraken.image
  line, or `-` before a valid one;
- one `rw on` or `rw off errno=<hex>` line, the writable /app0 test
  (`init` in `rt/rw.rs`): the errno of `access("/app0", W_OK)`
  ([writable-app0.md](writable-app0.md));
- every failed file event `/fsfail` would keep, and every module load (`K`);
- probe events once per (op, path), whatever their result; a served `I`
  line shows what the game did with packed files before it died.
- the index load (rt/index.rs `ensure_ready_slow`): one `idx <how>
  files=<count>` line per load attempt, `how` one of `Loaded`, `Missing`,
  `Invalid`, `Memory`, `Unreadable`, or `walk ok`/`walk fail` when a walk
  build replaced it; then `idx join ok|fail` for the pack join of a title
  with packs (a failed join unlinks every packed row). The count is the
  files loaded, in hex, and 0 on a failed load. A run of `Unreadable`
  loads is written up to its third attempt; later retries are not.

Successful file calls are not written. The file is truncated at each start;
copy it off before relaunching.

## Comparing runs and installs

To measure a change, run the same game and scene with each build and read
`/metrics` at the same points (say, start of load and level loaded). Compare
game wait per read, pack job and disk read, and note the game, build (the
`build` line) and settings next to the numbers.

When one install of a game works and another does not, run the same debug
build on both and diff their `/fsfail` and `/modules`. A module missing from
one list, or a path failing on one install only, points at the cause.

Folder installs on the internal SSD are case-sensitive; retail pfs and exFAT
are not, and games rely on that. A path that skips the index (an unhooked
libc call) fails only on such an install. The system module loader opens
files itself, so module loads go through the index
(`sceKernelLoadStartModule_observer` in `rt/hook.rs`).
