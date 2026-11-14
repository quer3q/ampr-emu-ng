# Debug build

`libSceAmpr-debug.sprx` is the release runtime plus a metrics server, a
tuning file, a failed-call log and a crash trace. Test a game or a change
with it, then ship the release build.

## How it differs from release

`./ps5/build-docker.sh` (`make dist`) builds both files. The debug one is
`make AMPR_MEM_REPORT=1` (Cargo feature `mem_report`) with the pool set to
`AMPR_DEBUG_POOL_SIZE` (`0x9e78000`, 158.47 MiB); the release pool is
`0x9fd4000` (159.83 MiB). The smaller pool offsets the larger debug code, so
both PRX files load to 168.47 MiB with the same ledger caps, cache and
thread limits.

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
  `AMPR_ZSTD_LIBC_HOOKS` bit is clear still installs and only observes;
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
| `/queues` | Event queue waits in progress and queues with pending events. |
| `/threads` | Thread counts; `?hold=N`, `?release=1`, `?yield=N` and `?yield_workers=N` test the game's thread limit. |

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
since load; `*_max` values reset on each scrape; the `save_*_last_*` codes
hold the last value, so do not subtract them between scrapes.

The index page cache (`rt/index_pages.rs`) reads the index files that do not
fit the Index ledger whole in 16 KiB pages through an arena of
`index_arena_bytes` (a 16 MiB floor plus the room the lookup tables left;
0 while every index file is read whole; `index_fast_bytes` is the resident
fast tables of the paged files): `index_page_hits` (pages
served from the arena), `index_page_misses` and `index_page_miss_ns` (pages
read from the file and the time spent), `index_page_evictions` (pages dropped
to make room), `index_page_resident` (pages in the arena now),
`index_page_direct_reads` (reads served from the file past the arena,
because another thread was loading that page or no slot could be evicted;
no reader waits on another thread) and `index_files_bytes` (the registered
index files together). When
`index_files_bytes` fits the arena, misses stop at one per page and
evictions stay 0; growing evictions mean the index files outgrew it.
`index_fast_bytes` covers the fast tables of all three index files (zstd
16 B per file for hash and size, 8 B per chunk and volume; AMPRIDX3 12 B per file; LZ4 48 B per
file, 12 B per chunk, 32 B per pack); a paged index whose fast table does
not fit is not served (the one index notice). `index_lookup_io` counts
file index lookups that could not read the index file: they go to the
real call instead of answering ENOENT.

Pack chunks are read with exact-size reads, the only read path: one disk
read covers a chunk's stored bytes, adjacent chunks coalesced.
`pack_disk_reads` counts those reads and `pack_disk_bytes` their bytes.
Read bytes are not cached; decoded chunks go to the 64 MiB decoded cache.

Most runs compare three numbers:

- game wait per read: `apr_read_ns / apr_reads`;
- pack job (a packed read from submit to completion):
  `pack_job_ns / pack_jobs`;
- disk read: `pread_read_ns / pread_reads` in the pread pool,
  `ext_read_ns / ext_reads` for the reactor's kernel AIO reads.

In pkg mode (this title's .pkg named by `/app0/kraken.image`) chunks of the .pkg are
read the same way, one exact-size read of their stored bytes, and count in
the same `pack_disk_reads`, `pack_disk_bytes` and disk read times as other
pack reads; `pack_disk_bytes / pack_disk_reads` is the average read size.

Save data (`rt/save.rs`) shows what the save service answered.
`save_mounts` counts sceSaveDataMount3 calls, `save_busy` those answered
SAVE_DATA_ERROR_BUSY, `save_mount_errors` those answered non-zero (BUSY
included) and `save_mount_last_error` the last non-zero code. A packed icon
handed over through sceSaveDataSaveIcon adds its bytes to `save_icon_bytes`
or, refused or unreadable, 1 to `save_icon_skipped`;
`save_icon_last_result` is what sceSaveDataSaveIcon answered the last
packed icon, before the hook answers the game 0 for a failure.
`save_icon_path_last_result` is what the original
sceSaveDataSaveIconByPath answered the last call forwarded to it (a loose
or missing icon). The three codes are the last value, not totals, and
print as `0x` and 8 hex digits; `0x00000000` also means no such call yet.
Every answer goes back to the game unchanged except the packed icon one.

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

## Tune file

The knobs are in `crates/ampr-sys/src/rt/tune.rs`. The debug build reads
`/data/ampr_emu_tune.txt` once, at module start before the hooks install,
so titles without packs read it too.

```sh
curl http://<ps5-ip>:9090/set                       # list knobs, ranges, live or next launch
curl 'http://<ps5-ip>:9090/set?ra=4&pread_threads=4'
curl 'http://<ps5-ip>:9090/set?profile=low'         # low, medium or high
```

`/set` applies the pairs in order and stops at the first bad one, then
rewrites the file and lists every knob. Live knobs (read-ahead and its gate,
pread pool switches, reactor issue limits, lane EOP overlap, thread budget,
`spin_us`, `regrow_s`, `pread_wake_all`) apply from the next read or reactor
pass. Startup knobs (`decoded_mib`, workers, pipelines, `pread_threads`,
`zstd_verify`, `equeue_local`, `worker_stack_kib`) apply at the next launch.
A profile sets `decoded_mib`, `workers` and `pipelines` (low 24 MiB, 4, 8;
medium 80 MiB, 8, 16; high 160 MiB, 8, 32, `PROFILES` in `rt/tune.rs`); a
decoded cache past the 64 MiB Cache ledger is cut to fit. The I/O windows
are taken at the worker start and the pipelines are the windows the Buffer
ledger grants after the worker buffers; workers are cut until each has a
pipeline (medium and high run 8 workers with 9 pipelines,
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
| `O A a l` with lookup `p` or `d` | A libc hook with its `AMPR_ZSTD_LIBC_HOOKS` bit clear saw a packed file or directory and did not route it. |
| `I` | The game's own AIO submit on a packed fd, served by the runtime (logged whatever the result). |
| `X Y` | mmap, `sceKernelMmap` of a virtual fd: lookup `k` disk cache file, `f` decode on access, `F` decode-on-access failure, `v` other failure. `/fsfail` keeps failures only. |
| `Z` | A pack chunk failed to decode, or a zstd checksum mismatched. |
| `V` | A save data icon handed over from a pack, with its result. |
| `U` | A failed `getdents` or `getdirentries` on a virtual directory fd, lookup `d`: path `read <directory> rc=0x<8 hex>`. Each distinct result of a directory is kept once, `/fsfail` counts the repeats. Lookup `x`: path `realfail <directory> errno=<n>`, the physical `getdents` behind the directory failed with `n`, so the listing goes on with the packed entries only. |
| `P` | A failed game thread creation: lookup `s` scePthreadCreate, `p` pthread_create, `r` its retry, `h` the `/threads` probe (black box only). |
| `Q` | Packed fd and open failures: `H` raw SCE error of a packed open, `R` errno of a physical open (`fs` ring only), `S` the 512-slot packed-fd table full. |

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
- every failed file event `/fsfail` would keep, and every module load (`K`);
- probe events once per (op, path), whatever their result; a served `I`
  line shows what the game did with packed files before it died.

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
(`sceKernelLoadStartModule_equeue_observer` in `rt/hook.rs`).
