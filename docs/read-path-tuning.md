# Loose read path tuning

Measured on one game, loose files on the internal SSD
(ShadowMount folder mode, nullfs bind of `/data/homebrew/...` to `/app0`),
debug build `libSceAmpr-debug.sprx`, numbers read once per second from
`http://<ps5-ip>:9090/metrics`. Each run is a fresh game launch through the
same section (~12-13 GB read, ~24k APR reads, ~15k APR jobs). Runs differ by
about 5% from play timing alone.

"Per job" is an estimate: submit -> first read issued, plus read time per
job, plus last read -> game notified (`job_first_issue_ns`, `apr_read_ns`
/ `job_count`, `job_notify_ns`).

## Final defaults (release and debug)

| Setting | Value | Where |
|---|---|---|
| Loose APR reads through the blocking pread pool | on | `AMPR_EMU_APR_LOOSE_PREAD`, reactor/loose_pread.rs |
| Split each loose read into parallel parts | 64 KiB | `AMPR_EMU_APR_LOOSE_PREAD_PART_KIB` |
| pread pool threads | 32 (4 kept for pack reads) | `tune::RELEASE_PREAD_THREADS` |
| Lane EOP overlap | off | `AMPR_EMU_APR_LANE_EOP_OVERLAP` |
| Read pass / per-read active limits | 512 KiB / 4 chunks, 2 MiB (unchanged) | reactor/mod.rs |

Result: 1.09 ms per read vs 2.53 ms with kernel AIO (-57%), 27.9 s vs
61.0 s of read time per session, ~5.9 ms per job, 0 errors, pool peak
72.0 MiB of 88 MiB (unchanged).

## What helped

| Change | Per read | Why |
|---|---|---|
| Kernel AIO (baseline) | 2.53 ms | the game keeps ~1 read in flight per priority lane |
| pread pool, no split | 2.51 ms | same: one 512 KiB pread still costs ~2.5 ms under load |
| pread pool, 64 KiB parts, 16 threads | 1.35 ms | parts of one read run in parallel |
| pread pool, 64 KiB parts, 32 threads | 1.10 ms | 98% of reads split instead of 73% |

`/bench` (idle disk): one pread costs ~0.8 ms for any size up to 512 KiB;
8 threads of parallel 256 KiB preads reach ~1.9-2.0 GB/s, kernel AIO tops
out at ~730 MB/s even 32 deep. Parallel preads are what the disk wants.

## Off or removed, and why

| Thing | Result | Decision |
|---|---|---|
| 128 / 256 KiB parts | 1.50 / 2.09 ms per read (32 threads) | 64 KiB: more parallel parts per read beat fewer larger ones; under load a 256 KiB part takes 2.4x a 64 KiB part |
| 256 KiB parts with overlap on | ~12.6 ms per job vs ~6.4 | same reason |
| Larger read pass / per-read active limits (4 MiB pass, 16 chunks / 8 MiB) | 1.10 vs 1.13 ms per read, first-issue wait unchanged | not the bottleneck; constants kept, debug knobs remain |
| Lane EOP overlap (next job in a lane starts while the head only has completion writes left) | 32 threads: ~7.7 ms per job on vs ~6.1 off; 64 threads: ~6.4 on vs ~6.6 off | off: it removes the lane wait (4.8 -> 1.8 ms) but the extra reads only queue for the 28 loose pread tasks, and completions must still publish in lane order (~0.5-1 ms). Code kept, debug knob `lane_eop_overlap` |
| Reading through the backing folder instead of `/app0` (`app0_direct`) | ~6.2 vs ~6.4 ms per job (64 KiB); no split ~14.8 ms | removed: nullfs costs ~1% in parallel benches (256 KiB x 8 threads: 1,971 vs 2,045 MB/s), and libkernel exports neither `statfs` nor `fstatfs`, so the folder cannot be detected |
| Read-ahead (`AMPR_PACK_READAHEAD_CHUNKS`, Makefile) | ~46% cache hit on prefetched data; the extra prefetch reads add disk traffic and raise latency for the reads the game waits on | off (0): roughly half the prefetched bytes are never used, and the noise costs more than the hits save. Not re-measured in these runs |

## Still true

- The remaining wait is mostly the job queue in each priority lane (4.2 ms
  submit -> first read) and disk time per 64 KiB part (0.88 ms).
- Unverified: loose reads are now filled by CPU pread instead of kernel AIO.
  The pack path has always CPU-copied into game buffers and packed games
  run, but GPU visibility of CPU-written data was not tested separately.
  `loose_pread=0` (debug) returns to kernel AIO.
- Not measured here: packed games (pack reads share the pool; 4 threads are
  reserved for them) and other titles. Re-check with `/metrics` and
  `/bench?path=/app0/<big file>&backing=<folder>/<big file>` before changing
  defaults.
