# Loose read path tuning

These numbers come from one game with loose files on the internal SSD
(ShadowMount folder mode, a nullfs bind of `/data/homebrew/...` to `/app0`),
running the debug build `libSceAmpr-debug.sprx`. They were read once per
second from `http://<ps5-ip>:9090/metrics`. Each run is a fresh game launch
through the same section, about 12-13 GB read in ~24k APR reads and ~15k APR
jobs. Play timing alone moves the results by about 5% between runs.

"Per job" is an estimate built from three parts: the time from submit to the
first read issued (`job_first_issue_ns`), the read time per job
(`apr_read_ns` / `job_count`), and the time from the last read to the game
being notified (`job_notify_ns`).

## Final defaults (release and debug)

| Setting | Value | Where |
|---|---|---|
| Loose APR reads through the blocking pread pool | on | `AMPR_EMU_APR_LOOSE_PREAD`, reactor/loose_pread.rs |
| Split each loose read into parallel parts | 64 KiB | `AMPR_EMU_APR_LOOSE_PREAD_PART_KIB` |
| pread pool threads | 32 (4 kept for pack reads) | `tune::RELEASE_PREAD_THREADS` |
| Lane EOP overlap | off | `AMPR_EMU_APR_LANE_EOP_OVERLAP` |
| Read pass / per-read active limits | 512 KiB / 4 chunks, 2 MiB (unchanged) | reactor/mod.rs |

With these defaults a read takes 1.09 ms, against 2.53 ms with kernel AIO
(-57%). Read time per session drops from 61.0 s to 27.9 s, a job takes about
5.9 ms, and there are 0 errors.

## What helped

| Change | Per read | Why |
|---|---|---|
| Kernel AIO (baseline) | 2.53 ms | the game keeps about 1 read in flight per priority lane |
| pread pool, no split | 2.51 ms | one 512 KiB pread still costs about 2.5 ms under load |
| pread pool, 64 KiB parts, 16 threads | 1.35 ms | the parts of one read run in parallel |
| pread pool, 64 KiB parts, 32 threads | 1.10 ms | 98% of reads are split instead of 73% |

On an idle disk, `/bench` shows that one pread costs about 0.8 ms at any size
up to 512 KiB. Eight threads of parallel 256 KiB preads reach about
1.9-2.0 GB/s, while kernel AIO stays near 730 MB/s even 32 requests deep, so
the pool issues many parallel preads.

## Off or removed, and why

| Thing | Result | Decision |
|---|---|---|
| 128 / 256 KiB parts | 1.50 / 2.09 ms per read (32 threads) | 64 KiB: more, smaller parts per read win; under load a 256 KiB part takes 2.4x as long as a 64 KiB part |
| 256 KiB parts with overlap on | about 12.6 ms per job vs about 6.4 | off, for the same reason |
| Larger read pass / per-read active limits (4 MiB pass, 16 chunks / 8 MiB) | 1.10 vs 1.13 ms per read, first-issue wait unchanged | not the bottleneck; the constants stay and the debug knobs remain |
| Lane EOP overlap (the next job in a lane starts while the head has only completion writes left) | 32 threads: about 7.7 ms per job on vs 6.1 off; 64 threads: about 6.4 on vs 6.6 off | off: it cuts the lane wait from 4.8 to 1.8 ms, but the extra reads only queue for the 28 loose pread tasks, and completions still publish in lane order (about 0.5-1 ms). The code stays, behind the debug knob `lane_eop_overlap` |
| Reading through the backing folder instead of `/app0` (`app0_direct`) | about 6.2 vs 6.4 ms per job (64 KiB parts); without the split about 14.8 ms | removed: nullfs costs about 1% in parallel benches (256 KiB x 8 threads: 1,971 vs 2,045 MB/s), and libkernel exports neither `statfs` nor `fstatfs`, so the runtime cannot detect the folder |
| Read-ahead (`AMPR_PACK_READAHEAD_CHUNKS`, Makefile) | about 46% cache hits on prefetched data; the extra prefetch reads add disk traffic and raise latency for the reads the game waits on | off (0): roughly half the prefetched bytes go unused, and the extra traffic costs more than the hits save. Not re-measured in these runs |

## Known limits

- Most of the remaining wait is the job queue in each priority lane (4.2 ms
  from submit to the first read) and the disk time per 64 KiB part
  (0.88 ms).
- Loose reads are now filled by CPU pread instead of kernel AIO, and that was
  not verified on its own. The pack path has always copied into game buffers
  with the CPU and packed games run, but nobody tested separately whether the
  GPU sees data the CPU wrote. `loose_pread=0` (debug) goes back to kernel
  AIO.
- Packed games were not measured here (pack reads share the pool, which keeps
  4 threads for them), and neither were other titles. Check with `/metrics`
  and `/bench?path=/app0/<big file>&backing=<folder>/<big file>` before
  changing defaults.
