# Loose read path tuning

Measured on one game with loose files on the internal SSD (ShadowMount
folder mode, a nullfs bind of `/data/homebrew/...` to `/app0`) with the
debug build, reading `http://<ps5-ip>:9090/metrics` once a second. Each
run is a fresh launch through the same section: 12-13 GB in ~24k APR reads
and ~15k jobs. Play timing alone moves results by about 5%.

"Per job" adds submit to first read (`job_first_issue_ns`), read time per
job (`apr_read_ns` / `job_count`) and last read to notify
(`job_notify_ns`).

## Defaults

| Setting | Value | Where |
|---|---|---|
| Loose APR reads through the pread pool | on | `AMPR_EMU_APR_LOOSE_PREAD`, reactor/loose_pread.rs |
| Loose read split into parallel parts | 64 KiB | `AMPR_EMU_APR_LOOSE_PREAD_PART_KIB` |
| pread pool threads | at most 6, grown by backlog, retired by load | `tune::RELEASE_PREAD_THREADS` |
| Threads kept for pack reads | 4 (loose tasks: threads minus 4, at least 1) | `AMPR_EMU_APR_LOOSE_PREAD_PACK_RESERVE` |
| Lane EOP overlap | off | `AMPR_EMU_APR_LANE_EOP_OVERLAP` |
| Read pass / per-read active limits | 512 KiB / 4 chunks, 2 MiB | reactor/mod.rs |

The numbers below come from the earlier 32-thread pool: 1.09 ms per read
against 2.53 ms on kernel AIO (-57%), read time per session 27.9 s instead
of 61.0 s, about 5.9 ms per job, 0 errors. Game wait per read did not
change between 8 and 32 threads (Makefile). At 6 threads the loose task
cap is 2, so only reads of up to two parts split.

## What helped

| Change | Per read | Why |
|---|---|---|
| Kernel AIO (baseline) | 2.53 ms | the game keeps about 1 read in flight per priority lane |
| pread pool, no split | 2.51 ms | one 512 KiB pread still costs about 2.5 ms under load |
| pread pool, 64 KiB parts, 16 threads | 1.35 ms | the parts of one read run in parallel |
| pread pool, 64 KiB parts, 32 threads | 1.10 ms | 98% of reads split instead of 73% |

On an idle disk (`/bench`) one pread costs about 0.8 ms at any size up to
512 KiB. Eight threads of 256 KiB preads reach 1.9-2.0 GB/s, while kernel
AIO stays near 730 MB/s even 32 requests deep.

## Off or removed

| Thing | Result | Decision |
|---|---|---|
| 128 / 256 KiB parts | 1.50 / 2.09 ms per read (32 threads) | 64 KiB: under load a 256 KiB part takes 2.4x as long as a 64 KiB one |
| 256 KiB parts, overlap on | about 12.6 vs 6.4 ms per job | off |
| Larger read pass / per-read limits (4 MiB pass, 16 chunks / 8 MiB) | 1.10 vs 1.13 ms per read, first-issue wait unchanged | not the bottleneck; debug knobs remain |
| Lane EOP overlap (next job in a lane starts while the head has only completion writes left) | about 7.7 ms per job on vs 6.1 off (32 threads); 6.4 vs 6.6 (64 threads) | off: lane wait drops from 4.8 to 1.8 ms, but the extra reads queue for the 28 loose tasks (32 threads) and completions still publish in lane order (0.5-1 ms). Debug knob `lane_eop_overlap` |
| Reading the backing folder instead of `/app0` (`app0_direct`) | about 6.2 vs 6.4 ms per job; 14.8 ms without the split | removed: nullfs costs about 1% (256 KiB x 8 threads: 1,971 vs 2,045 MB/s), and libkernel exports neither `statfs` nor `fstatfs` to detect the folder |
| Read-ahead (`AMPR_PACK_READAHEAD_CHUNKS`) | load latency 1.62 vs 1.60 ms; worst read 36.2 ms on vs 26.7 off. A lighter game read 1.69 vs 0.78 disk bytes per game byte, worst read 13.4 vs 5.6 ms | off (0). Earlier runs hit about 46% of prefetched data. Not re-measured since prefetched chunks land in the 64 MiB decoded cache |

## Known limits

- Most remaining wait is the lane job queue (4.2 ms submit to first read)
  and disk time per 64 KiB part (0.88 ms).
- Loose reads are now CPU preads. Whether the GPU sees CPU-written data was
  never tested on its own, though the pack path has always filled game
  buffers with the CPU. A failed or short pread goes to kernel AIO, and
  `loose_pread=0` (debug) turns the pool off.
- Packed games and other titles were not measured. Check `/metrics` and
  `/bench?path=/app0/<big file>&backing=<folder>/<big file>` before
  changing defaults.
