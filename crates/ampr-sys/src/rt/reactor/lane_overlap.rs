//! Lane EOP overlap: lets a priority lane's next job parse while the head job
//! has only completion commands left. On in release; the debug build reads
//! `lane_eop_overlap` (default 1).
//!
//! Why: the lane loop (progress.rs) parses a successor only once the head has
//! consumed its whole source. A head whose last read is in flight parks on its
//! EOP (address write, counter, equeue) at the read fence (native.rs
//! progress_native_or_address_command), so the successor's first read waits a
//! full read time and a lane runs one command buffer at a time. Console,
//! debug, one run each at equal reads, a command buffer from submit to
//! release (`job_total_ns`), off against on: a zstd title 97.9 vs 5.3 ms
//! (first read issued after 97.5 vs 1.5 ms, 982,578 vs 271 lane stops on the
//! fence), two pkg titles 6.09 vs 5.51 and 9.78 vs 8.90 ms. Wait per read
//! rises meanwhile (0.42 to 1.93 ms on the zstd title): more reads are in
//! flight at once.
//!
//! Rule: the head qualifies when it has not failed, has no non-batch native
//! micro op in flight, and every command left in its source is a completion
//! command (lane_completion_op): no read, wait, map begin/end, AMM op,
//! gather/scatter command or ResetGatherScatterState. The head keeps running
//! its own tail through the unchanged native.rs path, so its EOPs still wait
//! for its own read fence, publish in command order, and fail or cancel
//! exactly as today. The successor runs with the prior read fence held
//! (lane_successor_prior_fence), so none of its non-SOP commands can publish
//! before the head is released, and with `priorLaneOverlap` set, which stops
//! it at any command that would touch the lane's native APR batch or AMM
//! engine (overlap_successor_op_allowed): the head may still own the lane's
//! single deferred native EOP gate (batch_buffer.rs deferredReleaseSequence).
//! The successor may use the lane GatherScatterState because the head's tail
//! has no command that reads or writes it (checked by decoding the tail once).

use super::*;
use super::progress::{lane_block_kind, lane_completion_signals, LaneBlock};
use crate::rt::stats::{self, Stat};

// ---- tail classification ----

/// A command that only tells the game the job's earlier work is done and
/// touches no read, wait, map or gather/scatter state: the at-completion
/// forms of WriteAddress, WriteCounter, WriteKernelEventQueue and the
/// WriteAddressFrom{TimeCounter,Counter,CounterPair} writes (the `_04_00`
/// exports decode to the same op types), plus nops and markers.
pub(crate) fn lane_completion_op(op: &Op) -> bool {
    match op.op_type {
        NOP | MARKER_SET | MARKER_PUSH | MARKER_POP => true,
        WRITE_ADDRESS
        | WRITE_EQUEUE
        | WRITE_COUNTER
        | WRITE_ADDRESS_FROM_TIME_COUNTER
        | WRITE_ADDRESS_FROM_COUNTER
        | WRITE_ADDRESS_FROM_COUNTER_PAIR => !AprAioReactor::software_op_is_sop(op),
        _ => false,
    }
}

/// Decodes the packed APR commands in `src[offset..]` once. Some(signals) when
/// every one is a completion command (signals = how many signal the game);
/// None at the first other command, on a decode error or an empty tail.
pub(crate) fn completion_tail_signals(src: &[u8], offset: u32) -> Option<u32> {
    let bytes = u32::try_from(src.len()).ok()?;
    if offset >= bytes {
        return None;
    }
    let mut off = offset;
    let mut signals = 0u32;
    while off < bytes {
        let mut op = Op::default();
        let mut opBytes = 0u32;
        let mut errorOffset = 0u32;
        let rc = unsafe {
            ampr_decode_apr_packed_op(
                src.as_ptr().cast(),
                bytes,
                off,
                &mut op,
                &mut opBytes,
                &mut errorOffset,
            )
        };
        if rc != 0 || opBytes == 0 || opBytes > bytes - off || !lane_completion_op(&op) {
            return None;
        }
        signals += lane_completion_signals(&op) as u32;
        off += opBytes;
    }
    Some(signals)
}

// ---- successor rules ----

/// The prior read fence a lane job passes to its successor: held while any
/// earlier job has reads outstanding or an overlapped (unfinished) tail.
pub(crate) fn lane_successor_prior_fence(
    prior: bool,
    headHasOutstandingReads: bool,
    headOverlapped: bool,
) -> bool {
    prior || headHasOutstandingReads || headOverlapped
}

/// Non-read commands a successor may run while an earlier job of its lane is
/// overlapped: only software address writes and waits, which use no lane
/// state. Native batch, AMM, local equeue (its native fallback appends to the
/// batch) and map commands wait until the overlapped job is released.
pub(crate) fn overlap_successor_op_allowed(t: OpType) -> bool {
    matches!(t, WRITE_ADDRESS | WAIT_ON_ADDRESS)
}

/// Lane loop (progress.rs): after the head is released in a pass, go on to
/// its successor in the same pass instead of the next reactor iteration.
/// Without it a run of overlapped jobs whose reads are done publishes one job
/// per reactor iteration.
#[inline(always)]
pub(crate) fn lane_release_cascades() -> bool {
    crate::rt::tune::lane_eop_overlap()
}

// ---- reactor glue (progress.rs lane loop) ----

impl AprAioReactor {
    /// Lane loop: may `j`'s successor parse although `j` has source left?
    /// True only with `lane_eop_overlap` on and a completion-only tail.
    pub(crate) fn lane_eop_overlap_allows(j: &mut JobState, nativeSubmitted: bool) -> bool {
        if !crate::rt::tune::lane_eop_overlap()
            || Self::job_failed(j)
            || j.sourceOffset >= j.sourceBytes
            || j.nativeSubmitRetryAtNs != 0
            || (nativeSubmitted && j.nativeMicroEngine != NativeMicroEngine::AprBatch)
        {
            return false;
        }
        // Only a head parked on a completion command; this also skips the
        // tail decode while the head is still reading.
        if !Self::lane_cursor_op(j).is_some_and(lane_completion_op) {
            return false;
        }
        Self::job_tail_completion_only(j)
    }

    /// progress_job_commands (native.rs): after `op`, a completion command
    /// that was consumed, run `j`'s next command in the same pass when its
    /// tail is known completion-only (laneTailMark, set by the lane loop).
    /// Each command still goes through the unchanged fence and batch checks;
    /// one that cannot publish stops without advancing. Without this a tail
    /// of k commands takes k reactor passes, and the head is released (and
    /// the cascade reaches its successor) only after the last one.
    #[inline(always)]
    pub(crate) fn lane_tail_runs_on(j: &JobState, op: &Op, advanced: bool) -> bool {
        if !crate::rt::tune::lane_eop_overlap()
            || !advanced
            || !lane_completion_op(op)
            || Self::job_failed(j)
            || j.sourceOffset >= j.sourceBytes
        {
            return false;
        }
        j.laneTailMark != 0 && j.laneTailCompletionOnly && j.sourceOffset >= j.laneTailMark - 1
    }

    /// Decodes `j`'s remaining commands once per cursor position (cached in
    /// laneTailMark) and counts eop_deferred the first time they qualify.
    fn job_tail_completion_only(j: &mut JobState) -> bool {
        let at = j.sourceOffset;
        if j.laneTailMark != 0 {
            let markAt = j.laneTailMark - 1;
            if j.laneTailCompletionOnly && at >= markAt {
                return true;
            }
            if !j.laneTailCompletionOnly && at == markAt {
                return false;
            }
        }
        let src = unsafe { core::slice::from_raw_parts(j.sourceBuffer, j.sourceBytes as usize) };
        let signals = completion_tail_signals(src, at);
        j.laneTailMark = at + 1;
        j.laneTailCompletionOnly = signals.is_some();
        if let Some(n) = signals {
            stats::add(Stat::EopDeferred, n as u64);
        }
        signals.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn op(op_type: OpType) -> Op {
        Op {
            op_type,
            ..Op::default()
        }
    }
    fn write(op_type: OpType, sop: bool) -> Op {
        let mut o = op(op_type);
        o.ptra = 0x1000;
        o.u64a = 7;
        o.u64b = 0x2000;
        o.u32b = 3;
        match op_type {
            WRITE_ADDRESS | WRITE_EQUEUE => o.u8a = sop as u8,
            WRITE_COUNTER => {
                o.u8b = 1;
                o.u32c = sop as u32;
            }
            _ => o.u8b = sop as u8,
        }
        o
    }
    const WRITES: [OpType; 6] = [
        WRITE_ADDRESS,
        WRITE_EQUEUE,
        WRITE_COUNTER,
        WRITE_ADDRESS_FROM_TIME_COUNTER,
        WRITE_ADDRESS_FROM_COUNTER,
        WRITE_ADDRESS_FROM_COUNTER_PAIR,
    ];
    fn nop() -> Op {
        let mut o = op(NOP);
        o.u32a = 1;
        o
    }
    fn read_file() -> Op {
        let mut o = op(APR_READ_FILE);
        o.u32a = 1;
        o.ptra = 0x10000;
        o.u64a = 4096;
        o
    }
    fn wait_address() -> Op {
        let mut o = op(WAIT_ON_ADDRESS);
        o.ptra = 0x1000;
        o.u64a = 1;
        o
    }
    /// Packs `ops`; returns the buffer and each op's byte offset.
    fn pack(ops: &[Op]) -> (Vec<u8>, Vec<u32>) {
        let (mut buf, mut offs) = (Vec::new(), Vec::new());
        for o in ops {
            offs.push(buf.len() as u32);
            let (w, n) = o.encode_words().unwrap();
            for x in &w[..n] {
                buf.extend_from_slice(&x.to_ne_bytes());
            }
        }
        (buf, offs)
    }

    #[test]
    fn completion_ops_are_eop_writes_nops_and_markers_also_after_decode() {
        for t in WRITES {
            assert!(lane_completion_op(&write(t, false)), "{t}");
            assert!(lane_completion_signals(&write(t, false)), "{t}");
            assert!(!lane_completion_op(&write(t, true)), "sop {t}");
        }
        assert!(lane_completion_op(&nop()) && !lane_completion_signals(&nop()));
        assert!(lane_completion_op(&op(MARKER_POP)));
        for t in [
            APR_READ_FILE,
            APR_READ_GATHER,
            APR_READ_SCATTER,
            APR_READ_GATHER_SCATTER,
            APR_RESET_GATHER_SCATTER,
            APR_MAP_BEGIN,
            APR_MAP_DIRECT_BEGIN,
            APR_MAP_END,
            WAIT_ON_ADDRESS,
            WAIT_ON_COUNTER,
            AMM_MAP,
            AMM_UNMAP,
        ] {
            assert!(!lane_completion_op(&op(t)), "{t}");
        }
        // Packed and decoded again, every op keeps its class.
        let mut ops: Vec<Op> = WRITES.iter().map(|&t| write(t, false)).collect();
        ops.extend(WRITES.iter().map(|&t| write(t, true)));
        ops.extend([
            nop(),
            op(MARKER_POP),
            read_file(),
            op(APR_RESET_GATHER_SCATTER),
        ]);
        ops.extend([wait_address(), op(APR_MAP_END)]);
        let (buf, offs) = pack(&ops);
        for (o, &off) in ops.iter().zip(&offs) {
            let (mut d, mut n, mut e) = (Op::default(), 0u32, 0u32);
            let rc = unsafe {
                ampr_decode_apr_packed_op(
                    buf.as_ptr().cast(),
                    buf.len() as u32,
                    off,
                    &mut d,
                    &mut n,
                    &mut e,
                )
            };
            assert_eq!(rc, 0, "{}", o.op_type);
            assert_eq!(d.op_type, o.op_type);
            assert_eq!(
                lane_completion_op(&d),
                lane_completion_op(o),
                "{}",
                o.op_type
            );
        }
    }

    #[test]
    fn tail_qualifies_only_when_every_remaining_command_completes() {
        let eops: Vec<Op> = WRITES.iter().map(|&t| write(t, false)).collect();
        let mut ops = vec![read_file()];
        ops.extend(eops.iter().copied());
        ops.extend([nop(), op(MARKER_POP)]);
        let (buf, offs) = pack(&ops);
        assert_eq!(completion_tail_signals(&buf, offs[1]), Some(6));
        assert_eq!(completion_tail_signals(&buf, offs[6]), Some(1));
        assert_eq!(completion_tail_signals(&buf, offs[7]), Some(0));
        assert_eq!(completion_tail_signals(&buf, 0), None, "read left");
        assert_eq!(
            completion_tail_signals(&buf, buf.len() as u32),
            None,
            "empty"
        );
        // Any read, wait, map, GS reset or SOP write after the EOP rejects it.
        for later in [
            read_file(),
            op(APR_RESET_GATHER_SCATTER),
            wait_address(),
            op(APR_MAP_END),
            write(WRITE_ADDRESS, true),
        ] {
            let (buf, offs) = pack(&[write(WRITE_ADDRESS, false), later]);
            assert_eq!(
                completion_tail_signals(&buf, offs[0]),
                None,
                "{}",
                later.op_type
            );
        }
        // A tail that does not decode is rejected, not trusted.
        let (mut buf, offs) = pack(&[write(WRITE_EQUEUE, false)]);
        buf.truncate(8);
        assert_eq!(completion_tail_signals(&buf, offs[0]), None);
    }

    #[test]
    fn block_kind_and_successor_rules() {
        let eop = write(WRITE_ADDRESS, false);
        assert_eq!(lane_block_kind(Some(&eop), true), LaneBlock::Fence);
        assert_eq!(lane_block_kind(Some(&eop), false), LaneBlock::Other);
        assert_eq!(
            lane_block_kind(Some(&wait_address()), false),
            LaneBlock::Wait
        );
        assert_eq!(
            lane_block_kind(Some(&op(WAIT_ON_COUNTER)), true),
            LaneBlock::Wait
        );
        assert_eq!(lane_block_kind(Some(&read_file()), true), LaneBlock::Other);
        assert_eq!(lane_block_kind(Some(&nop()), true), LaneBlock::Other);
        assert_eq!(lane_block_kind(None, true), LaneBlock::Other);
        // An overlapped successor stays off native, AMM and map state.
        assert!(overlap_successor_op_allowed(WRITE_ADDRESS));
        assert!(overlap_successor_op_allowed(WAIT_ON_ADDRESS));
        for t in [
            WRITE_COUNTER,
            WRITE_EQUEUE,
            WRITE_ADDRESS_FROM_TIME_COUNTER,
            WAIT_ON_COUNTER,
            APR_MAP_BEGIN,
            APR_MAP_END,
            AMM_MAP,
        ] {
            assert!(!overlap_successor_op_allowed(t), "{t}");
        }
    }

    /// One lane job in the ordering model: packed commands (APR reads and
    /// EOP address writes whose value names the EOP), its cursor and reads.
    struct ModelJob {
        ops: Vec<Op>,
        buf: Vec<u8>,
        offs: Vec<u32>,
        pos: usize,
        issued: u32,
        completed: u32,
    }

    /// Runs the lane loop rules of progress.rs/native.rs on a model lane:
    /// a read issues at once; an EOP publishes only with the prior fence and
    /// its own reads clear; the loop passes a job whose source is consumed,
    /// or (overlap on) whose tail passes completion_tail_signals; only the
    /// head is released. One read completes per pass, newest job first.
    /// Returns the published EOP values and the pass at which job 1 issued.
    fn run_lane(jobs: &[&[Op]], overlap: bool) -> (Vec<u64>, usize) {
        let (published, job1Issue) = run_lane_passes(jobs, overlap, false);
        (published.iter().map(|p| p.0).collect(), job1Issue)
    }

    /// run_lane with `cascade` (lane_release_cascades): a head released in a
    /// pass hands the pass to its successor. Returns (EOP value, pass) pairs.
    fn run_lane_passes(jobs: &[&[Op]], overlap: bool, cascade: bool) -> (Vec<(u64, usize)>, usize) {
        let mut lane: Vec<ModelJob> = jobs
            .iter()
            .map(|ops| {
                let (buf, offs) = pack(ops);
                ModelJob {
                    ops: ops.to_vec(),
                    buf,
                    offs,
                    pos: 0,
                    issued: 0,
                    completed: 0,
                }
            })
            .collect();
        let (mut published, mut job1Issue, mut released) = (Vec::new(), usize::MAX, 0usize);
        for pass in 0..1000 {
            if lane.is_empty() {
                return (published, job1Issue);
            }
            let mut prior = false;
            let mut i = 0;
            while i < lane.len() {
                let j = &mut lane[i];
                while let Some(o) = j.ops.get(j.pos) {
                    if o.op_type == APR_READ_FILE {
                        j.issued += 1;
                        if released + i == 1 {
                            job1Issue = job1Issue.min(pass);
                        }
                    } else if !lane_completion_signals(o) {
                        // Nops and markers advance without the fence.
                    } else if prior || j.completed < j.issued {
                        break;
                    } else {
                        published.push((o.u64a, pass));
                    }
                    j.pos += 1;
                }
                let done = j.pos == j.ops.len();
                if i == 0 && done && j.completed == j.issued {
                    lane.remove(0);
                    released += 1;
                    // Only the head is released, so `prior` is still false.
                    assert!(!prior);
                    if cascade {
                        continue;
                    }
                    break;
                }
                let overlapped =
                    !done && overlap && completion_tail_signals(&j.buf, j.offs[j.pos]).is_some();
                if !done && !overlapped {
                    break;
                }
                prior = lane_successor_prior_fence(prior, j.completed < j.issued, overlapped);
                i += 1;
            }
            if let Some(j) = lane.iter_mut().rev().find(|j| j.completed < j.issued) {
                j.completed += 1;
            }
        }
        panic!("lane did not drain");
    }

    fn eop(v: u64) -> Op {
        let mut o = write(WRITE_ADDRESS, false);
        o.u64a = v;
        o
    }

    #[test]
    fn overlap_keeps_eop_order_and_issues_the_successor_read_early() {
        let a = [read_file(), eop(1), eop(2)];
        let b = [read_file(), read_file(), eop(3)];
        let c = [read_file(), eop(4), nop(), eop(5)];
        let jobs: [&[Op]; 3] = [&a, &b, &c];
        let (serial, serialIssue) = run_lane(&jobs, false);
        let (overlapped, overlapIssue) = run_lane(&jobs, true);
        assert_eq!(serial, [1, 2, 3, 4, 5]);
        assert_eq!(overlapped, serial);
        assert_eq!(overlapIssue, 0, "job 1 reads in the head's first pass");
        assert!(serialIssue > overlapIssue, "{serialIssue}");
        // A wait in the head's tail keeps the lane serialized.
        let d = [read_file(), eop(1), wait_address(), eop(2)];
        let (_, waitIssue) = run_lane(&[&d, &b], true);
        assert!(waitIssue > 0);
    }

    /// Successors' reads finish first (the model completes newest first), so
    /// their EOPs wait on lane order. Without the cascade each later job
    /// publishes one pass after its predecessor's release; with it every job
    /// whose reads are done publishes in the head's pass, still in order,
    /// up to the first successor still reading.
    #[test]
    fn release_cascade_publishes_ready_successors_in_order() {
        let a = [read_file(), eop(1), eop(2)];
        let b = [read_file(), eop(3)];
        let c = [read_file(), eop(4), nop(), eop(5)];
        let jobs: [&[Op]; 3] = [&a, &b, &c];
        let (stepped, _) = run_lane_passes(&jobs, true, false);
        let (cascaded, _) = run_lane_passes(&jobs, true, true);
        let values = |p: &[(u64, usize)]| p.iter().map(|e| e.0).collect::<Vec<_>>();
        assert_eq!(values(&stepped), [1, 2, 3, 4, 5]);
        assert_eq!(values(&cascaded), [1, 2, 3, 4, 5]);
        let headPass = cascaded[0].1;
        assert!(cascaded.iter().all(|e| e.1 == headPass), "{cascaded:?}");
        assert_eq!(stepped[0].1, headPass, "the head itself is not delayed");
        assert_eq!(stepped[2].1, headPass + 1);
        assert_eq!(stepped[4].1, headPass + 2);
        // Serial lanes (overlap off) are unchanged by the cascade.
        let (serial, _) = run_lane_passes(&jobs, false, false);
        let (serialCascade, _) = run_lane_passes(&jobs, false, true);
        assert_eq!(values(&serial), values(&serialCascade));

        // The cascade stops at the first successor whose own reads are
        // still in flight: its EOP waits for its reads, and a later job
        // never publishes before it. b issues its second read only after
        // eop(2), so the cascade from a reaches b while that read is in flight.
        let a = [read_file(), eop(1)];
        let b = [read_file(), eop(2), read_file(), eop(3)];
        let c = [read_file(), eop(4)];
        let jobs: [&[Op]; 3] = [&a, &b, &c];
        let (cascaded, _) = run_lane_passes(&jobs, true, true);
        assert_eq!(values(&cascaded), [1, 2, 3, 4]);
        let pass = |v: u64| cascaded.iter().find(|e| e.0 == v).unwrap().1;
        assert_eq!(pass(2), pass(1), "b's first EOP rides the cascade");
        assert!(pass(3) > pass(2), "b's second EOP waits for its own read");
        assert!(pass(4) >= pass(3), "c never publishes before b");
    }
}
