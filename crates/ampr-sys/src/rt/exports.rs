//! Public PRX surface: module_start/module_stop and the 118 sceAmpr* exports.
//! The export layer is stateless: every export forwards to the leaves in
//! rt/amm.rs, rt/command_buffer.rs, rt/equeue.rs, rt/pack and rt/reactor.
//!
//! Layout:
//! 1. helpers (`rc32`, measure helpers) and SDK imports
//! 2. module_start / module_stop
//! 3. sceAmprAmm* (command-buffer appends, leaves, measures)
//! 4. sceAmprCommandBuffer* (header, wait/write/nop/marker)
//! 5. sceAmprAprCommandBuffer*
//! 6. sceAmprMeasureCommandSize*
//!
//! Symbol names and argument order are the retail ABI (see
//! tools/generate_payload_exports.py, which discovers sceAmpr* via nm).
//! `self` is `this` for command-buffer member exports; retail returns 32-bit
//! SDK error codes zero-extended in a 64-bit register (`rc32`).
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;

use ampr_command::{op_type::*, OpRecord, SceAmprCommandBuffer as Cb};

use super::sys::{
    off_t, SceAmmResultBuffer, SceAmmSubmitId, SceAprFileId, SceKernelEqueue,
    SCE_KERNEL_ERROR_EINVAL as EINVAL, SCE_KERNEL_ERROR_EPERM as EPERM,
};
use super::{amm, command_buffer as cb, equeue, hook};

use super::pack::ampr_pack_shutdown;
use super::reactor::apr_reactor_shutdown;

#[inline]
fn rc32(rc: c_int) -> i64 {
    rc as u32 as i64
}

fn op(op_type: u8) -> OpRecord {
    OpRecord {
        op_type,
        ..OpRecord::default()
    }
}

/// `ampr_measure_op`: packed byte size, or the rc32 error.
fn measure_op(op: OpRecord) -> i64 {
    let mut bytes = 0u32;
    let rc = unsafe { cb::ampr_op_size_bytes_checked(&op, &mut bytes) };
    if rc == 0 {
        bytes as i64
    } else {
        rc32(rc)
    }
}

unsafe fn measure_marker(op_type: u8, msg: *const c_char, with_color: bool) -> i64 {
    let mut o = op(op_type);
    o.u32b = with_color as u32;
    if !unsafe { cb::ampr_set_marker_text(&mut o, msg) } {
        return rc32(EINVAL);
    }
    measure_op(o)
}

fn measure_einval() -> i64 {
    rc32(EINVAL)
}

// ---- module entry --------------------------------------------------------

/// Runtime version, from the crate (Cargo.toml `version`).
const VERSION: &str = env!("CARGO_PKG_VERSION");
/// Runtime identity, "ampr-emu-ng <version>": pack tools read it to
/// tell this runtime and its version from upstream ampr_emu builds.
#[used]
static AMPR_EMU_VERSION: [u8; IDENTITY.len()] = IDENTITY;
const IDENTITY: [u8; 12 + VERSION.len() + 1] = {
    let mut out = [0u8; 12 + VERSION.len() + 1];
    let (name, ver) = (b"ampr-emu-ng ", VERSION.as_bytes());
    let mut i = 0;
    while i < name.len() {
        out[i] = name[i];
        i += 1;
    }
    let mut j = 0;
    while j < ver.len() {
        out[name.len() + j] = ver[j];
        j += 1;
    }
    out
};

/// Layout from ps5-payload-sdk samples/hello_world: message at offset 45.
#[repr(C)]
struct NotifyRequest {
    head: [u8; 45],
    message: [u8; 3075],
}

extern "C" {
    fn sceKernelSendNotificationRequest(
        device: c_int,
        req: *mut NotifyRequest,
        size: usize,
        blocking: c_int,
    ) -> c_int;
}

/// Best effort system notification; errors are ignored.
unsafe fn notify(text: &[u8]) {
    let mut req = NotifyRequest {
        head: [0; 45],
        message: [0; 3075],
    };
    let len = text.len().min(req.message.len() - 1);
    req.message[..len].copy_from_slice(&text[..len]);
    let _ = unsafe { sceKernelSendNotificationRequest(0, &mut req, size_of::<NotifyRequest>(), 0) };
}

/// "ampr-emu-ng: v0.1.0 (zstd) running" into `out`; its length.
fn load_notice(zstd: bool, out: &mut [u8; 64]) -> usize {
    let mode: &[u8] = if zstd { b"zstd" } else { b"lz4" };
    let mut n = 0;
    for part in [
        b"ampr-emu-ng: v" as &[u8],
        VERSION.as_bytes(),
        b" (",
        mode,
        b") running",
    ] {
        out[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    n
}

/// Tells the owner the module runs; also keeps AMPR_EMU_VERSION linked.
unsafe fn notify_loaded() {
    let _ = unsafe { core::ptr::read_volatile(&raw const AMPR_EMU_VERSION) };
    let mut text = [0u8; 64];
    let n = load_notice(super::pack::zstd_mode(), &mut text);
    unsafe { notify(&text[..n]) };
}

#[cfg(test)]
mod notice_tests {
    #[test]
    fn notice_names_version_and_format() {
        let mut out = [0u8; 64];
        let n = super::load_notice(true, &mut out);
        assert_eq!(&out[..n], b"ampr-emu-ng: v0.1.0 (zstd) running");
        let n = super::load_notice(false, &mut out);
        assert_eq!(&out[..n], b"ampr-emu-ng: v0.1.0 (lz4) running");
        assert_eq!(&super::IDENTITY, b"ampr-emu-ng 0.1.0\0");
    }
}

/// Debug build (`make AMPR_MEM_REPORT=1`): a low-priority thread serves the
/// internal pool usage and rt/stats.rs counters as plain text over TCP
/// (`GET /metrics` on port METRICS_PORT, one client at a time). Counters are
/// totals since load; `*_max` values reset on each scrape. `GET /set?k=v&...`
/// changes rt/tune.rs knobs (no arguments: list them). No release impact.
#[cfg(feature = "mem_report")]
mod mem_report {
    use super::super::pack::{
        bench_volume_path, real_aio_delete_single, real_aio_submit_single, real_aio_wait_single,
        SceKernelAioRWRequest, SceKernelAioResult, SceKernelAioSubmitId,
    };
    use super::super::runtime_memory::{ampr_internal_amm_pool_alloc, ampr_internal_amm_pool_free};
    use super::super::runtime_memory::{pool_tags, pool_usage, TagTotals};
    use super::super::stats::{read, NAMES};
    use super::super::sys::{
        errno, monotonic_ns, off_t, real_physical_close, real_physical_pread, real_posix_open,
        sceKernelUsleep, sce_errno, SceKernelUseconds, SCE_KERNEL_ERROR_ETIMEDOUT,
    };
    use super::super::tune;
    use core::ffi::{c_char, c_int, c_void};

    pub(super) const METRICS_PORT: u16 = 9090;

    extern "C" {
        fn scePthreadCreate(
            thread: *mut *mut c_void,
            attr: *const *mut c_void,
            entry: unsafe extern "C" fn(*mut c_void) -> *mut c_void,
            arg: *mut c_void,
            name: *const c_char,
        ) -> c_int;
        fn socket(domain: c_int, kind: c_int, protocol: c_int) -> c_int;
        fn setsockopt(
            fd: c_int,
            level: c_int,
            name: c_int,
            value: *const c_void,
            len: u32,
        ) -> c_int;
        fn bind(fd: c_int, addr: *const SockAddrIn, len: u32) -> c_int;
        fn listen(fd: c_int, backlog: c_int) -> c_int;
        fn accept(fd: c_int, addr: *mut c_void, len: *mut u32) -> c_int;
        fn recv(fd: c_int, buf: *mut c_void, len: usize, flags: c_int) -> isize;
        fn send(fd: c_int, buf: *const c_void, len: usize, flags: c_int) -> isize;
    }

    // FreeBSD socket ABI.
    const AF_INET: u8 = 2;
    const SOCK_STREAM: c_int = 1;
    const SOL_SOCKET: c_int = 0xffff;
    const SO_REUSEADDR: c_int = 0x0004;

    #[repr(C)]
    struct SockAddrIn {
        len: u8,
        family: u8,
        port: u16,
        addr: u32,
        zero: [u8; 8],
    }
    const _: () = assert!(size_of::<SockAddrIn>() == 16);

    /// Fixed-capacity text buffer; output past the end is dropped.
    struct Text {
        buf: [u8; 4096],
        len: usize,
    }

    impl Text {
        fn s(&mut self, s: &[u8]) -> &mut Self {
            let n = s.len().min(self.buf.len() - self.len);
            self.buf[self.len..self.len + n].copy_from_slice(&s[..n]);
            self.len += n;
            self
        }
        fn u(&mut self, mut v: u64) -> &mut Self {
            let mut d = [0u8; 20];
            let mut n = 0;
            loop {
                d[n] = b'0' + (v % 10) as u8;
                n += 1;
                v /= 10;
                if v == 0 {
                    break;
                }
            }
            d[..n].reverse();
            self.s(&d[..n])
        }
        fn kv(&mut self, k: &str, v: u64) -> &mut Self {
            self.s(k.as_bytes()).s(b" ").u(v).s(b"\n")
        }
        fn x(&mut self, v: u32) -> &mut Self {
            let mut d = *b"0x00000000";
            for (i, c) in d[2..].iter_mut().enumerate() {
                *c = b"0123456789abcdef"[(v >> (28 - 4 * i) as u32) as usize & 15];
            }
            self.s(&d)
        }
    }

    const KIB: usize = 1024;
    const MIB: usize = 1024 * KIB;
    const QD_MAX: usize = 8;
    /// (bytes, requests, elapsed ns) or an SCE error code.
    type BenchResult = Result<(u64, u64, u64), c_int>;

    /// Sequential single-thread pread of `bytes` from `off` in `req` chunks.
    unsafe fn bench_pread(
        fd: c_int,
        buf: *mut u8,
        req: usize,
        off: u64,
        bytes: u64,
    ) -> BenchResult {
        let (t0, mut done, mut reqs) = (monotonic_ns(), 0u64, 0u64);
        while done < bytes {
            let n = (bytes - done).min(req as u64) as usize;
            let r = unsafe { real_physical_pread(fd, buf.cast(), n, (off + done) as off_t) };
            if r <= 0 {
                return Err(if r < 0 {
                    sce_errno(errno())
                } else {
                    sce_errno(0)
                });
            }
            done += r as u64;
            reqs += 1;
        }
        Ok((done, reqs, monotonic_ns().saturating_sub(t0)))
    }

    /// Kernel AIO with up to `qd` single-request submits in flight (FIFO).
    unsafe fn bench_aio(
        fd: c_int,
        buf: *mut u8,
        req: usize,
        off: u64,
        bytes: u64,
        qd: usize,
    ) -> BenchResult {
        let (Some(submit), Some(wait), Some(delete)) = (unsafe {
            (
                real_aio_submit_single(),
                real_aio_wait_single(),
                real_aio_delete_single(),
            )
        }) else {
            return Err(0);
        };
        let mut rq = [SceKernelAioRWRequest::EMPTY; QD_MAX];
        let mut res = [SceKernelAioResult::EMPTY; QD_MAX];
        let mut ids = [0 as SceKernelAioSubmitId; QD_MAX];
        let (t0, mut issued, mut done, mut reqs) = (monotonic_ns(), 0u64, 0u64, 0u64);
        let (mut head, mut inflight, mut err) = (0usize, 0usize, 0 as c_int);
        loop {
            while err == 0 && inflight < qd && issued < bytes {
                let s = (head + inflight) % qd;
                let n = (bytes - issued).min(req as u64) as usize;
                res[s] = SceKernelAioResult::EMPTY;
                rq[s] = SceKernelAioRWRequest {
                    offset: (off + issued) as off_t,
                    nbyte: n,
                    buf: unsafe { buf.add(s * req) }.cast(),
                    result: &raw mut res[s],
                    fd,
                };
                let rc = unsafe { submit(&raw mut rq[s], 1, 0, &raw mut ids[s]) };
                if rc != 0 {
                    err = rc;
                    break;
                }
                issued += n as u64;
                inflight += 1;
            }
            if inflight == 0 {
                break;
            }
            // Never return with a request in flight: `res` lives on this stack.
            let mut state = 0;
            let rc = loop {
                let mut usec: SceKernelUseconds = 1_000_000;
                let rc = unsafe { wait(ids[head], &mut state, &mut usec) };
                if rc != SCE_KERNEL_ERROR_ETIMEDOUT {
                    break rc;
                }
            };
            let _ = unsafe { delete(ids[head], &mut state) };
            let rv = res[head].return_value;
            if err == 0 && rc != 0 {
                err = rc;
            } else if err == 0 && rv <= 0 {
                err = if rv < 0 { rv as c_int } else { sce_errno(0) };
            }
            done += rv.max(0) as u64;
            reqs += 1;
            head = (head + 1) % qd;
            inflight -= 1;
        }
        if err != 0 {
            Err(err)
        } else {
            Ok((done, reqs, monotonic_ns().saturating_sub(t0)))
        }
    }

    /// GET /bench: raw read speed of pack volume 0 through the unhooked kernel
    /// calls. Each test reads its own 64 KiB aligned region so earlier tests do
    /// not warm the OS cache for later ones. Blocks only the metrics thread.
    unsafe fn bench(out: &mut Text) {
        let mut path = [0u8; 1024];
        let Some((len, size)) = (unsafe { bench_volume_path(&mut path) }) else {
            out.s(b"bench: manifest not ready\n");
            return;
        };
        if len >= path.len() {
            out.s(b"bench: path too long\n");
            return;
        }
        path[len] = 0;
        out.s(b"bench path=")
            .s(&path[..len])
            .s(b" file_size=")
            .u(size)
            .s(b"\n");
        let (mut cap, mut got, mut buf) = (8 * MIB, 0usize, core::ptr::null_mut::<c_void>());
        while cap >= 256 * KIB {
            buf = unsafe {
                ampr_internal_amm_pool_alloc(cap, &mut got, c"bench".as_ptr(), false, 16 * KIB)
            };
            if !buf.is_null() {
                break;
            }
            cap /= 2;
        }
        if buf.is_null() {
            out.s(b"bench: buffer alloc failed\n");
            return;
        }
        let fd = unsafe { real_posix_open(path.as_ptr().cast(), 0, 0) };
        if fd < 0 {
            out.s(b"bench open error rc=")
                .x(sce_errno(errno()) as u32)
                .s(b"\n");
        } else {
            const TESTS: [(&str, usize, usize); 5] = [
                ("pread_256k", 256 * KIB, 0),
                ("pread_1m", MIB, 0),
                ("pread_4m", 4 * MIB, 0),
                ("aio_256k_qd1", 256 * KIB, 1),
                ("aio_256k_qd8", 256 * KIB, 8),
            ];
            let stride = (size / TESTS.len() as u64) & !(64 * KIB as u64 - 1);
            let bytes = if stride == 0 {
                size
            } else {
                stride.min(32 * MIB as u64)
            };
            for (i, &(name, req, qd)) in TESTS.iter().enumerate() {
                let (off, req) = (i as u64 * stride, req.min(cap / qd.max(1)));
                let r = if qd == 0 {
                    unsafe { bench_pread(fd, buf.cast(), req, off, bytes) }
                } else {
                    unsafe { bench_aio(fd, buf.cast(), req, off, bytes, qd) }
                };
                match r {
                    Ok((b, n, ns)) => {
                        let ns = ns.max(1);
                        out.s(b"bench ")
                            .s(name.as_bytes())
                            .s(b" MBps=")
                            .u(b.saturating_mul(1000) / ns)
                            .s(b" us_per_req=")
                            .u(ns / n.max(1) / 1000)
                            .s(b" bytes=")
                            .u(b)
                            .s(b"\n");
                    }
                    Err(0) => {
                        out.s(b"aio: unavailable\n");
                        break;
                    }
                    Err(rc) => {
                        out.s(b"bench ")
                            .s(name.as_bytes())
                            .s(b" error rc=")
                            .x(rc as u32)
                            .s(b"\n");
                    }
                }
            }
            let _ = unsafe { real_physical_close(fd) };
        }
        let _ = unsafe { ampr_internal_amm_pool_free(buf, c"bench".as_ptr()) };
    }

    fn body(start_ns: u64, out: &mut Text) {
        let (used, peak, size) = pool_usage();
        out.kv("uptime_ns", monotonic_ns().saturating_sub(start_ns))
            .kv("pool_used_bytes", used as u64)
            .kv("pool_peak_bytes", peak as u64)
            .kv("pool_size_bytes", size as u64)
            // Live gauges: physical reads in flight, open fds, pack load state.
            .kv(
                "disk_inflight",
                super::super::pack::PACK_DISK_INFLIGHT.load(core::sync::atomic::Ordering::Relaxed)
                    as u64,
            )
            .kv(
                "fd_direct_open",
                super::super::fd_cache::ampr_index_fd_direct_open_count() as u64,
            )
            .kv(
                "fd_pack_open",
                super::super::fd_cache::ampr_index_fd_pack_open_count() as u64,
            )
            .kv(
                "pack_load_state",
                super::super::pack::LOAD_STATE.load(core::sync::atomic::Ordering::Relaxed) as u64,
            );
        for (name, v) in NAMES.iter().zip(read()) {
            out.kv(name, v);
        }
        {
            use super::super::stats::{FS_EVENTS, FS_LOG};
            let log = unsafe { &*FS_LOG.get() };
            let n = log.next.min(FS_EVENTS);
            for k in 0..n {
                let slot = (log.next - n + k) % FS_EVENTS;
                out.s(b"fs ")
                    .s(&[log.op[slot], b' ', log.how[slot], b' '])
                    .x(log.rc[slot] as u32)
                    .s(b" ")
                    .s(&log.path[slot][..log.len[slot]])
                    .s(b"\n");
            }
            out.kv("hooks_installed_lo", super::super::hook::installed_bits(0))
                .kv("hooks_installed_hi", super::super::hook::installed_bits(64));
        }
        // What the pack runtime actually got at startup (caches may be halved
        // when the pool is short), then the knobs as set now.
        let state = super::super::pack::g_pack_state.load(core::sync::atomic::Ordering::Acquire);
        if !state.is_null() {
            // Raw place reads only: other threads mutate PackState, so no
            // reference to it is formed (see `pack_state()`).
            let s = state;
            unsafe {
                out.kv("pack_decoded_cache_bytes", (*s).cache_bytes as u64)
                    .kv(
                        "pack_physical_cache_bytes",
                        (*s).physical_cache_bytes as u64,
                    )
                    .kv("pack_workers", (*s).workers_started as u64)
                    .kv("pack_pipelines", (*s).pipeline_capacity as u64);
            }
        }
        tune_lines(b"tune_", out);
        let (now, peak) = pool_tags();
        tag_lines(b"pool_now:", &now, out);
        tag_lines(b"pool_peak:", &peak, out);
    }

    fn tune_lines(prefix: &[u8], out: &mut Text) {
        for knob in tune::KNOBS.iter() {
            out.s(prefix)
                .s(knob.name.as_bytes())
                .s(b" ")
                .u(tune::value(knob) as u64)
                .s(b"\n");
        }
    }

    fn tag_lines(prefix: &[u8], tags: &TagTotals, out: &mut Text) {
        for &(tag, bytes) in tags.iter().filter(|t| t.1 != 0) {
            let name = if tag.is_null() {
                b"slab" as &[u8]
            } else {
                unsafe { core::ffi::CStr::from_ptr(tag) }.to_bytes()
            };
            out.s(prefix).s(name).s(b" ").u(bytes as u64).s(b"\n");
        }
    }

    /// `GET /set?k=v&...`: applies the pairs, saves the knob file, lists knobs.
    unsafe fn set(req: &[u8], out: &mut Text) {
        let line = req
            .split(|&c| c == b'\r' || c == b'\n')
            .next()
            .unwrap_or(&[]);
        let target = line.split(|&c| c == b' ').nth(1).unwrap_or(&[]);
        let query = match target.iter().position(|&c| c == b'?') {
            Some(q) => &target[q + 1..],
            None => &[],
        };
        if !query.is_empty() {
            if let Err(bad) = tune::apply(query) {
                out.s(b"error: bad pair '")
                    .s(bad)
                    .s(b"' (later pairs not applied)\n");
            }
            if !unsafe { tune::save() } {
                out.s(b"error: could not write ")
                    .s(tune::TUNE_PATH.to_bytes())
                    .s(b"\n");
            }
        }
        out.s(b"knobs (").s(tune::TUNE_PATH.to_bytes()).s(b"):\n");
        for knob in tune::KNOBS.iter() {
            out.s(knob.name.as_bytes())
                .s(b"=")
                .u(tune::value(knob) as u64);
            out.s(b" [")
                .u(knob.min as u64)
                .s(b"..")
                .u(knob.max as u64)
                .s(b"] ");
            out.s(if knob.live {
                b"live\n" as &[u8]
            } else {
                b"next launch\n"
            });
        }
        out.s(b"profile=low|medium|high sets decoded_mib, physical_mib, workers, pipelines, reserve_mib\n");
    }

    unsafe fn serve(listener: c_int, start_ns: u64) -> ! {
        loop {
            let client = unsafe { accept(listener, core::ptr::null_mut(), core::ptr::null_mut()) };
            if client < 0 {
                unsafe { sceKernelUsleep(100_000) };
                continue;
            }
            // "GET /bench" runs the read benchmark; anything else gets the metrics.
            let mut req = [0u8; 512];
            let n = unsafe { recv(client, req.as_mut_ptr().cast(), req.len(), 0) };
            let mut text = Text {
                buf: [0; 4096],
                len: 0,
            };
            let mut metrics = Text {
                buf: [0; 4096],
                len: 0,
            };
            if n > 0 && req[..n as usize].starts_with(b"GET /bench") {
                unsafe { bench(&mut metrics) };
            } else if n > 0 && req[..n as usize].starts_with(b"GET /set") {
                unsafe { set(&req[..n as usize], &mut metrics) };
            } else {
                body(start_ns, &mut metrics);
            }
            text.s(b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ")
                .u(metrics.len as u64)
                .s(b"\r\nConnection: close\r\n\r\n")
                .s(&metrics.buf[..metrics.len]);
            let mut sent = 0;
            while sent < text.len {
                let n =
                    unsafe { send(client, text.buf[sent..].as_ptr().cast(), text.len - sent, 0) };
                if n <= 0 {
                    break;
                }
                sent += n as usize;
            }
            let _ = unsafe { real_physical_close(client) };
        }
    }

    unsafe extern "C" fn run(_: *mut c_void) -> *mut c_void {
        let start_ns = monotonic_ns();
        // Let module_start finish (hook slots used by close) before serving.
        unsafe { sceKernelUsleep(1_000_000) };
        let fd = unsafe { socket(AF_INET as c_int, SOCK_STREAM, 0) };
        let one: c_int = 1;
        let addr = SockAddrIn {
            len: 16,
            family: AF_INET,
            port: METRICS_PORT.to_be(),
            addr: 0,
            zero: [0; 8],
        };
        let ok = fd >= 0
            && unsafe { setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (&raw const one).cast(), 4) } >= 0
            && unsafe { bind(fd, &addr, 16) } >= 0
            && unsafe { listen(fd, 4) } >= 0;
        if !ok {
            if fd >= 0 {
                let _ = unsafe { real_physical_close(fd) };
            }
            unsafe { super::notify(b"AMPR metrics: could not open TCP port 9090") };
            return core::ptr::null_mut();
        }
        unsafe { super::notify(b"AMPR metrics: listening on TCP port 9090 (GET /metrics, /set)") };
        unsafe { serve(fd, start_ns) }
    }

    pub(super) unsafe fn start() {
        let mut thread = core::ptr::null_mut();
        let _ = unsafe {
            scePthreadCreate(
                &mut thread,
                core::ptr::null(),
                run,
                core::ptr::null_mut(),
                c"ampr_metrics".as_ptr(),
            )
        };
    }
}

#[no_mangle]
pub unsafe extern "C" fn module_start(_args: usize, _argp: *const c_void) -> c_int {
    // Before any hook: the mode picks the hooks and the notification text.
    unsafe { super::pack::select_pack_format() };
    unsafe { notify_loaded() };
    let rc = unsafe { hook::amprInstallLibkernelHooks() };
    // zstd: most game files exist only inside ampr_zstd-NNN.pak, and the game
    // opens some (e.g. its UE project descriptor) with plain open() before
    // any AMPR call. Hooks never load the index, so load AMPRIDX3, mount
    // ampr_zstd.index and build the id projection here, before the game runs.
    if super::pack::zstd_mode() && rc == 0 && unsafe { super::index::ensure_ready(false) } {
        unsafe { super::pack::ampr_pack_ensure_manifest_ready_safe() };
    }
    // Only after hooks install: a failed module_start may be unloaded.
    #[cfg(feature = "mem_report")]
    if rc == 0 {
        unsafe { mem_report::start() };
    }
    rc
}

#[no_mangle]
pub unsafe extern "C" fn module_stop(_args: usize, _argp: *const c_void) -> c_int {
    if unsafe { ampr_pack_shutdown() } != 0 || unsafe { apr_reactor_shutdown() } != 0 {
        return -1;
    }
    // shutdownCommandLog/shutdownDebugLog are no-ops returning 0.
    unsafe { hook::amprUninstallLibkernelHooks() }
}

// ---- sceAmprAmm* ---------------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn sceAmprAmmCommandBufferConstructor(this: *mut Cb) -> i64 {
    unsafe { equeue::apr_equeue_register_amm_command_buffer(this.cast()) };
    0
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprAmmCommandBufferDestructor(this: *mut Cb) -> i64 {
    unsafe { equeue::apr_equeue_unregister_amm_command_buffer(this.cast()) };
    0
}

/// `this->method(args)` forwards on the AmmCommandBuffer header.
macro_rules! amm_cb {
    ($($name:ident => $f:ident($($a:ident: $t:ty),*);)*) => {$(
        #[no_mangle]
        pub unsafe extern "C" fn $name(this: *mut Cb, $($a: $t),*) -> i64 {
            rc32(unsafe { amm::$f(this, $($a),*) })
        }
    )*};
}

amm_cb! {
    sceAmprAmmCommandBufferMap => ampr_amm_cb_map(va: u64, size: u64, ty: c_int, prot: c_int);
    sceAmprAmmCommandBufferMapWithGpuMaskId => ampr_amm_cb_map_with_gpu_mask_id(va: u64, size: u64, ty: c_int, prot: c_int, gpu: u8);
    sceAmprAmmCommandBufferMapDirect => ampr_amm_cb_map_direct(va: u64, dmem: u64, size: usize, ty: c_int, prot: c_int);
    sceAmprAmmCommandBufferMapDirectWithGpuMaskId => ampr_amm_cb_map_direct_with_gpu_mask_id(va: u64, dmem: u64, size: u64, ty: c_int, prot: c_int, gpu: u8);
    sceAmprAmmCommandBufferUnmap => ampr_amm_cb_unmap(va: u64, size: usize);
    sceAmprAmmCommandBufferRemap => ampr_amm_cb_remap(va_new: u64, va_old: u64, size: u64, prot: c_int);
    sceAmprAmmCommandBufferRemapWithGpuMaskId => ampr_amm_cb_remap_with_gpu_mask_id(va_new: u64, va_old: u64, size: u64, prot: c_int, gpu: u8);
    sceAmprAmmCommandBufferMultiMap => ampr_amm_cb_multi_map(va: u64, va_alias: u64, size: u64, prot: c_int);
    sceAmprAmmCommandBufferMultiMapWithGpuMaskId => ampr_amm_cb_multi_map_with_gpu_mask_id(va: u64, va_alias: u64, size: u64, prot: c_int, gpu: u8);
    sceAmprAmmCommandBufferModifyProtect => ampr_amm_cb_modify_protect(va: u64, size: u64, prot: c_int, mask: c_int);
    sceAmprAmmCommandBufferModifyProtectWithGpuMaskId => ampr_amm_cb_modify_protect_with_gpu_mask_id(va: u64, size: u64, prot: c_int, mask: c_int, gpu: u8);
    sceAmprAmmCommandBufferModifyMtypeProtect => ampr_amm_cb_modify_mtype_protect(va: u64, size: u64, ty: c_int, prot: c_int, mask: c_int);
    sceAmprAmmCommandBufferModifyMtypeProtectWithGpuMaskId => ampr_amm_cb_modify_mtype_protect_with_gpu_mask_id(va: u64, size: u64, ty: c_int, prot: c_int, mask: c_int, gpu: u8);
    sceAmprAmmCommandBufferMapAsPrt => ampr_amm_cb_map_as_prt(va: u64, size: u64);
    sceAmprAmmCommandBufferAllocatePaForPrt => ampr_amm_cb_allocate_pa_for_prt(va: u64, size: u64, ty: c_int, prot: c_int);
    sceAmprAmmCommandBufferRemapIntoPrt => ampr_amm_cb_remap_into_prt(va_prt: u64, va_old: u64, size: u64, prot: c_int, opcode: u32);
    sceAmprAmmCommandBufferUnmapToPrt => ampr_amm_cb_unmap_to_prt(va: u64, size: u64);
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprAmmGetVirtualAddressRanges(
    va_start: *mut u64,
    va_end: *mut u64,
    mm_start: *mut u64,
    mm_end: *mut u64,
) -> i64 {
    rc32(unsafe { amm::ammGetVirtualAddressRangesLeaf(va_start, va_end, mm_start, mm_end) })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprAmmGiveDirectMemory(
    start: off_t,
    end: off_t,
    size: usize,
    align: usize,
    usage: c_int,
    dmem_offset: *mut off_t,
) -> i64 {
    rc32(unsafe { amm::ammGiveDirectMemory(start, end, size, align, usage, dmem_offset) })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprAmmSubmitCommandBuffer(base: u64, offset: u32, prio: u32) -> i64 {
    rc32(unsafe { amm::ammSubmitCommandBufferLeaf(base, offset, prio, null_mut()) })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprAmmSubmitCommandBuffer2(
    base: u64,
    offset: u32,
    prio: u32,
    result: *mut SceAmmResultBuffer,
    id: *mut SceAmmSubmitId,
) -> i64 {
    rc32(unsafe { amm::ammSubmitCommandBufferAndGetResultLeaf(base, offset, prio, result, id) })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprAmmSubmitCommandBuffer3(
    base: u64,
    offset: u32,
    prio: u32,
    id: *mut SceAmmSubmitId,
) -> i64 {
    rc32(unsafe { amm::ammSubmitCommandBufferLeaf(base, offset, prio, id) })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprAmmWaitCommandBufferCompletion(id: SceAmmSubmitId) -> i64 {
    rc32(unsafe { amm::ammWaitCommandBufferCompletion(id) })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprAmmGetUsageStatsData(data: *mut u64) -> i64 {
    rc32(unsafe { amm::mapperGetUsageStatsData(data) })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprAmmSetPageTablePoolOccupancyNotificationThreshold(
    threshold: c_int,
) -> i64 {
    rc32(unsafe { amm::mapperSetPageTablePoolOccupancyNotificationThreshold(threshold) })
}

/// Measures return the int as-is, sign-extended (no rc32).
macro_rules! amm_measure {
    ($($name:ident => $f:ident($($a:ident: $t:ty),*);)*) => {$(
        #[no_mangle]
        pub unsafe extern "C" fn $name($($a: $t),*) -> i64 {
            unsafe { amm::$f($($a),*) as i64 }
        }
    )*};
}

amm_measure! {
    sceAmprAmmMeasureAmmCommandSizeMap => measureAmmMap(va: u64, size: u64, ty: c_int, prot: c_int);
    sceAmprAmmMeasureAmmCommandSizeMapDirect => measureAmmMapDirect(va: u64, dmem: u64, size: usize, ty: c_int, prot: c_int);
    sceAmprAmmMeasureAmmCommandSizeMapWithGpuMaskId => measureAmmMapWithGpuMaskId(va: u64, size: u64, ty: c_int, prot: c_int, gpu: u8);
    sceAmprAmmMeasureAmmCommandSizeMapDirectWithGpuMaskId => measureAmmMapDirectWithGpuMaskId(va: u64, dmem: u64, size: u64, ty: c_int, prot: c_int, gpu: u8);
    sceAmprAmmMeasureAmmCommandSizeUnmap => measureAmmUnmap(va: u64, size: usize);
    sceAmprAmmMeasureAmmCommandSizeRemap => measureAmmRemap(va_new: u64, va_old: u64, size: u64, prot: c_int);
    sceAmprAmmMeasureAmmCommandSizeRemapWithGpuMaskId => measureAmmRemapWithGpuMaskId(va_new: u64, va_old: u64, size: u64, prot: c_int, gpu: u8);
    sceAmprAmmMeasureAmmCommandSizeMultiMap => measureAmmMultiMap(va: u64, va_alias: u64, size: u64, prot: c_int);
    sceAmprAmmMeasureAmmCommandSizeMultiMapWithGpuMaskId => measureAmmMultiMapWithGpuMaskId(va: u64, va_alias: u64, size: u64, prot: c_int, gpu: u8);
    sceAmprAmmMeasureAmmCommandSizeModifyProtect => measureAmmModifyProtect(va: u64, size: u64, prot: c_int, mask: c_int);
    sceAmprAmmMeasureAmmCommandSizeModifyMtypeProtect => measureAmmModifyMtypeProtect(va: u64, size: u64, ty: c_int, prot: c_int, mask: c_int);
    sceAmprAmmMeasureAmmCommandSizeModifyProtectWithGpuMaskId => measureAmmModifyProtectWithGpuMaskId(va: u64, size: u64, prot: c_int, mask: c_int, gpu: u8);
    sceAmprAmmMeasureAmmCommandSizeModifyMtypeProtectWithGpuMaskId => measureAmmModifyMtypeProtectWithGpuMaskId(va: u64, size: u64, ty: c_int, prot: c_int, mask: c_int, gpu: u8);
    sceAmprAmmMeasureAmmCommandSizeMapAsPrt => measureAmmMapAsPrt(va: u64, size: u64);
    sceAmprAmmMeasureAmmCommandSizeAllocatePaForPrt => measureAmmAllocatePaForPrt(va: u64, size: u64, ty: c_int, prot: c_int);
}

// ---- sceAmprCommandBuffer* ------------------------------------------------

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferConstructor(this: *mut Cb) -> i64 {
    // Retail clears only the 24-byte header.
    if !this.is_null() {
        unsafe {
            this.write(Cb {
                r#type: 0,
                offset: 0,
                num: 0,
                bufsize: 0,
                buffer: null_mut(),
            })
        };
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferDestructor(_this: *mut Cb) -> i64 {
    0
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferReset(this: *mut Cb) -> i64 {
    rc32(if this.is_null() {
        EPERM
    } else {
        unsafe { cb::ampr_cb_reset(this) }
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferSetBuffer(
    this: *mut Cb,
    buffer: *mut c_void,
    size: u32,
) -> i64 {
    rc32(if this.is_null() {
        EINVAL
    } else {
        unsafe { cb::ampr_cb_set_buffer(this, buffer, size) }
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferClearBuffer(this: *mut Cb) -> i64 {
    unsafe { cb::ampr_cb_clear_buffer(this) as i64 }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferGetType(this: *mut Cb) -> i64 {
    unsafe { (*this).r#type as i64 }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferGetSize(this: *mut Cb) -> i64 {
    unsafe { (*this).bufsize as i64 }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferGetBufferBaseAddress(this: *mut Cb) -> i64 {
    unsafe { (*this).buffer as i64 }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferGetNumCommands(this: *mut Cb) -> i64 {
    unsafe { core::ptr::addr_of!((*this).num).read_volatile() as u32 as i64 }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferGetCurrentOffset(this: *mut Cb) -> i64 {
    unsafe { (*this).offset as i64 }
}

/// `this->method(args)` forwards on the CommandBuffer header; `expr` builds
/// the leaf argument list after `this`.
macro_rules! cb_fwd {
    ($($name:ident($($a:ident: $t:ty),*) => $f:ident($($e:expr),*);)*) => {$(
        #[no_mangle]
        pub unsafe extern "C" fn $name(this: *mut Cb, $($a: $t),*) -> i64 {
            rc32(unsafe { cb::$f(this, $($e),*) })
        }
    )*};
}

cb_fwd! {
    sceAmprCommandBufferWaitOnAddress_04_00(addr: *mut u64, reference: u64, cmp: u8, flush: u8)
        => ampr_cb_wait_on_address_04_00(addr, reference, cmp, flush);
    sceAmprCommandBufferWaitOnAddress(addr: *mut u64, reference: u64, cmp: u8, flush: u8)
        => ampr_cb_wait_on_address(addr, reference, cmp, flush);
    sceAmprCommandBufferWaitOnCounter_04_00(index: u8, width: u8, reference: u64, cmp: u8, extra: u8, extra_value: u64, flush: u8)
        => ampr_cb_wait_on_counter_04_00(index, width, reference, cmp, extra, extra_value, flush);
    sceAmprCommandBufferWaitOnCounter(index: u8, reference: u32, cmp: u8, flush: u8)
        => ampr_cb_wait_on_counter(index, reference, cmp, flush);
    sceAmprCommandBufferWriteAddress_04_00(addr: *mut u64, value: u64, at_sop: u64)
        => ampr_cb_write_address_04_00(addr, value, at_sop != 0);
    sceAmprCommandBufferWriteAddressOnCompletion(addr: *mut u64, value: u64)
        => ampr_cb_write_address_04_00(addr, value, false);
    sceAmprCommandBufferWriteCounter_04_00(index: u8, width: u8, value: u64, counter_mode: u8, mode: u8)
        => ampr_cb_write_counter_04_00(index, width, value, counter_mode, mode != 0);
    sceAmprCommandBufferWriteCounterOnCompletion(index: u8, value: u32)
        => ampr_cb_write_counter_04_00(index, 1, value as u64, 0, false);
    sceAmprCommandBufferWriteKernelEventQueue_04_00(eq: SceKernelEqueue, id: i32, data: u64, at_sop: u64)
        => ampr_cb_write_kernel_event_queue_04_00(eq, id, data, at_sop != 0);
    sceAmprCommandBufferWriteKernelEventQueueOnCompletion(eq: SceKernelEqueue, id: i32, data: u64)
        => ampr_cb_write_kernel_event_queue_04_00(eq, id, data, false);
    sceAmprCommandBufferWriteAddressFromTimeCounter_04_00(addr: *mut u64, at_sop: u64)
        => ampr_cb_write_address_from_time_counter_04_00(addr, at_sop != 0);
    sceAmprCommandBufferWriteAddressFromTimeCounterOnCompletion(addr: *mut u64)
        => ampr_cb_write_address_from_time_counter_04_00(addr, false);
    sceAmprCommandBufferWriteAddressFromCounter_04_00(addr: *mut u64, index: u8, at_sop: u64)
        => ampr_cb_write_address_from_counter_04_00(addr, index, at_sop != 0);
    sceAmprCommandBufferWriteAddressFromCounterOnCompletion(addr: *mut u64, index: u8)
        => ampr_cb_write_address_from_counter_04_00(addr, index, false);
    sceAmprCommandBufferWriteAddressFromCounterPair_04_00(addr: *mut u64, index: u8, at_sop: u64)
        => ampr_cb_write_address_from_counter_pair_04_00(addr, index, at_sop != 0);
    sceAmprCommandBufferWriteAddressFromCounterPairOnCompletion(addr: *mut u64, index: u8)
        => ampr_cb_write_address_from_counter_pair_04_00(addr, index, false);
    sceAmprCommandBufferConstructNop(nop_type: i16, payload: *const c_void, size: u32, opt: *const u32)
        => ampr_cb_construct_nop(nop_type as u32, payload, size, opt);
    sceAmprCommandBufferNop(num_u32: u32) => ampr_cb_nop(num_u32);
    sceAmprCommandBufferNopWithData(num_u32: u32, data: *const u32) => ampr_cb_nop_with_data(num_u32, data);
    sceAmprCommandBufferSetMarker(msg: *const c_char) => ampr_cb_marker(false, msg, 0, false);
    sceAmprCommandBufferPushMarkerWithColor(msg: *const c_char, color: u32) => ampr_cb_marker(true, msg, color, true);
    sceAmprCommandBufferPushMarker(msg: *const c_char) => ampr_cb_marker(true, msg, 0, false);
    sceAmprCommandBufferPopMarker() => ampr_cb_pop_marker();
}

/// FW10 type values: 1=set, 2=push, 3=pop, 5=setWithColor, 6=pushWithColor.
#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferConstructMarker(
    this: *mut Cb,
    marker_type: u32,
    msg: *const c_char,
    opt: *const u32,
) -> i64 {
    let color = |push| match unsafe { opt.as_ref() } {
        Some(&c) => unsafe { cb::ampr_cb_marker(this, push, msg, c, true) },
        None => EINVAL,
    };
    rc32(match marker_type {
        1 => unsafe { cb::ampr_cb_marker(this, false, msg, 0, false) },
        2 => unsafe { cb::ampr_cb_marker(this, true, msg, 0, false) },
        3 => unsafe { cb::ampr_cb_pop_marker(this) },
        5 => color(false),
        6 => color(true),
        _ => EINVAL,
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprCommandBufferSetMarkerWithColor(
    this: *mut Cb,
    msg: *const c_char,
    color: *const u32,
) -> i64 {
    rc32(match unsafe { color.as_ref() } {
        Some(&c) => unsafe { cb::ampr_cb_marker(this, false, msg, c, true) },
        None => EINVAL,
    })
}

// ---- sceAmprAprCommandBuffer* ---------------------------------------------
// SDK wrappers pass `this` plus hidden pointers to its map state (this+24)
// and scatter/gather state (this+32). The leaves only use the header.

/// SDK wrapper sequence: sceAmprCommandBufferConstructor(this), then this
/// with (this, this+24, this+32). Initialize only the APR tail.
#[no_mangle]
pub unsafe extern "C" fn sceAmprAprCommandBufferConstructor(
    _this: *mut Cb,
    map_state: *mut u64,
    sg_state: *mut u64,
) -> i64 {
    for p in [map_state, sg_state] {
        if !p.is_null() {
            unsafe { p.write(0) };
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprAprCommandBufferDestructor(
    _this: *mut Cb,
    _map_state: *mut u64,
    _sg_state: *mut u64,
) -> i64 {
    0
}

macro_rules! apr_fwd {
    ($($name:ident($($a:ident: $t:ty),*) => $f:ident;)*) => {$(
        #[no_mangle]
        pub unsafe extern "C" fn $name(
            this: *mut Cb, _map_state: *mut u64, _sg_state: *mut u64, $($a: $t),*
        ) -> i64 {
            rc32(unsafe { cb::$f(this, $($a),*) })
        }
    )*};
}

apr_fwd! {
    sceAmprAprCommandBufferReadFile(file_id: SceAprFileId, buffer: *mut c_void, length: u64, offset: u64)
        => ampr_apr_cb_read_file;
    sceAmprAprCommandBufferReadFileGather(length: u64, offset: u64) => ampr_apr_cb_read_file_gather;
    sceAmprAprCommandBufferReadFileScatter(buffer: *mut c_void, length: u64) => ampr_apr_cb_read_file_scatter;
    sceAmprAprCommandBufferReadFileGatherScatter(buffer: *mut c_void, length: u64, offset: u64)
        => ampr_apr_cb_read_file_gather_scatter;
}

cb_fwd! {
    sceAmprAprCommandBufferResetGatherScatterState() => ampr_apr_cb_reset_gather_scatter_state();
    sceAmprAprCommandBufferMapBegin(va: u64, size: u64, ty: c_int, prot: c_int)
        => ampr_apr_cb_map_begin(va, size, ty, prot);
    sceAmprAprCommandBufferMapDirectBegin(va: u64, dmem: u64, size: usize, ty: c_int, prot: c_int)
        => ampr_apr_cb_map_direct_begin(va, dmem, size, ty, prot);
    sceAmprAprCommandBufferMapEnd() => ampr_apr_cb_map_end();
}

// ---- sceAmprMeasureCommandSize* -------------------------------------------
// Bytes the matching append would emit; mirrors the SDK static wrappers.

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWaitOnAddress_04_00(
    addr: *mut u64,
    reference: u64,
    cmp: u8,
    flush: u8,
) -> i64 {
    if !cb::ampr_valid_u64_wait_addr_04_00(addr as u64)
        || !cb::ampr_valid_wait_compare_04_00(cmp)
        || !cb::ampr_valid_wait_flush(flush)
    {
        return measure_einval();
    }
    measure_op(OpRecord {
        u64a: reference,
        ..op(WAIT_ON_ADDRESS)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWaitOnAddress(
    addr: *mut u64,
    reference: u64,
    cmp: u8,
    flush: u8,
) -> i64 {
    if !cb::ampr_valid_u64_wait_addr(addr as u64)
        || !cb::ampr_valid_wait_compare_modern(cmp)
        || !cb::ampr_valid_wait_flush(flush)
    {
        return measure_einval();
    }
    measure_op(OpRecord {
        u64a: reference,
        ..op(WAIT_ON_ADDRESS)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWaitOnCounter_04_00(
    index: u8,
    width: u8,
    reference: u64,
    cmp: u8,
    extra: u8,
    extra_value: u64,
    flush: u8,
) -> i64 {
    if !cb::ampr_valid_wait_counter_04_00(width, cmp, extra, flush) {
        return measure_einval();
    }
    measure_op(OpRecord {
        u8a: index,
        u8b: width,
        u64a: reference,
        u64b: extra_value,
        u32c: (flush as u32 & 1) | ((extra as u32 & 3) << 8),
        ..op(WAIT_ON_COUNTER)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWaitOnCounter(
    index: u8,
    reference: u32,
    cmp: u8,
    flush: u8,
) -> i64 {
    if !cb::ampr_valid_wait_counter_modern(index, cmp, flush) {
        return measure_einval();
    }
    measure_op(OpRecord {
        u8a: index,
        u8b: 1,
        u64a: reference as u64,
        u32c: flush as u32 & 1,
        ..op(WAIT_ON_COUNTER)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteAddress_04_00(
    addr: *mut u64,
    value: u64,
) -> i64 {
    if !cb::ampr_valid_u64_write_addr(addr as u64) {
        return measure_einval();
    }
    measure_op(OpRecord {
        u64a: value,
        ..op(WRITE_ADDRESS)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteAddressOnCompletion(
    addr: *mut u64,
    value: u64,
) -> i64 {
    unsafe { sceAmprMeasureCommandSizeWriteAddress_04_00(addr, value) }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteAddressFromTimeCounter_04_00(
    addr: *mut u64,
) -> i64 {
    if !cb::ampr_valid_u64_write_addr(addr as u64) {
        return measure_einval();
    }
    measure_op(op(WRITE_ADDRESS_FROM_TIME_COUNTER))
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteAddressFromTimeCounterOnCompletion(
    addr: *mut u64,
) -> i64 {
    unsafe { sceAmprMeasureCommandSizeWriteAddressFromTimeCounter_04_00(addr) }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteAddressFromCounter_04_00(
    addr: *mut u64,
    index: u8,
) -> i64 {
    if !cb::ampr_valid_u64_write_addr(addr as u64) {
        return measure_einval();
    }
    measure_op(OpRecord {
        u8a: index,
        ..op(WRITE_ADDRESS_FROM_COUNTER)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteAddressFromCounterOnCompletion(
    addr: *mut u64,
    index: u8,
) -> i64 {
    unsafe { sceAmprMeasureCommandSizeWriteAddressFromCounter_04_00(addr, index) }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteAddressFromCounterPair_04_00(
    addr: *mut u64,
    index: u8,
) -> i64 {
    if !cb::ampr_valid_u64_write_addr(addr as u64) || index & 1 != 0 {
        return measure_einval();
    }
    measure_op(OpRecord {
        u8a: index,
        ..op(WRITE_ADDRESS_FROM_COUNTER_PAIR)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteAddressFromCounterPairOnCompletion(
    addr: *mut u64,
    index: u8,
) -> i64 {
    unsafe { sceAmprMeasureCommandSizeWriteAddressFromCounterPair_04_00(addr, index) }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteCounter_04_00(
    index: u8,
    width: u8,
    value: u64,
    mode: u8,
) -> i64 {
    if !cb::ampr_valid_write_counter_04_00(index, width, mode) {
        return measure_einval();
    }
    measure_op(OpRecord {
        u8a: index,
        u8b: width,
        u64a: value,
        u32b: mode as u32,
        ..op(WRITE_COUNTER)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteCounterOnCompletion(
    index: u8,
    value: u32,
) -> i64 {
    if !cb::ampr_valid_counter_index_signed7(index) {
        return measure_einval();
    }
    measure_op(OpRecord {
        u8a: index,
        u8b: 1,
        u64a: value as u64,
        ..op(WRITE_COUNTER)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteKernelEventQueue_04_00(
    eq: SceKernelEqueue,
    id: i32,
    data: u64,
) -> i64 {
    measure_op(OpRecord {
        u64b: eq as u64,
        u32b: id as u32,
        u64a: data,
        ..op(WRITE_EQUEUE)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeWriteKernelEventQueueOnCompletion(
    eq: SceKernelEqueue,
    id: i32,
    data: u64,
) -> i64 {
    unsafe { sceAmprMeasureCommandSizeWriteKernelEventQueue_04_00(eq, id, data) }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeNop(num_u32: u32) -> i64 {
    if num_u32 == 0 || num_u32 > 16 {
        return measure_einval();
    }
    measure_op(OpRecord {
        u32a: num_u32,
        ..op(NOP)
    })
}

/// Retail measures total record dwords here, while append takes payload
/// dwords and adds the header.
#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeNopWithData(num_u32: u32) -> i64 {
    if num_u32 == 0 || num_u32 > 16 {
        return measure_einval();
    }
    measure_op(OpRecord {
        u32a: num_u32 - 1,
        u32b: 1,
        ..op(NOP)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeReadFile(
    file_id: SceAprFileId,
    buffer: *mut c_void,
    length: u64,
    offset: u64,
) -> i64 {
    if cb::aprValidateReadArgs(buffer, length, offset) != 0 {
        return measure_einval();
    }
    measure_op(OpRecord {
        u32a: file_id,
        ptra: buffer as u64,
        u64a: length,
        u64b: offset,
        ..op(APR_READ_FILE)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeReadFileGather(length: u64, offset: u64) -> i64 {
    if cb::aprValidateReadLength(length) != 0 || cb::aprValidateReadOffset(offset) != 0 {
        return measure_einval();
    }
    measure_op(OpRecord {
        u64a: length,
        u64b: offset,
        ..op(APR_READ_GATHER)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeReadFileScatter(
    buffer: *mut c_void,
    length: u64,
) -> i64 {
    if cb::aprValidateReadArgs(buffer, length, 0) != 0 {
        return measure_einval();
    }
    measure_op(OpRecord {
        ptra: buffer as u64,
        u64a: length,
        ..op(APR_READ_SCATTER)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeReadFileGatherScatter(
    buffer: *mut c_void,
    length: u64,
    offset: u64,
) -> i64 {
    if cb::aprValidateReadArgs(buffer, length, offset) != 0 {
        return measure_einval();
    }
    measure_op(OpRecord {
        ptra: buffer as u64,
        u64a: length,
        u64b: offset,
        ..op(APR_READ_GATHER_SCATTER)
    })
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeResetGatherScatterState() -> i64 {
    measure_op(op(APR_RESET_GATHER_SCATTER))
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeMapBegin(
    va: u64,
    size: u64,
    ty: u32,
    prot: u32,
) -> i64 {
    match cb::aprValidateMapBeginArgs(va, size, ty as c_int, prot as c_int) {
        0 => measure_op(op(APR_MAP_BEGIN)),
        rc => rc32(rc),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeMapDirectBegin(
    va: u64,
    dmem: u64,
    size: u64,
    ty: u32,
    prot: u32,
) -> i64 {
    match cb::aprValidateMapDirectBeginArgs(va, dmem, size, ty as c_int, prot as c_int) {
        0 => measure_op(op(APR_MAP_DIRECT_BEGIN)),
        rc => rc32(rc),
    }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeMapEnd() -> i64 {
    measure_op(op(APR_MAP_END))
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeSetMarkerWithColor(
    msg: *const c_char,
    _color: u32,
) -> i64 {
    unsafe { measure_marker(MARKER_SET, msg, true) }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizeSetMarker(msg: *const c_char) -> i64 {
    unsafe { measure_marker(MARKER_SET, msg, false) }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizePushMarkerWithColor(
    msg: *const c_char,
    _color: u32,
) -> i64 {
    unsafe { measure_marker(MARKER_PUSH, msg, true) }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizePushMarker(msg: *const c_char) -> i64 {
    unsafe { measure_marker(MARKER_PUSH, msg, false) }
}

#[no_mangle]
pub unsafe extern "C" fn sceAmprMeasureCommandSizePopMarker() -> i64 {
    measure_op(op(MARKER_POP))
}
