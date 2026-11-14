//! Public PRX surface: module_start/module_stop and the 118 sceAmpr* exports.
//! The PRX exports 137 symbols in all: the other 19 are the libc/libc++
//! re-exports of retail libSceAmpr, in rt/libc_exports.rs.
//! The export layer is stateless: every export forwards to the leaves in
//! rt/amm.rs, rt/command_buffer.rs, rt/equeue.rs, rt/pack and rt/reactor.
//!
//! Layout:
//! 1. helpers (`rc32`, measure helpers) and SDK imports
//! 2. load notice and, in the debug build, the `/metrics` server
//!    (`mem_report`); module_start / module_stop
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
pub(crate) unsafe fn notify(text: &[u8]) {
    let mut req = NotifyRequest {
        head: [0; 45],
        message: [0; 3075],
    };
    let len = text.len().min(req.message.len() - 1);
    req.message[..len].copy_from_slice(&text[..len]);
    // Host tests reach this through the ledgers and have no libkernel.
    if cfg!(test) {
        return;
    }
    let _ = unsafe { sceKernelSendNotificationRequest(0, &mut req, size_of::<NotifyRequest>(), 0) };
}

/// Git revision the PRX was built from: short hash, "-dirty" when tracked
/// files had changes. ps5/build-docker.sh computes it on the host (the
/// Docker image has no git) and the Makefile passes it as AMPR_GIT_REV;
/// host builds and tests without it say "unknown". Debug `/metrics` only.
#[cfg(feature = "mem_report")]
pub(crate) const BUILD_REV: &str = match option_env!("AMPR_GIT_REV") {
    Some(v) => v,
    None => "unknown",
};
/// Build flavor: only the debug build serves `/metrics`.
#[cfg(feature = "mem_report")]
const BUILD_FLAVOR: &str = "debug";

/// Git revision on a beta build (AMPR_BETA=1, set by CI for every push to
/// main), so the launch notice tells a beta from the release it follows;
/// empty otherwise.
const BETA_REV: &str = match (option_env!("AMPR_BETA"), option_env!("AMPR_GIT_REV")) {
    (Some(b), Some(rev)) if b.len() == 1 && b.as_bytes()[0] == b'1' => rev,
    _ => "",
};
// The notice buffer is 64 bytes; "-dirty" hashes are 13.
const _: () = assert!(BETA_REV.len() <= 16, "AMPR_GIT_REV too long for the notice");

/// "ampr-emu-ng: v<version>[-beta.<rev>] (<mode>) running" into `out`; its
/// length. Mode:
/// "zstd" (ampr_zstd.index), "pkg" (this title's .pkg in /app0/kraken/), "lz4"
/// (ampr_assets.index) or "plain" (no packs, loose files only).
fn load_notice(mode: &[u8], out: &mut [u8; 64]) -> usize {
    let mut n = 0;
    for part in [
        b"ampr-emu-ng: v" as &[u8],
        VERSION.as_bytes(),
        if BETA_REV.is_empty() { b"" } else { b"-beta." },
        BETA_REV.as_bytes(),
        b" (",
        mode,
        b") running",
    ] {
        out[n..n + part.len()].copy_from_slice(part);
        n += part.len();
    }
    n
}

#[cfg(test)]
#[test]
fn load_notice_names_the_beta_rev() {
    let mut out = [0u8; 64];
    let n = load_notice(b"plain", &mut out);
    let beta = if BETA_REV.is_empty() { String::new() } else { format!("-beta.{BETA_REV}") };
    assert_eq!(out[..n], *format!("ampr-emu-ng: v{VERSION}{beta} (plain) running").as_bytes());
}

/// Tells the owner the module runs; also keeps AMPR_EMU_VERSION linked.
unsafe fn notify_loaded() {
    let _ = unsafe { core::ptr::read_volatile(&raw const AMPR_EMU_VERSION) };
    let mut text = [0u8; 64];
    let n = load_notice(super::pack::pack_format().label(), &mut text);
    unsafe { notify(&text[..n]) };
}

// ---- /bench query parsing and region planning ---------------------------

/// Pure parts of the debug build's `GET /bench?path=/app0/...`, kept apart
/// from `mem_report` so host tests cover them without the feature.
#[cfg(any(test, feature = "mem_report"))]
mod bench_args {
    /// Each test reads 32 MiB per path.
    pub(super) const REGION: u64 = 32 << 20;
    /// Loose-file tests (rt/exports.rs LOOSE_TESTS).
    pub(super) const TESTS: u64 = 6;
    /// Every test times two paths, each on its own region.
    pub(super) const SLOTS: u64 = 2 * TESTS;
    /// Unread file between two regions, so kernel read-ahead past one region
    /// cannot reach the next. 32 MiB keeps the twelve regions inside a
    /// 736 MiB file.
    pub(super) const GAP: u64 = 32 << 20;
    /// Twelve regions plus eleven gaps: 12 * 32 + 11 * 32 = 736 MiB.
    pub(super) const MIN_FILE: u64 = SLOTS * REGION + (SLOTS - 1) * GAP;
    /// Deepest AIO queue a test asks for.
    pub(super) const QD_MAX: usize = 32;
    /// pread threads of the thread-pool test, each on REGION / THREADS.
    #[cfg_attr(not(feature = "mem_report"), allow(dead_code))]
    pub(super) const THREADS: usize = 8;

    /// (request bytes, queue depth) that fit a `cap`-byte buffer: depth
    /// `qd` (0 = pread, 1 slot) lowered to QD_MAX and to `cap / req`, at
    /// least 1, and `req` cut to `cap` when even one slot does not fit.
    pub(super) fn fit(req: usize, qd: usize, cap: usize) -> (usize, usize) {
        let req = req.min(cap);
        if qd == 0 {
            return (req, 0);
        }
        (req, qd.min(QD_MAX).min(cap / req.max(1)).max(1))
    }
    pub(super) const APP0: &[u8] = b"/app0";

    /// Target (`/bench?...`) of the first request line, or empty.
    pub(super) fn target(req: &[u8]) -> &[u8] {
        let line = req
            .split(|&c| c == b'\r' || c == b'\n')
            .next()
            .unwrap_or(&[]);
        line.split(|&c| c == b' ').nth(1).unwrap_or(&[])
    }

    /// Query string after '?', or empty.
    pub(super) fn query(target: &[u8]) -> &[u8] {
        match target.iter().position(|&c| c == b'?') {
            Some(q) => &target[q + 1..],
            None => &[],
        }
    }

    /// Raw (still percent-encoded) value of `key` in `a=b&c=d`.
    /// The last `key=` value: tune::apply also lets the last pair win, so
    /// /set validates the value it stores.
    pub(super) fn param<'a>(query: &'a [u8], key: &[u8]) -> Option<&'a [u8]> {
        query
            .split(|&c| c == b'&')
            .filter_map(|pair| {
                let eq = pair.iter().position(|&c| c == b'=')?;
                (&pair[..eq] == key).then(|| &pair[eq + 1..])
            })
            .last()
    }

    /// Percent-decoding (rt/tune.rs).
    pub(super) use super::super::tune::url_decode;

    /// True for `/app0/<something>`.
    pub(super) fn is_app0_file(path: &[u8]) -> bool {
        path.len() > APP0.len() + 1 && path.starts_with(APP0) && path[APP0.len()] == b'/'
    }

    /// Distance between region starts: regions spread evenly over the file
    /// with the last one ending at or before EOF, 64 KiB aligned; None when
    /// the file is under MIN_FILE.
    pub(super) fn region_stride(size: u64) -> Option<u64> {
        let gap = size.checked_sub(MIN_FILE)? / (SLOTS - 1) + GAP;
        Some((REGION + gap) & !0xffff)
    }

    /// /app0 runs first on even tests, the backing path on odd ones, so
    /// neither path always gets the cold start.
    pub(super) fn app0_first(test: usize) -> bool {
        test.is_multiple_of(2)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        /// Request target and query parsing, percent-decoding, bench region
        /// layout and queue-depth fitting.
        #[test]
        fn bench_request_helpers() {
            let req = b"GET /bench?path=%2Fapp0%2Fdata.bin&backing=/x HTTP/1.1\r\nHost: a\r\n";
            let q = query(target(req));
            assert_eq!(q, b"path=%2Fapp0%2Fdata.bin&backing=/x");
            assert_eq!(param(q, b"path"), Some(&b"%2Fapp0%2Fdata.bin"[..]));
            assert_eq!(param(q, b"backing"), Some(&b"/x"[..]));
            assert_eq!(param(q, b"pat"), None);
            assert_eq!(query(target(b"GET /bench HTTP/1.0\r\n")), b"");
            assert_eq!(param(b"flag&path=", b"path"), Some(&b""[..]));
            assert!(
                is_app0_file(b"/app0/a") && !is_app0_file(b"/app0/") && !is_app0_file(b"/app0x")
            );
            let mut out = [0xffu8; 32];
            let n = url_decode(b"%2Fapp0%2fa+b%20c", &mut out).unwrap();
            assert_eq!(&out[..n], b"/app0/a+b c");
            assert_eq!(out[n], 0);
            assert_eq!(url_decode(b"%2", &mut out), None);
            assert_eq!(url_decode(b"%zz", &mut out), None);
            assert_eq!(url_decode(b"a%00", &mut out), None);
            assert_eq!(url_decode(b"abcd", &mut [0u8; 4]), None);
            assert_eq!(url_decode(b"abc", &mut [0u8; 4]), Some(3));
            assert_eq!(region_stride(MIN_FILE - 1), None);
            let s = region_stride(MIN_FILE).unwrap();
            assert_eq!(s % 0x10000, 0);
            // Gaps of at least GAP (32 MiB), all twelve regions inside the file.
            assert_eq!(s, REGION + GAP);
            assert!((SLOTS - 1) * s + REGION <= MIN_FILE);
            let big = 8_130_000_123;
            let s = region_stride(big).unwrap();
            assert_eq!(s % 0x10000, 0);
            assert!(s - REGION >= GAP && (SLOTS - 1) * s + REGION <= big);
            assert!(app0_first(0) && !app0_first(1) && app0_first(2));
            assert_eq!(MIN_FILE, 736 << 20);
            const K: usize = 1024;
            // 8 MiB buffer: every test runs at the depth it names.
            assert_eq!(fit(256 * K, 32, 8192 * K), (256 * K, 32));
            assert_eq!(fit(64 * K, 8, 8192 * K), (64 * K, 8));
            // A halved 2 MiB buffer caps qd32 at 8; qd is never 0 for AIO.
            assert_eq!(fit(256 * K, 32, 2048 * K), (256 * K, 8));
            assert_eq!(fit(512 * K, 8, 256 * K), (256 * K, 1));
            assert_eq!(fit(64 * K, 64, 8192 * K), (64 * K, QD_MAX));
            assert_eq!(fit(512 * K, 0, 256 * K), (256 * K, 0));
        }
    }
}

/// Debug build (`make AMPR_MEM_REPORT=1`): a low-priority thread serves the
/// internal pool usage and rt/stats.rs counters as plain text over TCP
/// (`GET /metrics` on port METRICS_PORT, one client at a time). Counters are
/// totals since load; `*_max` values reset on each scrape. `GET /set?k=v&...`
/// changes rt/tune.rs knobs (no arguments: list them). `GET /bench` reads
/// pack volume 0; `GET /bench?path=/app0/<file>[&backing=/abs/file]` reads a
/// loose file through /app0 and, with `backing=`, the same file at that
/// path. No release impact.
#[cfg(feature = "mem_report")]
mod mem_report {
    use super::super::pack::{
        bench_volume_path, real_aio_delete_single, real_aio_submit_single, real_aio_wait_single,
        scePthreadJoin, SceKernelAioRWRequest, SceKernelAioResult, SceKernelAioSubmitId,
    };
    use super::super::index_memory::{index_free, index_scratch_alloc};
    use super::super::runtime_memory::{pool_tags, pool_usage, TagTotals};
    use super::super::stats::{read, NAMES};
    use super::super::sys::{
        errno, monotonic_ns, off_t, real_physical_close, real_physical_fstat, real_physical_pread,
        real_posix_open, sceKernelUsleep, sce_errno, SceKernelUseconds, SCE_KERNEL_ERROR_ETIMEDOUT,
    };
    use super::super::tune;
    use super::bench_args;
    use core::ffi::{c_int, c_void};

    pub(super) const METRICS_PORT: u16 = 9090;

    extern "C" {
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

    /// Fixed-capacity text buffer; output past the end is dropped. 16 KiB:
    /// the body reached ~3.4 KiB of the old 4 KiB with the fs log, before the
    /// reactor stats, and the tune_/pool_ lines print last.
    struct Text {
        buf: [u8; 16384],
        len: usize,
    }

    /// Response and body buffers of the single server thread, in .bss rather
    /// than on its default-size stack (debug build only).
    static mut BUFS: (Text, Text) = (
        Text {
            buf: [0; 16384],
            len: 0,
        },
        Text {
            buf: [0; 16384],
            len: 0,
        },
    );

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
    /// Deepest AIO queue the bench runs (aio_256k_qd32); bench_args::fit
    /// lowers it when the buffer is short.
    const QD_MAX: usize = bench_args::QD_MAX;
    /// sceKernelAioSubmitReadCommands priority. The bench passed 0 before
    /// and every submit failed with 0x80020016 (EINVAL) on a console
    /// run; the reactor submits with 1..=3 (reactor/mod.rs).
    const AIO_PRIORITY: c_int = 2;
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

    /// Kernel AIO with up to `qd` single-request submits in flight (FIFO);
    /// slot `s` reads into `buf + s * req`, so `buf` holds `qd * req` bytes
    /// (bench_args::fit).
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
                let rc = unsafe { submit(&raw mut rq[s], 1, AIO_PRIORITY, &raw mut ids[s]) };
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
            // A request the kernel will not delete may still write `res` and
            // the buffer: never leave this frame while it is live.
            // This parks the metrics thread forever on a stuck request.
            while unsafe { delete(ids[head], &mut state) } != 0 {
                let mut usec: SceKernelUseconds = 100_000;
                let _ = unsafe { wait(ids[head], &mut state, &mut usec) };
            }
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

    // ---- /bench?path=: /app0 against its backing path ----

    /// `b` up to its first NUL.
    fn cstr(b: &[u8]) -> &[u8] {
        &b[..b.iter().position(|&c| c == 0).unwrap_or(b.len())]
    }

    /// Opens `path` (NUL-terminated) read-only; (fd, st_size) or the error
    /// is printed. st_size sits at offset 72 of the PS5 stat (rt/index.rs).
    unsafe fn open_sized(label: &[u8], path: &[u8], out: &mut Text) -> Option<(c_int, u64)> {
        let fd = unsafe { real_posix_open(path.as_ptr().cast(), 0, 0) };
        let mut st = [0u64; 32];
        let rc = if fd < 0 {
            sce_errno(errno())
        } else if unsafe { real_physical_fstat(fd, st.as_mut_ptr().cast()) } != 0 {
            let rc = sce_errno(errno());
            let _ = unsafe { real_physical_close(fd) };
            rc
        } else {
            return Some((fd, st[9]));
        };
        out.s(b"bench ")
            .s(label)
            .s(b" open error rc=")
            .x(rc as u32)
            .s(b" path=")
            .s(cstr(path))
            .s(b"\n");
        None
    }

    /// Bench buffer from the index ledger (rt/index_memory.rs): 8 MiB,
    /// halved down to `min`, held under the index cap.
    unsafe fn alloc_buf(min: usize) -> Option<(*mut c_void, usize)> {
        let mut cap = 8 * MIB;
        while cap >= min {
            let buf = unsafe { index_scratch_alloc(cap, 16 * KIB, c"bench".as_ptr()) };
            if !buf.is_null() {
                return Some((buf.cast(), cap));
            }
            cap /= 2;
        }
        None
    }

    /// `bench <label> <test> [depth=N] MB/s=.. us_per_req=.. bytes=..
    /// off_mib=..`. depth is the AIO queue depth or thread count used
    /// (bench_args::fit may lower it); us_per_req is wall time over requests,
    /// so a request's latency is about depth times it.
    fn result_line(
        out: &mut Text,
        label: &[u8],
        test: &str,
        off: u64,
        depth: usize,
        r: BenchResult,
    ) {
        out.s(b"bench ").s(label).s(b" ").s(test.as_bytes());
        if depth > 0 {
            out.s(b" depth=").u(depth as u64);
        }
        match r {
            Ok((b, n, ns)) => {
                let ns = ns.max(1);
                out.s(b" MB/s=")
                    .u(b.saturating_mul(1000) / ns)
                    .s(b" us_per_req=")
                    .u(ns / n.max(1) / 1000)
                    .s(b" bytes=")
                    .u(b)
            }
            Err(0) => out.s(b" error aio unavailable"),
            Err(rc) => out.s(b" error rc=").x(rc as u32),
        };
        out.s(b" off_mib=").u(off >> 20).s(b"\n");
    }

    /// How a loose-file test reads its region.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Kind {
        /// One thread, sequential pread.
        Pread,
        /// Kernel AIO, `depth` requests in flight.
        Aio,
        /// `depth` threads, each sequential pread on its own slice: the
        /// shape of the reactor's pread pool (reactor/pread_pool.rs).
        Threads,
    }

    /// Loose-file tests: (name, request bytes, depth, kind). In game, 256
    /// KiB pread parts took 4.15 ms against 1.70 ms for 64 KiB parts with
    /// up to ~60 in flight (a game); the 256 KiB concurrent
    /// tests show whether /app0 or its backing folder causes that.
    const LOOSE_TESTS: [(&str, usize, usize, Kind); bench_args::TESTS as usize] = [
        ("pread_64k", 64 * KIB, 0, Kind::Pread),
        ("pread_512k", 512 * KIB, 0, Kind::Pread),
        ("aio_64k_qd8", 64 * KIB, 8, Kind::Aio),
        ("aio_256k_qd8", 256 * KIB, 8, Kind::Aio),
        ("aio_256k_qd32", 256 * KIB, 32, Kind::Aio),
        (
            "pread_256k_t8",
            256 * KIB,
            bench_args::THREADS,
            Kind::Threads,
        ),
    ];

    /// One thread of bench_pread_threads.
    struct PreadJob {
        fd: c_int,
        buf: *mut u8,
        req: usize,
        off: u64,
        bytes: u64,
        r: BenchResult,
    }

    unsafe extern "C" fn pread_job(arg: *mut c_void) -> *mut c_void {
        let j = unsafe { &mut *arg.cast::<PreadJob>() };
        j.r = unsafe { bench_pread(j.fd, j.buf, j.req, j.off, j.bytes) };
        core::ptr::null_mut()
    }

    /// `threads` threads, thread `t` reading `bytes / threads` from
    /// `off + t * bytes / threads` into `buf + t * req`. Elapsed time is wall
    /// time from the first create to the last join; the first error wins.
    unsafe fn bench_pread_threads(
        fd: c_int,
        buf: *mut u8,
        req: usize,
        off: u64,
        bytes: u64,
        threads: usize,
    ) -> BenchResult {
        const T: usize = bench_args::THREADS;
        let n = threads.clamp(1, T);
        let part = (bytes / n as u64) & !(req as u64 - 1);
        let mut jobs: [PreadJob; T] = core::array::from_fn(|t| PreadJob {
            fd,
            buf: unsafe { buf.add(t * req) },
            req,
            off: off + t as u64 * part,
            bytes: part,
            r: Err(0),
        });
        let mut ids = [core::ptr::null_mut(); T];
        let t0 = monotonic_ns();
        let mut started = 0;
        let mut err = 0;
        while started < n {
            let rc = unsafe {
                super::super::thread_hooks::create_internal(
                    &mut ids[started],
                    core::ptr::null(),
                    pread_job,
                    (&raw mut jobs[started]).cast(),
                    c"ampr_bench_pread".as_ptr(),
                )
            };
            if rc != 0 {
                err = rc;
                break;
            }
            started += 1;
        }
        for &id in &ids[..started] {
            // A worker that failed to join may still use `jobs`, the buffer
            // and the fd: park the metrics thread rather than free them.
            while unsafe { scePthreadJoin(id, core::ptr::null_mut()) } != 0 {
                unsafe { sceKernelUsleep(1_000_000) };
            }
        }
        let ns = monotonic_ns().saturating_sub(t0);
        if err != 0 {
            return Err(err);
        }
        let (mut b, mut r) = (0, 0);
        for j in &jobs[..n] {
            let (jb, jr, _) = j.r?;
            b += jb;
            r += jr;
        }
        Ok((b, r, ns))
    }

    /// Opens the backing file and keeps it only if its size matches /app0's.
    unsafe fn open_backing(path: &[u8], how: &[u8], size: u64, out: &mut Text) -> c_int {
        let Some((fd, got)) = (unsafe { open_sized(b"backing", path, out) }) else {
            return -1;
        };
        out.s(b"bench backing path=")
            .s(cstr(path))
            .s(b" source=")
            .s(how)
            .s(b"\n");
        if got == size {
            return fd;
        }
        out.s(b"bench backing file_size=")
            .u(got)
            .s(b" differs from /app0; benching /app0 only\n");
        let _ = unsafe { real_physical_close(fd) };
        -1
    }

    /// Backing fd from `backing=` (an absolute path, percent-decoded);
    /// -1 when it is absent or does not open with /app0's size, and /app0
    /// is then benched alone. The backing path is not detected: statfs and
    /// fstatfs are not exported by libkernel on the console.
    unsafe fn find_backing(q: &[u8], size: u64, out: &mut Text) -> c_int {
        let mut path = [0u8; 1024];
        let Some(raw) = bench_args::param(q, b"backing") else {
            out.s(b"bench: no backing= given; benching /app0 only\n");
            return -1;
        };
        if bench_args::url_decode(raw, &mut path).is_none() || path[0] != b'/' {
            out.s(b"bench: backing= must be an absolute path; benching /app0 only\n");
            return -1;
        }
        unsafe { open_backing(&path, b"param", size, out) }
    }

    /// GET /bench?path=/app0/<file>[&backing=/abs/file]: the same file read
    /// through /app0 (a ShadowMount nullfs mount) and through its backing
    /// path. nullfs shares the lower vnode's page cache, so each test and
    /// path reads its own 32 MiB region with 32 MiB (GAP) or more of unread file
    /// between regions, and the path that runs first alternates per test.
    unsafe fn bench_loose(q: &[u8], raw_path: &[u8], out: &mut Text) {
        let mut app0 = [0u8; 1024];
        let n = match bench_args::url_decode(raw_path, &mut app0) {
            Some(n) if bench_args::is_app0_file(&app0[..n]) => n,
            _ => {
                out.s(b"bench: path= must be /app0/<file> (%2F escapes allowed)\n");
                return;
            }
        };
        out.s(b"bench app0 path=").s(&app0[..n]).s(b"\n");
        let Some((fd_a, size)) = (unsafe { open_sized(b"app0", &app0, out) }) else {
            return;
        };
        let fd_b = unsafe { find_backing(q, size, out) };
        out.s(b"bench file_size=").u(size).s(b"\n");
        let stride = bench_args::region_stride(size);
        let buf = unsafe { alloc_buf(512 * KIB) };
        match (stride, buf) {
            (None, _) => {
                out.s(b"bench: file_size under 736 MiB; pick a larger file\n");
            }
            (_, None) => {
                out.s(b"bench: buffer alloc failed\n");
            }
            (Some(stride), Some((buf, cap))) => {
                out.s(b"note: results are invalid if the file is in the OS cache; use a file not read since boot (a repeat run reads the same regions)\n");
                for (i, &(name, req, depth, kind)) in LOOSE_TESTS.iter().enumerate() {
                    for k in 0..2 {
                        let (label, fd) = if bench_args::app0_first(i) == (k == 0) {
                            (b"app0" as &[u8], fd_a)
                        } else {
                            (b"backing" as &[u8], fd_b)
                        };
                        if fd < 0 {
                            continue;
                        }
                        let off = (2 * i + k) as u64 * stride;
                        let len = bench_args::REGION;
                        let (req, depth) = bench_args::fit(req, depth, cap);
                        let b = buf.cast();
                        let r = match kind {
                            Kind::Pread => unsafe { bench_pread(fd, b, req, off, len) },
                            Kind::Aio => unsafe { bench_aio(fd, b, req, off, len, depth) },
                            Kind::Threads => unsafe {
                                bench_pread_threads(fd, b, req, off, len, depth)
                            },
                        };
                        result_line(out, label, name, off, depth, r);
                    }
                }
            }
        }
        if let Some((buf, _)) = buf {
            unsafe { index_free(buf, c"bench".as_ptr()) };
        }
        for fd in [fd_a, fd_b] {
            if fd >= 0 {
                let _ = unsafe { real_physical_close(fd) };
            }
        }
    }

    /// GET /bench: `path=` benches a loose /app0 file (bench_loose), else
    /// pack volume 0 (bench_volume).
    unsafe fn bench(req: &[u8], out: &mut Text) {
        let q = bench_args::query(bench_args::target(req));
        match bench_args::param(q, b"path") {
            Some(raw) => unsafe { bench_loose(q, raw, out) },
            None => unsafe { bench_volume(out) },
        }
    }

    /// Raw read speed of pack volume 0 through the unhooked kernel
    /// calls. Each test reads its own 64 KiB aligned region so earlier tests do
    /// not warm the OS cache for later ones. Blocks only the metrics thread.
    unsafe fn bench_volume(out: &mut Text) {
        let mut path = [0u8; 1024];
        let Some((len, size)) = (unsafe { bench_volume_path(&mut path) }) else {
            out.s(b"bench: manifest not ready (loose game: /bench?path=/app0/<file>)\n");
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
        let Some((buf, cap)) = (unsafe { alloc_buf(256 * KIB) }) else {
            out.s(b"bench: buffer alloc failed\n");
            return;
        };
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
                let off = i as u64 * stride;
                let (req, qd) = bench_args::fit(req, qd, cap);
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
        unsafe { index_free(buf, c"bench".as_ptr()) };
    }

    /// `GET /threads?hold=N` holds up to N more idle threads, stopping at the
    /// first failed creation; `?release=1` frees them; `?yield=N` makes the
    /// read pool give N threads back as a failed game creation would (N at
    /// least the live count turns the pool off); `?yield_workers=N` does the
    /// same for the pack workers (the last only with no pack work); no
    /// argument reports.
    /// Measures the game's thread limit (rt/thread_hooks.rs `limit_probe`).
    unsafe fn threads(req: &[u8], out: &mut Text) {
        use super::super::thread_hooks::limit_probe as lp;
        let q = bench_args::query(bench_args::target(req));
        let number = |n: &[u8]| {
            n.iter()
                .take_while(|c| c.is_ascii_digit())
                .fold(0usize, |v, &c| v.saturating_mul(10).saturating_add((c - b'0') as usize))
        };
        if bench_args::param(q, b"release").is_some() {
            unsafe { lp::release() };
        } else if let Some(n) = bench_args::param(q, b"yield") {
            // Simulates a failed game creation: the pool gives n threads back.
            let given = unsafe { super::super::reactor::pread_pool_yield(number(n) as u32) };
            out.kv("threads_yielded_now", given as u64);
        } else if let Some(n) = bench_args::param(q, b"yield_workers") {
            // As a failed game creation once the pool has none: the pack
            // workers give n back (the last only with no pack work).
            let given = unsafe { super::super::pack::pack_workers_yield(number(n) as u32) };
            out.kv("threads_yielded_now", given as u64);
        } else if let Some(n) = bench_args::param(q, b"hold") {
            unsafe { lp::grow(number(n).min(lp::MAX_HELD)) };
        }
        let (held, rc) = lp::status();
        let (live, ceiling, idle) = super::super::reactor::pread_pool_state();
        out.kv("threads_held", held as u64)
            .s(b"threads_hold_last_rc ")
            .x(rc as u32)
            .s(b"\n");
        for (name, v) in NAMES.iter().zip(read()) {
            if name.starts_with("thread")
                || name.starts_with("pread_thread")
                || name.starts_with("pack_worker")
            {
                out.kv(name, v);
            }
        }
        let (workers, worker_ceiling) = super::super::pack::pack_workers_state();
        out.kv("pread_threads_live", live)
            .kv("pread_threads_ceiling", ceiling)
            .kv("pread_threads_idle", idle)
            .kv("pack_workers_live", workers as u64)
            .kv("pack_workers_ceiling", worker_ceiling as u64);
    }

    /// `GET /fsfail`: every distinct failed path hook call since load (op,
    /// lookup, result, count, path), first stats::FS_FAILS kept.
    fn fsfail(out: &mut Text) {
        use super::super::stats::{FS_FAILS, FS_FAIL_LOG};
        let log = unsafe { &*FS_FAIL_LOG.get() };
        out.kv("fsfail_distinct", log.count as u64)
            .kv("fsfail_dropped", log.dropped.load(core::sync::atomic::Ordering::Relaxed));
        for i in 0..log.count.min(FS_FAILS) {
            out.s(b"fsfail ")
                .s(&[log.op[i], b' ', log.how[i], b' '])
                .x(log.rc[i] as u32)
                .s(b" ")
                .u(log.hits[i] as u64)
                .s(b" ")
                .s(&log.path[i][..log.len[i]])
                .s(b"\n");
        }
    }

    /// `GET /queues`: event queue waits in progress, queues with pending
    /// events and the queues AMPR jobs signal.
    /// Its own page, so a busy title cannot crowd `/metrics` out of its
    /// 16 KiB buffer.
    fn queues(out: &mut Text) {
        // Event queue waits in progress and queues with pending events
        // (rt/equeue.rs `equeue_views`).
        let mut views = [super::super::equeue::EqueueView::default(); 48];
        let count = super::super::equeue::equeue_views(&mut views);
        for v in &views[..count] {
            out.s(if v.waiting { b"eqwait eq=" } else { b"eqpend eq=" }).u(v.eq as u64);
            if v.waiting {
                out.s(b" age_ms=").u(v.age_ms).s(b" timeout_us=");
                if v.timeout_us == u64::MAX {
                    out.s(b"none");
                } else {
                    out.u(v.timeout_us);
                }
            }
            if v.tracked {
                out.s(b" pending=").u(v.pending.into()).s(b" regs=").u(v.registrations.into());
                out.s(b" native_intent=").u(v.native_intent.into()).s(b" parked=");
                out.u(v.parked.into()).s(b" trigger=").u(v.trigger.into());
                out.s(b" flags=").u(v.flags.into());
            } else {
                out.s(b" untracked");
            }
            out.s(b"\n");
        }
        // WriteKernelEventQueue targets (reactor/native.rs).
        let now = super::super::services::time_counter_now();
        for t in &super::super::reactor::EQUEUE_TARGETS {
            use core::sync::atomic::Ordering::Relaxed;
            let eq = t.eq.load(core::sync::atomic::Ordering::Acquire);
            if eq == 0 {
                continue;
            }
            out.s(b"eqtarget eq=").u(eq as u64).s(b" id=").u(t.id.load(Relaxed).into());
            out.s(b" writes=").u(t.writes.load(Relaxed)).s(b" data=").u(t.data.load(Relaxed));
            out.s(b" changes=").u(t.changes.load(Relaxed)).s(b" age_ms=");
            out.u(now.saturating_sub(t.last_ns.load(Relaxed)) / 1_000_000).s(b"\n");
        }
    }

    /// `GET /modules`: loaded modules as name, segment count, first segment
    /// size and fingerprint, to tell a backport fakelib from the system copy
    /// of the same library. SceKernelModuleInfo is the PS4/OpenOrbis layout
    /// (0x160 bytes: name +0x08, segments +0x108, count +0x148, fp +0x14C).
    unsafe fn modules(out: &mut Text) {
        type ListFn = unsafe extern "C" fn(*mut c_int, usize, *mut usize) -> c_int;
        type InfoFn = unsafe extern "C" fn(c_int, *mut u8) -> c_int;
        let list = unsafe { crate::rt::sys::resolve_kernel::<ListFn>(c"sceKernelGetModuleList") };
        let info = unsafe { crate::rt::sys::resolve_kernel::<InfoFn>(c"sceKernelGetModuleInfo") };
        let (Some(list), Some(info)) = (list, info) else {
            out.s(b"modules unavailable\n");
            return;
        };
        let mut mods = [0 as c_int; 256];
        let mut n = 0usize;
        let rc = unsafe { list(mods.as_mut_ptr(), mods.len(), &mut n) };
        out.kv("modules_rc", rc as u32 as u64).kv("modules_count", n as u64);
        for &m in &mods[..n.min(mods.len())] {
            let mut buf = [0u8; 0x160];
            buf[..8].copy_from_slice(&0x160u64.to_ne_bytes());
            let rc = unsafe { info(m, buf.as_mut_ptr()) };
            let name = &buf[8..0x108];
            let name = &name[..name.iter().position(|&b| b == 0).unwrap_or(name.len())];
            let seg0 = u32::from_ne_bytes(buf[0x110..0x114].try_into().unwrap_or([0; 4]));
            out.s(b"module ").x(m as u32).s(b" ").x(rc as u32).s(b" ").s(name);
            out.s(b" segs=").u(buf[0x148] as u64).s(b" seg0=").u(seg0 as u64).s(b" fp=");
            for &b in &buf[0x14C..0x160] {
                out.s(&[b"0123456789abcdef"[(b >> 4) as usize], b"0123456789abcdef"[(b & 15) as usize]]);
            }
            out.s(b"\n");
        }
    }

    fn body(start_ns: u64, out: &mut Text) {
        let (used, peak, size) = pool_usage();
        // Which PRX answered: a stale debug build looks like the new one.
        out.s(b"build ampr-emu-ng ")
            .s(super::VERSION.as_bytes())
            .s(b" ")
            .s(super::BUILD_REV.as_bytes())
            .s(b" ")
            .s(super::BUILD_FLAVOR.as_bytes())
            .s(b"\n");
        // Pack format (load notice mode): plain, lz4, zstd or pkg.
        out.s(b"pack_format ")
            .s(super::super::pack::pack_format().label())
            .s(b"\n");
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
        for (i, (name, v)) in NAMES.iter().zip(read()).enumerate() {
            if super::super::stats::is_code(i) {
                out.s(name.as_bytes()).s(b" ").x(v as u32).s(b"\n");
            } else {
                out.kv(name, v);
            }
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
        // What the pack runtime actually got at startup (the cache is cut to
        // what is left under the Cache cap), then the knobs as set now.
        let state = super::super::pack::g_pack_state.load(core::sync::atomic::Ordering::Acquire);
        if !state.is_null() {
            // Raw place reads only: other threads mutate PackState, so no
            // reference to it is formed (see `pack_state()`).
            let s = state;
            unsafe {
                out.kv("pack_decoded_cache_bytes", (*s).cache_bytes as u64)
                    .kv("pack_workers", (*s).workers_started as u64)
                    .kv("pack_pipelines", (*s).pipeline_capacity as u64);
            }
        }
        {
            // The game's flexible memory, free and configured: tells whether
            // the static pool comes out of the game's budget.
            type FlexFn = unsafe extern "C" fn(*mut usize) -> c_int;
            let flex = |name: &core::ffi::CStr| {
                let mut v = 0usize;
                match unsafe { super::super::sys::resolve_kernel::<FlexFn>(name) } {
                    Some(f) if unsafe { f(&mut v) } == 0 => v as u64,
                    _ => 0,
                }
            };
            out.kv(
                "flex_at_start_bytes",
                super::FLEX_AT_START.load(core::sync::atomic::Ordering::Relaxed),
            )
            .kv(
                "flex_after_start_bytes",
                super::FLEX_AFTER_START.load(core::sync::atomic::Ordering::Relaxed),
            );
            out.kv("flex_free_bytes", flex(c"sceKernelAvailableFlexibleMemorySize"))
                .kv(
                    "flex_configured_bytes",
                    flex(c"sceKernelConfiguredFlexibleMemorySize"),
                );
            // Pool ledgers (rt/index_memory.rs), all inside the static pool.
            // ledger_mem_bytes is the sum of the three; an allocation
            // refused by a cap counts in ledger_alloc_refused, a failed
            // pool one in pool_alloc_failed.
            use super::super::index_memory as im;
            out.kv("index_mem_bytes", im::index_mem_bytes() as u64)
                .kv("index_mem_cap_bytes", im::INDEX_MEMORY_MAX as u64);
            out.kv("cache_mem_bytes", im::cache_mem_bytes() as u64)
                .kv("cache_mem_cap_bytes", im::CACHE_MEMORY_MAX as u64);
            out.kv("buffer_mem_bytes", im::buffer_mem_bytes() as u64)
                .kv("buffer_mem_cap_bytes", im::BUFFER_MEMORY_MAX as u64);
            out.kv("ledger_mem_bytes", im::ledger_mem_bytes() as u64)
                .kv("ledger_mem_cap_bytes", im::LEDGER_MEMORY_MAX as u64)
                .kv("ledger_alloc_refused", im::ledger_alloc_refused())
                .kv("pool_alloc_failed", im::pool_alloc_failed());
        }
        {
            // The descriptor table limit (getrlimit RLIMIT_NOFILE, 0 when
            // libkernel lacks it), how many real fds are open and the
            // highest one (fstat on 0..scan, the limit or 1024, at most
            // 4096). Virtual pack fds are above the table and not counted.
            #[repr(C)]
            struct Rlimit {
                cur: i64,
                max: i64,
            }
            type RlimitFn = unsafe extern "C" fn(c_int, *mut Rlimit) -> c_int;
            type FstatFn = unsafe extern "C" fn(c_int, *mut c_void) -> c_int;
            let mut lim = Rlimit { cur: 0, max: 0 };
            let limit = match unsafe { super::super::sys::resolve_kernel::<RlimitFn>(c"getrlimit") } {
                Some(f) if unsafe { f(8, &mut lim) } == 0 && lim.cur > 0 => lim.cur as usize,
                _ => 0,
            };
            let scan = if limit != 0 { limit.min(4096) } else { 1024 };
            // fstat, not fcntl: the libkernel fcntl entry returned -1 for
            // every fd here, even the pack volumes'.
            let fstat = unsafe {
                super::super::sys::kernel_slot::<FstatFn>(super::super::sys::hook::fstat)
            }
            .or_else(|| unsafe { super::super::sys::resolve_kernel::<FstatFn>(c"fstat") });
            let (mut open, mut highest) = (0u64, 0u64);
            #[repr(C, align(16))]
            struct StatBuf([u8; 512]);
            let mut st = StatBuf([0; 512]);
            if let Some(f) = fstat {
                for fd in 0..scan as c_int {
                    if unsafe { f(fd, st.0.as_mut_ptr().cast()) } == 0 {
                        open += 1;
                        highest = fd as u64;
                    }
                }
            }
            out.kv("fd_limit", limit as u64)
                .kv("fd_open", open)
                .kv("fd_highest_open", highest)
                .kv("fd_scanned", scan as u64);
        }
        {
            let (live, ceiling, idle) = super::super::reactor::pread_pool_state();
            out.kv("pread_threads_ceiling", ceiling)
                .kv("pread_threads_idle", idle);
            let (counted, budget) = super::super::thread_hooks::budget_state();
            out.kv("runtime_threads_live", counted.into()).kv("thread_budget", budget.into());
            out.kv("thread_mode", super::super::thread_hooks::pressure() as u64);
            let (workers, worker_ceiling) = super::super::pack::pack_workers_state();
            out.kv("pack_workers_ceiling", worker_ceiling as u64);
            let (fd_live, fd_load) = super::super::pack::read_threads_load();
            // Per group (rt/thread_hooks.rs LoadGroup): live, peak, target,
            // busy median (rounded up), retired by load, under pressure.
            let groups = [
                (&b"decode"[..], workers as u64, super::super::pack::pack_workers_load()),
                (b"pread", live, super::super::reactor::pread_pool_load()),
                (b"fdread", fd_live as u64, fd_load),
            ];
            const KEYS: [&[u8]; 6] = [
                b"_threads_live ",
                b"_threads_peak ",
                b"_target ",
                b"_busy_median ",
                b"_retired_load ",
                b"_retired_pressure ",
            ];
            for (name, live, load) in groups {
                let values = [live, load[0], load[1], load[2], load[3], load[4]];
                for (key, v) in KEYS.iter().zip(values) {
                    out.s(name).s(key).u(v).s(b"\n");
                }
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
        let query = bench_args::query(bench_args::target(req));
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
            out.s(knob.name.as_bytes()).s(b"=");
            out.u(tune::value(knob) as u64);
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
        out.s(b"profile=low|medium|high sets decoded_mib, workers, pipelines\n");
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
            // Only this thread touches BUFS.
            let (text, metrics) = unsafe { &mut *core::ptr::addr_of_mut!(BUFS) };
            text.len = 0;
            metrics.len = 0;
            if n > 0 && req[..n as usize].starts_with(b"GET /bench") {
                unsafe { bench(&req[..n as usize], metrics) };
            } else if n > 0 && req[..n as usize].starts_with(b"GET /set") {
                unsafe { set(&req[..n as usize], metrics) };
            } else if n > 0 && req[..n as usize].starts_with(b"GET /fsfail") {
                fsfail(metrics);
            } else if n > 0 && req[..n as usize].starts_with(b"GET /threads") {
                unsafe { threads(&req[..n as usize], metrics) };
            } else if n > 0 && req[..n as usize].starts_with(b"GET /queues") {
                queues(metrics);
            } else if n > 0 && req[..n as usize].starts_with(b"GET /modules") {
                unsafe { modules(metrics) };
            } else {
                body(start_ns, metrics);
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
            super::super::thread_hooks::create_internal(
                &mut thread,
                core::ptr::null(),
                run,
                core::ptr::null_mut(),
                c"ampr_metrics".as_ptr(),
            )
        };
    }
}

/// Debug: the game's free flexible memory when module_start began and when
/// it ended (hooks, index, pack manifest), to measure the runtime's own
/// share of the game's budget (/metrics flex_at_start_bytes,
/// flex_after_start_bytes).
#[cfg(feature = "mem_report")]
static FLEX_AT_START: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
#[cfg(feature = "mem_report")]
static FLEX_AFTER_START: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

/// The process's free flexible memory, 0 when libkernel lacks the call.
#[cfg(feature = "mem_report")]
fn flex_free_now() -> u64 {
    type FlexFn = unsafe extern "C" fn(*mut usize) -> c_int;
    let mut v = 0usize;
    match unsafe { super::sys::resolve_kernel::<FlexFn>(c"sceKernelAvailableFlexibleMemorySize") } {
        Some(f) if unsafe { f(&mut v) } == 0 => v as u64,
        _ => 0,
    }
}

#[no_mangle]
pub unsafe extern "C" fn module_start(_args: usize, _argp: *const c_void) -> c_int {
    #[cfg(feature = "mem_report")]
    FLEX_AT_START.store(flex_free_now(), core::sync::atomic::Ordering::Relaxed);
    // The knobs once (debug only; release returns at once), before the hooks
    // and the pack state, so titles with no packs read them too (thread
    // budget, pool size, equeue_local).
    unsafe { super::tune::load() };
    // Before any hook: the mode picks the hooks and the notification text.
    unsafe { super::pack::select_pack_format() };
    // Writable /app0: before the hooks, which consult it.
    unsafe { super::rw::init() };
    #[cfg(feature = "mem_report")]
    {
        unsafe { super::blackbox::open() };
        super::pack::log_discovery();
    }
    unsafe { notify_loaded() };
    let rc = unsafe { hook::amprInstallLibkernelHooks() };
    // Packed files have no physical copy (ampr_zstd-NNN.pak or the AMPRPAK4
    // volumes), and the game opens some with plain open() before any AMPR
    // call (an engine project descriptor in a zstd title, a data file in an
    // LZ4 one). Hooks never load the index, so
    // load AMPRIDX3 and the pack manifest here, before the game runs (zstd
    // also mounts ampr_zstd.index and builds the id projection). Without a
    // shipped index this fails at once: ensure_ready(false) never builds one.
    // A title with no packs skips it and loads its index on the first AMPR
    // call.
    if super::pack::packs_present() && rc == 0 && unsafe { super::index::ensure_ready(false) } {
        unsafe { super::pack::ampr_pack_ensure_manifest_ready_safe() };
    }
    // Only after hooks install: a failed module_start may be unloaded.
    #[cfg(feature = "mem_report")]
    if rc == 0 {
        unsafe { mem_report::start() };
    }
    #[cfg(feature = "mem_report")]
    FLEX_AFTER_START.store(flex_free_now(), core::sync::atomic::Ordering::Relaxed);
    rc
}

#[no_mangle]
pub unsafe extern "C" fn module_stop(_args: usize, _argp: *const c_void) -> c_int {
    if unsafe { ampr_pack_shutdown() } != 0 || unsafe { apr_reactor_shutdown() } != 0 {
        return -1;
    }
    // shutdownCommandLog/shutdownDebugLog are no-ops returning 0.
    let rc = unsafe { hook::amprUninstallLibkernelHooks() };
    if rc == 0 {
        unsafe { super::index::release_resident_index() };
    }
    #[cfg(feature = "mem_report")]
    super::blackbox::close();
    rc
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
