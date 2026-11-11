//! The 19 libc/libc++ symbols that retail libSceAmpr.sprx exports besides
//! the sceAmpr* API. Retail links these statically, so a title built against
//! the retail stub library can import them from libSceAmpr; without them the
//! title does not resolve. The list and the semantics follow AnyPS5
//! (core/libs/prx/libSceAmpr/Export.cpp and core/libs/prx/libc/include/SonyCrt.hpp).
//!
//! Each function is defined under an `ampr_libc_*` name and exported under the
//! libc NID by the table in tools/generate_payload_exports.py (EXTRA_EXPORTS).
//! No new static libc import is added: a NID that libc.prx does not export
//! would stop the whole fakelib from loading. Most functions are native
//! (retail's copies are statically linked too, with their own "C" locale and
//! constraint-handler state). Only `_Cnd_init_with_name` and the local-time
//! step of `ctime_s` need libc's state; they find libc at run time through
//! sceKernelGetModuleList + sceKernelDlsym and skip this module's own export.
#![allow(non_snake_case)]

use core::ffi::{c_char, c_int, c_void};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

use super::sys;

/// FreeBSD errno values, as returned by the `_s` functions (errno_t).
const EINVAL: c_int = 22;
const ERANGE: c_int = 34;
const EILSEQ: c_int = 86;
/// RSIZE_MAX as used by AnyPS5 (SIZE_MAX >> 1).
const RSIZE_MAX: usize = usize::MAX >> 1;

// ---- run-time libc lookup ----

/// Resolve-once cache for a symbol of another loaded module.
struct ModuleSym {
    name: &'static core::ffi::CStr,
    p: AtomicUsize, // 0 = unresolved, 1 = absent
}

impl ModuleSym {
    const fn new(name: &'static core::ffi::CStr) -> Self {
        Self {
            name,
            p: AtomicUsize::new(0),
        }
    }

    /// First definition of `name` in the loaded modules whose address is
    /// not `own` (this module exports the same NID).
    unsafe fn get(&self, own: usize) -> *mut c_void {
        let mut v = self.p.load(Ordering::Acquire);
        if v == 0 {
            let r = unsafe { find_in_modules(self.name.as_ptr(), own) } as usize;
            v = if r == 0 { 1 } else { r };
            self.p.store(v, Ordering::Release);
        }
        if v == 1 {
            null_mut()
        } else {
            v as *mut c_void
        }
    }
}

unsafe fn find_in_modules(name: *const c_char, own: usize) -> *mut c_void {
    type ListFn = unsafe extern "C" fn(*mut sys::SceKernelModule, usize, *mut usize) -> c_int;
    let Some(list) = (unsafe { sys::resolve_kernel::<ListFn>(c"sceKernelGetModuleList") }) else {
        return null_mut();
    };
    let mut mods = [0 as sys::SceKernelModule; 256];
    let mut n = 0usize;
    if unsafe { list(mods.as_mut_ptr(), mods.len(), &mut n) } != 0 {
        return null_mut();
    }
    for &m in &mods[..n.min(mods.len())] {
        let mut p = null_mut();
        if unsafe { sys::sceKernelDlsym(m, name, &mut p) } == 0 && !p.is_null() && p as usize != own
        {
            return p;
        }
    }
    null_mut()
}

// ---- integer and float helpers ----

/// `__udivti3`: unsigned 128-bit division. Division by zero traps like the
/// x86 `div` instruction would (AnyPS5 throws).
#[no_mangle]
pub extern "C" fn ampr_libc_udivti3(a: u128, b: u128) -> u128 {
    if b == 0 {
        sys::abort();
    }
    a / b
}

/// `_Fltrounds`: FLT_ROUNDS. 1 is round-to-nearest.
/// Returns the default mode instead of reading MXCSR: titles do not
/// change the SSE rounding mode in practice.
#[no_mangle]
pub extern "C" fn ampr_libc_fltrounds() -> c_int {
    1
}

/// `__fpclassifyd`: Dinkumware class codes (_NANCODE 2, _INFCODE 1, 0 for
/// zero, _DENORM -2, _FINITE -1), as AnyPS5 SonyFpclassifyd.
#[no_mangle]
pub extern "C" fn ampr_libc_fpclassifyd(x: f64) -> c_int {
    let bits = x.to_bits();
    let exp = (bits >> 52) & 0x7ff;
    let frac = bits & ((1u64 << 52) - 1);
    match (exp, frac) {
        (0x7ff, 0) => 1,
        (0x7ff, _) => 2,
        (0, 0) => 0,
        (0, _) => -2,
        _ => -1,
    }
}

/// `_Sinh(x, y)`: `y * sinh(x)` (AnyPS5 SonySinh).
#[no_mangle]
pub extern "C" fn ampr_libc_sinh(x: f64, y: f64) -> f64 {
    y * sinh(x)
}

fn fabs(x: f64) -> f64 {
    f64::from_bits(x.to_bits() & !(1u64 << 63))
}

/// e^t for 0 <= t <= 356: t = k*ln2 + r with |r| <= ln2/2, a degree-14
/// Taylor polynomial for e^r (truncation below 1e-17 relative), then 2^k.
fn exp_small(t: f64) -> f64 {
    const LN2_HI: f64 = 6.931_471_803_691_238_164_90e-1;
    const LN2_LO: f64 = 1.908_214_929_270_587_700_02e-10;
    const INV_LN2: f64 = 1.442_695_040_888_963_387_00;
    let k = (t * INV_LN2 + 0.5) as i64;
    let kf = k as f64;
    let r = (t - kf * LN2_HI) - kf * LN2_LO;
    let mut p = 1.0;
    let mut i = 14;
    while i > 0 {
        p = 1.0 + p * r / i as f64;
        i -= 1;
    }
    p * f64::from_bits(((1023 + k) as u64) << 52)
}

fn sinh(x: f64) -> f64 {
    let a = fabs(x);
    if a.is_nan() || a == f64::INFINITY {
        return x;
    }
    let s = if a < 1.0 {
        // Odd Taylor series; the x^27 term is below 1e-28.
        let a2 = a * a;
        let mut sum = 1.0;
        let mut n = 27.0;
        while n > 1.0 {
            sum = 1.0 + sum * a2 / (n * (n - 1.0));
            n -= 2.0;
        }
        a * sum
    } else if a < 22.0 {
        let e = exp_small(a);
        (e - 1.0 / e) * 0.5
    } else if a < 711.0 {
        // e^-a is below one ulp; split e^a so it does not overflow early.
        let h = exp_small(a * 0.5);
        h * (h * 0.5)
    } else {
        f64::INFINITY
    };
    if x < 0.0 {
        -s
    } else {
        s
    }
}

// ---- bounds-checked string functions ----

type ConstraintHandler = unsafe extern "C" fn(*const c_char, *mut c_void, c_int);

/// Installed constraint handler; null means the default (abort).
static CONSTRAINT_HANDLER: AtomicPtr<c_void> = AtomicPtr::new(null_mut());

/// Default handler, as AnyPS5 SonyDefaultConstraintHandler: abort.
unsafe extern "C" fn default_constraint_handler(_: *const c_char, _: *mut c_void, _: c_int) {
    sys::abort();
}

unsafe fn invoke_constraint_handler(msg: &core::ffi::CStr, ptr: *mut c_void, err: c_int) {
    let h = CONSTRAINT_HANDLER.load(Ordering::Acquire);
    let h: ConstraintHandler = match unsafe { sys::fn_from_ptr(h) } {
        Some(f) => f,
        None => default_constraint_handler,
    };
    unsafe { h(msg.as_ptr(), ptr, err) };
}

/// `set_constraint_handler_s`: install `handler` (null restores the
/// default) and return the previous one.
#[no_mangle]
pub unsafe extern "C" fn ampr_libc_set_constraint_handler_s(handler: *mut c_void) -> *mut c_void {
    let prev = CONSTRAINT_HANDLER.swap(handler, Ordering::AcqRel);
    if prev.is_null() {
        default_constraint_handler as *mut c_void
    } else {
        prev
    }
}

/// `ignore_handler_s`: the do-nothing constraint handler.
#[no_mangle]
pub unsafe extern "C" fn ampr_libc_ignore_handler_s(_: *const c_char, _: *mut c_void, _: c_int) {}

unsafe fn in_set(c: c_char, set: *const c_char) -> bool {
    let mut p = set;
    loop {
        let d = unsafe { *p };
        if d == 0 {
            return false;
        }
        if d == c {
            return true;
        }
        p = unsafe { p.add(1) };
    }
}

/// `strtok_s(str, delim, context)`: the 3-argument form AnyPS5 implements.
#[no_mangle]
pub unsafe extern "C" fn ampr_libc_strtok_s(
    s: *mut c_char,
    delim: *const c_char,
    context: *mut *mut c_char,
) -> *mut c_char {
    if delim.is_null() || context.is_null() {
        return null_mut();
    }
    let mut cur = if s.is_null() { unsafe { *context } } else { s };
    if cur.is_null() {
        return null_mut();
    }
    while unsafe { *cur } != 0 && unsafe { in_set(*cur, delim) } {
        cur = unsafe { cur.add(1) };
    }
    if unsafe { *cur } == 0 {
        unsafe { *context = cur };
        return null_mut();
    }
    let token = cur;
    while unsafe { *cur } != 0 && !unsafe { in_set(*cur, delim) } {
        cur = unsafe { cur.add(1) };
    }
    if unsafe { *cur } != 0 {
        unsafe { *cur = 0 };
        unsafe { *context = cur.add(1) };
    } else {
        unsafe { *context = cur };
    }
    token
}

/// `wcscpy_s` with the 16-bit wchar_t of the PS5 ABI (AnyPS5 SonyWcscpyS).
#[no_mangle]
pub unsafe extern "C" fn ampr_libc_wcscpy_s(dest: *mut u16, size: usize, src: *const u16) -> c_int {
    let fail = |err: c_int, clear: bool| {
        if clear {
            unsafe { *dest = 0 };
        }
        unsafe { invoke_constraint_handler(c"wcscpy_s", dest.cast(), err) };
        err
    };
    if dest.is_null() || size == 0 {
        return fail(EINVAL, false);
    }
    if size > RSIZE_MAX / 2 {
        return fail(ERANGE, false);
    }
    if src.is_null() {
        return fail(EINVAL, true);
    }
    let mut len = 0usize;
    while len < size && unsafe { *src.add(len) } != 0 {
        len += 1;
    }
    if len >= size {
        return fail(ERANGE, true);
    }
    let (d, s) = (dest as usize, src as usize);
    let distance = d.abs_diff(s);
    if distance < (len + 1) * 2 {
        return fail(EINVAL, true);
    }
    unsafe { core::ptr::copy_nonoverlapping(src, dest, len + 1) };
    0
}

// ---- locale and multibyte ("C" locale) ----

/// Sony `struct lconv` (AnyPS5 SonyLconv: 0x90 bytes, decimal_point at 0x48).
#[repr(C)]
pub struct SonyLconv {
    monetary: [*const c_char; 7],
    chars: [c_char; 14],
    pad: [c_char; 2],
    decimal_point: *const c_char,
    grouping: *const c_char,
    thousands_sep: *const c_char,
    frac_grouping: *const c_char,
    frac_sep: *const c_char,
    false_text: *const c_char,
    true_text: *const c_char,
    no_text: *const c_char,
    yes_text: *const c_char,
}

struct SyncLconv(SonyLconv);
// SAFETY: read-only after init; the pointers name static strings.
unsafe impl Sync for SyncLconv {}

const EMPTY: *const c_char = c"".as_ptr();
static C_LCONV: SyncLconv = SyncLconv(SonyLconv {
    monetary: [EMPTY; 7],
    chars: [c_char::MAX; 14],
    pad: [0; 2],
    decimal_point: c".".as_ptr(),
    grouping: EMPTY,
    thousands_sep: EMPTY,
    frac_grouping: EMPTY,
    frac_sep: EMPTY,
    false_text: c"false".as_ptr(),
    true_text: c"true".as_ptr(),
    no_text: EMPTY,
    yes_text: EMPTY,
});

/// `localeconv`: the "C" locale values of AnyPS5 SonyLocaleconv. Callers
/// must not write through the result (C says the same).
#[no_mangle]
pub extern "C" fn ampr_libc_localeconv() -> *mut SonyLconv {
    &C_LCONV.0 as *const SonyLconv as *mut SonyLconv
}

/// `mbstowcs`: "C" locale, one byte per wide char (AnyPS5 SonyMbstowcs).
#[no_mangle]
pub unsafe extern "C" fn ampr_libc_mbstowcs(
    dest: *mut u16,
    src: *const c_char,
    size: usize,
) -> usize {
    if src.is_null() {
        return 0;
    }
    if dest.is_null() {
        return unsafe { sys::strlen(src) };
    }
    for i in 0..size {
        let b = unsafe { *src.add(i) } as u8;
        unsafe { *dest.add(i) = b as u16 };
        if b == 0 {
            return i;
        }
    }
    size
}

/// `wcstombs_s` (C11 K.3.6.5.2) in the "C" locale: a wide char above 0xff
/// is an encoding error.
/// No multibyte locales: Dinkumware's "C" locale maps 0..=0xff 1:1.
#[no_mangle]
pub unsafe extern "C" fn ampr_libc_wcstombs_s(
    retval: *mut usize,
    dst: *mut c_char,
    dstmax: usize,
    src: *const u16,
    len: usize,
) -> c_int {
    let bad = retval.is_null()
        || src.is_null()
        || (dst.is_null() && dstmax != 0)
        || (!dst.is_null() && dstmax == 0)
        || dstmax > RSIZE_MAX
        || len > RSIZE_MAX;
    if bad {
        if !retval.is_null() {
            unsafe { *retval = usize::MAX };
        }
        if !dst.is_null() && dstmax != 0 && dstmax <= RSIZE_MAX {
            unsafe { *dst = 0 };
        }
        unsafe { invoke_constraint_handler(c"wcstombs_s", dst.cast(), EINVAL) };
        return EINVAL;
    }
    let limit = if dst.is_null() { usize::MAX } else { len };
    let mut n = 0usize;
    loop {
        if n >= limit {
            break;
        }
        let w = unsafe { *src.add(n) };
        if w == 0 {
            break;
        }
        if w > 0xff {
            unsafe { *retval = usize::MAX };
            if !dst.is_null() {
                unsafe { *dst = 0 };
            }
            return EILSEQ;
        }
        if !dst.is_null() {
            if n + 1 >= dstmax {
                unsafe { *retval = usize::MAX };
                unsafe { *dst = 0 };
                unsafe { invoke_constraint_handler(c"wcstombs_s", dst.cast(), ERANGE) };
                return ERANGE;
            }
            unsafe { *dst.add(n) = w as c_char };
        }
        n += 1;
    }
    if !dst.is_null() {
        unsafe { *dst.add(n) = 0 };
    }
    unsafe { *retval = n };
    0
}

// ---- time formatting ----

/// FreeBSD `struct tm` (AnyPS5 GuestTm, 56 bytes).
#[repr(C)]
pub struct Tm {
    tm_sec: c_int,
    tm_min: c_int,
    tm_hour: c_int,
    tm_mday: c_int,
    tm_mon: c_int,
    tm_year: c_int,
    tm_wday: c_int,
    tm_yday: c_int,
    tm_isdst: c_int,
    tm_gmtoff: i64,
    tm_zone: *const c_char,
}

/// asctime layout "Www Mmm dd hh:mm:ss yyyy\n" (26 bytes with the NUL), as
/// AnyPS5 SonyFormatAsctime: fields out of range give EINVAL.
/// The callers check `buf` and size >= 26.
unsafe fn format_asctime(buf: *mut c_char, t: &Tm) -> c_int {
    const DAYS: &[u8; 21] = b"SunMonTueWedThuFriSat";
    const MONTHS: &[u8; 36] = b"JanFebMarAprMayJunJulAugSepOctNovDec";
    let year = t.tm_year as i64 + 1900;
    let ok = (0..=6).contains(&t.tm_wday)
        && (0..=11).contains(&t.tm_mon)
        && (1..=31).contains(&t.tm_mday)
        && (0..=23).contains(&t.tm_hour)
        && (0..=59).contains(&t.tm_min)
        && (0..=60).contains(&t.tm_sec)
        && (0..=9999).contains(&year);
    if !ok {
        unsafe { *buf = 0 };
        return EINVAL;
    }
    let mut out = [b' '; 26];
    let (w, m) = (t.tm_wday as usize * 3, t.tm_mon as usize * 3);
    out[0..3].copy_from_slice(&DAYS[w..w + 3]);
    out[4..7].copy_from_slice(&MONTHS[m..m + 3]);
    let two = |o: &mut [u8], v: c_int, pad: u8| {
        o[0] = if v >= 10 { b'0' + (v / 10) as u8 } else { pad };
        o[1] = b'0' + (v % 10) as u8;
    };
    two(&mut out[8..10], t.tm_mday, b' ');
    two(&mut out[11..13], t.tm_hour, b'0');
    out[13] = b':';
    two(&mut out[14..16], t.tm_min, b'0');
    out[16] = b':';
    two(&mut out[17..19], t.tm_sec, b'0');
    // "%4d": right-aligned, space padded.
    let mut y = year as u32;
    for i in (20..24).rev() {
        out[i] = if y == 0 && i < 23 {
            b' '
        } else {
            b'0' + (y % 10) as u8
        };
        y /= 10;
    }
    out[24] = b'\n';
    out[25] = 0;
    unsafe { core::ptr::copy_nonoverlapping(out.as_ptr().cast(), buf, out.len()) };
    0
}

/// `asctime_s(buf, size, tm)` (AnyPS5 SonyAsctimeS).
#[no_mangle]
pub unsafe extern "C" fn ampr_libc_asctime_s(buf: *mut c_char, size: usize, t: *const Tm) -> c_int {
    if buf.is_null() || size < 26 {
        return EINVAL;
    }
    if t.is_null() {
        unsafe { *buf = 0 };
        return EINVAL;
    }
    unsafe { format_asctime(buf, &*t) }
}

static LOCALTIME_R: ModuleSym = ModuleSym::new(c"localtime_r");
static GMTIME_R: ModuleSym = ModuleSym::new(c"gmtime_r");

/// `ctime_s(buf, size, time)` (AnyPS5 SonyCtimeS): local time through libc's
/// localtime_r, found at run time (a static import would add a NID to the
/// PRX import table; this path is rare enough to resolve lazily).
/// Falls back to UTC (gmtime_r) when localtime_r is not found.
#[no_mangle]
pub unsafe extern "C" fn ampr_libc_ctime_s(
    buf: *mut c_char,
    size: usize,
    time: *const i64,
) -> c_int {
    if buf.is_null() || size < 26 {
        return EINVAL;
    }
    if time.is_null() {
        unsafe { *buf = 0 };
        return EINVAL;
    }
    type LocalFn = unsafe extern "C" fn(*const i64, *mut Tm) -> *mut Tm;
    let mut parts: Tm = unsafe { core::mem::zeroed() };
    let mut f = unsafe { sys::fn_from_ptr::<LocalFn>(LOCALTIME_R.get(0)) };
    if f.is_none() {
        f = unsafe { sys::fn_from_ptr::<LocalFn>(GMTIME_R.get(0)) };
    }
    let r = match f {
        Some(f) => unsafe { f(time, &mut parts) },
        None => null_mut(),
    };
    if r.is_null() {
        unsafe { *buf = 0 };
        return EINVAL;
    }
    unsafe { format_asctime(buf, &parts) }
}

// ---- threads and C++ runtime ----

/// One global flag, as AnyPS5 `sharedPtrSpinLock`.
static SHARED_PTR_SPIN_LOCK: AtomicBool = AtomicBool::new(false);

/// `_Lock_shared_ptr_spin_lock`: libc++ atomic shared_ptr access lock.
#[no_mangle]
pub extern "C" fn ampr_libc_lock_shared_ptr_spin_lock() {
    let mut spins = 0u32;
    while SHARED_PTR_SPIN_LOCK
        .compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed)
        .is_err()
    {
        super::sync::spin_pause_or_yield(&mut spins);
    }
}

/// `_Unlock_shared_ptr_spin_lock`.
#[no_mangle]
pub extern "C" fn ampr_libc_unlock_shared_ptr_spin_lock() {
    SHARED_PTR_SPIN_LOCK.store(false, Ordering::Release);
}

/// Dinkumware `_Thrd_error`.
const THRD_ERROR: c_int = 4;

static CND_INIT_WITH_NAME: ModuleSym = ModuleSym::new(c"_Cnd_init_with_name");
static CND_INIT: ModuleSym = ModuleSym::new(c"_Cnd_init");

/// `_Cnd_init_with_name(handle, name)`: the handle is later passed to libc's
/// _Cnd_wait/_Cnd_signal, so it must come from libc. AnyPS5 maps it to
/// _Cnd_init; this forwards to libc's _Cnd_init_with_name, else _Cnd_init.
#[no_mangle]
pub unsafe extern "C" fn ampr_libc_cnd_init_with_name(
    handle: *mut *mut c_void,
    name: *const c_char,
) -> c_int {
    type WithName = unsafe extern "C" fn(*mut *mut c_void, *const c_char) -> c_int;
    type Plain = unsafe extern "C" fn(*mut *mut c_void) -> c_int;
    let own = ampr_libc_cnd_init_with_name as *const () as usize;
    if let Some(f) = unsafe { sys::fn_from_ptr::<WithName>(CND_INIT_WITH_NAME.get(own)) } {
        return unsafe { f(handle, name) };
    }
    if let Some(f) = unsafe { sys::fn_from_ptr::<Plain>(CND_INIT.get(own)) } {
        return unsafe { f(handle) };
    }
    THRD_ERROR
}

/// `std::time_get<char>::get(...)`: stub returning 0, as AnyPS5.
/// Not implemented: no title is known to reach it through libSceAmpr.
#[no_mangle]
pub extern "C" fn ampr_libc_time_get_get() -> c_int {
    0
}

/// `std::time_get<char>::_Getcat(...)`: stub returning 0, as AnyPS5.
/// Not implemented; see ampr_libc_time_get_get.
#[no_mangle]
pub extern "C" fn ampr_libc_time_get_getcat() -> c_int {
    0
}

/// `__cxa_call_unexpected`: an exception escaped a dynamic exception
/// specification; terminate (AnyPS5 calls __cxa_call_terminate).
#[no_mangle]
pub extern "C" fn ampr_libc_cxa_call_unexpected(_: *mut c_void) -> ! {
    sys::abort()
}

// ---- tests ----

#[cfg(test)]
mod tests {
    use super::*;

    fn wide(s: &str) -> [u16; 16] {
        let mut out = [0u16; 16];
        for (o, b) in out.iter_mut().zip(s.bytes()) {
            *o = b as u16;
        }
        out
    }

    fn quiet_handler() {
        unsafe { ampr_libc_set_constraint_handler_s(ampr_libc_ignore_handler_s as *mut c_void) };
    }

    /// udivti3 matches u128 division, fpclassifyd uses Dinkumware codes, and
    /// sinh scales by `y` and matches std.
    #[test]
    fn math_helpers_match_reference() {
        let a = (0x1234_5678_9abc_def0u128 << 64) | 0xfedc_ba98_7654_3210;
        assert_eq!(ampr_libc_udivti3(a, 3), a / 3);
        assert_eq!(ampr_libc_udivti3(a, a), 1);
        assert_eq!(ampr_libc_udivti3(7, u128::MAX), 0);
        assert_eq!(ampr_libc_udivti3(u128::MAX, 1 << 64), u64::MAX as u128);
        assert_eq!(ampr_libc_fpclassifyd(f64::NAN), 2);
        assert_eq!(ampr_libc_fpclassifyd(f64::NEG_INFINITY), 1);
        assert_eq!(ampr_libc_fpclassifyd(-0.0), 0);
        assert_eq!(ampr_libc_fpclassifyd(f64::MIN_POSITIVE / 4.0), -2);
        assert_eq!(ampr_libc_fpclassifyd(1.5), -1);
        assert_eq!(ampr_libc_fltrounds(), 1);
        for &x in &[
            0.0f64, 1e-300, 1e-8, 0.3, -0.99, 1.0, -2.5, 10.0, 21.9, 22.5, -300.0, 709.0, 710.4,
        ] {
            let want = -0.5 * x.sinh();
            let got = ampr_libc_sinh(x, -0.5);
            let err = ((got - want) / want).abs();
            assert!(
                x == 0.0 && got == 0.0 || err < 4e-16,
                "x={x} got={got} want={want}"
            );
        }
        assert_eq!(ampr_libc_sinh(711.0, 1.0), f64::INFINITY);
        assert_eq!(ampr_libc_sinh(f64::NEG_INFINITY, 1.0), f64::NEG_INFINITY);
        assert!(ampr_libc_sinh(f64::NAN, 1.0).is_nan());
    }

    /// strtok_s keeps its context; wcscpy_s, asctime_s and wcstombs_s copy,
    /// format and reject bad sizes, null pointers and overlap.
    #[test]
    fn bounds_checked_string_functions() {
        quiet_handler();
        let mut buf = *b",,ab,c;;d\0";
        let delim = c",;".as_ptr();
        let mut ctx = null_mut();
        let mut tokens = [[0u8; 4]; 4];
        let mut n = 0;
        let mut s = buf.as_mut_ptr().cast::<c_char>();
        loop {
            let t = unsafe { ampr_libc_strtok_s(s, delim, &mut ctx) };
            if t.is_null() {
                break;
            }
            let c = unsafe { core::ffi::CStr::from_ptr(t) }.to_bytes();
            tokens[n][..c.len()].copy_from_slice(c);
            n += 1;
            s = null_mut();
        }
        assert_eq!(n, 3);
        assert_eq!(&tokens[..3], &[*b"ab\0\0", *b"c\0\0\0", *b"d\0\0\0"]);
        assert!(unsafe { ampr_libc_strtok_s(null_mut(), delim, &mut ctx) }.is_null());
        assert!(
            unsafe { ampr_libc_strtok_s(buf.as_mut_ptr().cast(), delim, null_mut()) }.is_null()
        );
        let src = wide("hello");
        let mut dst = [0xffffu16; 8];
        assert_eq!(
            unsafe { ampr_libc_wcscpy_s(dst.as_mut_ptr(), 8, src.as_ptr()) },
            0
        );
        assert_eq!(&dst[..6], &src[..6]);
        let mut small = [0xffffu16; 5];
        assert_eq!(
            unsafe { ampr_libc_wcscpy_s(small.as_mut_ptr(), 5, src.as_ptr()) },
            ERANGE
        );
        assert_eq!(small[0], 0);
        assert_eq!(
            unsafe { ampr_libc_wcscpy_s(dst.as_mut_ptr(), 8, core::ptr::null()) },
            EINVAL
        );
        assert_eq!(
            unsafe { ampr_libc_wcscpy_s(null_mut(), 8, src.as_ptr()) },
            EINVAL
        );
        assert_eq!(
            unsafe { ampr_libc_wcscpy_s(dst.as_mut_ptr(), 0, src.as_ptr()) },
            EINVAL
        );
        let mut overlap = wide("abc");
        let p = overlap.as_mut_ptr();
        assert_eq!(unsafe { ampr_libc_wcscpy_s(p.add(1), 8, p) }, EINVAL);
        // An empty string copied onto itself overlaps too.
        let mut empty = wide("");
        let e = empty.as_mut_ptr();
        assert_eq!(unsafe { ampr_libc_wcscpy_s(e, 8, e) }, EINVAL);
        let t = Tm {
            tm_sec: 5,
            tm_min: 4,
            tm_hour: 3,
            tm_mday: 1,
            tm_mon: 10,
            tm_year: 126,
            tm_wday: 0,
            tm_yday: 0,
            tm_isdst: 0,
            tm_gmtoff: 0,
            tm_zone: core::ptr::null(),
        };
        let mut buf = [0 as c_char; 26];
        assert_eq!(unsafe { ampr_libc_asctime_s(buf.as_mut_ptr(), 26, &t) }, 0);
        let got = unsafe { core::ffi::CStr::from_ptr(buf.as_ptr()) }.to_bytes();
        assert_eq!(got, b"Sun Nov  1 03:04:05 2026\n");
        assert_eq!(
            unsafe { ampr_libc_asctime_s(buf.as_mut_ptr(), 25, &t) },
            EINVAL
        );
        let src = wide("abc");
        let (mut n, mut out) = (0usize, [0 as c_char; 4]);
        assert_eq!(
            unsafe { ampr_libc_wcstombs_s(&mut n, out.as_mut_ptr(), 4, src.as_ptr(), 3) },
            0
        );
        assert_eq!((n, out), (3, [97, 98, 99, 0]));
        assert_eq!(
            unsafe { ampr_libc_wcstombs_s(&mut n, out.as_mut_ptr(), 3, src.as_ptr(), 3) },
            ERANGE
        );
        assert_eq!(
            unsafe { ampr_libc_wcstombs_s(&mut n, null_mut(), 0, src.as_ptr(), 0) },
            0
        );
        assert_eq!(n, 3);
    }
}
