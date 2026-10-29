//! PRX startup/shutdown contract, formerly ps5/crt (crti.S, crtbeginS.c,
//! crtendS.c, crtn.S). Same sections, symbols and init/fini order; the data
//! that needs section placement or weak references lives in the asm block,
//! the loops are Rust. Relies on ampr-sys being one codegen unit, so the
//! `.hidden` directives see the Rust definitions of `_init`/`_fini`.

use core::ffi::{c_int, c_void};
use core::sync::atomic::{AtomicBool, Ordering};

type CrtFn = Option<unsafe extern "C" fn()>;
type ModuleFn = Option<unsafe extern "C" fn(usize, *const c_void) -> c_int>;

core::arch::global_asm!(
    // .sceversion records in the old link order: crti, crtbeginS, crtendS, crtn.
    ".pushsection .sceversion,\"\",@progbits",
    ".byte 0x00,0x00,0x16,0x00,0x08,0x63,0x72,0x74,0x69,0x3a,0x02,0x00,0x00",
    ".byte 0x09,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x09,0x00,0x00,0x00,0x01",
    ".byte 0x00,0x00,0x1b,0x00,0x08,0x63,0x72,0x74,0x62,0x65,0x67,0x69,0x6e,0x53,0x3a,0x02",
    ".byte 0x00,0x00,0x09,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x09,0x00,0x00,0x00,0x01",
    ".byte 0x00,0x00,0x19,0x00,0x08,0x63,0x72,0x74,0x65,0x6e,0x64,0x53,0x3a,0x02,0x00,0x00",
    ".byte 0x09,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x09,0x00,0x00,0x00,0x01",
    ".byte 0x00,0x00,0x16,0x00,0x08,0x63,0x72,0x74,0x6e,0x3a,0x02,0x00,0x00",
    ".byte 0x09,0x00,0x00,0x00,0x01,0x02,0x00,0x00,0x09,0x00,0x00,0x00,0x01",
    ".popsection",
    // DSO handle and the libSceLibcInternal anchor.
    ".pushsection .data.__dso_handle,\"aw\",@progbits",
    ".p2align 3",
    ".globl __dso_handle",
    ".hidden __dso_handle",
    "__dso_handle: .quad __dso_handle",
    ".popsection",
    ".pushsection .data.sceLibcInternal,\"aw\",@progbits",
    ".p2align 3",
    ".globl ampr_crt_libc_anchor",
    ".hidden ampr_crt_libc_anchor",
    "ampr_crt_libc_anchor: .quad Need_sceLibcInternal",
    ".popsection",
    // ctor/dtor sentinels: -1 start marker, 0 end marker (no entries between).
    ".pushsection .ctors,\"aw\",@progbits",
    ".p2align 3",
    ".quad -1",
    ".quad 0",
    ".popsection",
    ".pushsection .dtors,\"aw\",@progbits",
    ".p2align 3",
    ".quad -1",
    ".quad 0",
    ".popsection",
    // Module parameters read by the loader.
    ".pushsection .sce_module_param,\"a\",@progbits",
    ".p2align 3",
    ".globl _sceModuleParam",
    ".hidden _sceModuleParam",
    "_sceModuleParam:",
    ".byte 0x20,0x00,0x00,0x00,0x00,0x00,0x00,0x00",
    ".byte 0xbf,0xf4,0x13,0x3c,0x03,0x00,0x00,0x00",
    ".byte 0x01,0x00,0x05,0x08,0x09,0x00,0x00,0x02",
    ".byte 0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00",
    ".popsection",
    // Weak __cxa_finalize: resolves to the libSceLibcInternal import, or 0.
    ".weak __cxa_finalize",
    ".pushsection .data.rel.ro.ampr_crt,\"aw\",@progbits",
    ".p2align 3",
    ".globl ampr_crt_cxa_finalize",
    ".hidden ampr_crt_cxa_finalize",
    "ampr_crt_cxa_finalize: .quad __cxa_finalize",
    ".popsection",
    ".hidden _init",
    ".hidden _fini",
);

extern "C" {
    static ampr_crt_cxa_finalize: Option<unsafe extern "C" fn(*mut c_void)>;
    static ampr_crt_libc_anchor: *const c_int;
    static __dso_handle: *mut c_void;
    static __start__Zpreinit_array: [CrtFn; 0];
    static __stop__Zpreinit_array: [CrtFn; 0];
    static __CTOR_LIST__: [CrtFn; 0];
    static __CTOR_END__: [CrtFn; 0];
    static __DTOR_LIST__: [CrtFn; 0];
    static __DTOR_END__: [CrtFn; 0];
}

static FINI_COMPLETED: AtomicBool = AtomicBool::new(false);
const SENTINEL: usize = usize::MAX;

fn entry_addr(f: CrtFn) -> usize {
    f.map_or(0, |f| f as usize)
}

/// Loader entry (DT_INIT): preinit array, constructors, then module_start.
#[no_mangle]
#[link_section = ".init"]
pub unsafe extern "C" fn _init(args: usize, argp: *const c_void, over: ModuleFn) -> c_int {
    unsafe {
        // Keeps the libSceLibcInternal anchor alive under --gc-sections.
        let _ = core::ptr::read_volatile(&raw const ampr_crt_libc_anchor);
        let mut p = __start__Zpreinit_array.as_ptr();
        while p < __stop__Zpreinit_array.as_ptr() {
            if let Some(f) = *p {
                f();
            }
            p = p.add(1);
        }
        let mut p = __CTOR_END__.as_ptr();
        while p > __CTOR_LIST__.as_ptr() {
            p = p.sub(1);
            let addr = entry_addr(*p);
            if addr != 0 && addr != SENTINEL {
                if let Some(f) = *p {
                    f();
                }
            }
        }
        match over {
            Some(f) => f(args, argp),
            None => crate::rt::exports::module_start(args, argp),
        }
    }
}

/// Loader exit (DT_FINI): module_stop, __cxa_finalize, destructors; runs once.
#[no_mangle]
#[link_section = ".fini"]
pub unsafe extern "C" fn _fini(args: usize, argp: *const c_void, over: ModuleFn) -> c_int {
    if FINI_COMPLETED.load(Ordering::Acquire) {
        return 0;
    }
    unsafe {
        let result = match over {
            Some(f) => f(args, argp),
            None => crate::rt::exports::module_stop(args, argp),
        };
        if let Some(fin) = ampr_crt_cxa_finalize {
            fin(__dso_handle);
        }
        let mut p = __DTOR_LIST__.as_ptr().add(1);
        while p < __DTOR_END__.as_ptr() {
            match *p {
                Some(f) => f(),
                None => break,
            }
            p = p.add(1);
        }
        FINI_COMPLETED.store(true, Ordering::Release);
        result
    }
}
