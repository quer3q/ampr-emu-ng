#![cfg_attr(not(test), no_std)]

extern crate alloc;
// Host staticlib builds need std's panic runtime; the PS5 target stays no_std.
#[cfg(all(not(test), not(target_os = "freebsd")))]
extern crate std;

mod cache_ffi;
#[cfg(all(not(test), target_os = "freebsd"))]
mod crt;
mod handle_ffi;
mod overlay_ffi;
mod rt;
mod volume_ffi;

#[cfg(not(test))]
use core::ffi::c_void;
#[cfg(all(not(test), target_os = "freebsd"))]
use core::panic::PanicInfo;

// LLVM lowers some byte-slice equality checks to bcmp. Volatile loads keep
// this shim from being folded back into a call to itself. Host tests link std,
// which already provides it.
#[cfg(not(test))]
#[no_mangle]
pub unsafe extern "C" fn bcmp(left: *const c_void, right: *const c_void, len: usize) -> i32 {
    let left = left.cast::<u8>();
    let right = right.cast::<u8>();
    for i in 0..len {
        let a = unsafe { core::ptr::read_volatile(left.wrapping_add(i)) };
        let b = unsafe { core::ptr::read_volatile(right.wrapping_add(i)) };
        if a != b {
            return 1;
        }
    }
    0
}

// iced-x86 (ampr-hook) needs `alloc`. libc malloc is 16-byte aligned; refuse
// stricter layouts rather than over-allocate. Host tests use std's allocator.
#[cfg(not(test))]
struct LibcAlloc;

#[cfg(not(test))]
unsafe impl core::alloc::GlobalAlloc for LibcAlloc {
    unsafe fn alloc(&self, layout: core::alloc::Layout) -> *mut u8 {
        if layout.align() > 16 {
            return core::ptr::null_mut();
        }
        unsafe { rt::sys::malloc(layout.size()) }.cast()
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _: core::alloc::Layout) {
        unsafe { rt::sys::free(ptr.cast()) }
    }
}

#[cfg(not(test))]
#[global_allocator]
static ALLOC: LibcAlloc = LibcAlloc;

// The PS5 CRT has no Rust startup or unwinder. Trap directly on x86-64 so the
// Rust archive does not introduce a plain, un-NID-mapped libc import.
#[cfg(all(not(test), target_os = "freebsd", not(target_arch = "x86_64")))]
unsafe extern "C" {
    fn abort() -> !;
}

#[cfg(all(not(test), target_os = "freebsd"))]
#[panic_handler]
fn panic(_: &PanicInfo<'_>) -> ! {
    #[cfg(target_arch = "x86_64")]
    unsafe {
        core::arch::asm!("ud2", options(noreturn))
    }
    #[cfg(not(target_arch = "x86_64"))]
    unsafe {
        abort()
    }
}

// Marker the SDK link uses to record the libSceLibcInternal dependency
// (formerly src/ampr_libc_internal_link.cpp).
#[no_mangle]
#[used]
static Need_sceLibcInternal: core::ffi::c_int = 0;
