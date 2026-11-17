//! Memory of the Rust global allocator (lib.rs `LibcAlloc`), whose only
//! user is iced-x86 (ampr-hook) while hooks are installed or removed.
//!
//! iced-x86 builds its decoder handler tables on the first decode and never
//! frees them: on the host, with the features ampr-hook uses, the first
//! decode made 4246 allocations, 181,300 B live after, a 190,276 B peak and
//! 246,688 B allocated in all at 16-byte steps, no alignment above 8 (a
//! counting allocator around `Decoder::new` and `decode`). So the heap is a
//! 384 KiB bump block in the pool, a fixed site (rt/runtime_memory.rs
//! `POOL_SITES`), taken at the first allocation, instead of the game's libc
//! heap. A free gives back only the last block; nothing else is ever
//! reused. Past the block, or without it, allocations go to libc malloc as
//! before (debug /metrics `heap_libc_bytes`).

use super::runtime_memory::ampr_internal_amm_pool_alloc;
use super::stats::{self, Stat};
use super::sync::{SpinLock, SyncCell};
use super::sys::SCE_KERNEL_PAGE_SIZE;

/// The pool heap: 384 KiB. The bump top reached 246,688 B on a console
/// (debug, with the save probes' extra hooks), and later hook installs and
/// a Vec's regrowth only add to it; past it allocations go to libc
/// (debug `heap_libc_bytes`).
pub(crate) const HEAP_BYTES: usize = 384 << 10;
/// libc malloc's alignment; stricter layouts are refused (lib.rs).
pub(crate) const HEAP_ALIGN: usize = 16;

/// A bump allocator over `cap` bytes, offsets only (host-testable).
struct Bump {
    cap: usize,
    top: usize,
    /// Offset of the last block, the only one a free gives back.
    last: usize,
}

impl Bump {
    const fn new(cap: usize) -> Self {
        Self {
            cap,
            top: 0,
            last: usize::MAX,
        }
    }

    /// Offset of a new `size`-byte block, `HEAP_ALIGN` aligned; None when
    /// it does not fit.
    fn take(&mut self, size: usize) -> Option<usize> {
        let size = size.checked_add(HEAP_ALIGN - 1)? & !(HEAP_ALIGN - 1);
        if size > self.cap - self.top {
            return None;
        }
        let at = self.top;
        self.top += size;
        self.last = at;
        Some(at)
    }

    /// Frees the block at `at`: only the last block moves the top back.
    fn give(&mut self, at: usize) {
        if at == self.last {
            self.top = at;
            self.last = usize::MAX;
        }
    }
}

struct Heap {
    /// Pool block, 0 until taken.
    base: usize,
    /// The pool refused the block: libc only from then on.
    refused: bool,
    bump: Bump,
    /// Bytes live, pool and libc (debug /metrics `heap_bytes`).
    live: usize,
}

static LOCK: SpinLock = SpinLock::new();
static HEAP: SyncCell<Heap> = SyncCell::new(Heap {
    base: 0,
    refused: false,
    bump: Bump::new(HEAP_BYTES),
    live: 0,
});

/// Debug /metrics: live bytes of both sources after `size` more or less.
fn count(h: &mut Heap, add: bool, size: usize) {
    h.live = if add {
        h.live + size
    } else {
        h.live.saturating_sub(size)
    };
    stats::set(Stat::HeapBytes, h.live as u64);
    stats::max(Stat::HeapBytesMax, h.live as u64);
    stats::set(Stat::HeapBumpTop, h.bump.top as u64);
}

/// A `size`-byte block, 16-byte aligned: from the pool heap while it has
/// room, else libc malloc.
#[cfg_attr(test, allow(dead_code))]
pub(crate) unsafe fn alloc(size: usize) -> *mut u8 {
    {
        let _g = LOCK.lock();
        let h = unsafe { &mut *HEAP.get() };
        if h.base == 0 && !h.refused {
            let mut got = 0usize;
            let tag = c"iced-x86 heap".as_ptr();
            let b = unsafe {
                ampr_internal_amm_pool_alloc(HEAP_BYTES, &mut got, tag, false, SCE_KERNEL_PAGE_SIZE)
            };
            h.base = b as usize;
            h.refused = b.is_null();
        }
        if h.base != 0 {
            if let Some(at) = h.bump.take(size) {
                count(h, true, size);
                return (h.base + at) as *mut u8;
            }
        }
    }
    let p = unsafe { libc_malloc(size) };
    if !p.is_null() {
        stats::add(Stat::HeapLibcBytes, size as u64);
        let _g = LOCK.lock();
        count(unsafe { &mut *HEAP.get() }, true, size);
    }
    p
}

/// Frees a block from `alloc`.
#[cfg_attr(test, allow(dead_code))]
pub(crate) unsafe fn dealloc(ptr: *mut u8, size: usize) {
    {
        let _g = LOCK.lock();
        let h = unsafe { &mut *HEAP.get() };
        let at = (ptr as usize).wrapping_sub(h.base);
        let pooled = h.base != 0 && at < HEAP_BYTES;
        if pooled {
            h.bump.give(at);
        }
        count(h, false, size);
        if pooled {
            return;
        }
    }
    unsafe { libc_free(ptr) }
}

// libc only in the PRX (rt/sys.rs); host tests use std's allocator and
// never call these.
#[cfg(not(test))]
pub(crate) unsafe fn libc_malloc(size: usize) -> *mut u8 {
    unsafe { super::sys::malloc(size) }.cast()
}
#[cfg(not(test))]
pub(crate) unsafe fn libc_free(ptr: *mut u8) {
    unsafe { super::sys::free(ptr.cast::<core::ffi::c_void>()) }
}
#[cfg(test)]
pub(crate) unsafe fn libc_malloc(_: usize) -> *mut u8 {
    core::ptr::null_mut()
}
#[cfg(test)]
pub(crate) unsafe fn libc_free(_: *mut u8) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bump_takes_aligned_blocks_until_full() {
        let mut b = Bump::new(64);
        assert_eq!(b.take(1), Some(0));
        assert_eq!(b.take(16), Some(16));
        assert_eq!(b.take(17), Some(32));
        assert_eq!(b.top, 64);
        assert_eq!(b.take(1), None);
        assert_eq!(b.take(usize::MAX), None);
    }

    #[test]
    fn only_the_last_block_comes_back() {
        let mut b = Bump::new(64);
        let a = b.take(16).unwrap();
        let c = b.take(16).unwrap();
        b.give(a);
        assert_eq!(b.top, 32);
        b.give(c);
        assert_eq!(b.top, 16);
        // A second free of the same block, or an older one, changes nothing.
        b.give(c);
        b.give(a);
        assert_eq!(b.top, 16);
        assert_eq!(b.take(48), Some(16));
        assert_eq!(b.take(1), None);
    }

    #[test]
    fn the_heap_holds_the_measured_iced_tables() {
        // 246,688 B at 16-byte steps measured on the host (module doc).
        assert!(246_688 <= HEAP_BYTES);
        assert_eq!(HEAP_BYTES % SCE_KERNEL_PAGE_SIZE, 0);
    }
}
