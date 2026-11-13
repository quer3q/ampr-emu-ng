//! Optional phase profiling (`--features phase_timing`): cycle-counter totals per phase.
//! Without the feature `timed!` is just its expression.

#[cfg(feature = "phase_timing")]
pub mod phase {
    use core::sync::atomic::{AtomicU64, Ordering::Relaxed};

    /// Phase names; `T[i]` are ticks, `C[i]` the bytes (or items) each phase handled.
    pub const NAMES: [&str; 9] = [
        "huff array: literals",
        "huff array: commands",
        "huff array: offsets+lengths",
        "huff table build (in the above)",
        "command loop, plain literals",
        "command loop, delta literals",
        "tail literals + checks",
        "non-LZ half (raw/entropy)",
        "(count only: commands)",
    ];
    pub static T: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];
    pub static C: [AtomicU64; 9] = [const { AtomicU64::new(0) }; 9];

    #[inline(always)]
    pub fn now() -> u64 {
        #[cfg(target_arch = "x86_64")]
        // SAFETY: rdtsc has no preconditions.
        unsafe {
            core::arch::x86_64::_rdtsc()
        }
        #[cfg(target_arch = "aarch64")]
        {
            let v: u64;
            // SAFETY: reads the virtual counter, always readable from EL0 on macOS/FreeBSD.
            unsafe { core::arch::asm!("mrs {}, cntvct_el0", out(reg) v) };
            v
        }
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        0
    }

    #[inline(always)]
    pub fn add(i: usize, t0: u64, n: usize) {
        T[i].fetch_add(now().wrapping_sub(t0), Relaxed);
        C[i].fetch_add(n as u64, Relaxed);
    }

    pub fn reset() {
        for i in 0..9 {
            T[i].store(0, Relaxed);
            C[i].store(0, Relaxed);
        }
    }
}

/// `timed!(phase, count, expr)`: `expr`, its ticks added to `phase` with `count`.
macro_rules! timed {
    ($i:expr, $n:expr, $e:expr) => {{
        #[cfg(feature = "phase_timing")]
        let t0 = crate::kraken::timing::phase::now();
        let r = $e;
        #[cfg(feature = "phase_timing")]
        crate::kraken::timing::phase::add($i, t0, $n);
        r
    }};
}
