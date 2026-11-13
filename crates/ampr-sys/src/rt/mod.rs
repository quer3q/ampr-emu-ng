//! The emulator runtime. Modules call each other directly; only SDK and PRX
//! entry points cross a C ABI boundary.
mod amm;
#[cfg(feature = "mem_report")]
mod blackbox;
mod command_buffer;
mod equeue;
pub(crate) mod exports;
mod fd_cache;
mod hook;
mod index;
pub(crate) mod index_memory;
mod index_pages;
mod libc_exports;
#[cfg(feature = "mem_report")]
mod probe;
pub(crate) mod thread_hooks;
pub(crate) mod pack;
mod reactor;
mod runtime_memory;
mod rw;
mod save;
mod services;
pub(crate) mod stats;
pub mod sync;
pub mod sys;
pub(crate) mod tune;
