//! The emulator runtime. Modules call each other directly; only SDK and PRX
//! entry points cross a C ABI boundary.
mod amm;
#[cfg(feature = "mem_report")]
mod blackbox;
mod command_buffer;
mod equeue;
pub(crate) mod exports;
mod fd_cache;
pub(crate) mod heap;
mod hook;
mod index;
mod index_file;
pub(crate) mod index_memory;
mod index_view;
mod libc_exports;
pub(crate) mod pack;
#[cfg(feature = "mem_report")]
mod probe;
mod reactor;
mod runtime_memory;
mod rw;
mod save;
mod services;
pub(crate) mod stats;
pub mod sync;
pub mod sys;
mod thread_stack;
pub(crate) mod thread_hooks;
pub(crate) mod tune;
