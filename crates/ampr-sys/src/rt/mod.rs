//! The emulator runtime. Modules call each other directly; only SDK and PRX
//! entry points cross a C ABI boundary.
mod amm;
mod command_buffer;
mod equeue;
pub(crate) mod exports;
mod fd_cache;
mod hook;
mod index;
pub(crate) mod pack;
mod reactor;
mod runtime_memory;
mod services;
pub(crate) mod stats;
pub mod sync;
pub mod sys;
pub(crate) mod tune;
