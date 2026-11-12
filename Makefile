# libSceAmpr PRX build: Rust staticlib (crates/ampr-sys) linked into a PS5 PRX
# with ps5-payload-sdk. Run through ./ps5/build-docker.sh.

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
PYTHON ?= python3
RUST_CARGO ?= cargo
RUST_TARGET := ps5/target/x86_64-ps5-freebsd.json
BUILD_MAKEFILE := $(lastword $(MAKEFILE_LIST))

# 1 = debug build: TCP metrics endpoint on port 9090 (rt/exports.rs, rt/stats.rs).
AMPR_MEM_REPORT ?= 0
# Internal pool size in bytes, read by rt/runtime_memory.rs: all runtime
# memory. It holds the Index 64 (index files read whole or through a page
# cache of at least 16 MiB, plus up to 48 MiB of lookup tables) +
# Cache 64 + Buffer 28.44 MiB ledger caps (rt/index_memory.rs; Cache is one
# 64 MiB decoded chunk cache, chunks are read with exact-size reads and
# no read pages are kept; buffers are 4 x 1 MiB decode + 4 x 112 KiB zstd
# decoder workspaces + 12 x 2 MiB I/O)
# and a 2 MiB budget for the fixed sites (1.56 MiB used); a pool below that
# fails the build. Both builds have the same PRX size T (PT_LOAD memsz
# total), below 192 MiB: 167.94 MiB (v0.3.4 loaded at 200.7 MiB, so a PRX
# of this size loads). Each pool is T minus its build's non-pool part (code,
# data, reactor storage), rounded down to a 16 KiB page. Non-pool parts:
# release 8506402 B (8.11 MiB), debug 9929746 B (9.47 MiB; more code,
# /fsfail and retry records, rt/stats.rs), so the release pool is 1.36 MiB
# (87 pages) larger: 159.83 vs 158.47 MiB. Deleting the physical page cache
# took about 589 KiB off both non-pool parts (229 KiB of PackState .bss,
# the rest code). `AMPR_ZSTD_MMAP=1` adds 448 KiB to both pools (4
# decode-on-access decoder workspaces, Buffer ledger): T 168.38 MiB.
# `dist` checks both totals
# (tools/verify_payload_prx.py --prx-totals): they must match within 64 KiB
# and stay below 192 MiB, else update the gap here.
# The first pool allocation publishes the pool (mprotect), so the startup
# cache carve can use it; a carve before the pool was published failed
# (pool_alloc_failed 1, cache off).
# Nothing comes from the game's direct or flexible memory: the pool is .bss
# and did not lower the game's free direct memory, while direct allocations
# did (a title had 42 MiB of direct memory free during play), and flexible
# memory had 0-28 MiB free in another title (debug /metrics flex_* and the
# former direct memory lines).
AMPR_INTERNAL_POOL_SIZE ?= $(if $(filter 1,$(AMPR_ZSTD_MMAP)),0xa044000,0x9fd4000)
# Debug build pool (passed to it as AMPR_INTERNAL_POOL_SIZE by `dist`):
# T minus the debug non-pool part, 158.47 MiB, the same ledger caps as
# release; host tests build with it (rt/runtime_memory.rs).
AMPR_DEBUG_POOL_SIZE ?= $(if $(filter 1,$(AMPR_ZSTD_MMAP)),0x9ee8000,0x9e78000)
# Pread pool threads: at most 6 (tune::RELEASE_PREAD_THREADS), grown by
# backlog and retired by load within the runtime-wide budget of 16 worker
# threads (rt/thread_hooks.rs); a zstd title peaked at 5-6, two titles at
# 4-5, and game wait per read did not change between 8 and 32 (debug
# /metrics). 6 instead of 8 shrinks AprAioReactor by 72 B (release, host
# size_of). Their 32 KiB stacks are libkernel memory outside the pool.
# Static reactor storage, also
# outside the pool (host size_of vs commit 52ef644): AprAioReactor
# 1985736 -> 1988440 B release (+2.6 KiB), 1985864 -> 2054232 B debug
# (+66.8 KiB); ActiveRead 264 -> 280 B. Debug only (host size_of): the
# gather/scatter retry record grows JobState 408 -> 432 B
# and AprAioReactor 2054232 -> 2152536 B (+96 KiB, 4096 slots), and the
# /fsfail table adds ~14 KiB of .bss; release sizes unchanged.
# One runtime reads LZ4 (AMPRPAK4) and zstd (AMPRZPK1) packs, picked at load,
# with the same pool and ledgers (above). The at most 4 virtual-fd read threads
# (rt/pack/fd_read.rs) have 128 KiB libkernel stacks outside the pool.
# Virtual fds, the libc hooks and mmap below serve both formats, in a title
# that ships packs only (a plain title keeps the v0.2.0 hooks, rt/hook.rs
# `hook_enabled`).
# Pack decode workers (1..16), read by rt/pack/mod.rs. Each has a 1 MiB
# decode buffer from startup to shutdown; its thread starts at 1, grows
# while jobs queue and retires by load, so the game gets thread slots back.
# 4: decode takes 14-29 us per chunk and ~0.21 cores on a zstd title, and
# 4 vs 8 gave 312 vs 315 us game wait per read (debug /metrics).
AMPR_PACK_WORKERS ?= 4
# Pack read pipelines (1..32), read by rt/pack/mod.rs and rt/tune.rs: the
# slot count and the default pipeline count, debug build too, so the debug
# `pipelines` knob and profiles stop at it (build with 32 to tune above 12).
# Each pipeline has a 2 MiB I/O window under the Buffer ledger, allocated
# at the worker start and kept to shutdown; a refused window lowers the
# pipeline count (rt/pack/worker.rs `buffer_split`). 12: a
# zstd title used at most 9-10 of 16, and 12 vs 16 gave 312 vs 315 us game
# wait per read; at 6 it used all 6, 333 vs 345 us at 16 (debug /metrics).
AMPR_PACK_PIPELINES ?= 12
# Both formats (the knob keeps its zstd name), titles with packs only:
# libkernel internal-entry hooks that route through the index, bit i = hook
# id 84 + i (rt/sys.rs: _open .. sceKernelFcntl, 12 bits). The measurements
# below are from zstd packs. libc stdio
# and dirent (fopen, opendir, ...) call these entries, not the exported
# open/read, so a fully packed game needs them for fopen/opendir of packed
# files: a UE5 title reads uecommandline.txt with fopen; with _open only
# observed the open failed and UE fell back to its /devlog/app/ devkit path.
# 0xfff: every entry routes. The full set used to crash that title ~1 s
# after start: runtime physical opens went through libkernel
# `open`, which calls `_open`, so a directory open of /app0/.. looped _open
# hook -> ampr_pack_open_directory -> open -> _open hook until the main
# thread's stack ran out (0xA80 B a level). Fixed by opening through the
# `_open` original (pack::libkernel::real_open, sys::real_posix_open).
# With 0xfff (debug): the UE5 title, folder, 102 s, game wait
# per read 1.82 ms, pack job 1.54 ms, disk read 0.81 ms, 0 errors. Tested on
# a console with the release defaults too.
# A cleared bit leaves that entry unrouted; the debug build then still
# installs _open, _openat, access and lstat as pass-through observers that
# log packed paths (rt/probe.rs), to see what a game would have opened.
AMPR_ZSTD_LIBC_HOOKS ?= 0xfff
# Both formats (the knob keeps its zstd name), titles with packs only: mmap
# and sceKernelMmap of a packed file (rt/pack/mmap.rs). A packed file has no
# physical copy, so the
# original call fails on a virtual pack fd.
# 0: not hooked, mmap of a virtual fd fails as before.
# 2 (default): disk cache. The file is decoded once into a temp file in
# /data/ampr_cache, unlinked before it is mapped and kept open (up to 64
# files; the oldest is closed for a new one), and the original maps a dup of
# that fd. It is a kernel file mapping, so
# mprotect, write faults and thread stacks behave as for any file. Memory:
# one transient 256 KiB pool buffer while the file is written.
# 1: decode on access (rt/pack/mmap_fault.rs), zstd packs only (an LZ4
# packed file takes the disk cache), opt-in and not run on a console: none
# of the three measured fully packed games mmapped a packed file
# (mmap_virtual 0), so it has never served a game.
# It adds 2 MiB of index memory scratch (4 slots of 512 KiB) plus 4 x 112
# KiB zstd decoder workspaces (Buffer ledger; both pools grow by 448 KiB
# for them, above) and one pool byte per mapped 256 KiB chunk (a
# mapping over 512 MiB takes the disk cache), and its known
# limits (mprotect not tracked, handler on the faulting thread's stack,
# handler kept after module_stop; module doc of mmap_fault.rs) are unsolved.
AMPR_ZSTD_MMAP ?= 2
# Sequential read-ahead window in chunks (0 = off), read by rt/pack/mod.rs.
# 0: with the pread pool (reactor/pread_pool) read-ahead no longer cut load latency
# (1.62 vs 1.60 ms) and off shortened the worst read (26.7 vs 36.2 ms). On a
# second, lighter game it doubled disk bytes (1.69 vs 0.78 per game byte) and
# the worst read (13.4 vs 5.6 ms). Prefetched chunks land in the decoded
# cache (64 MiB, rt/pack/readahead.rs); read-ahead was not re-measured with it.
AMPR_PACK_READAHEAD_CHUNKS ?= 0
AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT ?= 2
# Git revision in the debug build's /metrics (rt/exports.rs BUILD_REV):
# short hash, "-dirty" with uncommitted tracked changes. ps5/build-docker.sh
# sets it from the host, since the Docker image has no git.
AMPR_GIT_REV ?= unknown

# Each knob is one word. `build-docker.sh dist "A=1 B=2"` (one argument)
# sets A to "1 B=2": B keeps its default and the shell splits A when it runs
# cargo, so a dist run with the pool knobs in one argument built a debug
# PRX identical to the default one (out/*/obj/build-config.txt).
BUILD_KNOBS := AMPR_MEM_REPORT AMPR_INTERNAL_POOL_SIZE AMPR_DEBUG_POOL_SIZE \
  AMPR_PACK_WORKERS AMPR_PACK_PIPELINES AMPR_ZSTD_LIBC_HOOKS AMPR_ZSTD_MMAP \
  AMPR_PACK_READAHEAD_CHUNKS AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT \
  AMPR_GIT_REV
$(foreach k,$(BUILD_KNOBS),$(if $(filter 1,$(words $($(k)))),,\
  $(error $(k) must be one word, got '$($(k))'; pass each knob as its own argument)))

include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk

LLVM_BINDIR := $(shell $(PS5_PAYLOAD_SDK)/bin/prospero-llvm-config --bindir)
PRX_LD := $(LLVM_BINDIR)/ld.lld

OUT ?= out/release
OBJ := $(OUT)/obj
GENERATED := $(OBJ)/generated
LINK_DIR := $(OBJ)/link
BUILD_CONFIG := $(OBJ)/build-config.txt
PRX := $(OUT)/libSceAmpr.prx
SPRX := $(OUT)/libSceAmpr.sprx
LINKED_PRX := $(LINK_DIR)/libSceAmpr.prx
COMBINED_OBJ := $(LINK_DIR)/libSceAmpr.combined.o
RUST_STATICLIB := $(OUT)/cargo/x86_64-ps5-freebsd/release/libampr_sys.a
RENAMED_RUST_STATICLIB := $(OBJ)/nids/rust/libampr_sys.a
UNDEFINED_LIST := $(GENERATED)/libSceAmpr.undefined.txt
DEFINED_LIST := $(GENERATED)/libSceAmpr.defined.txt
RENAME_MAP := $(GENERATED)/libSceAmpr.rename.txt
EXPORT_RESPONSE := $(GENERATED)/libSceAmpr.exports.rsp
VERSION_SCRIPT := $(GENERATED)/libSceAmpr.version.script
LIBC_ASM := $(GENERATED)/libSceLibcInternal.imports.S
LIBC_LIST := $(GENERATED)/libSceLibcInternal.imports.txt
KERNEL_ASM := $(GENERATED)/libkernel.imports.S
KERNEL_LIST := $(GENERATED)/libkernel.imports.txt
METADATA_ASM := $(GENERATED)/libSceAmpr.metadata.S
LIBC_SO := $(GENERATED)/libSceLibcInternal.prx.so
KERNEL_SO := $(GENERATED)/libkernel.prx.so
METADATA_OBJ := $(GENERATED)/libSceAmpr.metadata.o
GENERATED_STAMP := $(GENERATED)/libSceAmpr.nids.stamp
PRX_SCRIPT_SOURCE := ps5/prx/prx.script
PRX_SCRIPT := $(GENERATED)/prx.script

PROSPERO_200_FSELF_VERSION := 0x02000001

PRX_LDFLAGS := \
  -m elf_x86_64 --shared --eh-frame-hdr -mllvm -emulated-tls \
  -T $(PRX_SCRIPT) --hash-style=sysv --build-id=sha1 -z relro \
  -z max-page-size=0x4000 -z common-page-size=0x4000 \
  --version-script=$(VERSION_SCRIPT) --gc-sections

.DELETE_ON_ERROR:
.DEFAULT_GOAL := all
.PHONY: all verify dist clean FORCE

all: $(PRX) $(SPRX)

FORCE:

# Rebuilds when any knob changes.
$(BUILD_CONFIG): FORCE
	@mkdir -p $(dir $@)
	@{ \
	  printf '%s\n' 'PRX_LD=$(PRX_LD)'; \
	  printf '%s\n' 'RUST_CARGO=$(RUST_CARGO)'; \
	  printf '%s\n' 'AMPR_MEM_REPORT=$(AMPR_MEM_REPORT)'; \
	  printf '%s\n' 'AMPR_INTERNAL_POOL_SIZE=$(AMPR_INTERNAL_POOL_SIZE)'; \
	  printf '%s\n' 'AMPR_PACK_WORKERS=$(AMPR_PACK_WORKERS)'; \
	  printf '%s\n' 'AMPR_PACK_PIPELINES=$(AMPR_PACK_PIPELINES)'; \
	  printf '%s\n' 'AMPR_ZSTD_LIBC_HOOKS=$(AMPR_ZSTD_LIBC_HOOKS)'; \
	  printf '%s\n' 'AMPR_ZSTD_MMAP=$(AMPR_ZSTD_MMAP)'; \
	  printf '%s\n' 'AMPR_PACK_READAHEAD_CHUNKS=$(AMPR_PACK_READAHEAD_CHUNKS)'; \
	  printf '%s\n' 'AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT=$(AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT)'; \
	  printf '%s\n' 'AMPR_GIT_REV=$(AMPR_GIT_REV)'; \
	  printf '%s\n' 'PRX_LDFLAGS=$(PRX_LDFLAGS)'; \
	  printf '%s\n' 'PROSPERO_200_FSELF_VERSION=$(PROSPERO_200_FSELF_VERSION)'; \
	} > $@.tmp
	@if ! cmp -s $@.tmp $@; then mv $@.tmp $@; else rm -f $@.tmp; fi

# zstd packs' libzstd (zstd-sys, C) for the PS5 target: the SDK clang, position
# independent, one section per function so the PRX link drops the compressor.
# No -march: the SDK's x86_64-sie-ps5 target already builds for Zen 2
# (-march=znver2 gave byte-identical objects).
ZSTD_CFLAGS := -O3 -fPIC -ffunction-sections -fdata-sections -DZSTD_LEGACY_SUPPORT=0 -DZSTD_TRACE=0

RUST_SOURCES := $(wildcard crates/*/src/*.rs crates/*/src/*/*.rs crates/*/src/*/*/*.rs crates/*/Cargo.toml)

$(RUST_STATICLIB): Cargo.toml Cargo.lock $(RUST_SOURCES) $(RUST_TARGET) $(BUILD_MAKEFILE) $(BUILD_CONFIG)
	CC_x86_64_ps5_freebsd=$(PS5_PAYLOAD_SDK)/bin/prospero-clang AR_x86_64_ps5_freebsd=$(PS5_PAYLOAD_SDK)/bin/prospero-ar CRATE_CC_NO_DEFAULTS=1 CFLAGS_x86_64_ps5_freebsd="$(ZSTD_CFLAGS)" \
	RUSTC_BOOTSTRAP=1 AMPR_INTERNAL_POOL_SIZE=$(AMPR_INTERNAL_POOL_SIZE) AMPR_PACK_WORKERS=$(AMPR_PACK_WORKERS) AMPR_PACK_PIPELINES=$(AMPR_PACK_PIPELINES) AMPR_ZSTD_LIBC_HOOKS=$(AMPR_ZSTD_LIBC_HOOKS) AMPR_ZSTD_MMAP=$(AMPR_ZSTD_MMAP) AMPR_PACK_READAHEAD_CHUNKS=$(AMPR_PACK_READAHEAD_CHUNKS) AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT=$(AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT) AMPR_GIT_REV=$(AMPR_GIT_REV) CARGO_TARGET_DIR=$(abspath $(OUT)/cargo) \
	  $(RUST_CARGO) build -Z build-std=core,alloc -Z json-target-spec \
	    --release --target $(RUST_TARGET) -p ampr-sys $(if $(filter 1,$(AMPR_MEM_REPORT)),--features mem_report)

# One relocatable object, so references between archive members do not count as imports.
$(COMBINED_OBJ): $(RUST_STATICLIB)
	@mkdir -p $(dir $@)
	$(PRX_LD) -m elf_x86_64 -r -o $@ --whole-archive $(RUST_STATICLIB) --no-whole-archive

# nm and sort run as separate commands so an nm failure stops the build (no pipefail in sh).
$(UNDEFINED_LIST): $(COMBINED_OBJ)
	@mkdir -p $(dir $@)
	$(NM) -u -j $< > $@.tmp
	LC_ALL=C sort -u $@.tmp > $@
	@rm -f $@.tmp

$(DEFINED_LIST): $(COMBINED_OBJ)
	@mkdir -p $(dir $@)
	$(NM) -g -j --defined-only $< > $@.tmp
	LC_ALL=C sort -u $@.tmp > $@
	@rm -f $@.tmp

$(GENERATED_STAMP): $(UNDEFINED_LIST) $(DEFINED_LIST) tools/generate_payload_exports.py $(BUILD_MAKEFILE)
	@mkdir -p $(GENERATED)
	$(PYTHON) tools/generate_payload_exports.py \
	  --defined $(DEFINED_LIST) \
	  --undefined $(UNDEFINED_LIST) \
	  --response $(EXPORT_RESPONSE) \
	  --version-script $(VERSION_SCRIPT) \
	  --rename-map $(RENAME_MAP) \
	  --libc-asm $(LIBC_ASM) \
	  --libc-list $(LIBC_LIST) \
	  --kernel-asm $(KERNEL_ASM) \
	  --kernel-list $(KERNEL_LIST) \
	  --metadata-asm $(METADATA_ASM)
	@touch $@

$(EXPORT_RESPONSE) $(VERSION_SCRIPT) $(RENAME_MAP) $(LIBC_ASM) $(LIBC_LIST) $(KERNEL_ASM) $(KERNEL_LIST) $(METADATA_ASM): \
    $(GENERATED_STAMP)
	@test -f $@ || { echo "missing generated PRX input: $@" >&2; exit 1; }

$(RENAMED_RUST_STATICLIB): $(RUST_STATICLIB) $(RENAME_MAP)
	@mkdir -p $(dir $@)
	cp $< $@
	$(OBJCOPY) @$(RENAME_MAP) $@

$(LIBC_SO): $(LIBC_ASM) $(BUILD_MAKEFILE)
	$(CC) -shared -nostdlib -nodefaultlibs \
	  -Wl,--hash-style=sysv -Wl,-soname,libSceLibcInternal.prx -o $@ $<

$(KERNEL_SO): $(KERNEL_ASM) $(BUILD_MAKEFILE)
	$(CC) -shared -nostdlib -nodefaultlibs \
	  -Wl,--hash-style=sysv -Wl,-soname,libkernel.prx -o $@ $<

$(METADATA_OBJ): $(METADATA_ASM) $(BUILD_MAKEFILE)
	$(CC) -c $< -o $@

$(PRX_SCRIPT): $(PRX_SCRIPT_SOURCE) tools/prepare_prx_link_script.py $(BUILD_MAKEFILE)
	@mkdir -p $(dir $@)
	$(PYTHON) tools/prepare_prx_link_script.py "$(PRX_SCRIPT_SOURCE)" $@

$(LINKED_PRX): \
    $(RENAMED_RUST_STATICLIB) $(METADATA_OBJ) $(LIBC_SO) $(KERNEL_SO) \
    $(EXPORT_RESPONSE) $(VERSION_SCRIPT) $(PRX_SCRIPT) \
    tools/stamp_payload_prx.py $(BUILD_MAKEFILE) $(BUILD_CONFIG)
	@mkdir -p $(dir $@)
	$(PRX_LD) $(PRX_LDFLAGS) -o $@ \
	  --whole-archive $(RENAMED_RUST_STATICLIB) --no-whole-archive $(METADATA_OBJ) \
	  --no-as-needed $(LIBC_SO) $(KERNEL_SO) --as-needed \
	  @$(EXPORT_RESPONSE)
	$(PYTHON) tools/stamp_payload_prx.py $@

$(PRX): $(LINKED_PRX) tools/prx_hash_fix.py $(BUILD_MAKEFILE)
	$(PYTHON) tools/prx_hash_fix.py $(LINKED_PRX) $@ --module libSceAmpr

$(SPRX): $(PRX) tools/make_fself.py $(BUILD_MAKEFILE) $(BUILD_CONFIG)
	$(PYTHON) tools/make_fself.py $(PRX) $@ \
	  --ptype fake \
	  --app-version $(PROSPERO_200_FSELF_VERSION) \
	  --fw-version $(PROSPERO_200_FSELF_VERSION)

verify: all
	$(PYTHON) tools/verify_payload_prx.py --prx $(PRX) \
	  --linked $(LINKED_PRX) \
	  --libc-imports $(LIBC_LIST) \
	  --kernel-imports $(KERNEL_LIST) \
	  --defined $(DEFINED_LIST) \
	  --sprx $(SPRX) \
	  --fself-version $(PROSPERO_200_FSELF_VERSION)

# Release and debug SPRX, verified, copied to the project root.
dist:
	$(MAKE) verify OUT=out/release AMPR_MEM_REPORT=0
	$(MAKE) verify OUT=out/debug AMPR_MEM_REPORT=1 AMPR_INTERNAL_POOL_SIZE=$(AMPR_DEBUG_POOL_SIZE)
	$(PYTHON) tools/verify_payload_prx.py --prx-totals out/release/libSceAmpr.prx out/debug/libSceAmpr.prx
	cp out/release/libSceAmpr.sprx libSceAmpr.sprx
	cp out/debug/libSceAmpr.sprx libSceAmpr-debug.sprx

clean:
	rm -rf out
