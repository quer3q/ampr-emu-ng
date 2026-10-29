# libSceAmpr PRX build: Rust staticlib (crates/ampr-sys) linked into a PS5 PRX
# with ps5-payload-sdk. Run through ./ps5/build-docker.sh.

PS5_PAYLOAD_SDK ?= /opt/ps5-payload-sdk
PYTHON ?= python3
RUST_CARGO ?= cargo
RUST_TARGET := ps5/target/x86_64-ps5-freebsd.json
BUILD_MAKEFILE := $(lastword $(MAKEFILE_LIST))

# 1 = debug build: TCP metrics endpoint on port 9090 (rt/exports.rs, rt/stats.rs).
AMPR_MEM_REPORT ?= 0
# Internal pool size in bytes, read by rt/runtime_memory.rs.
# 88 MiB: physical cache 32 (no decoded cache) + 4 worker buffers x 1 MiB +
# index ~8 MiB (this game; it grows with file count) + all 16 pipeline I/O
# windows x 2 MiB = ~76 MiB worst case in play. Startup peak ~80 MiB
# (cache-reserve 4 + 16 windows + 4 workers = 40, physical cache 32, index 8).
AMPR_INTERNAL_POOL_SIZE ?= 0x5800000
# Debug build pool: same as release (was 352 MiB), so it shows the release
# memory. Profiles bigger than the release config no longer fit: the decoded
# cache halves until it does (see pack_decoded_cache_bytes in /metrics).
AMPR_DEBUG_POOL_SIZE ?= $(AMPR_INTERNAL_POOL_SIZE)
# One runtime reads LZ4 (AMPRPAK4) and zstd (AMPRZPK1) packs, picked at load.
# The pool fits the larger of the two: LZ4 above (peak 79.9 MiB); zstd peaks
# at 73.3 MiB (reserve 40 + cache 32 + ampr_zstd.index 1.3).
# Pack decode worker threads (1..16), read by rt/pack/mod.rs.
# 4: decode takes 14-29 us per chunk, 1.6% of 4 workers on average and 0.16
# cores in the busiest second; 4 keeps a wide margin.
AMPR_PACK_WORKERS ?= 4
# zstd: libkernel internal-entry hooks to install, bit i = hook id 84 + i
# (rt/sys.rs). Off: the full set crashed a UE5 title at startup (CE-108255-1),
# and zstd packs only what LZ4 packs, so plain libc I/O never needs them.
AMPR_ZSTD_LIBC_HOOKS ?= 0
# Sequential read-ahead window in chunks (0 = off), read by rt/pack.
# 0: with the pread pool (reactor/pread_pool) read-ahead no longer cut load latency
# (1.62 vs 1.60 ms) and off shortened the worst read (26.7 vs 36.2 ms). On a
# second, lighter game it doubled disk bytes (1.69 vs 0.78 per game byte) and
# the worst read (13.4 vs 5.6 ms). Its decoded cache is gone too.
AMPR_PACK_READAHEAD_CHUNKS ?= 0
AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT ?= 2
# Read extension: total bytes of a cold-page backing request, the following
# uncached pages filling the physical cache (0 = off), read by rt/pack.
# Off: 1 MiB extension made cold reads 2-3x bigger; off cut APR latency ~20%.
AMPR_PACK_READ_EXTEND_BYTES ?= 0
# Extend reads only while fewer than this many pack disk reads are in flight.
AMPR_PACK_READ_EXTEND_MAX_DISK_INFLIGHT ?= 2

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
	  printf '%s\n' 'AMPR_ZSTD_LIBC_HOOKS=$(AMPR_ZSTD_LIBC_HOOKS)'; \
	  printf '%s\n' 'AMPR_PACK_READAHEAD_CHUNKS=$(AMPR_PACK_READAHEAD_CHUNKS)'; \
	  printf '%s\n' 'AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT=$(AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT)'; \
	  printf '%s\n' 'AMPR_PACK_READ_EXTEND_BYTES=$(AMPR_PACK_READ_EXTEND_BYTES)'; \
	  printf '%s\n' 'AMPR_PACK_READ_EXTEND_MAX_DISK_INFLIGHT=$(AMPR_PACK_READ_EXTEND_MAX_DISK_INFLIGHT)'; \
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
	RUSTC_BOOTSTRAP=1 AMPR_INTERNAL_POOL_SIZE=$(AMPR_INTERNAL_POOL_SIZE) AMPR_PACK_WORKERS=$(AMPR_PACK_WORKERS) AMPR_ZSTD_LIBC_HOOKS=$(AMPR_ZSTD_LIBC_HOOKS) AMPR_PACK_READAHEAD_CHUNKS=$(AMPR_PACK_READAHEAD_CHUNKS) AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT=$(AMPR_PACK_READAHEAD_MAX_DISK_INFLIGHT) AMPR_PACK_READ_EXTEND_BYTES=$(AMPR_PACK_READ_EXTEND_BYTES) AMPR_PACK_READ_EXTEND_MAX_DISK_INFLIGHT=$(AMPR_PACK_READ_EXTEND_MAX_DISK_INFLIGHT) CARGO_TARGET_DIR=$(abspath $(OUT)/cargo) \
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
    tools/stamp_payload_prx.py $(BUILD_MAKEFILE)
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
	cp out/release/libSceAmpr.sprx libSceAmpr.sprx
	cp out/debug/libSceAmpr.sprx libSceAmpr-debug.sprx

clean:
	rm -rf out
