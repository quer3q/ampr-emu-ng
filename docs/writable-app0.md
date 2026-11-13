# Writable /app0

When /app0 is mounted read-write, the runtime lets the game create and
write files there, in pkg, LZ4, zstd and plain titles alike. Detection and
parent directories are in `crates/ampr-sys/src/rt/rw.rs`; the routing is
in `rt/index.rs`.

A game never writes files that are in its packs, so writes only need the
real filesystem, and packed files stay read-only. On a read-only /app0 the
runtime behaves as upstream: an index hit is served from the index or the
pack, an authoritative miss returns ENOENT without touching the
filesystem, and `access(W_OK)` on a hit returns EROFS.

## Detection

`rw::init` runs at module_start, after `select_pack_format` and before the
hooks install (`module_start` in `rt/exports.rs`). It calls
`access("/app0", W_OK)`, resolved by name because no hook is installed
yet, and turns the mode on when the call succeeds. On a read-only mount
the kernel refuses W_OK with EROFS, the same answer `statfs` would give
through `MNT_RDONLY`; libkernel exports neither `statfs` nor `fstatfs`
(docs/read-path-tuning.md). Any error counts as read-only.
`app0_writable()` is one Relaxed load, and every change below depends on
it.

## Misses go to the filesystem

With a writable /app0 no index miss is authoritative (`miss_authority`,
called from `lookup_resident_path`). `open`, `stat`, `lstat`, `access` and
`sceKernelCheckReachability` of a path the index lacks call the real
function, so the runtime finds files the game created in this session or
an earlier one, including files made through calls it does not hook. The
debug build traces such a miss with lookup letter `M`
([debug-build.md](debug-build.md)).

Each miss costs one real call. Some titles probe many paths that do not
exist, and that cost has not been measured on a console yet.

## Loose hits go to the filesystem

A loose file hit is a real file the index lists, as opposed to a packed
one. The game can rewrite, truncate or unlink it after the index was
built, so with a writable /app0 `stat`, `lstat`, `access` and
`sceKernelCheckReachability` of a loose hit call the real function on the
indexed spelling (`live_loose_hit` in `rt/index.rs`). Packed hits and
directories are still answered from the index. A hit is packed when
`file_id_is_packed` says so; until the pack manifest is ready, every hit in
a title with packs counts as packed.

## Creating a file

When an `O_CREAT` open misses the index and its parent is an indexed
directory, the runtime opens the index's spelling of that directory plus
the caller's file name (`create_in_indexed_parent` in `rt/index.rs`), so a
case-sensitive install finds the directory. If that directory has no real
copy (it exists only in the pack), the runtime makes it first: `make_dirs`
in `rt/rw.rs` tries mkdir from the deepest level up until one exists
(EEXIST) or is made, then makes the levels below it, so an existing parent
costs one mkdir. On any other mkdir error, or when the index does not know
the parent, the runtime opens the caller's path as given and the open
reports the error. Directories are created 0777, trimmed by the umask.

Later calls on a miss under an indexed directory use the same spelling
without making anything (`with_miss_path` in `rt/index.rs`): `open`,
`stat`, `lstat`, `access`, `sceKernelCheckReachability`, `unlink` and both
sides of `rename`. So a file created under the indexed spelling is found
again by the caller's spelling, and a game that writes a temp file and
renames it over the real one works on a case-sensitive install.

A creating open of a loose hit that fails with ENOENT goes through the
same path once more. This covers a game that unlinked the file and removed
its real parent directory while the index still lists both. A packed hit
does not get the retry, so a write-open of a packed file never creates
real directories.

## Packed files

A write-open of a packed file gets the upstream answer: the pack does not
take it, and it goes to the real call on the indexed path
(`pack_open_flags_supported` in `rt/pack/slots.rs`). Later reads of that
path still come from the pack.

## Access

`access(W_OK)` returns 0 on an indexed directory instead of EROFS
(`indexed_access_errno`). On a packed file it returns EROFS, because packed
files stay read-only, and `X_OK` on a packed file still returns EACCES. A
loose file hit goes to the real `access`, as described above.

Hook coverage is the same as upstream. `open`, `stat`,
`sceKernelCheckReachability`, `unlink` and `rename` install in every title;
`access`, `lstat`, `_open`, `_openat`, `sceKernelOpen` and `sceKernelStat`
install only in a title with packs (`hook_enabled` in `rt/hook.rs`).
Unhooked calls reach the filesystem directly.

## ShadowMount mounts

The mode depends on what `access("/app0", W_OK)` answers, not on how the
title was mounted. A read-only image mount (EROFS) behaves as upstream. A
writable folder-mode nullfs bind of the dump folder gets writable mode.
Neither case has been checked on a console yet.

## Out of scope

- Directory listings are not merged. An indexed directory stays virtual,
  so a file the game creates in it does not show in `getdents` of that
  directory. A directory the index does not know lists from the
  filesystem.
- `unlink` and `rename` of a packed file behave as upstream: the real call
  finds no file, and the packed file stays.
- `mkdir` is not hooked, so a game's own mkdir inside a packed-only
  directory fails with ENOENT. Only creating opens make the real parents.

## Memory

Writable /app0 takes no pool or heap memory. It adds one static,
`APP0_WRITABLE` (1 byte of .bss outside the pool, in both builds). A
creating open on a miss puts two path buffers (`RUNTIME_PATH_CAPACITY`,
1025 bytes each) on the game thread's stack.

## Console checks

Not run yet. With `libSceAmpr-debug.sprx`:

- Miss cost: game wait per read and `/fsfail` on a title that probes many
  missing paths, with /app0 read-only and then writable.
- A file the game creates under /app0, including one below a packed-only
  directory, is still there after a relaunch.
