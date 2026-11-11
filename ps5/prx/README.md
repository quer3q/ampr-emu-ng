# PRX linker layout

`prx.script` holds the PRX section and program-header layout; the build
reads only this checked-in file. `tools/prepare_prx_link_script.py` swaps
the SCE-only PHDR type names for their numbers and adds the dynamic
entries upstream LLVM LLD needs. It keeps the 14 segments as written.
