# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Reading of `.ARM.exidx` and `.ARM.extab` as specified by EHABI32 release
  2025Q4: index entries, the compact model (personality routines 0–2) with
  descriptors, the generic model, and the GCC/LLVM generic-model layout.
- Decoding of every frame unwinding instruction, including the PACBTI-M
  instructions `0xb4` and `0xb5` and all spare encodings.
- Binary-search lookup of the entry for an address (`ExIdx::find`).
- Reading of relocatable objects through `RelocateReader` and `Relocate`.
- Writing through `UnwindTable`, with `R_ARM_PREL31`, `R_ARM_TARGET2` and
  `R_ARM_NONE` relocations recorded by `RelocateWriter`.
- Lossless conversion of parsed tables with `UnwindTable::from_read`.
- Shortest-encoding helpers: `vsp_add`, `vsp_sub`, `pop_core` and `pop_vfp`.
- `no_std` support (requires `alloc`) and an optional `fallible-iterator`
  feature.
- The `ehdump` example, which dumps the tables of an ELF file.

[Unreleased]: https://github.com/Fee0/ehabi/commits/main
