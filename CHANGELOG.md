# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2026-10-14

### Added

- The `lsda` feature, which reads and writes the language-specific data
  area of generic-model entries with the `lsda` crate:
  `GenericEntry::parse_gnu_lsda` and the `LsdaReader` adapter,
  `GenericData::GnuLsda`, which is written in place with `R_ARM_TARGET2`
  relocations for symbol references, `UnwindTable::from_read_with_lsdas`,
  and `lsda::Endianity` for the byte order types.
- `write::Error::Lsda`, with the `lsda` feature.

### Changed

- `write::GenericData` is `#[non_exhaustive]`, so that variants such as
  `GnuLsda` can be added without breaking matches. This is a breaking
  change.

## [0.1.0] - 2026-10-14

Initial release.

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
- A virtual unwinder (`unwinder` feature): `unwinder::execute` runs
  unwinding instructions against a register set, and
  `unwinder::Module::unwind_frame` unwinds one frame of a stopped program.
- The `ehdump` example, which dumps the tables of an ELF file.

[Unreleased]: https://github.com/Fee0/ehabi/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/Fee0/ehabi/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/Fee0/ehabi/releases/tag/v0.1.0
