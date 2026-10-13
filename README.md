# ehabi

A Rust library for reading and writing the 32-bit Arm exception-handling
tables, `.ARM.exidx` and `.ARM.extab`.

* `no_std` (needs `alloc`), zero-copy reading, no required dependencies
* Read and write, with a byte-exact round trip for linked images (a
  non-minimal uleb128 in a compact entry is the one thing that gets normalized)
* Little- and big-endian
* Relocation support on both sides: read relocatable objects through a
  `Relocate` hook, and record relocations when writing
* Compact model (personality routines 0, 1, 2) with all descriptor kinds,
  plus the generic model, including the GCC/LLVM layout used by
  `__gxx_personality_v0`

## Specification

The format is defined by the **Exception Handling ABI for the Arm
Architecture (EHABI32)**, published in
[ARM-software/abi-aa](https://github.com/ARM-software/abi-aa)
(`ehabi32/ehabi32.rst`). This crate follows **release 2025Q4** (issued
23 January 2026), the latest release. Its content has not changed since
2022Q3, which added the PACBTI-M return-address-authentication instructions
(`0xb4`, `0xb5`); both are supported.

The relevant sections are "Index table entries", "Exception-handling table
entries", "Personality routine exception-handling table entries" and "Frame
unwinding instructions". The GCC/LLVM generic-model layout is not part of the
EHABI. It follows libgcc (`unwind-arm-common.inc`, `pr-support.c`).

## Reading

```rust
use ehabi::read::{ExIdx, ExTab, UnwindEntry};
use ehabi::{BaseAddresses, LittleEndian};

let exidx = ExIdx::new(exidx_data, LittleEndian);
let extab = ExTab::new(extab_data, LittleEndian);
let bases = BaseAddresses::default()
    .set_exidx(exidx_address)
    .set_extab(extab_address);

if let Some(entry) = exidx.find(pc, &bases)? {
    match entry.resolve(&extab, &bases)? {
        UnwindEntry::CantUnwind => {}
        UnwindEntry::Compact(entry) => {
            let mut instructions = entry.instructions()?;
            while let Some(instruction) = instructions.next()? {
                println!("{instruction}"); // e.g. "pop {r4, r5, lr}"
            }
            if let Some(mut descriptors) = entry.descriptors()? {
                while let Some(descriptor) = descriptors.next()? { /* ... */ }
            }
        }
        UnwindEntry::Generic(entry) => {
            let instructions = entry.gnu_instructions()?;
            let lsda = entry.gnu_lsda()?;
        }
    }
}
```

## Writing

```rust
use ehabi::write::*;
use ehabi::{BaseAddresses, LittleEndian, PersonalityIndex, UnwindInstruction};

let mut table = UnwindTable::new();
let mut entry = CompactEntry::new(PersonalityIndex::SU16);
entry.instructions.extend(UnwindInstruction::vsp_add(16)?);
entry.instructions.extend(UnwindInstruction::pop_core(0x40f0)?); // {r4-r7, lr}
table.add_index_entry(IndexEntry {
    function: Address::Constant(0x8000),
    data: IndexEntryData::Inline(entry),
});

let mut sections = Sections::new(EndianVec::new(LittleEndian));
table.write(&mut sections, &BaseAddresses::default().set_exidx(0x9000).set_extab(0x9100))?;
```

For relocatable output, implement `RelocateWriter` and use `Address::Symbol`.
References from `.ARM.exidx` into `.ARM.extab` become `R_ARM_PREL31`
relocations against the `.ARM.extab` section. `set_personality_symbol` and
`set_call_unexpected_symbol` emit the `R_ARM_NONE` dependencies that the EHABI
requires of object producers.

## Tools

`cargo run --example ehdump -- <elf file>` prints both tables, similar to
`llvm-readobj --unwind`.

## Limitations

* The crate works on one `.ARM.exidx`/`.ARM.extab` pair. Choosing sections,
  for example the per-function `.ARM.exidx.text.*` sections that
  `-ffunction-sections` produces, and following `sh_link` is up to the
  caller.
* The LSDA of generic entries (the `.gcc_except_table` format) is exposed as
  raw bytes and not parsed. When written, any relocations inside it are not
  recorded.
* `R_ARM_TARGET2` values are returned raw, because their meaning is
  platform-specific (absolute, GOT-relative, ...).
* `UnwindTable::write` emits index entries in insertion order. Sort them for
  linked images.
* There is no unwinder: the crate parses and encodes instructions but does
  not execute them against a register set.

## Tests

`cargo test` runs unit tests and integration tests against objects built by
clang from `tests/data/src` (an assembly file using every unwinding
directive, and a C++ file with `try`/`catch`, cleanups and `noexcept`, built
as both ARM and Thumb). The tests cover:

* exhaustive decode/encode round trip of every one- and two-byte instruction
* the expected decoding of every function in the assembly fixture, both
  little- and big-endian, through the relocation layer
* a byte-identical read → `UnwindTable` → write round trip of a linked
  shared library
* lookup of every function in the linked table

