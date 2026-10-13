# ehabi

A Rust library for reading and writing the exception-handling tables of the
32-bit Arm architecture: `.ARM.exidx` and `.ARM.extab`.

- **Read and write.** Parse tables from ELF section data, or build them in
  memory and encode them.
- **Lossless.** Converting the tables of a linked image and writing them back
  reproduces the original sections byte for byte (see
  [Limitations](#limitations) for the exact conditions).
- **Relocation-aware.** Read relocatable objects through a `Relocate` hook,
  and record `R_ARM_PREL31`, `R_ARM_TARGET2` and `R_ARM_NONE` relocations when
  writing.
- **Portable.** `no_std` (requires `alloc`), zero-copy reading, little- and
  big-endian, no required dependencies.

## Specification

| | |
|---|---|
| Document | *Exception Handling ABI for the Arm® Architecture* (EHABI32) |
| Release | 2025Q4, issued 23 January 2026 |
| Source | [`ehabi32/ehabi32.rst`](https://github.com/ARM-software/abi-aa/blob/main/ehabi32/ehabi32.rst) in [ARM-software/abi-aa](https://github.com/ARM-software/abi-aa) |
| Relevant sections | Index table entries · Exception-handling table entries · Personality routine exception-handling table entries · Frame unwinding instructions |

The table content has been unchanged since release 2022Q3, which added the
PACBTI-M return address authentication instructions.

The generic-model layout used by GCC and LLVM (for example by
`__gxx_personality_v0`) is not defined by the EHABI. This crate follows
libgcc (`unwind-arm-common.inc`, `pr-support.c`) for it.

## Coverage

| Area | Supported |
|---|---|
| Index table entries | `EXIDX_CANTUNWIND`, inline compact entries, `prel31` references into `.ARM.extab` |
| Compact model | Personality routines 0 (`Su16`), 1 (`Lu16`) and 2 (`Lu32`); routines 3–15 are reserved and exposed as raw data |
| Descriptors | Cleanup, catch (including `catch(...)` and the fail variant), function exception specification; 16- and 32-bit scopes |
| Generic model | Personality reference and raw data; GCC/LLVM layout decoded into unwinding instructions and LSDA |
| Unwinding instructions | Every encoding in the EHABI, including spare and reserved encodings and `0xb4`/`0xb5` (PACBTI-M) |

## Installation

The crate is not yet published on crates.io. Add it as a path or Git
dependency:

```toml
[dependencies]
ehabi = { path = "../ehabi" }
```

Minimum supported Rust version: **1.88** (edition 2024).

### Cargo features

| Feature | Default | Description |
|---|:---:|---|
| `read` | ✓ | The `read` module |
| `write` | ✓ | The `write` module |
| `fallible-iterator` | | Implements `fallible_iterator::FallibleIterator` for all iterators |

## Usage

### Reading

```rust
use ehabi::read::{ExIdx, ExTab, UnwindEntry};
use ehabi::{BaseAddresses, LittleEndian};

let exidx = ExIdx::new(exidx_data, LittleEndian);
let extab = ExTab::new(extab_data, LittleEndian);
let bases = BaseAddresses::default()
    .set_exidx(exidx_address)
    .set_extab(extab_address);

// Binary search for the function containing `pc`.
if let Some(entry) = exidx.find(pc, &bases)? {
    match entry.resolve(&extab, &bases)? {
        UnwindEntry::CantUnwind => {}
        UnwindEntry::Compact(entry) => {
            let mut instructions = entry.instructions()?;
            while let Some(instruction) = instructions.next()? {
                println!("{instruction}"); // e.g. "pop {r4, r5, lr}"
            }
            if let Some(mut descriptors) = entry.descriptors()? {
                while let Some(descriptor) = descriptors.next()? {
                    println!("{:?}", descriptor.scope());
                }
            }
        }
        UnwindEntry::Generic(entry) => {
            let instructions = entry.gnu_instructions()?;
            let lsda = entry.gnu_lsda()?;
        }
    }
}
```

All `prel31` references are returned as `Prel31` values, which record their
section offset and resolve against `BaseAddresses`.

### Relocatable objects

In a relocatable object the table words hold only REL addends. Wrap the
section data in a `RelocateReader` with an implementation of `Relocate`,
which maps each relocated word to its value under a layout of your choice.
`read::relocate_prel31(word, symbol, place)` implements the `R_ARM_PREL31`
calculation.

### Writing

```rust
use ehabi::write::{
    Address, CompactEntry, EndianVec, IndexEntry, IndexEntryData, Sections, UnwindTable,
};
use ehabi::{BaseAddresses, LittleEndian, PersonalityIndex, UnwindInstruction};

let mut table = UnwindTable::new();

// push {r4-r7, lr}; sub sp, sp, #16
let mut entry = CompactEntry::new(PersonalityIndex::SU16);
entry.instructions.extend(UnwindInstruction::vsp_add(16)?);
entry.instructions.extend(UnwindInstruction::pop_core(0x40f0)?);
table.add_index_entry(IndexEntry {
    function: Address::Constant(0x8000),
    data: IndexEntryData::Inline(entry),
});

let bases = BaseAddresses::default().set_exidx(0x9000).set_extab(0x9100);
let mut sections = Sections::new(EndianVec::new(LittleEndian));
table.write(&mut sections, &bases)?;
```

`vsp_add`, `vsp_sub`, `pop_core` and `pop_vfp` select the shortest encoding.
`UnwindTable::from_read` converts parsed tables for modification and
rewriting.

For relocatable output, implement `RelocateWriter` and use `Address::Symbol`:

- References from `.ARM.exidx` into `.ARM.extab` become `R_ARM_PREL31`
  relocations against the `.ARM.extab` section.
- `set_personality_symbol` and `set_call_unexpected_symbol` emit the
  `R_ARM_NONE` dependencies that the EHABI requires of object producers.
- Addends are also stored in the relocated word, as REL relocations require.

### Dumping an ELF file

```sh
cargo run --example ehdump -- path/to/file.elf
```

Prints every index entry with its unwinding instructions, descriptors and
personality routine, in a format similar to `llvm-readobj --unwind`.

## Limitations

- **One section pair.** The crate operates on a single `.ARM.exidx` /
  `.ARM.extab` pair. Selecting sections (for example the per-function
  `.ARM.exidx.text.*` sections produced by `-ffunction-sections`) and
  following `sh_link` is left to the caller.
- **LSDA not parsed.** The language-specific data of generic entries
  (`.gcc_except_table` format) is exposed as raw bytes. When written,
  relocations inside it are not recorded.
- **`R_ARM_TARGET2` values are raw.** Their interpretation is
  platform-specific (absolute, GOT-relative or place-relative).
- **No sorting.** `UnwindTable::write` emits index entries in insertion
  order; sort them before writing a linked image.
- **Round-trip conditions.** `UnwindTable::from_read` reproduces the
  sections exactly when every `.ARM.extab` entry is referenced from the index
  and the entries are contiguous. A non-minimal uleb128 operand in a compact
  entry is re-encoded in its minimal form, which can shorten the entry.
- **No unwinder.** Instructions are decoded and encoded, not executed against
  a register set.

## Testing

```sh
cargo test
```

The integration tests use objects built by clang from `tests/data/src`: an
assembly file exercising every unwinding directive, and a C++ file with
`try`/`catch`, cleanups and `noexcept`, compiled for ARM and Thumb. They
verify:

- decoding and re-encoding of every one- and two-byte instruction sequence;
- the expected decoding of each assembly function, in little- and big-endian
  objects, through the relocation layer;
- a byte-identical read → `UnwindTable` → write round trip of a linked shared
  library;
- address lookup of every function in the linked table.
