# ehabi

[![Crates.io](https://img.shields.io/crates/v/ehabi.svg)](https://crates.io/crates/ehabi)
[![Docs.rs](https://docs.rs/ehabi/badge.svg)](https://docs.rs/ehabi)
[![CI](https://github.com/Fee0/ehabi/actions/workflows/ci.yml/badge.svg)](https://github.com/Fee0/ehabi/actions/workflows/ci.yml)
[![MSRV 1.88](https://img.shields.io/badge/MSRV-1.88-blue.svg)](#installation)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A Rust library for reading, writing and executing the exception-handling
tables of the 32-bit Arm architecture: `.ARM.exidx` and `.ARM.extab`.

- **Read and write.** Parse tables from ELF section data, or build them in
  memory and encode them.
- **Unwind.** A virtual unwinder recovers the caller's registers from a
  stopped frame, for debuggers, profilers and crash-dump tools.
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
| Unwinder | Executes every instruction: core and VFP registers (FSTMX and VPUSH), iWMMXt (skipped), Return Address Authentication Code and modifier |

## Installation

```toml
[dependencies]
ehabi = "0.1"
```

Minimum supported Rust version: **1.88** (edition 2024).

### Cargo features

| Feature | Default | Description |
|---|:---:|---|
| `read` | ✓ | The `read` module |
| `write` | ✓ | The `write` module |
| `unwinder` | ✓ | The `unwinder` module; implies `read` |
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
entry.instructions.extend(UnwindInstruction::pop_core(0x40f0));
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

### Unwinding

```rust
use ehabi::unwinder::{Module, Registers};

let module = Module::new(exidx, extab, bases);

// The registers of the stopped thread; unknown registers may be left unset.
let mut regs = Registers::from_core(core_registers);
let mut memory = |address: u32| read_target_word(address);

let mut first = true;
loop {
    let caller = match module.unwind_frame(&regs, first, &mut memory) {
        Ok(caller) => caller,
        Err(_) => break, // EXIDX_CANTUNWIND, no table entry, unreadable stack, ...
    };
    if caller.sp() <= regs.sp() {
        break; // no progress: corrupt stack
    }
    println!("return address {:#x}", caller.pc().unwrap_or(0));
    regs = caller;
    first = false;
}
```

`unwind_frame` looks up the program counter in the index (for return
addresses, the address before it, which is inside the call), executes the
entry's instructions and returns the caller's registers. Registers that the
frame saved are restored; caller-saved registers (r0-r3, r12) keep their
values from the unwound frame. `unwinder::execute` runs an instruction
sequence directly.

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
  entry is re-encoded in its minimal form and the entry padded with *Finish*,
  so its bytes change but its length, and every later entry, stay the same.
- **One module per unwinder.** `unwinder::Module` covers one image; a
  process with several shared libraries needs one module per library, chosen
  by address. Frame-pointer and stack-scanning fallbacks are left to the
  caller.

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
- address lookup of every function in the linked table;
- the unwinder against simulated call stacks: random prologues saving core
  and VFP registers in both byte orders, encoded as inline, compact and
  generic entries, called in random chains, then unwound frame by frame up
  to the `EXIDX_CANTUNWIND` entry of the outermost caller.

### Robustness

`tests/fuzz.rs` feeds random sections and mutations of the fixture sections,
in both byte orders and with arbitrary base addresses, through every read
path, `UnwindTable::from_read`, the writer and the unwinder. Every call must
return `Ok` or `Err`; a panic or an endless loop fails the test. It runs
20,000 iterations per input kind by default; set `EHABI_FUZZ_ITERATIONS` for
longer runs (preferably in debug mode, where integer overflow panics).

### Real-world corpus

`tests/corpus.rs` checks every ELF file with an `.ARM.exidx` section in the
directory named by `EHABI_CORPUS`: all entries must parse and decode, linked
files must round-trip byte for byte through `UnwindTable`, little-endian
files must match `llvm-readobj`, and the unwinder must execute every entry. `scripts/fetch_corpus.py` downloads a corpus
of Debian `armhf` and `armel` packages (libstdc++, glibc, Qt, ICU, LLVM,
Boost, OpenSSL and others; about 450 MB):

```sh
python scripts/fetch_corpus.py ../ehabi-corpus
EHABI_CORPUS=../ehabi-corpus cargo test --release --test corpus -- --nocapture
```

On Debian 13.7 this covers 61 libraries with 281,470 index entries, all of
which pass. GCC uses the generic model for C++, so the corpus contains no
compact-model descriptors; those are covered by the clang fixtures.

### Differential testing against LLVM

`tests/llvm_oracle.rs` compares ehabi with LLVM's independent EHABI decoder,
`llvm-readobj --unwind`, on the little-endian fixtures and on 8,000 randomly
generated index entries written by ehabi. For every entry it checks the
function address, model, personality index, `.ARM.extab` entry address,
generic personality address, and every opcode of compact entries (byte
grouping and meaning).

Install the tool with `rustup component add llvm-tools`, or point
`LLVM_READOBJ` at an `llvm-readobj` binary. Without it, the tests are
skipped with a notice.

`llvm-readobj` does not print descriptors or the contents of generic
entries, and deviates from the EHABI in a few places that the test accounts
for: big-endian files, the `0xb5` opcode (added in 2022Q3), `0xb1 0x00`, the
count byte of inline personality 1 and 2 entries, uleb128 operands longer
than 4 bytes, and VFP ranges beyond D31. The full list is in the test's
documentation.

## License

Licensed under the [MIT License](LICENSE).
