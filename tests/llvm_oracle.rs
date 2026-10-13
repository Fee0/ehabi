//! Differential tests against LLVM's EHABI decoder (`llvm-readobj --unwind`).
//!
//! `llvm-readobj` is located through the `LLVM_READOBJ` environment variable,
//! then the `llvm-tools` rustup component, then `PATH`. If it cannot be
//! found, the tests print a notice and pass without checking anything.
//!
//! `llvm-readobj` prints, for each index entry, the function address, the
//! model, the personality index, the `.ARM.extab` entry address and every
//! opcode byte of compact entries with its meaning. It does not print
//! descriptors or the contents of generic entries, and it has these known
//! deviations, which the random generator avoids:
//!
//! * it reads all words as little-endian, so big-endian files are skipped;
//! * for inline entries of personality routines 1 and 2 it decodes the
//!   extra-word count in bits 16-23 as an opcode (the EHABI defines it as the
//!   count N), so a leading `0x00` ("vsp = vsp + 4") is expected there;
//! * `0xb5` (EHABI 2022Q3) is printed as "spare";
//! * `0xb1 0x00` is printed as an empty "pop" rather than "spare";
//! * uleb128 operands of more than 4 bytes overflow;
//! * VFP ranges extending beyond D31 overflow the register mask.

use std::path::Path;

use ehabi::read::{ExIdx, ExTab, decode_unwind_instruction};
use ehabi::write::{
    Address, CatchType, CompactEntry, Descriptor, EndianVec, ExTabEntry as WExTabEntry,
    GenericData, GenericEntry, IndexEntry, IndexEntryData, Sections, UnwindTable,
};
use ehabi::{BaseAddresses, LittleEndian, PersonalityIndex, Scope, UnwindInstruction};

mod llvm;
use llvm::{Layout, compare, ehabi_entries, llvm_readobj};

// ---------------------------------------------------------------------------
// Fixtures built by clang
// ---------------------------------------------------------------------------

#[test]
fn fixtures_match_llvm() {
    let Some(tool) = llvm_readobj() else {
        eprintln!("llvm-readobj not found; skipping (install the llvm-tools component)");
        return;
    };
    use object::{Object, ObjectSection};
    for name in [
        "unwind-armv7.o",
        "eh-armv7.o",
        "eh-thumbv7.o",
        "eh-armv7.so",
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/data")
            .join(name);
        let data = std::fs::read(&path).unwrap();
        let file = object::File::parse(&*data).unwrap();
        let relocatable = file.kind() == object::ObjectKind::Relocatable;

        // llvm-readobj prints every index section in section order. Each one
        // pairs with the `.ARM.extab` section of the same suffix (for example
        // `.ARM.exidx.text.f` with `.ARM.extab.text.f`).
        let mut expected = Vec::new();
        for exidx in file.sections() {
            let Some(suffix) = exidx.name().unwrap().strip_prefix(".ARM.exidx") else {
                continue;
            };
            let extab = file.section_by_name(&format!(".ARM.extab{suffix}"));
            let extab_data = extab.as_ref().map(|s| s.data().unwrap()).unwrap_or(&[]);
            let layout = if relocatable {
                Layout::Relocatable
            } else {
                let mut bases = BaseAddresses::default().set_exidx(exidx.address() as u32);
                if let Some(extab) = &extab {
                    bases = bases.set_extab(extab.address() as u32);
                }
                Layout::Linked(bases)
            };
            expected.extend(ehabi_entries(exidx.data().unwrap(), extab_data, &layout));
        }
        let count = compare(&tool, &path, expected);
        eprintln!("{name}: {count} entries match llvm-readobj");
    }
}

// ---------------------------------------------------------------------------
// Random tables written by ehabi
// ---------------------------------------------------------------------------

/// xorshift64*: a small deterministic generator, so failures are reproducible.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn byte(&mut self) -> u8 {
        self.next() as u8
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// A random instruction from the whole encoding space, decoded from random
/// bytes, excluding the encodings llvm-readobj is known to mishandle.
fn random_instruction(rng: &mut Rng) -> UnwindInstruction {
    loop {
        let op = rng.byte();
        let operand = rng.byte();
        let bytes: Vec<u8> = if op == 0xb2 {
            // uleb128 of 1 to 4 bytes.
            let len = 1 + rng.below(4) as usize;
            let mut v = vec![op];
            for i in 0..len {
                let b = rng.byte() & 0x7f;
                v.push(if i + 1 < len { b | 0x80 } else { b });
            }
            v
        } else {
            vec![op, operand]
        };
        let mut iter = bytes.iter().copied();
        let Ok(Some(instruction)) = decode_unwind_instruction(&mut iter) else {
            continue;
        };
        let known_deviation = match instruction {
            UnwindInstruction::UseVspAsRaAuthModifier => true,
            UnwindInstruction::Spare {
                opcode: 0xb1,
                operand: Some(0),
            } => true,
            UnwindInstruction::PopVfpVpush { first, count } => first + count > 32,
            UnwindInstruction::IncrementVspLarge(_) => {
                // Only minimal encodings re-encode to the same bytes.
                let mut out = Vec::new();
                instruction.encode(&mut out).unwrap();
                out != bytes[..bytes.len() - iter.len()]
            }
            _ => false,
        };
        if !known_deviation {
            return instruction;
        }
    }
}

fn random_instructions(rng: &mut Rng, max_bytes: usize) -> Vec<UnwindInstruction> {
    let mut instructions = Vec::new();
    let mut len = 0;
    loop {
        let instruction = random_instruction(rng);
        let mut encoded = Vec::new();
        instruction.encode(&mut encoded).unwrap();
        if len + encoded.len() > max_bytes || rng.chance(15) {
            return instructions;
        }
        len += encoded.len();
        instructions.push(instruction);
    }
}

fn random_scope(rng: &mut Rng, wide: bool) -> Scope {
    let limit = if wide { 1 << 24 } else { 0x7fff };
    Scope {
        offset: (rng.below(limit) as u32) & !1,
        length: ((rng.below(limit - 2) as u32) & !1) + 2,
    }
}

fn random_address(rng: &mut Rng) -> Address {
    Address::Constant(0x0100_0000 + (rng.below(0x10_0000) as u32 & !1))
}

fn random_descriptors(rng: &mut Rng, wide: bool) -> Vec<Descriptor> {
    (0..rng.below(4))
        .map(|_| {
            let scope = random_scope(rng, wide);
            match rng.below(3) {
                0 => Descriptor::Cleanup {
                    scope,
                    landing_pad: random_address(rng),
                },
                1 => Descriptor::Catch {
                    scope,
                    landing_pad: rng.chance(80).then(|| random_address(rng)),
                    catches_reference: rng.chance(50),
                    catch_type: match rng.below(3) {
                        0 => CatchType::Any,
                        1 => CatchType::AnyAndFail,
                        _ => CatchType::TypeInfo(random_address(rng)),
                    },
                },
                _ => Descriptor::ExceptionSpec {
                    scope,
                    type_infos: (0..rng.below(4)).map(|_| random_address(rng)).collect(),
                    landing_pad: rng.chance(50).then(|| random_address(rng)),
                },
            }
        })
        .collect()
}

fn random_compact(rng: &mut Rng, inline: bool) -> CompactEntry {
    let personality = PersonalityIndex(rng.below(3) as u8);
    let max_bytes = match (inline, personality.is_long()) {
        (true, true) => 2,
        (_, false) => 3,
        (false, true) => 2 + 4 * rng.below(6) as usize,
    };
    CompactEntry {
        personality,
        instructions: random_instructions(rng, max_bytes),
        descriptors: if inline {
            Vec::new()
        } else {
            random_descriptors(rng, personality.has_wide_scopes())
        },
    }
}

fn random_table(rng: &mut Rng, entries: usize) -> UnwindTable {
    let mut table = UnwindTable::new();
    let mut function = 0x1000u32;
    for _ in 0..entries {
        let data = match rng.below(5) {
            0 => IndexEntryData::CantUnwind,
            1 => IndexEntryData::Inline(random_compact(rng, true)),
            2 | 3 => {
                let entry = random_compact(rng, false);
                IndexEntryData::ExTab(table.add_extab_entry(WExTabEntry::Compact(entry)))
            }
            _ => {
                let data = if rng.chance(70) {
                    let max_bytes = 3 + 4 * rng.below(4) as usize;
                    GenericData::Gnu {
                        instructions: random_instructions(rng, max_bytes),
                        lsda: (0..rng.below(24)).map(|_| rng.byte()).collect(),
                    }
                } else {
                    GenericData::Raw((0..rng.below(24)).map(|_| rng.byte()).collect())
                };
                let entry = GenericEntry {
                    personality: random_address(rng),
                    data,
                };
                IndexEntryData::ExTab(table.add_extab_entry(WExTabEntry::Generic(entry)))
            }
        };
        table.add_index_entry(IndexEntry {
            function: Address::Constant(function),
            data,
        });
        function += 2 + (rng.below(0x400) as u32 & !1);
    }
    table
}

/// Write a minimal little-endian ELF32 executable containing the two
/// sections at the given addresses.
fn write_elf(path: &Path, exidx: &[u8], extab: &[u8], bases: &BaseAddresses) {
    const SHT_PROGBITS: u32 = 1;
    const SHT_STRTAB: u32 = 3;
    const SHF_ALLOC: u32 = 2;
    const SHF_LINK_ORDER: u32 = 0x80;
    let shstrtab = b"\0.ARM.exidx\0.ARM.extab\0.shstrtab\0";

    let mut out = vec![0u8; 52];
    let mut sections = vec![[0u32; 10]];
    let mut add = |out: &mut Vec<u8>, name: u32, kind: u32, flags: u32, addr: u32, data: &[u8]| {
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
        let offset = out.len() as u32;
        out.extend_from_slice(data);
        sections.push([
            name,
            kind,
            flags,
            addr,
            offset,
            data.len() as u32,
            0,
            0,
            4,
            0,
        ]);
    };
    let exidx_addr = bases.exidx.unwrap();
    let extab_addr = bases.extab.unwrap();
    add(
        &mut out,
        1,
        ehabi::constants::SHT_ARM_EXIDX,
        SHF_ALLOC | SHF_LINK_ORDER,
        exidx_addr,
        exidx,
    );
    add(&mut out, 12, SHT_PROGBITS, SHF_ALLOC, extab_addr, extab);
    add(&mut out, 23, SHT_STRTAB, 0, 0, shstrtab);
    while !out.len().is_multiple_of(4) {
        out.push(0);
    }
    let shoff = out.len() as u32;
    for section in &sections {
        for field in section {
            out.extend_from_slice(&field.to_le_bytes());
        }
    }

    let header = &mut out[..52];
    header[..4].copy_from_slice(b"\x7fELF");
    header[4] = 1; // ELFCLASS32
    header[5] = 1; // ELFDATA2LSB
    header[6] = 1; // EV_CURRENT
    header[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    header[18..20].copy_from_slice(&40u16.to_le_bytes()); // EM_ARM
    header[20..24].copy_from_slice(&1u32.to_le_bytes()); // e_version
    header[32..36].copy_from_slice(&shoff.to_le_bytes());
    header[36..40].copy_from_slice(&0x0500_0000u32.to_le_bytes()); // EABI v5
    header[40..42].copy_from_slice(&52u16.to_le_bytes()); // e_ehsize
    header[46..48].copy_from_slice(&40u16.to_le_bytes()); // e_shentsize
    header[48..50].copy_from_slice(&(sections.len() as u16).to_le_bytes());
    header[50..52].copy_from_slice(&3u16.to_le_bytes()); // e_shstrndx
    std::fs::write(path, out).unwrap();
}

#[test]
fn random_tables_match_llvm() {
    let Some(tool) = llvm_readobj() else {
        eprintln!("llvm-readobj not found; skipping (install the llvm-tools component)");
        return;
    };
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"));
    let bases = BaseAddresses::default()
        .set_exidx(0x0010_0000)
        .set_extab(0x0020_0000);
    let mut total = 0;
    for seed in 1..=16u64 {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15));
        let table = random_table(&mut rng, 500);
        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        table.write(&mut sections, &bases).unwrap();
        let path = dir.join(format!("llvm-oracle-{seed}.elf"));
        write_elf(
            &path,
            sections.exidx.slice(),
            sections.extab.slice(),
            &bases,
        );

        let layout = Layout::Linked(bases);
        let expected = ehabi_entries(sections.exidx.slice(), sections.extab.slice(), &layout);
        total += compare(&tool, &path, expected);

        // ehabi reads back what it wrote.
        let exidx = ExIdx::new(sections.exidx.slice(), LittleEndian);
        let extab = ExTab::new(sections.extab.slice(), LittleEndian);
        let reread = UnwindTable::from_read(&exidx, &extab, &bases).unwrap();
        assert_eq!(reread.index_entries().len(), table.index_entries().len());
    }
    eprintln!("{total} random entries match llvm-readobj");
}
