//! Tests against objects produced by clang; see `tests/data/src` for the
//! sources and build commands.

use ehabi::read::{CatchType, Descriptor, Reader, UnwindEntry};
use ehabi::write::{self, EndianVec, Sections, UnwindTable, Writer};
use ehabi::{PersonalityIndex, Scope, UnwindInstruction, UnwindInstruction::*};

mod elf;

fn load(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Return the resolved unwinding information for the named function.
fn entry_for<'a>(s: &elf::EhSections<'a>, function: &str) -> UnwindEntry<elf::Reader<'a>> {
    let mut entries = s.exidx.entries();
    while let Some(entry) = entries.next().unwrap() {
        let address = entry.function_address(&s.bases).unwrap();
        if s.symbol_name(address) == Some(function) {
            return entry.resolve(&s.extab, &s.bases).unwrap();
        }
    }
    panic!("no entry for {function}");
}

fn instructions(entry: &UnwindEntry<elf::Reader<'_>>) -> Vec<UnwindInstruction> {
    let iter = match entry {
        UnwindEntry::Compact(compact) => compact.instructions().unwrap(),
        UnwindEntry::Generic(generic) => generic.gnu_instructions().unwrap(),
        UnwindEntry::CantUnwind => panic!("cannot unwind"),
    };
    iter.collect::<Result<_, _>>().unwrap()
}

fn compact_personality(entry: &UnwindEntry<elf::Reader<'_>>) -> (PersonalityIndex, bool) {
    match entry {
        UnwindEntry::Compact(compact) => (compact.personality(), compact.is_inline()),
        _ => panic!("expected compact entry"),
    }
}

fn descriptors<'a>(entry: &UnwindEntry<elf::Reader<'a>>) -> Vec<Descriptor<elf::Reader<'a>>> {
    match entry {
        UnwindEntry::Compact(compact) => compact
            .descriptors()
            .unwrap()
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap(),
        _ => panic!("expected compact entry"),
    }
}

/// The functions in `unwind.s` decode to what their directives specify.
fn check_unwind_object(name: &str) {
    let data = load(name);
    let file = object::File::parse(&*data).unwrap();
    let s = elf::load(&file).unwrap();
    assert!(s.relocatable);
    assert_eq!(s.exidx.len(), 10);

    let f = entry_for(&s, "f_save_lr");
    assert_eq!(compact_personality(&f), (PersonalityIndex::SU16, true));
    assert_eq!(
        instructions(&f),
        [PopCoreRange { last: 4, lr: true }, Finish]
    );

    let f = entry_for(&s, "f_save_pad");
    assert_eq!(
        instructions(&f),
        [
            IncrementVsp(16),
            PopCoreRange { last: 11, lr: true },
            Finish
        ]
    );

    let f = entry_for(&s, "f_vfp_large");
    assert_eq!(compact_personality(&f), (PersonalityIndex::LU16, false));
    assert_eq!(
        instructions(&f),
        [
            IncrementVspLarge(0x300),
            PopVfpVpush {
                first: 16,
                count: 2
            },
            PopVfpVpush { first: 8, count: 8 },
            PopCoreRange { last: 5, lr: true },
            Finish,
        ]
    );

    assert!(matches!(
        entry_for(&s, "f_cantunwind"),
        UnwindEntry::CantUnwind
    ));

    let f = entry_for(&s, "f_setfp");
    assert_eq!(
        instructions(&f),
        [
            SetVsp(7),
            DecrementVsp(4),
            PopCore {
                mask: (1 << 4) | (1 << 7) | (1 << 14)
            },
            Finish
        ]
    );

    let f = entry_for(&s, "f_low_regs");
    assert_eq!(
        instructions(&f),
        [
            PopCore { mask: 0xf },
            PopCore {
                mask: (1 << 11) | (1 << 14)
            },
            Finish
        ]
    );

    // Descriptors with 16-bit scopes. The landing pad is 0x10 bytes into the
    // function.
    let f = entry_for(&s, "f_pr1_descriptors");
    assert_eq!(compact_personality(&f), (PersonalityIndex::LU16, false));
    let function = s
        .symbols
        .iter()
        .find(|(_, n)| n == "f_pr1_descriptors")
        .unwrap()
        .0;
    let type_info = s.symbols.iter().find(|(_, n)| n == "_ZTIi").unwrap().0;
    let extab = s.bases.extab.unwrap();
    let pad = function + 0x10;
    let d = descriptors(&f);
    assert_eq!(d.len(), 4);
    match &d[0] {
        Descriptor::Cleanup { scope, landing_pad } => {
            assert_eq!(
                *scope,
                Scope {
                    offset: 4,
                    length: 8
                }
            );
            assert_eq!(landing_pad.address(extab), pad);
        }
        other => panic!("unexpected {other:?}"),
    }
    match &d[1] {
        Descriptor::Catch {
            scope,
            landing_pad,
            catches_reference,
            catch_type,
        } => {
            assert_eq!(
                *scope,
                Scope {
                    offset: 8,
                    length: 4
                }
            );
            assert_eq!(landing_pad.address(extab), pad);
            assert!(*catches_reference);
            assert_eq!(*catch_type, CatchType::Any);
        }
        other => panic!("unexpected {other:?}"),
    }
    match &d[2] {
        Descriptor::Catch {
            catches_reference,
            catch_type: CatchType::TypeInfo(t),
            ..
        } => {
            assert!(!catches_reference);
            assert_eq!(t.value, type_info);
        }
        other => panic!("unexpected {other:?}"),
    }
    match &d[3] {
        Descriptor::ExceptionSpec(spec) => {
            assert_eq!(
                spec.scope(),
                Scope {
                    offset: 0,
                    length: 12
                }
            );
            let types: Vec<u32> = spec.type_infos().map(|t| t.unwrap().value).collect();
            assert_eq!(types, [type_info]);
            assert_eq!(spec.landing_pad().unwrap().address(extab), pad);
        }
        other => panic!("unexpected {other:?}"),
    }

    // Descriptors with 32-bit scopes.
    let f = entry_for(&s, "f_pr2_descriptors");
    assert_eq!(compact_personality(&f), (PersonalityIndex::LU32, false));
    let d = descriptors(&f);
    assert!(matches!(
        &d[0],
        Descriptor::Catch {
            scope: Scope { offset: 0, length: 8 },
            catch_type: CatchType::AnyAndFail,
            landing_pad,
            ..
        } if landing_pad.value == 0
    ));
    match &d[1] {
        Descriptor::ExceptionSpec(spec) => {
            assert_eq!(spec.count(), 0);
            assert_eq!(spec.landing_pad(), None);
        }
        other => panic!("unexpected {other:?}"),
    }

    // Generic model with the GCC/LLVM layout.
    let f = entry_for(&s, "f_generic");
    let UnwindEntry::Generic(generic) = &f else {
        panic!("expected generic entry");
    };
    let personality = generic.personality_address(&s.bases).unwrap();
    assert_eq!(s.symbol_name(personality), Some("__gxx_personality_v0"));
    assert_eq!(
        instructions(&f),
        [
            PopCore {
                mask: (1 << 11) | (1 << 14)
            },
            Finish
        ]
    );
    let lsda = generic.gnu_lsda().unwrap();
    assert_eq!(&lsda.to_slice().unwrap()[..4], [0xff, 0xff, 0x03, 0x00]);

    // Raw opcodes, including the PACBTI-M ones.
    let f = entry_for(&s, "f_raw");
    assert_eq!(
        instructions(&f),
        [
            RefuseToUnwind,
            UseVspAsRaAuthModifier,
            PopRaAuthCode,
            Finish
        ]
    );
}

#[test]
fn unwind_object_little_endian() {
    check_unwind_object("unwind-armv7.o");
}

#[test]
fn unwind_object_big_endian() {
    check_unwind_object("unwind-armebv7.o");
}

/// Converting a linked image's tables and writing them with the same base
/// addresses reproduces the sections byte for byte.
#[test]
fn linked_roundtrip() {
    let data = load("eh-armv7.so");
    let file = object::File::parse(&*data).unwrap();
    let s = elf::load(&file).unwrap();
    assert!(!s.relocatable);

    let table = UnwindTable::from_read(&s.exidx, &s.extab, &s.bases).unwrap();
    assert_eq!(table.index_entries().len(), s.exidx.len());
    let mut sections = Sections::new(EndianVec::new(s.endian));
    table.write(&mut sections, &s.bases).unwrap();
    assert_eq!(sections.exidx.slice(), s.exidx_data);
    assert_eq!(sections.extab.slice(), s.extab_data);

    // The 8 C++ functions with handlers and `f_generic` use the GCC/LLVM
    // generic layout, and every generic
    // entry was recognised as such.
    let mut gnu = 0;
    for entry in table.index_entries() {
        if let write::IndexEntryData::ExTab(id) = entry.data
            && let write::ExTabEntry::Generic(generic) = table.extab_entry(id)
        {
            assert!(matches!(generic.data, write::GenericData::Gnu { .. }));
            gnu += 1;
        }
    }
    assert_eq!(gnu, 9);
}

/// Every function can be found by address in the sorted, linked table.
#[test]
fn linked_lookup() {
    let data = load("eh-armv7.so");
    let file = object::File::parse(&*data).unwrap();
    let s = elf::load(&file).unwrap();

    let mut entries = s.exidx.entries();
    let mut previous = None;
    while let Some(entry) = entries.next().unwrap() {
        let address = entry.function_address(&s.bases).unwrap();
        if let Some(previous) = previous {
            assert!(address > previous, "table is sorted");
        }
        previous = Some(address);
        for probe in [address, address + 2] {
            let found = s.exidx.find(probe, &s.bases).unwrap().unwrap();
            assert_eq!(found.offset(), entry.offset());
        }
        // Every entry resolves, and its instructions decode.
        match entry.resolve(&s.extab, &s.bases).unwrap() {
            UnwindEntry::CantUnwind => {}
            resolved => {
                instructions(&resolved);
            }
        }
    }
    let first = s
        .exidx
        .entry(0)
        .unwrap()
        .function_address(&s.bases)
        .unwrap();
    assert!(s.exidx.find(first - 1, &s.bases).unwrap().is_none());
}

/// Converting a relocatable object (through the relocation layer), writing
/// it, and reading it back gives the same table.
#[test]
fn object_roundtrip() {
    for name in [
        "unwind-armv7.o",
        "unwind-armebv7.o",
        "eh-armv7.o",
        "eh-thumbv7.o",
    ] {
        let data = load(name);
        let file = object::File::parse(&*data).unwrap();
        let s = elf::load(&file).unwrap();
        let table = UnwindTable::from_read(&s.exidx, &s.extab, &s.bases).unwrap();

        let mut sections = Sections::new(EndianVec::new(s.endian));
        table.write(&mut sections, &s.bases).unwrap();
        let exidx = ehabi::read::ExIdx::new(sections.exidx.slice(), s.endian);
        let extab = ehabi::read::ExTab::new(sections.extab.slice(), s.endian);
        let reread = UnwindTable::from_read(&exidx, &extab, &s.bases).unwrap();
        assert_eq!(table, reread, "{name}");
        assert_eq!(sections.extab.len(), s.extab_data.len(), "{name}");
    }
}

/// Writing with symbols records the relocations an assembler would emit.
#[test]
fn write_relocatable() {
    use ehabi::write::{
        Address, CompactEntry, ExTabEntry, IndexEntry, IndexEntryData, RelocateWriter, Relocation,
        RelocationKind, RelocationTarget,
    };
    use ehabi::{LittleEndian, SectionId};

    struct Object {
        data: EndianVec<LittleEndian>,
        relocations: Vec<Relocation>,
    }

    impl Clone for Object {
        fn clone(&self) -> Self {
            Object {
                data: EndianVec::new(LittleEndian),
                relocations: Vec::new(),
            }
        }
    }

    impl RelocateWriter for Object {
        type Writer = EndianVec<LittleEndian>;
        fn writer(&self) -> &Self::Writer {
            &self.data
        }
        fn writer_mut(&mut self) -> &mut Self::Writer {
            &mut self.data
        }
        fn relocate(&mut self, relocation: Relocation) {
            self.relocations.push(relocation);
        }
    }

    const TEXT: usize = 1;
    const PR0: usize = 2;
    const PR1: usize = 3;

    let mut table = UnwindTable::new();
    table.set_personality_symbol(PersonalityIndex::SU16, PR0);
    table.set_personality_symbol(PersonalityIndex::LU16, PR1);
    let mut inline = CompactEntry::new(PersonalityIndex::SU16);
    inline.instructions = UnwindInstruction::pop_core(0x4010).unwrap();
    table.add_index_entry(IndexEntry {
        function: Address::Symbol {
            symbol: TEXT,
            addend: 0,
        },
        data: IndexEntryData::Inline(inline),
    });
    let mut long = CompactEntry::new(PersonalityIndex::LU16);
    long.instructions = UnwindInstruction::vsp_add(0x300).unwrap();
    long.instructions
        .extend(UnwindInstruction::pop_vfp(8, 8).unwrap());
    let id = table.add_extab_entry(ExTabEntry::Compact(long));
    table.add_index_entry(IndexEntry {
        function: Address::Symbol {
            symbol: TEXT,
            addend: 8,
        },
        data: IndexEntryData::ExTab(id),
    });

    let mut sections = Sections::new(Object {
        data: EndianVec::new(LittleEndian),
        relocations: Vec::new(),
    });
    table
        .write(&mut sections, &ehabi::BaseAddresses::default())
        .unwrap();

    let words = |data: &[u8]| -> Vec<u32> {
        data.chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect()
    };
    // The same words clang emits for f_save_lr and (the start of) f_vfp_large.
    assert_eq!(words(sections.exidx.data.slice()), [0, 0x80a8_b0b0, 8, 0]);
    assert_eq!(
        words(sections.extab.data.slice()),
        [0x8101_b23f, 0xd7b0_b0b0, 0]
    );
    let prel31 = |offset, target, addend| Relocation {
        offset,
        kind: RelocationKind::Prel31,
        target,
        addend,
    };
    let none = |offset, symbol| Relocation {
        offset,
        kind: RelocationKind::None,
        target: RelocationTarget::Symbol(symbol),
        addend: 0,
    };
    assert_eq!(
        sections.exidx.relocations,
        [
            prel31(0, RelocationTarget::Symbol(TEXT), 0),
            none(4, PR0),
            prel31(8, RelocationTarget::Symbol(TEXT), 8),
            prel31(12, RelocationTarget::Section(SectionId::ArmExtab), 0),
        ]
    );
    assert_eq!(sections.extab.relocations, [none(0, PR1)]);
}

/// GNU as emits the `R_ARM_NONE` personality dependency after the
/// `R_ARM_PREL31` at the same offset; it must not replace it.
#[test]
fn relocation_order_gnu_as() {
    use ehabi::constants::{R_ARM_NONE, R_ARM_PREL31};
    use ehabi::read::Relocate;

    let function = 0x0010_0040;
    let pr0 = 0xf000_0010;
    for relocations in [
        [(0, R_ARM_PREL31, function), (0, R_ARM_NONE, pr0)],
        [(0, R_ARM_NONE, pr0), (0, R_ARM_PREL31, function)],
    ] {
        let relocations = elf::Relocations::new(0x0030_0000, relocations);
        let word = relocations.relocate_word(0, 0).unwrap();
        let place = 0x0030_0000u32;
        assert_eq!(word, function.wrapping_sub(place) & 0x7fff_ffff);
    }
}
