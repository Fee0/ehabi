//! The `lsda` feature: reading and writing the LSDA of generic-model entries
//! with the `lsda` crate.
//!
//! Set `EHABI_CORPUS` to also convert and rewrite every LSDA in a directory
//! of linked Arm ELF files (see `tests/corpus.rs`).

use std::path::{Path, PathBuf};

use ehabi::read::{ExIdx, ExTab, Section, UnwindEntry};
use ehabi::write::{
    Address, EndianVec, ExTabEntry, GenericData, GenericEntry, IndexEntry, IndexEntryData,
    RelocateWriter, Relocation, RelocationKind, RelocationTarget, Sections, UnwindTable,
};
use ehabi::{BaseAddresses, ExTabOffset, LittleEndian, UnwindInstruction};
use lsda::read::Filter;

mod elf;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!("{}/tests/data/{name}", env!("CARGO_MANIFEST_DIR"))).unwrap()
}

/// Every LSDA of the C++ fixtures parses, in place and through the
/// relocations of the relocatable objects.
#[test]
fn test_parse_gnu_lsdas() {
    for name in ["eh-armv7.so", "eh-armv7.o", "eh-thumbv7.o"] {
        let data = fixture(name);
        let file = object::File::parse(&*data).unwrap();
        let s = elf::load(&file).unwrap();
        let mut lsdas = 0;
        let mut catch_int = false;
        let mut entries = s.exidx.entries();
        while let Some(entry) = entries.next().unwrap() {
            let UnwindEntry::Generic(generic) = entry.resolve(&s.extab, &s.bases).unwrap() else {
                continue;
            };
            let function = s.describe(entry.function_address(&s.bases).unwrap());
            let lsda = generic.parse_gnu_lsda().expect(&function);
            let tables = lsda.parse_tables().expect(&function);
            lsdas += 1;

            // catch (int &) and catch (...), with the relocated type_info
            // reference named in the relocatable objects.
            if function.contains("catch_int") {
                let filters: Vec<_> = tables.actions.iter().map(|a| a.filter).collect();
                assert_eq!(filters, [Filter::Catch(1), Filter::Catch(2)], "{name}");
                let (null, int): (Vec<&lsda::read::Pointer>, Vec<_>) =
                    tables.types.iter().partition(|pointer| pointer.is_null());
                assert_eq!((null.len(), int.len()), (1, 1), "{name}");
                if s.relocatable {
                    let type_info = int[0].value() as u32;
                    assert_eq!(s.symbol_name(type_info), Some("_ZTIi"), "{name}");
                }
                catch_int = true;
            }
        }
        assert!(lsdas >= 4, "{name}: {lsdas} LSDAs");
        assert!(catch_int, "{name}");
    }
}

/// `from_read_with_lsdas` converts every LSDA of a linked file, and the
/// table writes back identically.
#[test]
fn test_roundtrip_with_lsdas() {
    let data = fixture("eh-armv7.so");
    let file = object::File::parse(&*data).unwrap();
    let s = elf::load(&file).unwrap();
    let (converted, raw) = roundtrip(&s.exidx, &s.extab, &s.bases, s.exidx_data, s.extab_data);
    assert_eq!(raw, 0);
    assert!(converted >= 4);
}

/// Convert the tables with their LSDAs and write them back, checking that
/// the sections are identical; return the numbers of LSDAs converted and
/// kept as bytes.
///
/// An LSDA may only be kept as bytes in the last `.ARM.extab` entry, if the
/// section ends with padding, which the writer does not add after the last
/// entry.
fn roundtrip<R: ehabi::read::Reader>(
    exidx: &ExIdx<R>,
    extab: &ExTab<R>,
    bases: &BaseAddresses,
    exidx_data: &[u8],
    extab_data: &[u8],
) -> (usize, usize) {
    let table = UnwindTable::from_read_with_lsdas(exidx, extab, bases).unwrap();
    let mut sections = Sections::new(EndianVec::new(exidx.reader().endian()));
    let offsets = table.write(&mut sections, bases).unwrap();
    assert!(sections.exidx.slice() == exidx_data, ".ARM.exidx differs");
    assert!(sections.extab.slice() == extab_data, ".ARM.extab differs");

    let mut ids: Vec<_> = table
        .index_entries()
        .iter()
        .filter_map(|entry| match entry.data {
            IndexEntryData::ExTab(id) => Some((offsets.get(id).0, id)),
            _ => None,
        })
        .collect();
    ids.sort_unstable_by_key(|(offset, _)| *offset);
    ids.dedup_by_key(|(offset, _)| *offset);
    let last = ids.last().map(|(offset, _)| *offset);
    let (mut converted, mut raw) = (0, 0);
    for (offset, id) in ids {
        if let ExTabEntry::Generic(generic) = table.extab_entry(id) {
            match generic.data {
                GenericData::GnuLsda { .. } => converted += 1,
                GenericData::Gnu { .. } => {
                    assert_eq!(Some(offset), last, "LSDA at {offset:#x} kept as bytes");
                    raw += 1;
                }
                _ => {}
            }
        }
    }
    (converted, raw)
}

/// GCC's LSDA for `try { g(); } catch (int) {}`: the type table is
/// pc-relative (`DW_EH_PE_pcrel | DW_EH_PE_indirect`).
fn gcc_lsda(type_info: lsda::write::Address) -> lsda::write::Lsda {
    use lsda::write::{Action, CallSite, Filter, Lsda};
    let mut lsda = Lsda::new();
    lsda.ttype_encoding = lsda::Encoding(0x90);
    let int = lsda.add_type(Some(type_info));
    let catch = lsda.add_action(Action {
        filter: Filter::Catch(int),
        next: None,
    });
    lsda.call_sites
        .push(CallSite::new(0x8, 0x4, 0x10, Some(catch)));
    lsda
}

/// Two generic entries, the second with `lsda`.
fn table(first: Vec<UnwindInstruction>, lsda: GenericData) -> UnwindTable {
    let mut table = UnwindTable::new();
    for (function, data) in [
        (
            0x8000,
            GenericData::Gnu {
                instructions: first,
                lsda: vec![0xff, 0xff, 0x01, 0x00],
            },
        ),
        (0x8100, lsda),
    ] {
        let id = table.add_extab_entry(ExTabEntry::Generic(GenericEntry {
            personality: Address::Constant(0x9000),
            data,
        }));
        table.add_index_entry(IndexEntry {
            function: Address::Constant(function),
            data: IndexEntryData::ExTab(id),
        });
    }
    table
}

/// Write a table, and return the `type_info` address and the raw type
/// table entry of the LSDA of its second entry.
fn type_info(table: &UnwindTable, bases: &BaseAddresses) -> (u64, u64) {
    let mut sections = Sections::new(EndianVec::new(LittleEndian));
    table.write(&mut sections, bases).unwrap();
    let exidx = ExIdx::new(sections.exidx.slice(), LittleEndian);
    let extab = ExTab::new(sections.extab.slice(), LittleEndian);
    let entry = exidx.entries().nth(1).unwrap().unwrap();
    let UnwindEntry::Generic(generic) = entry.resolve(&extab, bases).unwrap() else {
        panic!("expected a generic entry");
    };
    let lsda = generic.parse_gnu_lsda().unwrap();
    let entry = lsda.type_entry(1).unwrap();
    let lsda_bases = lsda::BaseAddresses::default().set_section(u64::from(bases.extab.unwrap()));
    (entry.address(&lsda_bases).unwrap(), entry.value())
}

/// An LSDA model is written where its entry ends up, so its pc-relative
/// references stay correct when entries move; LSDA bytes do not.
#[test]
fn test_moved_entry() {
    let bases = BaseAddresses::default().set_exidx(0x1000).set_extab(0x2000);
    let model = GenericData::GnuLsda {
        instructions: Vec::new(),
        lsda: gcc_lsda(lsda::write::Address::Constant(0x5000)),
    };
    let original = table(Vec::new(), model.clone());
    let (address, raw) = type_info(&original, &bases);
    assert_eq!(address, 0x5000);

    // Instructions that need an extra word move the second entry by 4.
    let mut longer = UnwindInstruction::vsp_add(0x1_0000).unwrap();
    longer.extend(UnwindInstruction::pop_core(0x4ff0));
    let moved = table(longer.clone(), model);
    let (address, moved_raw) = type_info(&moved, &bases);
    assert_eq!(address, 0x5000);
    assert_eq!(moved_raw, raw.wrapping_sub(4) & 0xffff_ffff);

    // The same LSDA as bytes keeps the value for its old place.
    let mut sections = Sections::new(EndianVec::new(LittleEndian));
    original.write(&mut sections, &bases).unwrap();
    let bytes = GenericData::Gnu {
        instructions: Vec::new(),
        // The second entry is at 0xc: personality, instructions, LSDA.
        lsda: sections.extab.slice()[0x14..].to_vec(),
    };
    assert_eq!(
        type_info(&table(Vec::new(), bytes.clone()), &bases).0,
        0x5000
    );
    assert_eq!(type_info(&table(longer, bytes), &bases).0, 0x5000 + 4);
}

/// A writer that records relocations.
#[derive(Debug)]
struct Recorder {
    section: EndianVec<LittleEndian>,
    relocations: Vec<Relocation>,
}

impl Recorder {
    fn new() -> Self {
        Recorder {
            section: EndianVec::new(LittleEndian),
            relocations: Vec::new(),
        }
    }
}

impl RelocateWriter for Recorder {
    type Writer = EndianVec<LittleEndian>;
    fn writer(&self) -> &Self::Writer {
        &self.section
    }
    fn writer_mut(&mut self) -> &mut Self::Writer {
        &mut self.section
    }
    fn relocate(&mut self, relocation: Relocation) {
        self.relocations.push(relocation);
    }
}

/// Errors of the `lsda` crate, and symbols it cannot relocate.
#[test]
fn test_write_errors() {
    let bases = BaseAddresses::default().set_exidx(0x1000).set_extab(0x2000);
    let write = |lsda: lsda::write::Lsda| {
        let table = table(
            Vec::new(),
            GenericData::GnuLsda {
                instructions: Vec::new(),
                lsda,
            },
        );
        let mut sections = Sections {
            exidx: ehabi::write::ExIdx(Recorder::new()),
            extab: ehabi::write::ExTab(Recorder::new()),
        };
        table.write(&mut sections, &bases).map(|_| ())
    };

    // @LPStart would need a relocation that is not recorded.
    let mut lsda = gcc_lsda(lsda::write::Address::Constant(0x5000));
    lsda.lpstart = Some(lsda::write::LpStart {
        encoding: lsda::Encoding::ABSPTR,
        address: lsda::write::Address::Symbol {
            symbol: 1,
            addend: 0,
        },
    });
    assert_eq!(write(lsda), Err(ehabi::write::Error::InvalidAddress));

    // The error of the lsda crate is the source.
    let mut lsda = gcc_lsda(lsda::write::Address::Constant(0x5000));
    lsda.ttype_encoding = lsda::Encoding::ULEB128;
    let error = write(lsda).unwrap_err();
    let lsda_error = lsda::write::Error::VariableSizeTypeEncoding(lsda::Encoding::ULEB128);
    assert_eq!(error, ehabi::write::Error::Lsda(lsda_error));
    let source = std::error::Error::source(&error).unwrap();
    assert_eq!(source.to_string(), lsda_error.to_string());
}

/// Symbol references to `type_info` objects in an LSDA model become
/// `R_ARM_TARGET2` relocations.
#[test]
fn test_type_info_relocations() {
    let mut lsda = gcc_lsda(lsda::write::Address::Symbol {
        symbol: 7,
        addend: 0,
    });
    lsda.add_exception_spec(lsda::write::ExceptionSpec::TypeInfos(vec![
        lsda::write::Address::Symbol {
            symbol: 8,
            addend: 4,
        },
    ]));
    let table = table(
        Vec::new(),
        GenericData::GnuLsda {
            instructions: Vec::new(),
            lsda,
        },
    );
    let bases = BaseAddresses::default().set_exidx(0x1000).set_extab(0x2000);
    let mut sections = Sections {
        exidx: ehabi::write::ExIdx(Recorder::new()),
        extab: ehabi::write::ExTab(Recorder::new()),
    };
    table.write(&mut sections, &bases).unwrap();

    let target2: Vec<_> = sections
        .extab
        .relocations
        .iter()
        .filter(|r| r.kind == RelocationKind::Target2)
        .map(|r| (r.target, r.addend))
        .collect();
    assert_eq!(
        target2,
        [
            (RelocationTarget::Symbol(7), 0),
            (RelocationTarget::Symbol(8), 4)
        ]
    );
    // The type reference is where the LSDA reader finds it. References to
    // `.ARM.extab` are relocations too, so find the entry by its offset.
    let extab = ExTab::new(sections.extab.section.slice(), LittleEndian);
    let ehabi::read::ExTabEntry::Generic(generic) = extab.entry_at(ExTabOffset(0xc)).unwrap()
    else {
        panic!("expected a generic entry");
    };
    let type_offset = generic
        .parse_gnu_lsda()
        .unwrap()
        .type_entry(1)
        .unwrap()
        .offset();
    let type_relocation = sections
        .extab
        .relocations
        .iter()
        .find(|r| r.target == RelocationTarget::Symbol(7))
        .unwrap();
    assert_eq!(type_relocation.offset, type_offset);

    // Without relocations, a symbol cannot be written.
    let mut plain = Sections::new(EndianVec::new(LittleEndian));
    assert_eq!(
        table.write(&mut plain, &bases),
        Err(ehabi::write::Error::InvalidAddress)
    );
}

/// Collect the files in `dir` and its subdirectories.
fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, out);
        } else {
            out.push(path);
        }
    }
}

/// Every LSDA of the linked files in `EHABI_CORPUS` converts and writes back
/// identically.
#[test]
fn test_corpus_lsdas() {
    let Ok(dir) = std::env::var("EHABI_CORPUS") else {
        return;
    };
    let mut paths = Vec::new();
    walk(Path::new(&dir), &mut paths);
    let (mut files, mut converted, mut raw) = (0, 0, 0);
    for path in paths {
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let Ok(file) = object::File::parse(&*data) else {
            continue;
        };
        let Some(s) = elf::load(&file) else {
            continue;
        };
        if s.relocatable {
            continue;
        }
        let (c, r) = roundtrip(&s.exidx, &s.extab, &s.bases, s.exidx_data, s.extab_data);
        if r != 0 {
            eprintln!("{}: the last LSDA is kept as bytes", path.display());
        }
        files += 1;
        converted += c;
        raw += r;
    }
    assert_ne!(converted, 0, "no LSDAs in {files} files");
    eprintln!("{files} files: {converted} LSDAs converted, {raw} kept as bytes");
}
