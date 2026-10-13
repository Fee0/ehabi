//! Glue for loading the EHABI sections of an ELF file with the `object` crate.
//!
//! Shared by the `ehdump` example and the integration tests.
#![allow(dead_code)]

use std::collections::HashMap;
use std::rc::Rc;

use ehabi::read::{EndianSlice, ExIdx, ExTab, Relocate, RelocateReader};
use ehabi::{BaseAddresses, RunTimeEndian, constants};
use object::{Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationTarget};

/// A reader for the EHABI sections of a loaded file.
pub type Reader<'data> = RelocateReader<EndianSlice<'data, RunTimeEndian>, Relocations>;

/// The EHABI sections of an ELF file.
pub struct EhSections<'data> {
    pub endian: RunTimeEndian,
    pub exidx: ExIdx<Reader<'data>>,
    pub extab: ExTab<Reader<'data>>,
    pub exidx_data: &'data [u8],
    pub extab_data: &'data [u8],
    pub bases: BaseAddresses,
    pub relocatable: bool,
    /// Symbol addresses (in the same layout as `bases`) and names, sorted.
    pub symbols: Vec<(u32, String)>,
}

impl<'data> EhSections<'data> {
    /// Return the name of the symbol at `address`, if any.
    ///
    /// The Thumb bit is ignored.
    pub fn symbol_name(&self, address: u32) -> Option<&str> {
        self.symbols
            .iter()
            .find(|(a, _)| a & !1 == address & !1)
            .map(|(_, name)| name.as_str())
    }
}

/// Applies `R_ARM_PREL31` and `R_ARM_TARGET2` relocations, using a synthetic
/// layout in which every section of a relocatable object has its own
/// address.
#[derive(Debug, Clone, Default)]
pub struct Relocations {
    section_address: u32,
    /// Section offset -> (relocation type, symbol address).
    relocations: Rc<HashMap<usize, (u32, u32)>>,
}

impl Relocate for Relocations {
    fn relocate_word(&self, offset: usize, word: u32) -> ehabi::read::Result<u32> {
        let Some(&(r_type, symbol)) = self.relocations.get(&offset) else {
            return Ok(word);
        };
        Ok(match r_type {
            constants::R_ARM_PREL31 => {
                let addend = ((word << 1) as i32 >> 1) as u32;
                let place = self.section_address.wrapping_add(offset as u32);
                let value = symbol.wrapping_add(addend).wrapping_sub(place);
                (word & 0x8000_0000) | (value & 0x7fff_ffff)
            }
            // Bare-metal semantics (R_ARM_ABS32).
            constants::R_ARM_TARGET2 | constants::R_ARM_ABS32 => symbol.wrapping_add(word),
            _ => word,
        })
    }
}

/// The synthetic address of a section in a relocatable object.
fn synthetic_section_address(index: object::SectionIndex) -> u32 {
    (index.0 as u32) << 20
}

/// The synthetic address of an undefined symbol.
fn synthetic_undefined_address(index: object::SymbolIndex) -> u32 {
    0xf000_0000 | ((index.0 as u32) << 4)
}

/// Load the `.ARM.exidx` and `.ARM.extab` sections of an ELF file.
///
/// Returns `None` if the file has no `.ARM.exidx` section. Relocatable
/// objects with several index sections (from `-ffunction-sections`) are not
/// supported: only the sections named exactly `.ARM.exidx` and `.ARM.extab`
/// are used.
pub fn load<'data>(file: &object::File<'data>) -> Option<EhSections<'data>> {
    let endian = if file.is_little_endian() {
        RunTimeEndian::Little
    } else {
        RunTimeEndian::Big
    };
    let relocatable = file.kind() == object::ObjectKind::Relocatable;
    let exidx = file.section_by_name(".ARM.exidx")?;
    let extab = file.section_by_name(".ARM.extab");

    let section_address = |section: &object::Section<'data, '_>| {
        if relocatable {
            synthetic_section_address(section.index())
        } else {
            section.address() as u32
        }
    };
    let symbol_address = |symbol: &object::Symbol<'data, '_>| match symbol.section_index() {
        Some(index) if relocatable => {
            synthetic_section_address(index).wrapping_add(symbol.address() as u32)
        }
        Some(_) => symbol.address() as u32,
        None => synthetic_undefined_address(symbol.index()),
    };

    let mut symbols: Vec<(u32, String)> = file
        .symbols()
        .filter(|symbol| !symbol.name().unwrap_or("").is_empty())
        .filter(|symbol| symbol.kind() != object::SymbolKind::Section)
        .filter(|symbol| !symbol.name().unwrap_or("").starts_with('$'))
        .map(|symbol| (symbol_address(&symbol), symbol.name().unwrap().to_string()))
        .collect();
    symbols.sort();

    let relocations = |section: &object::Section<'data, '_>| {
        let mut map = HashMap::new();
        if relocatable {
            for (offset, relocation) in section.relocations() {
                let RelocationFlags::Elf { r_type } = relocation.flags() else {
                    continue;
                };
                let RelocationTarget::Symbol(index) = relocation.target() else {
                    continue;
                };
                let symbol = file.symbol_by_index(index).unwrap();
                map.insert(offset as usize, (r_type, symbol_address(&symbol)));
            }
        }
        Relocations {
            section_address: section_address(section),
            relocations: Rc::new(map),
        }
    };

    let exidx_data = exidx.data().ok()?;
    let extab_data = extab.as_ref().and_then(|s| s.data().ok()).unwrap_or(&[]);
    let mut bases = BaseAddresses::default().set_exidx(section_address(&exidx));
    let extab_relocations = match &extab {
        Some(extab) => {
            bases = bases.set_extab(section_address(extab));
            relocations(extab)
        }
        None => Relocations::default(),
    };

    Some(EhSections {
        endian,
        exidx: ExIdx::from(RelocateReader::new(
            EndianSlice::new(exidx_data, endian),
            relocations(&exidx),
        )),
        extab: ExTab::from(RelocateReader::new(
            EndianSlice::new(extab_data, endian),
            extab_relocations,
        )),
        exidx_data,
        extab_data,
        bases,
        relocatable,
        symbols,
    })
}
