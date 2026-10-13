//! Glue for loading the EHABI sections of an ELF file with the `object` crate.
//!
//! Shared by the `ehdump` example and the integration tests.
#![allow(dead_code)]

use std::collections::HashMap;
use std::rc::Rc;

use ehabi::read::{EndianSlice, ExIdx, ExTab, Relocate, RelocateReader, relocate_prel31};
use ehabi::{BaseAddresses, RunTimeEndian, SectionId, constants};
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
    /// Return the address of the named symbol, if any.
    pub fn symbol_address(&self, name: &str) -> Option<u32> {
        self.symbols
            .iter()
            .find(|(_, n)| n == name)
            .map(|(a, _)| *a)
    }

    /// Format an address, followed by the name of the symbol there, if any.
    pub fn describe(&self, address: u32) -> String {
        match self.symbol_name(address) {
            Some(name) => format!("0x{address:08x} ({name})"),
            None => format!("0x{address:08x}"),
        }
    }

    /// Return the name of the symbol at `address`, if any.
    ///
    /// The Thumb bit is ignored.
    pub fn symbol_name(&self, address: u32) -> Option<&str> {
        // `symbols` is sorted by address, so it is also sorted with the
        // Thumb bit cleared.
        let key = address & !1;
        let index = self.symbols.partition_point(|(a, _)| a & !1 < key);
        self.symbols
            .get(index)
            .filter(|(a, _)| a & !1 == key)
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

impl Relocations {
    /// Create from `(offset, relocation type, symbol address)` triples.
    ///
    /// Only relocations that change the word are kept. In particular the
    /// `R_ARM_NONE` personality dependency, which GNU as emits at the same
    /// offset as the entry's `R_ARM_PREL31`, must not replace it.
    pub fn new(
        section_address: u32,
        relocations: impl IntoIterator<Item = (usize, u32, u32)>,
    ) -> Self {
        let relocations = relocations
            .into_iter()
            .filter(|&(_, r_type, _)| {
                matches!(
                    r_type,
                    constants::R_ARM_PREL31 | constants::R_ARM_TARGET2 | constants::R_ARM_ABS32
                )
            })
            .map(|(offset, r_type, symbol)| (offset, (r_type, symbol)))
            .collect();
        Relocations {
            section_address,
            relocations: Rc::new(relocations),
        }
    }
}

impl Relocate for Relocations {
    fn relocate_word(&self, offset: usize, word: u32) -> ehabi::read::Result<u32> {
        let Some(&(r_type, symbol)) = self.relocations.get(&offset) else {
            return Ok(word);
        };
        Ok(if r_type == constants::R_ARM_PREL31 {
            let place = self.section_address.wrapping_add(offset as u32);
            relocate_prel31(word, symbol, place)
        } else {
            // R_ARM_TARGET2 and R_ARM_ABS32, with bare-metal semantics.
            symbol.wrapping_add(word)
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
    let exidx = file.section_by_name(SectionId::ArmExidx.name())?;
    let extab = file.section_by_name(SectionId::ArmExtab.name());

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
        .filter(|symbol| symbol.kind() != object::SymbolKind::Section)
        .filter_map(|symbol| {
            // Skip unnamed symbols and mapping symbols ($a, $d, ...).
            let name = symbol
                .name()
                .ok()
                .filter(|n| !n.is_empty() && !n.starts_with('$'))?;
            Some((symbol_address(&symbol), name.to_string()))
        })
        .collect();
    symbols.sort();

    let relocations = |section: &object::Section<'data, '_>| {
        let mut list = Vec::new();
        if relocatable {
            for (offset, relocation) in section.relocations() {
                let RelocationFlags::Elf { r_type } = relocation.flags() else {
                    continue;
                };
                let RelocationTarget::Symbol(index) = relocation.target() else {
                    continue;
                };
                let symbol = file.symbol_by_index(index).unwrap();
                list.push((offset as usize, r_type, symbol_address(&symbol)));
            }
        }
        Relocations::new(section_address(section), list)
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
