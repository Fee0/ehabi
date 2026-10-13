use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use core::fmt;

use crate::common::{BaseAddresses, ExTabOffset, SectionId};
use crate::read::{self, Reader, Section};
use crate::write::{
    Address, CatchType, CompactEntry, Descriptor, Error, ExTabEntry, GenericData, GenericEntry,
    IndexEntry, IndexEntryData, UnwindTable, encode_unwind_instructions,
};

/// An error that occurred when converting a read value into a write value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConvertError {
    /// An error occurred when reading.
    Read(read::Error),
    /// An error occurred when writing.
    Write(Error),
}

impl fmt::Display for ConvertError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConvertError::Read(e) => write!(f, "read error: {e}"),
            ConvertError::Write(e) => write!(f, "write error: {e}"),
        }
    }
}

impl core::error::Error for ConvertError {}

impl From<read::Error> for ConvertError {
    fn from(e: read::Error) -> Self {
        ConvertError::Read(e)
    }
}

impl From<Error> for ConvertError {
    fn from(e: Error) -> Self {
        ConvertError::Write(e)
    }
}

/// The result of a conversion.
pub type ConvertResult<T> = Result<T, ConvertError>;

impl UnwindTable {
    /// Create a table from parsed `.ARM.exidx` and `.ARM.extab` sections.
    ///
    /// All references are resolved to constant addresses using `bases`, so
    /// writing the table with the same base addresses reproduces the
    /// original sections, provided that every `.ARM.extab` entry is
    /// referenced from the index and the entries are contiguous.
    ///
    /// The extent of a generic-model entry is not encoded, so it is taken to
    /// end where the next referenced entry (or the section) begins. If it
    /// follows the GCC/LLVM layout it is converted to [`GenericData::Gnu`],
    /// otherwise to [`GenericData::Raw`].
    pub fn from_read<R: Reader>(
        exidx: &read::ExIdx<R>,
        extab: &read::ExTab<R>,
        bases: &BaseAddresses,
    ) -> ConvertResult<UnwindTable> {
        let mut index = Vec::new();
        let mut extab_ids = BTreeMap::new();
        let mut entries = exidx.entries();
        while let Some(entry) = entries.next()? {
            if let Some(offset) = entry.extab_offset(bases)? {
                extab_ids.insert(offset.0, None);
            }
            index.push(entry);
        }

        let mut table = UnwindTable::new();
        let section = extab.reader().to_slice()?;
        let offsets: Vec<usize> = extab_ids.keys().copied().collect();
        for (i, &offset) in offsets.iter().enumerate() {
            let end = offsets.get(i + 1).copied().unwrap_or(section.len());
            let entry = match extab.entry_at(ExTabOffset(offset))? {
                read::ExTabEntry::Compact(entry) => {
                    ExTabEntry::Compact(convert_compact(&entry, bases)?)
                }
                read::ExTabEntry::Generic(entry) => {
                    ExTabEntry::Generic(convert_generic(&entry, &section[..end], bases)?)
                }
            };
            extab_ids.insert(offset, Some(table.add_extab_entry(entry)));
        }

        for entry in index {
            let data = match entry.data() {
                read::ExIdxEntryData::CantUnwind => IndexEntryData::CantUnwind,
                read::ExIdxEntryData::Inline(compact) => {
                    IndexEntryData::Inline(convert_compact(compact, bases)?)
                }
                read::ExIdxEntryData::ExTab(_) => {
                    let offset = entry.extab_offset(bases)?.map(|offset| offset.0);
                    let id = offset.and_then(|offset| extab_ids.get(&offset).copied().flatten());
                    IndexEntryData::ExTab(id.ok_or(read::Error::OffsetOutOfBounds)?)
                }
            };
            table.add_index_entry(IndexEntry {
                function: Address::Constant(entry.function_address(bases)?),
                data,
            });
        }
        Ok(table)
    }
}

fn extab_base(bases: &BaseAddresses) -> Result<u32, read::Error> {
    bases
        .extab
        .ok_or(read::Error::MissingBaseAddress(SectionId::ArmExtab))
}

fn convert_compact<R: Reader>(
    entry: &read::CompactEntry<R>,
    bases: &BaseAddresses,
) -> ConvertResult<CompactEntry> {
    let instructions = entry.instructions()?.collect::<read::Result<Vec<_>>>()?;
    let mut descriptors = Vec::new();
    if let Some(mut iter) = entry.descriptors()? {
        while let Some(descriptor) = iter.next()? {
            descriptors.push(convert_descriptor(descriptor, bases)?);
        }
    }
    Ok(CompactEntry {
        personality: entry.personality(),
        instructions,
        descriptors,
    })
}

fn convert_descriptor<R: Reader>(
    descriptor: read::Descriptor<R>,
    bases: &BaseAddresses,
) -> ConvertResult<Descriptor> {
    let extab = extab_base(bases)?;
    let address = |reference: read::Prel31| Address::Constant(reference.address(extab));
    Ok(match descriptor {
        read::Descriptor::Cleanup { scope, landing_pad } => Descriptor::Cleanup {
            scope,
            landing_pad: address(landing_pad),
        },
        read::Descriptor::Catch {
            scope,
            landing_pad,
            catches_reference,
            catch_type,
        } => Descriptor::Catch {
            scope,
            landing_pad: (landing_pad.value != 0).then(|| address(landing_pad)),
            catches_reference,
            catch_type: match catch_type {
                read::CatchType::Any => CatchType::Any,
                read::CatchType::AnyAndFail => CatchType::AnyAndFail,
                read::CatchType::TypeInfo(type_info) => {
                    CatchType::TypeInfo(Address::Constant(type_info.value))
                }
            },
        },
        read::Descriptor::ExceptionSpec(spec) => Descriptor::ExceptionSpec {
            scope: spec.scope(),
            type_infos: spec
                .type_infos()
                .map(|type_info| type_info.map(|t| Address::Constant(t.value)))
                .collect::<read::Result<_>>()?,
            landing_pad: spec.landing_pad().map(address),
        },
    })
}

fn convert_generic<R: Reader>(
    entry: &read::GenericEntry<R>,
    section: &[u8],
    bases: &BaseAddresses,
) -> ConvertResult<GenericEntry> {
    let personality = Address::Constant(entry.personality_address(bases)?);
    let start = entry.offset().0 + 4;
    let raw = || GenericData::Raw(section.get(start..).unwrap_or_default().to_vec());

    // Use the GCC/LLVM layout only if re-encoding it reproduces the original
    // length, so the LSDA stays where it was.
    let gnu = || -> read::Result<Option<GenericData>> {
        let original_len = entry.gnu_unwind_bytes()?.remaining();
        let instructions = entry
            .gnu_instructions()?
            .collect::<read::Result<Vec<_>>>()?;
        let lsda_offset = entry.gnu_lsda_offset()?.0;
        let Ok(encoded) = encode_unwind_instructions(&instructions) else {
            return Ok(None);
        };
        let encoded_len = 3 + encoded.len().saturating_sub(3).div_ceil(4) * 4;
        if encoded_len != original_len || lsda_offset > section.len() {
            return Ok(None);
        }
        Ok(Some(GenericData::Gnu {
            instructions,
            lsda: section[lsda_offset..].to_vec(),
        }))
    };
    let data = gnu().ok().flatten().unwrap_or_else(raw);
    Ok(GenericEntry { personality, data })
}
