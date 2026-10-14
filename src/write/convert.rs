use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;
use core::{fmt, iter};

use crate::common::{BaseAddresses, ExTabOffset, SectionId};
use crate::read::{self, Reader, Section};
use crate::unwind::UnwindInstruction::{self, Finish};
use crate::write::unwind::extra_unwind_words;
use crate::write::{
    Address, CatchType, CompactEntry, Descriptor, Error, ExTabEntry, GenericData, GenericEntry,
    IndexEntry, IndexEntryData, UnwindTable, encode_unwind_instructions,
};
#[cfg(feature = "lsda")]
use crate::write::{EndianVec, Writer};

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
    /// Every entry keeps its length, so no `.ARM.extab` entry moves and
    /// place-relative references inside entries (such as `R_ARM_TARGET2`
    /// `type_info` references) stay valid. Instructions after the first
    /// *Finish* are kept, and trailing *Finish* padding is dropped, since the
    /// writer adds it back. Two cases change the bytes of a compact entry,
    /// but not its length: a non-minimal uleb128 operand is re-encoded
    /// minimally, and bytes after the first *Finish* that do not decode are
    /// dropped. Either way the entry is padded with *Finish* to its original
    /// length.
    ///
    /// The extent of a generic-model entry is not encoded, so it is taken to
    /// end where the next referenced entry (or the section) begins. If it
    /// follows the GCC/LLVM layout and re-encodes to the same bytes, it is
    /// converted to [`GenericData::Gnu`], otherwise to [`GenericData::Raw`].
    ///
    /// Descriptors with a zero-length scope are rejected with
    /// [`read::Error::InvalidScope`], as the EHABI requires a non-zero length.
    ///
    /// # Errors
    ///
    /// Returns [`ConvertError::Read`] if an entry cannot be parsed or a base
    /// address is missing, and [`ConvertError::Write`] if a parsed entry cannot
    /// be represented in the table.
    pub fn from_read<R: Reader>(
        exidx: &read::ExIdx<R>,
        extab: &read::ExTab<R>,
        bases: &BaseAddresses,
    ) -> ConvertResult<UnwindTable> {
        convert_tables(exidx, extab, bases, false)
    }

    /// Create a table from parsed `.ARM.exidx` and `.ARM.extab` sections, as
    /// [`from_read`](Self::from_read) does, with the LSDA of each
    /// GCC/LLVM-layout entry as a model of the `lsda` crate:
    /// [`GenericData::GnuLsda`] instead of [`GenericData::Gnu`].
    ///
    /// An LSDA is converted only if writing it in place reproduces its bytes
    /// exactly, as [`lsda::write::GccExceptTable::from_read`] requires, with
    /// the padding before the next entry; otherwise the entry stays
    /// [`GenericData::Gnu`]. Its pointers become constant addresses, so a
    /// [`GnuLsda`](GenericData::GnuLsda) stays correct when entries move.
    ///
    /// Like [`from_read`](Self::from_read), this is for linked images. In a
    /// relocatable object, read through a
    /// [`RelocateReader`](read::RelocateReader), a type reference becomes the
    /// constant that its relocation gives, and no longer refers to its
    /// symbol.
    ///
    /// The personality routine is not checked: the data of any entry whose
    /// instructions follow the GCC/LLVM layout is converted if the rest reads
    /// and writes back exactly as an LSDA. For tables that use personality
    /// routines with another data format, use [`from_read`](Self::from_read),
    /// which keeps the data as bytes.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`from_read`](Self::from_read).
    #[cfg(feature = "lsda")]
    pub fn from_read_with_lsdas<R: Reader>(
        exidx: &read::ExIdx<R>,
        extab: &read::ExTab<R>,
        bases: &BaseAddresses,
    ) -> ConvertResult<UnwindTable> {
        convert_tables(exidx, extab, bases, true)
    }
}

/// Convert the tables, and the LSDAs if `lsdas` is set.
fn convert_tables<R: Reader>(
    exidx: &read::ExIdx<R>,
    extab: &read::ExTab<R>,
    bases: &BaseAddresses,
    lsdas: bool,
) -> ConvertResult<UnwindTable> {
    let mut index = Vec::new();
    let mut offsets = BTreeSet::new();
    let mut entries = exidx.entries();
    while let Some(entry) = entries.next()? {
        let offset = entry.extab_offset(bases)?.map(|offset| offset.0);
        offsets.extend(offset);
        index.push((entry, offset));
    }

    let mut table = UnwindTable::new();
    let section_len = extab.reader().len();
    let mut extab_ids = BTreeMap::new();
    let mut offsets = offsets.into_iter().peekable();
    while let Some(offset) = offsets.next() {
        let end = offsets.peek().copied().unwrap_or(section_len);
        let entry = match extab.entry_at(ExTabOffset(offset))? {
            read::ExTabEntry::Compact(entry) => {
                ExTabEntry::Compact(convert_compact(&entry, bases)?)
            }
            read::ExTabEntry::Generic(entry) => {
                ExTabEntry::Generic(convert_generic(entry, end, bases, lsdas)?)
            }
        };
        extab_ids.insert(offset, table.add_extab_entry(entry));
    }

    for (entry, offset) in index {
        let data = match entry.data() {
            read::ExIdxEntryData::CantUnwind => IndexEntryData::CantUnwind,
            read::ExIdxEntryData::Inline(compact) => {
                IndexEntryData::Inline(convert_compact(compact, bases)?)
            }
            read::ExIdxEntryData::ExTab(_) => {
                let id = offset.and_then(|offset| extab_ids.get(&offset).copied());
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

fn convert_compact<R: Reader>(
    entry: &read::CompactEntry<R>,
    bases: &BaseAddresses,
) -> ConvertResult<CompactEntry> {
    let head_len = entry.personality().unwind_head_len();
    let (instructions, _lossless) = convert_instructions(entry.unwind_bytes()?, head_len)?;
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

/// Decode a frame unwinding description, returning the instructions and
/// whether writing them reproduces the original bytes exactly.
///
/// All bytes are decoded, including those after the first *Finish*. If the
/// bytes after the first *Finish* do not decode, the instructions up to it are
/// kept and the result is not lossless. Either way, the instructions encode
/// to at least as many words as the original: a shorter encoding is padded
/// with *Finish*, and trailing *Finish* padding that the writer adds back is
/// dropped.
fn convert_instructions<R: Reader>(
    bytes: read::UnwindBytes<R>,
    head_len: usize,
) -> read::Result<(Vec<UnwindInstruction>, bool)> {
    let original: Vec<u8> = bytes.collect();
    let mut iter = original.iter().copied();
    let mut instructions = Vec::new();
    let mut first_finish = None;
    let mut decoded_all = true;
    loop {
        match read::decode_unwind_instruction(&mut iter) {
            Ok(Some(instruction)) => {
                if instruction == Finish && first_finish.is_none() {
                    first_finish = Some(instructions.len());
                }
                instructions.push(instruction);
            }
            Ok(None) => break,
            Err(e) => {
                let end = first_finish.ok_or(e)?;
                instructions.truncate(end + 1);
                decoded_all = false;
                break;
            }
        }
    }

    // Decoded instructions always re-encode; equality fails only for
    // non-minimal encodings or when bytes were dropped above.
    let encoded = encode_unwind_instructions(&instructions).unwrap_or_default();
    let lossless = decoded_all && encoded == original;

    // Each *Finish* is one byte. Pad a shorter encoding to the original
    // length, so the entry keeps its size, then drop the padding that the
    // writer restores.
    let mut len = encoded.len().max(original.len());
    instructions.extend(iter::repeat_n(Finish, len - encoded.len()));
    let words = extra_unwind_words(len, head_len);
    while instructions.last() == Some(&Finish) && extra_unwind_words(len - 1, head_len) == words {
        instructions.pop();
        len -= 1;
    }
    Ok((instructions, lossless))
}

fn convert_descriptor<R: Reader>(
    descriptor: read::Descriptor<R>,
    bases: &BaseAddresses,
) -> ConvertResult<Descriptor> {
    let extab = read::base_address(bases, SectionId::ArmExtab)?;
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

/// Convert a generic entry that ends at `end`. With `lsdas`, convert a
/// GCC/LLVM-layout LSDA to a model.
#[cfg_attr(not(feature = "lsda"), allow(unused_variables))]
fn convert_generic<R: Reader>(
    mut entry: read::GenericEntry<R>,
    end: usize,
    bases: &BaseAddresses,
    lsdas: bool,
) -> ConvertResult<GenericEntry> {
    let personality = Address::Constant(entry.personality_address(bases)?);
    entry.truncate((end - entry.offset().0).saturating_sub(4))?;

    // Use the GCC/LLVM layout only if it re-encodes to the same bytes, so
    // the LSDA stays where it was and nothing is normalized.
    let gnu = || -> Option<GenericData> {
        let (instructions, lossless) =
            convert_instructions(entry.gnu_unwind_bytes().ok()?, 3).ok()?;
        let lsda = entry.gnu_lsda().ok()?.to_slice().ok()?.into_owned();
        lossless.then_some(GenericData::Gnu { instructions, lsda })
    };
    let data = match gnu() {
        #[cfg(feature = "lsda")]
        Some(GenericData::Gnu { instructions, lsda }) if lsdas => {
            match convert_lsda(&entry, &lsda, bases) {
                Some(model) => GenericData::GnuLsda {
                    instructions,
                    lsda: model,
                },
                None => GenericData::Gnu { instructions, lsda },
            }
        }
        Some(data) => data,
        None => GenericData::Raw(entry.data().to_slice()?.into_owned()),
    };
    Ok(GenericEntry { personality, data })
}

/// Convert the LSDA of a GCC/LLVM-layout entry to a model of the `lsda`
/// crate, if writing the model in place reproduces `bytes`: the LSDA and
/// the padding up to the next entry (none after the last entry).
#[cfg(feature = "lsda")]
fn convert_lsda<R: Reader>(
    entry: &read::GenericEntry<R>,
    bytes: &[u8],
    bases: &BaseAddresses,
) -> Option<lsda::write::Lsda> {
    // Pc-relative pointers are relative to the place of the LSDA.
    let offset = entry.gnu_lsda_offset().ok()?.0;
    let last = offset + bytes.len() == entry.section().len();
    let address = u64::from(bases.extab?) + offset as u64;
    let section = read::LsdaReader::new(entry.gnu_lsda().ok()?);
    let table = lsda::read::GccExceptTable::from_reader(section, lsda::Format::arm_ehabi());
    let start = lsda::LsdaOffset(0);
    let lsda_bases = lsda::BaseAddresses::default().set_section(address);
    let (converted, ids) =
        lsda::write::GccExceptTable::from_read(&table, &[start], &lsda_bases).ok()?;
    let lsda::write::EntryData::Lsda(model) = &converted.get(*ids.get(&start)?).data else {
        return None;
    };

    let mut written = EndianVec::new(entry.section().endian());
    crate::write::gnu_lsda::write_lsda(&mut written, offset, model, bases).ok()?;
    if !last {
        let padding = (offset + written.len()).wrapping_neg() % 4;
        written.write(&[0; 3][..padding]).ok()?;
    }
    (written.slice() == bytes).then(|| model.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::LittleEndian;
    use crate::test_util::words_le;
    use crate::write::{EndianVec, Sections};

    /// Unusual but valid unwinding descriptions survive a round trip byte for
    /// byte, so later `.ARM.extab` entries do not move.
    #[test]
    fn test_roundtrip_unusual_instructions() {
        let bases = BaseAddresses::default().set_exidx(0x1000).set_extab(0x2000);
        let extab_data = words_le(&[
            // 0x00: Lu16 with 2 extra words; an instruction follows the
            // first Finish, then a whole word of padding.
            0x8102_a8b0,
            0xa9b0_b0b0,
            0xb0b0_b0b0,
            0,
            // 0x10: Su16 with padding.
            0x80a8_b0b0,
            0,
            // 0x18: generic, with a non-minimal uleb128 (b2 80 00) and an
            // LSDA word.
            0x7fff_0000,
            0x00b2_8000,
            0x1234_5678,
        ]);
        let exidx_data = words_le(&[
            0x10,
            0x2000 - 0x1004,
            0x20,
            0x2010 - 0x100c,
            0x30,
            0x2018 - 0x1014,
        ]);
        let exidx = read::ExIdx::new(&exidx_data, LittleEndian);
        let extab = read::ExTab::new(&extab_data, LittleEndian);
        let table = UnwindTable::from_read(&exidx, &extab, &bases).unwrap();

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        table.write(&mut sections, &bases).unwrap();
        assert_eq!(sections.extab.slice(), extab_data);
        assert_eq!(sections.exidx.slice(), exidx_data);

        // The instruction after the first Finish is kept, along with enough
        // Finish padding to keep two extra words.
        let ExTabEntry::Compact(compact) = table.extab_entry(table_id(&table, 0)) else {
            panic!("expected compact entry");
        };
        assert_eq!(
            compact.instructions[..4],
            [
                UnwindInstruction::PopCoreRange { last: 4, lr: true },
                Finish,
                UnwindInstruction::PopCoreRange { last: 5, lr: true },
                Finish,
            ]
        );
        // Plain padding is dropped, since the writer adds it back.
        let ExTabEntry::Compact(compact) = table.extab_entry(table_id(&table, 1)) else {
            panic!("expected compact entry");
        };
        assert_eq!(
            compact.instructions,
            [UnwindInstruction::PopCoreRange { last: 4, lr: true }]
        );
        // The non-minimal uleb128 would be normalized, so the generic entry
        // is kept as raw data.
        let ExTabEntry::Generic(generic) = table.extab_entry(table_id(&table, 2)) else {
            panic!("expected generic entry");
        };
        assert!(matches!(generic.data, GenericData::Raw(_)));
    }

    /// A compact entry whose instructions re-encode shorter keeps its length,
    /// so the entries after it do not move.
    #[test]
    fn test_shortened_entry_keeps_length() {
        let bases = BaseAddresses::default().set_exidx(0x1000).set_extab(0x2000);
        let extab_data = words_le(&[
            // 0x00: Lu16 with 2 extra words: `b2 80 80 80 80 80 00`, a uleb128
            // of 0 in 6 bytes (minimally `b2 00`), then Finish.
            0x8102_b280,
            0x8080_8080,
            0x00b0_b0b0,
            0,
            // 0x10: Su16, followed by a catch descriptor whose type_info is a
            // place-relative reference.
            0x80b0_b0b0,
            0x0000_0005,
            0x7fff_f000,
            0x0000_1234,
            0,
        ]);
        let exidx_data = words_le(&[0x10, 0x2000 - 0x1004, 0x20, 0x2010 - 0x100c]);
        let exidx = read::ExIdx::new(&exidx_data, LittleEndian);
        let extab = read::ExTab::new(&extab_data, LittleEndian);
        let table = UnwindTable::from_read(&exidx, &extab, &bases).unwrap();

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        table.write(&mut sections, &bases).unwrap();
        // Only the uleb128 bytes change; the second entry stays at 0x10.
        let mut expected = extab_data.clone();
        expected[..12].copy_from_slice(&words_le(&[0x8102_b200, 0xb0b0_b0b0, 0xb0b0_b0b0]));
        assert_eq!(sections.extab.slice(), expected);
        assert_eq!(sections.exidx.slice(), exidx_data);
    }

    fn table_id(table: &UnwindTable, index: usize) -> crate::write::ExTabEntryId {
        match table.index_entries()[index].data {
            IndexEntryData::ExTab(id) => id,
            _ => panic!("expected .ARM.extab entry"),
        }
    }
}
