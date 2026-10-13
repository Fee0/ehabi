use alloc::vec::Vec;

use crate::common::{BaseAddresses, ExTabOffset, PersonalityIndex, Scope, SectionId};
use crate::constants;
use crate::unwind::UnwindInstruction;
use crate::write::unwind::{extra_unwind_words, pack_unwind_bytes};
use crate::write::{
    Address, Error, Reference, Result, Sections, Writer, encode_unwind_instructions,
};

/// A table of unwinding information, which can be written to `.ARM.exidx`
/// and `.ARM.extab`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct UnwindTable {
    index: Vec<IndexEntry>,
    extab: Vec<ExTabEntry>,
    personality_symbols: [Option<usize>; 16],
    call_unexpected_symbol: Option<usize>,
}

/// An identifier for an entry added to an [`UnwindTable`] with
/// [`UnwindTable::add_extab_entry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExTabEntryId(usize);

impl UnwindTable {
    /// Create a new, empty table.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add an entry to the `.ARM.extab` section, returning its id for use in
    /// [`IndexEntryData::ExTab`]. An entry may be shared by several functions.
    pub fn add_extab_entry(&mut self, entry: ExTabEntry) -> ExTabEntryId {
        self.extab.push(entry);
        ExTabEntryId(self.extab.len() - 1)
    }

    /// Get an `.ARM.extab` entry.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    pub fn extab_entry(&self, id: ExTabEntryId) -> &ExTabEntry {
        &self.extab[id.0]
    }

    /// Get an `.ARM.extab` entry for modification.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    pub fn extab_entry_mut(&mut self, id: ExTabEntryId) -> &mut ExTabEntry {
        &mut self.extab[id.0]
    }

    /// Return the number of `.ARM.extab` entries.
    pub fn extab_entry_count(&self) -> usize {
        self.extab.len()
    }

    /// Add an entry to the `.ARM.exidx` table.
    ///
    /// Entries are written in the order they are added. For a linked image
    /// the table must be sorted by function address; for a relocatable object
    /// it must be in the order of the functions in the code section.
    pub fn add_index_entry(&mut self, entry: IndexEntry) {
        self.index.push(entry);
    }

    /// Return the `.ARM.exidx` entries.
    pub fn index_entries(&self) -> &[IndexEntry] {
        &self.index
    }

    /// Return the `.ARM.exidx` entries for modification, such as sorting.
    pub fn index_entries_mut(&mut self) -> &mut Vec<IndexEntry> {
        &mut self.index
    }

    /// Set the symbol for a compact-model personality routine (such as
    /// `__aeabi_unwind_cpp_pr0`).
    ///
    /// When set, every compact entry using this routine records an
    /// `R_ARM_NONE` dependency on the symbol, as the EHABI requires of object
    /// producers. This only has an effect with a writer that records
    /// relocations.
    pub fn set_personality_symbol(&mut self, personality: PersonalityIndex, symbol: usize) {
        self.personality_symbols[usize::from(personality.0 & 0xf)] = Some(symbol);
    }

    /// Set the symbol for `__cxa_call_unexpected`.
    ///
    /// When set, every exception specification descriptor without a landing
    /// pad records an `R_ARM_NONE` dependency on the symbol, as the EHABI
    /// requires of object producers.
    pub fn set_call_unexpected_symbol(&mut self, symbol: usize) {
        self.call_unexpected_symbol = Some(symbol);
    }

    /// Write the table to the given sections.
    ///
    /// The `.ARM.extab` entries are written first, each word aligned, followed
    /// by the `.ARM.exidx` entries. `bases` must contain the address of every
    /// section that holds a constant reference: the place of each `prel31`
    /// word, and the target section of references between the sections. A
    /// writer that records relocations does not need addresses for symbol
    /// and section references.
    pub fn write<W: Writer>(
        &self,
        sections: &mut Sections<W>,
        bases: &BaseAddresses,
    ) -> Result<ExTabOffsets> {
        let mut offsets = Vec::with_capacity(self.extab.len());
        for entry in &self.extab {
            let w = &mut *sections.extab;
            w.align_to_word()?;
            offsets.push(ExTabOffset(w.len()));
            match entry {
                ExTabEntry::Compact(entry) => self.write_compact(w, entry, false, bases)?,
                ExTabEntry::Generic(entry) => entry.write(w, bases)?,
            }
        }

        let w = &mut *sections.exidx;
        for entry in &self.index {
            w.write_prel31(
                SectionId::ArmExidx,
                Reference::Address(entry.function),
                false,
                bases,
            )?;
            match &entry.data {
                IndexEntryData::CantUnwind => w.write_u32(constants::EXIDX_CANTUNWIND)?,
                IndexEntryData::Inline(entry) => self.write_compact(w, entry, true, bases)?,
                IndexEntryData::ExTab(id) => {
                    let offset = offsets.get(id.0).ok_or(Error::InvalidExTabEntryId)?;
                    w.write_prel31(
                        SectionId::ArmExidx,
                        Reference::Section {
                            section: SectionId::ArmExtab,
                            offset: offset.0,
                        },
                        false,
                        bases,
                    )?;
                }
            }
        }
        Ok(ExTabOffsets(offsets))
    }

    fn write_compact<W: Writer>(
        &self,
        w: &mut W,
        entry: &CompactEntry,
        inline: bool,
        bases: &BaseAddresses,
    ) -> Result<()> {
        if inline && !entry.descriptors.is_empty() {
            return Err(Error::InlineEntryHasDescriptors);
        }
        let words = entry.encode_unwind_words(inline)?;
        if let Some(symbol) = self.personality_symbols[usize::from(entry.personality.0 & 0xf)] {
            w.write_dependency(symbol)?;
        }
        for word in words {
            w.write_u32(word)?;
        }
        if inline {
            return Ok(());
        }
        let wide = entry.personality.has_wide_scopes();
        for descriptor in &entry.descriptors {
            descriptor.write(w, wide, self.call_unexpected_symbol, bases)?;
        }
        w.write_u32(0)
    }
}

/// The offsets of the `.ARM.extab` entries written by [`UnwindTable::write`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExTabOffsets(Vec<ExTabOffset>);

impl ExTabOffsets {
    /// Get the offset of the entry with the given id.
    ///
    /// # Panics
    ///
    /// Panics if `id` is invalid.
    pub fn get(&self, id: ExTabEntryId) -> ExTabOffset {
        self.0[id.0]
    }
}

/// An entry in the `.ARM.exidx` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexEntry {
    /// The start address of the function.
    ///
    /// For relocatable objects the EHABI recommends a section-relative
    /// reference (the section symbol plus the function's offset, or-ed with 1
    /// for Thumb code) rather than the function symbol, so that symbol
    /// vectoring cannot break the association.
    pub function: Address,
    /// The unwinding information for the function.
    pub data: IndexEntryData,
}

/// The unwinding information in an [`IndexEntry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IndexEntryData {
    /// `EXIDX_CANTUNWIND`: frames of this function cannot be unwound.
    CantUnwind,
    /// A compact-model entry stored inline. It must have no descriptors, and
    /// its instructions must fit in 3 bytes for personality routine 0, or 2
    /// bytes for routines 1 and 2.
    Inline(CompactEntry),
    /// A reference to an entry in `.ARM.extab`.
    ExTab(ExTabEntryId),
}

/// An entry in the `.ARM.extab` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExTabEntry {
    /// An entry using the Arm-defined compact model.
    Compact(CompactEntry),
    /// An entry using the generic model.
    Generic(GenericEntry),
}

/// An exception-handling table entry using the Arm-defined compact model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactEntry {
    /// The personality routine: 0 (`Su16`), 1 (`Lu16`) or 2 (`Lu32`).
    ///
    /// Routine 0 holds at most 3 bytes of instructions. Routine 2 has 32-bit
    /// descriptor scopes, the others 16-bit scopes.
    pub personality: PersonalityIndex,
    /// The frame unwinding instructions. Padding with *Finish* is added when
    /// written.
    pub instructions: Vec<UnwindInstruction>,
    /// The descriptors, in depth-first block order.
    pub descriptors: Vec<Descriptor>,
}

impl CompactEntry {
    /// Create an entry with no instructions or descriptors.
    pub fn new(personality: PersonalityIndex) -> Self {
        CompactEntry {
            personality,
            instructions: Vec::new(),
            descriptors: Vec::new(),
        }
    }

    /// Return true if this entry can be stored inline in `.ARM.exidx`.
    pub fn can_inline(&self) -> bool {
        self.descriptors.is_empty() && self.encode_unwind_words(true).is_ok()
    }

    /// Encode the first word and any additional words of instructions.
    fn encode_unwind_words(&self, inline: bool) -> Result<Vec<u32>> {
        let personality = self.personality;
        if !personality.is_defined() {
            return Err(Error::UnsupportedPersonality(personality));
        }
        let bytes = encode_unwind_instructions(&self.instructions)?;
        let head_len = if personality.is_long() { 2 } else { 3 };
        let extra = extra_unwind_words(bytes.len(), head_len);
        if ((!personality.is_long() || inline) && extra > 0) || extra > 0xff {
            return Err(Error::TooManyUnwindBytes(bytes.len()));
        }

        let packed = pack_unwind_bytes(&bytes, head_len);
        let mut first = constants::EHT_COMPACT_MODEL | (u32::from(personality.0) << 24);
        if personality.is_long() {
            first |= (extra as u32) << 16;
        }
        let mut words = Vec::with_capacity(1 + extra);
        words.push(first | packed.head);
        words.extend(packed.words);
        Ok(words)
    }
}

/// An exception-handling table entry using the generic model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericEntry {
    /// The personality routine.
    pub personality: Address,
    /// The data that follows the personality routine reference.
    pub data: GenericData,
}

/// The data of a [`GenericEntry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenericData {
    /// The layout used by GCC and LLVM for personality routines such as
    /// `__gxx_personality_v0`: a word holding the count N of additional
    /// words in its top byte and three instruction bytes, the N words of
    /// instructions, and the language-specific data area.
    Gnu {
        /// The frame unwinding instructions. Padding with *Finish* is added
        /// when written.
        instructions: Vec<UnwindInstruction>,
        /// The language-specific data area. It is padded with zeros to a
        /// word boundary.
        ///
        /// This is written as-is: any relocations it requires are not
        /// recorded.
        lsda: Vec<u8>,
    },
    /// Uninterpreted data. It is padded with zeros to a word boundary.
    Raw(Vec<u8>),
}

impl GenericEntry {
    fn write<W: Writer>(&self, w: &mut W, bases: &BaseAddresses) -> Result<()> {
        w.write_prel31(
            SectionId::ArmExtab,
            Reference::Address(self.personality),
            false,
            bases,
        )?;
        match &self.data {
            GenericData::Gnu { instructions, lsda } => {
                let bytes = encode_unwind_instructions(instructions)?;
                let extra = extra_unwind_words(bytes.len(), 3);
                if extra > 0xff {
                    return Err(Error::TooManyUnwindBytes(bytes.len()));
                }
                let packed = pack_unwind_bytes(&bytes, 3);
                w.write_u32(((extra as u32) << 24) | packed.head)?;
                for word in packed.words {
                    w.write_u32(word)?;
                }
                w.write(lsda)?;
            }
            GenericData::Raw(data) => w.write(data)?,
        }
        w.align_to_word()
    }
}

/// A descriptor in a compact-model exception-handling table entry.
///
/// Scope offsets are relative to the start of the function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptor {
    /// A cleanup.
    Cleanup {
        /// The region of the function covered by this descriptor.
        scope: Scope,
        /// The landing pad.
        landing_pad: Address,
    },
    /// A catch handler.
    Catch {
        /// The region of the function covered by this descriptor.
        scope: Scope,
        /// The landing pad. `None` writes a zero offset, which the EHABI
        /// requires for [`CatchType::AnyAndFail`].
        landing_pad: Option<Address>,
        /// Whether the handler catches a reference type.
        catches_reference: bool,
        /// The type caught by the handler.
        catch_type: CatchType,
    },
    /// A function exception specification.
    ExceptionSpec {
        /// The region of the function covered by this descriptor.
        scope: Scope,
        /// References to the `type_info` objects of the types that may be
        /// thrown. Empty for `throw()`.
        type_infos: Vec<Address>,
        /// The landing pad to enter if no type matches. If `None`,
        /// `__cxa_call_unexpected` is called instead.
        landing_pad: Option<Address>,
    },
}

/// The type caught by a catch descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatchType {
    /// Any type, as in `catch(...)`.
    Any,
    /// Any type, and the personality routine returns `_URC_FAILURE`.
    AnyAndFail,
    /// A reference to a `type_info` object, written as `R_ARM_TARGET2`.
    TypeInfo(Address),
}

impl Descriptor {
    fn write<W: Writer>(
        &self,
        w: &mut W,
        wide: bool,
        call_unexpected: Option<usize>,
        bases: &BaseAddresses,
    ) -> Result<()> {
        let prel31 = |w: &mut W, target: Address, high_bit: bool| {
            w.write_prel31(
                SectionId::ArmExtab,
                Reference::Address(target),
                high_bit,
                bases,
            )
        };
        match self {
            Descriptor::Cleanup { scope, landing_pad } => {
                write_scope(w, *scope, (0, 0), wide)?;
                prel31(w, *landing_pad, false)?;
            }
            Descriptor::Catch {
                scope,
                landing_pad,
                catches_reference,
                catch_type,
            } => {
                write_scope(w, *scope, (1, 0), wide)?;
                match landing_pad {
                    Some(landing_pad) => prel31(w, *landing_pad, *catches_reference)?,
                    None => w.write_u32(u32::from(*catches_reference) << 31)?,
                }
                match catch_type {
                    CatchType::Any => w.write_u32(constants::CATCH_ANY)?,
                    CatchType::AnyAndFail => w.write_u32(constants::CATCH_ANY_AND_FAIL)?,
                    CatchType::TypeInfo(type_info) => w.write_target2(*type_info)?,
                }
            }
            Descriptor::ExceptionSpec {
                scope,
                type_infos,
                landing_pad,
            } => {
                write_scope(w, *scope, (0, 1), wide)?;
                if type_infos.len() > 0x7fff_ffff {
                    return Err(Error::TooManyTypeInfos(type_infos.len()));
                }
                let count = type_infos.len() as u32;
                match (landing_pad, call_unexpected) {
                    (Some(_), _) => w.write_u32(count | 0x8000_0000)?,
                    (None, Some(symbol)) => {
                        w.write_dependency(symbol)?;
                        w.write_u32(count)?;
                    }
                    (None, None) => w.write_u32(count)?,
                }
                for type_info in type_infos {
                    w.write_target2(*type_info)?;
                }
                if let Some(landing_pad) = landing_pad {
                    prel31(w, *landing_pad, false)?;
                }
            }
        }
        Ok(())
    }
}

fn write_scope<W: Writer>(w: &mut W, scope: Scope, kind: (u32, u32), wide: bool) -> Result<()> {
    let max = if wide { u32::MAX } else { 0xffff };
    if !scope.offset.is_multiple_of(2) || !scope.length.is_multiple_of(2) || scope.length == 0 {
        return Err(Error::InvalidScope(scope));
    }
    let length = scope.length | kind.0;
    let offset = scope.offset | kind.1;
    if length > max || offset > max {
        return Err(Error::InvalidScope(scope));
    }
    if wide {
        w.write_u32(length)?;
        w.write_u32(offset)
    } else {
        w.write_u16(length as u16)?;
        w.write_u16(offset as u16)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::LittleEndian;
    use crate::write::EndianVec;
    use UnwindInstruction::*;

    fn words(data: &[u8]) -> Vec<u32> {
        data.chunks(4)
            .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
            .collect()
    }

    #[test]
    fn test_compact_words() {
        let mut entry = CompactEntry::new(PersonalityIndex::SU16);
        assert_eq!(
            entry.encode_unwind_words(true),
            Ok(alloc::vec![0x80b0_b0b0])
        );
        entry.instructions = alloc::vec![IncrementVsp(8), PopCoreRange { last: 4, lr: true }];
        assert_eq!(
            entry.encode_unwind_words(true),
            Ok(alloc::vec![0x8001_a8b0])
        );
        entry.instructions.push(PopVfpVpushD8 { count: 1 });
        entry.instructions.push(Finish);
        assert_eq!(
            entry.encode_unwind_words(false),
            Err(Error::TooManyUnwindBytes(4))
        );

        entry.personality = PersonalityIndex::LU16;
        assert_eq!(
            entry.encode_unwind_words(false),
            Ok(alloc::vec![0x8101_01a8, 0xd0b0_b0b0])
        );
        assert!(!entry.can_inline());
        entry.instructions.truncate(2);
        assert!(entry.can_inline());
        assert_eq!(
            entry.encode_unwind_words(true),
            Ok(alloc::vec![0x8100_01a8])
        );
    }

    #[test]
    fn test_write() {
        let mut table = UnwindTable::new();
        let cleanup = table.add_extab_entry(ExTabEntry::Compact(CompactEntry {
            personality: PersonalityIndex::SU16,
            instructions: alloc::vec![PopCoreRange { last: 5, lr: true }],
            descriptors: alloc::vec![Descriptor::Cleanup {
                scope: Scope {
                    offset: 4,
                    length: 8
                },
                landing_pad: Address::Constant(0x1020),
            }],
        }));
        let generic = table.add_extab_entry(ExTabEntry::Generic(GenericEntry {
            personality: Address::Constant(0x2000),
            data: GenericData::Gnu {
                instructions: alloc::vec![SetVsp(7), PopCoreRange { last: 4, lr: true }],
                lsda: alloc::vec![0xff, 0x9b],
            },
        }));
        table.add_index_entry(IndexEntry {
            function: Address::Constant(0x1000),
            data: IndexEntryData::ExTab(cleanup),
        });
        table.add_index_entry(IndexEntry {
            function: Address::Constant(0x1100),
            data: IndexEntryData::CantUnwind,
        });
        table.add_index_entry(IndexEntry {
            function: Address::Constant(0x1200),
            data: IndexEntryData::ExTab(generic),
        });

        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        let bases = BaseAddresses::default().set_exidx(0x3000).set_extab(0x4000);
        let offsets = table.write(&mut sections, &bases).unwrap();
        assert_eq!(offsets.get(cleanup), ExTabOffset(0));
        assert_eq!(offsets.get(generic), ExTabOffset(16));

        assert_eq!(
            words(sections.extab.slice()),
            [
                0x80a9_b0b0,
                0x0004_0008,
                (0x1020u32.wrapping_sub(0x4008)) & 0x7fff_ffff,
                // The terminator ends the compact entry.
                0,
                (0x2000u32.wrapping_sub(0x4010)) & 0x7fff_ffff,
                0x0097_a8b0,
                0x0000_9bff,
            ]
        );
        assert_eq!(
            words(sections.exidx.slice()),
            [
                (0x1000u32.wrapping_sub(0x3000)) & 0x7fff_ffff,
                0x4000 - 0x3004,
                (0x1100u32.wrapping_sub(0x3008)) & 0x7fff_ffff,
                1,
                (0x1200u32.wrapping_sub(0x3010)) & 0x7fff_ffff,
                0x4010 - 0x3014,
            ]
        );
    }

    #[test]
    fn test_write_errors() {
        let bases = BaseAddresses::default().set_exidx(0).set_extab(0);
        let mut sections = Sections::new(EndianVec::new(LittleEndian));

        let mut table = UnwindTable::new();
        let mut entry = CompactEntry::new(PersonalityIndex::SU16);
        entry.descriptors.push(Descriptor::Catch {
            scope: Scope {
                offset: 0,
                length: 0x1_0000,
            },
            landing_pad: None,
            catches_reference: false,
            catch_type: CatchType::AnyAndFail,
        });
        table.add_index_entry(IndexEntry {
            function: Address::Constant(0),
            data: IndexEntryData::Inline(entry.clone()),
        });
        assert_eq!(
            table.write(&mut sections, &bases),
            Err(Error::InlineEntryHasDescriptors)
        );

        let mut table = UnwindTable::new();
        table.add_extab_entry(ExTabEntry::Compact(entry.clone()));
        assert_eq!(
            table.write(&mut sections, &bases),
            Err(Error::InvalidScope(Scope {
                offset: 0,
                length: 0x1_0000
            }))
        );

        // 32-bit scopes allow it.
        entry.personality = PersonalityIndex::LU32;
        let mut table = UnwindTable::new();
        table.add_extab_entry(ExTabEntry::Compact(entry));
        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        table.write(&mut sections, &bases).unwrap();
        assert_eq!(
            words(sections.extab.slice()),
            [
                0x8200_b0b0,
                0x0001_0001,
                0,
                0,
                constants::CATCH_ANY_AND_FAIL,
                0
            ]
        );
    }
}
