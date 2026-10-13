use crate::common::{BaseAddresses, ExTabOffset, PersonalityIndex, SectionId};
use crate::constants;
use crate::endianity::Endianity;
use crate::read::{
    DescriptorIter, EndianSlice, Error, Prel31, Reader, Result, Section, UnwindBytes,
    UnwindInstructionIter, base_address,
};

/// The `.ARM.extab` section: the exception-handling table.
///
/// Entries in this section are not self-delimiting (generic-model entries
/// contain data only their personality routine understands), so they are
/// accessed by offset, normally obtained from an
/// [`ExIdxEntry`](crate::read::ExIdxEntry).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExTab<R> {
    section: R,
}

impl<'input, Endian> ExTab<EndianSlice<'input, Endian>>
where
    Endian: Endianity,
{
    /// Construct a new `ExTab` instance from the data in the `.ARM.extab`
    /// section.
    pub fn new(section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianSlice::new(section, endian))
    }
}

impl<R: Reader> Section<R> for ExTab<R> {
    fn id() -> SectionId {
        SectionId::ArmExtab
    }

    fn reader(&self) -> &R {
        &self.section
    }
}

impl<R> From<R> for ExTab<R> {
    fn from(section: R) -> Self {
        ExTab { section }
    }
}

impl<R: Reader> ExTab<R> {
    /// Parse the entry at the given offset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnalignedExTabOffset`] if `offset` is not a multiple of
    /// 4, and [`Error::OffsetOutOfBounds`] if it is outside the section.
    pub fn entry_at(&self, offset: ExTabOffset) -> Result<ExTabEntry<R>> {
        let offset = offset.0;
        if offset % 4 != 0 {
            return Err(Error::UnalignedExTabOffset(offset));
        }
        if offset >= self.section.len() {
            return Err(Error::OffsetOutOfBounds);
        }
        let mut input = self.section.range_from(offset)?;
        let word = input.read_relocatable_u32()?;
        let offset = ExTabOffset(offset);
        Ok(if word & constants::EHT_COMPACT_MODEL != 0 {
            ExTabEntry::Compact(CompactEntry::new(
                Some(offset),
                word,
                input,
                self.section.clone(),
            ))
        } else {
            ExTabEntry::Generic(GenericEntry {
                offset,
                personality: Prel31::from_word(offset.0, word),
                data: input,
                section: self.section.clone(),
            })
        })
    }
}

/// An entry in the `.ARM.extab` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExTabEntry<R: Reader> {
    /// An entry using the Arm-defined compact model.
    Compact(CompactEntry<R>),
    /// An entry using the generic model.
    Generic(GenericEntry<R>),
}

impl<R: Reader> ExTabEntry<R> {
    /// Return the offset of this entry within the `.ARM.extab` section.
    pub fn offset(&self) -> ExTabOffset {
        match self {
            // Compact entries read from `.ARM.extab` always have an offset.
            ExTabEntry::Compact(entry) => entry.offset.unwrap_or(ExTabOffset(0)),
            ExTabEntry::Generic(entry) => entry.offset,
        }
    }
}

/// The unwinding information for a function, from either section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnwindEntry<R: Reader> {
    /// `EXIDX_CANTUNWIND`: frames of this function cannot be unwound.
    CantUnwind,
    /// A compact-model entry, stored either inline in `.ARM.exidx` or in
    /// `.ARM.extab`.
    Compact(CompactEntry<R>),
    /// A generic-model entry in `.ARM.extab`.
    Generic(GenericEntry<R>),
}

impl<R: Reader> From<ExTabEntry<R>> for UnwindEntry<R> {
    fn from(entry: ExTabEntry<R>) -> Self {
        match entry {
            ExTabEntry::Compact(entry) => UnwindEntry::Compact(entry),
            ExTabEntry::Generic(entry) => UnwindEntry::Generic(entry),
        }
    }
}

/// An exception-handling table entry using the Arm-defined compact model.
///
/// The first word has bit 31 set and selects a personality routine in bits
/// 24-27. For the EHABI-defined routines:
///
/// * **0** (`Su16`): three unwinding instruction bytes in bits 0-23, followed
///   by descriptors with 16-bit scopes.
/// * **1** (`Lu16`): an extra word count N in bits 16-23, two instruction
///   bytes in bits 0-15 and N further words of instructions, followed by
///   descriptors with 16-bit scopes.
/// * **2** (`Lu32`): as `Lu16`, but descriptors have 32-bit scopes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactEntry<R: Reader> {
    offset: Option<ExTabOffset>,
    word: u32,
    data: R,
    section: R,
}

impl<R: Reader> CompactEntry<R> {
    pub(crate) fn new(offset: Option<ExTabOffset>, word: u32, data: R, section: R) -> Self {
        CompactEntry {
            offset,
            word,
            data,
            section,
        }
    }

    /// Return the offset of this entry within `.ARM.extab`, or `None` if the
    /// entry is stored inline in `.ARM.exidx`.
    #[inline]
    pub fn offset(&self) -> Option<ExTabOffset> {
        self.offset
    }

    /// Return true if this entry is stored inline in `.ARM.exidx`.
    #[inline]
    pub fn is_inline(&self) -> bool {
        self.offset.is_none()
    }

    /// Return the first word of the entry.
    #[inline]
    pub fn word(&self) -> u32 {
        self.word
    }

    /// Return the index of the personality routine.
    #[inline]
    pub fn personality(&self) -> PersonalityIndex {
        PersonalityIndex(((self.word >> 24) & 0xf) as u8)
    }

    /// Return the data following the first word, up to the end of the section.
    ///
    /// This is empty for inline entries. It is mainly useful for the reserved
    /// personality routines, whose format is not defined by the EHABI.
    #[inline]
    pub fn data(&self) -> &R {
        &self.data
    }

    /// Return the number of additional words of unwinding instructions.
    fn extra_words(&self) -> Result<usize> {
        let personality = self.personality();
        if personality == PersonalityIndex::SU16 {
            Ok(0)
        } else if personality.is_long() {
            let count = ((self.word >> 16) & 0xff) as u8;
            if self.is_inline() && count != 0 {
                return Err(Error::InlineEntryHasExtraWords(count));
            }
            Ok(usize::from(count))
        } else {
            Err(Error::UnsupportedPersonality(personality))
        }
    }

    /// Return the bytes of the frame unwinding description, including any
    /// trailing padding.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedPersonality`] for a reserved personality
    /// routine, [`Error::InlineEntryHasExtraWords`] if an inline entry has a
    /// non-zero word count, and [`Error::UnexpectedEof`] if the words extend
    /// past the end of the section.
    pub fn unwind_bytes(&self) -> Result<UnwindBytes<R>> {
        let words = self.extra_words()?;
        let mut data = self.data.clone();
        let words = data.split(words * 4)?;
        let head_len = self.personality().unwind_head_len() as u8;
        Ok(UnwindBytes::new(self.word, head_len, words))
    }

    /// Return an iterator over the frame unwinding instructions.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`unwind_bytes`](Self::unwind_bytes).
    pub fn instructions(&self) -> Result<UnwindInstructionIter<R>> {
        Ok(UnwindInstructionIter::new(self.unwind_bytes()?))
    }

    /// Return an iterator over the descriptors, or `None` for inline entries,
    /// which cannot have descriptors.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnsupportedPersonality`] for a reserved personality
    /// routine, and [`Error::UnexpectedEof`] if the unwinding instructions
    /// extend past the end of the section.
    pub fn descriptors(&self) -> Result<Option<DescriptorIter<R>>> {
        if self.is_inline() {
            return Ok(None);
        }
        let words = self.extra_words()?;
        let mut data = self.data.clone();
        data.skip(words * 4)?;
        let wide = self.personality().has_wide_scopes();
        Ok(Some(DescriptorIter::new(data, self.section.clone(), wide)))
    }
}

/// An exception-handling table entry using the generic model.
///
/// The first word is a `prel31` reference to the personality routine. The
/// rest of the entry is defined by that routine.
///
/// GCC and LLVM use the same layout for their personality routines (such as
/// `__gxx_personality_v0`): a word whose top byte is a count N of additional
/// words, with three unwinding instruction bytes in its low 24 bits, then the
/// N words of instructions, then the language-specific data area (LSDA). The
/// `gnu_*` methods decode that layout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericEntry<R: Reader> {
    offset: ExTabOffset,
    personality: Prel31,
    data: R,
    section: R,
}

impl<R: Reader> GenericEntry<R> {
    /// Return the offset of this entry within `.ARM.extab`.
    #[inline]
    pub fn offset(&self) -> ExTabOffset {
        self.offset
    }

    /// Return the reference to the personality routine.
    #[inline]
    pub fn personality(&self) -> Prel31 {
        self.personality
    }

    /// Return the address of the personality routine.
    ///
    /// `bases.extab` must be set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingBaseAddress`] if `bases.extab` is not set.
    pub fn personality_address(&self, bases: &BaseAddresses) -> Result<u32> {
        let extab = base_address(bases, SectionId::ArmExtab)?;
        Ok(self.personality.address(extab))
    }

    /// Return the data following the personality routine reference.
    ///
    /// The length of a generic entry is not encoded, so this extends to the
    /// end of the section.
    #[inline]
    pub fn data(&self) -> &R {
        &self.data
    }

    /// Limit the entry's data to `len` bytes, for when its extent is known.
    #[cfg(feature = "write")]
    pub(crate) fn truncate(&mut self, len: usize) -> Result<()> {
        self.data.truncate(len)
    }

    /// Return the bytes of the frame unwinding description, using the
    /// GCC/LLVM layout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if the entry is shorter than its word
    /// count requires.
    pub fn gnu_unwind_bytes(&self) -> Result<UnwindBytes<R>> {
        let mut data = self.data.clone();
        let word = data.read_u32()?;
        let words = data.split((word >> 24) as usize * 4)?;
        Ok(UnwindBytes::new(word, 3, words))
    }

    /// Return an iterator over the frame unwinding instructions, using the
    /// GCC/LLVM layout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if the entry is shorter than its word
    /// count requires.
    pub fn gnu_instructions(&self) -> Result<UnwindInstructionIter<R>> {
        Ok(UnwindInstructionIter::new(self.gnu_unwind_bytes()?))
    }

    /// Return the language-specific data area, using the GCC/LLVM layout.
    ///
    /// The returned reader extends to the end of the section. For C++ this
    /// is in the `.gcc_except_table` format, with `R_ARM_TARGET2` type
    /// references.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if the entry is shorter than its word
    /// count requires.
    pub fn gnu_lsda(&self) -> Result<R> {
        let mut data = self.data.clone();
        let word = data.read_u32()?;
        data.skip((word >> 24) as usize * 4)?;
        Ok(data)
    }

    /// Return the offset of the language-specific data area within
    /// `.ARM.extab`, using the GCC/LLVM layout.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if the entry is shorter than its word
    /// count requires.
    pub fn gnu_lsda_offset(&self) -> Result<ExTabOffset> {
        Ok(ExTabOffset(self.gnu_lsda()?.offset_from(&self.section)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::LittleEndian;
    use crate::read::Descriptor;
    use crate::test_util::words_le;
    use crate::unwind::UnwindInstruction::*;
    use alloc::vec::Vec;

    #[test]
    fn test_compact_lu16() {
        let data = words_le(&[
            0xdead_beef,
            // Lu16, one extra word: vsp += 8; pop {r4-r6, lr}; vpush d8-d9; finish.
            0x8101_01aa,
            0xd1b0_b0b0,
            0,
        ]);
        let extab = ExTab::new(&data, LittleEndian);
        let ExTabEntry::Compact(entry) = extab.entry_at(ExTabOffset(4)).unwrap() else {
            panic!("expected compact entry");
        };
        assert_eq!(entry.personality(), PersonalityIndex::LU16);
        assert_eq!(entry.offset(), Some(ExTabOffset(4)));
        let instructions: Vec<_> = entry
            .instructions()
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(
            instructions,
            [
                IncrementVsp(8),
                PopCoreRange { last: 6, lr: true },
                PopVfpVpushD8 { count: 2 },
                Finish
            ]
        );
        let descriptors: Vec<Descriptor<_>> = entry
            .descriptors()
            .unwrap()
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(descriptors, []);
    }

    #[test]
    fn test_generic_gnu() {
        let data = words_le(&[
            // personality at extab - 0x100
            (-0x100i32).cast_unsigned() & 0x7fff_ffff,
            // One extra word: vsp = r11; pop {r10, lr}; pop {r4-r11, lr}; finish.
            0x019b_8440,
            0x84ff_b0b0,
            // LSDA
            0x1234_5678,
        ]);
        let extab = ExTab::new(&data, LittleEndian);
        let ExTabEntry::Generic(entry) = extab.entry_at(ExTabOffset(0)).unwrap() else {
            panic!("expected generic entry");
        };
        let bases = BaseAddresses::default().set_extab(0x1000);
        assert_eq!(entry.personality_address(&bases), Ok(0xf00));
        let instructions: Vec<_> = entry
            .gnu_instructions()
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(
            instructions,
            [
                SetVsp(11),
                PopCore { mask: 0x4400 },
                PopCore { mask: 0x4ff0 },
                Finish
            ]
        );
        assert_eq!(entry.gnu_lsda_offset(), Ok(ExTabOffset(12)));
        assert_eq!(entry.gnu_lsda().unwrap().slice(), &data[12..]);
    }

    #[test]
    fn test_errors() {
        let data = words_le(&[0x8301_0000, 0x8101_0000]);
        let extab = ExTab::new(&data, LittleEndian);
        assert_eq!(
            extab.entry_at(ExTabOffset(2)),
            Err(Error::UnalignedExTabOffset(2))
        );
        assert_eq!(
            extab.entry_at(ExTabOffset(8)),
            Err(Error::OffsetOutOfBounds)
        );
        let ExTabEntry::Compact(entry) = extab.entry_at(ExTabOffset(0)).unwrap() else {
            panic!("expected compact entry");
        };
        assert_eq!(
            entry.instructions().err(),
            Some(Error::UnsupportedPersonality(PersonalityIndex(3)))
        );
        let ExTabEntry::Compact(entry) = extab.entry_at(ExTabOffset(4)).unwrap() else {
            panic!("expected compact entry");
        };
        assert_eq!(entry.instructions().err(), Some(Error::UnexpectedEof));
    }
}
