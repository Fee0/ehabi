use crate::common::{BaseAddresses, ExIdxOffset, ExTabOffset, SectionId};
use crate::constants;
use crate::endianity::Endianity;
use crate::read::{
    CompactEntry, EndianSlice, Error, ExTab, Prel31, Reader, Result, Section, UnwindEntry,
    base_address,
};

/// The `.ARM.exidx` section: the exception index table.
///
/// The table is a sequence of 8-byte entries, one per function, sorted by
/// function address in a linked image.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ExIdx<R> {
    section: R,
}

impl<'input, Endian> ExIdx<EndianSlice<'input, Endian>>
where
    Endian: Endianity,
{
    /// Construct a new `ExIdx` instance from the data in the `.ARM.exidx`
    /// section.
    ///
    /// ```
    /// use ehabi::read::ExIdx;
    /// use ehabi::LittleEndian;
    ///
    /// # let buf = [0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07];
    /// # let read_exidx_section_somehow = || &buf;
    /// let exidx = ExIdx::new(read_exidx_section_somehow(), LittleEndian);
    /// ```
    pub fn new(section: &'input [u8], endian: Endian) -> Self {
        Self::from(EndianSlice::new(section, endian))
    }
}

impl<R: Reader> Section<R> for ExIdx<R> {
    fn id() -> SectionId {
        SectionId::ArmExidx
    }

    fn reader(&self) -> &R {
        &self.section
    }
}

impl<R> From<R> for ExIdx<R> {
    fn from(section: R) -> Self {
        ExIdx { section }
    }
}

impl<R: Reader> ExIdx<R> {
    /// Return the number of complete entries in the table.
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.section.len() / 8
    }

    /// Iterate over the entries of the table, in section order.
    ///
    /// If the section length is not a multiple of 8, the iterator returns an
    /// error after the last complete entry.
    pub fn entries(&self) -> ExIdxEntryIter<R> {
        ExIdxEntryIter {
            input: self.section.clone(),
            section: self.section.clone(),
        }
    }

    /// Parse the entry with the given index.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OffsetOutOfBounds`] if `index` is not less than
    /// [`len`](Self::len), and [`Error::InvalidExIdxFunctionWord`] if bit 31 of
    /// the function word is set.
    pub fn entry(&self, index: usize) -> Result<ExIdxEntry<R>> {
        if index >= self.len() {
            return Err(Error::OffsetOutOfBounds);
        }
        let mut input = self.section.range_from(index * 8)?;
        ExIdxEntry::parse(&mut input, &self.section)
    }

    /// Parse the entry at the given section offset.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OffsetOutOfBounds`] if `offset` is not a multiple of 8
    /// or is outside the section, and [`Error::InvalidExIdxFunctionWord`] if
    /// bit 31 of the function word is set.
    pub fn entry_at(&self, offset: ExIdxOffset) -> Result<ExIdxEntry<R>> {
        let offset = offset.0;
        if offset % 8 != 0 {
            return Err(Error::OffsetOutOfBounds);
        }
        self.entry(offset / 8)
    }

    /// Find the entry for the function containing `address`.
    ///
    /// This is a binary search for the last entry whose function address is
    /// less than or equal to `address`, which is how the EHABI runtime uses
    /// the table. It requires the table to be sorted, as it is in a linked
    /// image. Since the table does not record function lengths, any address
    /// beyond the last function start matches the last entry; linkers
    /// usually terminate the table with an `EXIDX_CANTUNWIND` entry to bound
    /// the final function.
    ///
    /// Bit 0 of the function addresses is ignored: the EHABI suggests that
    /// producers set it for Thumb functions, so that a function starting at
    /// `0x1000` may be recorded as `0x1001`.
    ///
    /// `bases.exidx` must be set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingBaseAddress`] if `bases.exidx` is not set, and
    /// [`Error::InvalidExIdxFunctionWord`] if bit 31 of a function word visited
    /// by the search is set.
    pub fn find(&self, address: u32, bases: &BaseAddresses) -> Result<Option<ExIdxEntry<R>>> {
        let exidx = base_address(bases, SectionId::ArmExidx)?;
        // Only the function word is needed to compare, so read just that and
        // parse the one matching entry at the end.
        let mut low = 0;
        let mut high = self.len();
        while low < high {
            let mid = low + (high - low) / 2;
            let offset = mid * 8;
            let function = read_function(&mut self.section.range_from(offset)?, offset)?;
            if function.address(exidx) & !1 <= address {
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        low.checked_sub(1)
            .map(|index| self.entry(index))
            .transpose()
    }
}

/// An iterator over the entries of an [`ExIdx`] table.
#[derive(Debug, Clone)]
pub struct ExIdxEntryIter<R: Reader> {
    input: R,
    section: R,
}

impl<R: Reader> ExIdxEntryIter<R> {
    /// Advance the iterator and return the next entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidExIdxLength`] if the section ends with an
    /// incomplete entry, and [`Error::InvalidExIdxFunctionWord`] if bit 31 of
    /// the function word is set. After an error, the iterator returns
    /// `Ok(None)`.
    pub fn next(&mut self) -> Result<Option<ExIdxEntry<R>>> {
        if self.input.is_empty() {
            return Ok(None);
        }
        if self.input.len() < 8 {
            self.input.empty();
            return Err(Error::InvalidExIdxLength(self.section.len()));
        }
        match ExIdxEntry::parse(&mut self.input, &self.section) {
            Ok(entry) => Ok(Some(entry)),
            Err(e) => {
                self.input.empty();
                Err(e)
            }
        }
    }
}

impl_iterators!(ExIdxEntryIter, ExIdxEntry<R>);

/// An entry in the `.ARM.exidx` table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExIdxEntry<R: Reader> {
    offset: ExIdxOffset,
    function: Prel31,
    data: ExIdxEntryData<R>,
}

/// The second word of an [`ExIdxEntry`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExIdxEntryData<R: Reader> {
    /// `EXIDX_CANTUNWIND`: frames of this function cannot be unwound.
    CantUnwind,
    /// A compact-model entry stored inline in the index table.
    ///
    /// Inline entries have no descriptors.
    Inline(CompactEntry<R>),
    /// A reference to the entry in `.ARM.extab`.
    ExTab(Prel31),
}

impl<R: Reader> ExIdxEntry<R> {
    fn parse(input: &mut R, section: &R) -> Result<Self> {
        let offset = input.offset_from(section);
        let function = read_function(input, offset)?;
        let word = input.read_relocatable_u32()?;
        let data = if word == constants::EXIDX_CANTUNWIND {
            ExIdxEntryData::CantUnwind
        } else if word & constants::EHT_COMPACT_MODEL != 0 {
            // Inline entries have no further data; the reader is only a
            // placeholder.
            let mut empty = input.clone();
            empty.empty();
            ExIdxEntryData::Inline(CompactEntry::new(None, word, empty.clone(), empty))
        } else {
            ExIdxEntryData::ExTab(Prel31::from_word(offset + 4, word))
        };
        Ok(ExIdxEntry {
            offset: ExIdxOffset(offset),
            function,
            data,
        })
    }

    /// Return the offset of this entry within the `.ARM.exidx` section.
    #[inline]
    pub fn offset(&self) -> ExIdxOffset {
        self.offset
    }

    /// Return the reference to the start of the function.
    #[inline]
    pub fn function(&self) -> Prel31 {
        self.function
    }

    /// Return the address of the start of the function.
    ///
    /// Bit 0 is set if the producer marked a Thumb function this way, as the
    /// EHABI suggests.
    ///
    /// `bases.exidx` must be set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingBaseAddress`] if `bases.exidx` is not set.
    pub fn function_address(&self, bases: &BaseAddresses) -> Result<u32> {
        Ok(self
            .function
            .address(base_address(bases, SectionId::ArmExidx)?))
    }

    /// Return the unwinding data for the function.
    #[inline]
    pub fn data(&self) -> &ExIdxEntryData<R> {
        &self.data
    }

    /// Return the offset of the `.ARM.extab` entry, if this entry refers to one.
    ///
    /// `bases.exidx` and `bases.extab` must be set.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingBaseAddress`] if the entry refers to
    /// `.ARM.extab` and `bases.exidx` or `bases.extab` is not set.
    pub fn extab_offset(&self, bases: &BaseAddresses) -> Result<Option<ExTabOffset>> {
        match self.data {
            ExIdxEntryData::ExTab(reference) => extab_offset(reference, bases).map(Some),
            _ => Ok(None),
        }
    }

    /// Return the unwinding information for this function, following the
    /// reference into `.ARM.extab` if necessary.
    ///
    /// `bases.exidx` and `bases.extab` must be set if the entry refers to
    /// `.ARM.extab`.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingBaseAddress`] if a required base address is not
    /// set, and the errors of [`ExTab::entry_at`] if the referenced
    /// `.ARM.extab` entry cannot be parsed.
    pub fn resolve(&self, extab: &ExTab<R>, bases: &BaseAddresses) -> Result<UnwindEntry<R>> {
        Ok(match &self.data {
            ExIdxEntryData::CantUnwind => UnwindEntry::CantUnwind,
            ExIdxEntryData::Inline(entry) => UnwindEntry::Compact(entry.clone()),
            ExIdxEntryData::ExTab(reference) => {
                extab.entry_at(extab_offset(*reference, bases)?)?.into()
            }
        })
    }
}

/// Read the function word of an index entry at `offset`.
fn read_function<R: Reader>(input: &mut R, offset: usize) -> Result<Prel31> {
    let word = input.read_relocatable_u32()?;
    if word & 0x8000_0000 != 0 {
        return Err(Error::InvalidExIdxFunctionWord(word));
    }
    Ok(Prel31::from_word(offset, word))
}

/// Return the `.ARM.extab` offset that an index entry's reference points to.
fn extab_offset(reference: Prel31, bases: &BaseAddresses) -> Result<ExTabOffset> {
    let exidx = base_address(bases, SectionId::ArmExidx)?;
    let extab = base_address(bases, SectionId::ArmExtab)?;
    let address = reference.address(exidx);
    Ok(ExTabOffset(address.wrapping_sub(extab) as usize))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::{BigEndian, LittleEndian};
    use crate::test_util::words_le;
    use crate::unwind::UnwindInstruction;
    use alloc::vec::Vec;

    #[test]
    fn test_entries() {
        // exidx at 0x2000; functions at 0x1000, 0x1100, 0x1200.
        let data = words_le(&[
            (0x1000u32.wrapping_sub(0x2000)) & 0x7fff_ffff,
            0x80a8_b0b0,
            (0x1100u32.wrapping_sub(0x2008)) & 0x7fff_ffff,
            constants::EXIDX_CANTUNWIND,
            (0x1200u32.wrapping_sub(0x2010)) & 0x7fff_ffff,
            // extab at 0x3000; entry at offset 8.
            0x3008 - 0x2014,
        ]);
        let exidx = ExIdx::new(&data, LittleEndian);
        let bases = BaseAddresses::default().set_exidx(0x2000).set_extab(0x3000);
        let entries: Vec<_> = exidx.entries().collect::<Result<_>>().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].function_address(&bases), Ok(0x1000));
        assert_eq!(entries[1].function_address(&bases), Ok(0x1100));
        assert_eq!(entries[2].function_address(&bases), Ok(0x1200));
        assert_eq!(entries[1].data(), &ExIdxEntryData::CantUnwind);
        assert_eq!(entries[2].extab_offset(&bases), Ok(Some(ExTabOffset(8))));

        let ExIdxEntryData::Inline(compact) = entries[0].data() else {
            panic!("expected inline entry");
        };
        let instructions: Vec<_> = compact
            .instructions()
            .unwrap()
            .collect::<Result<_>>()
            .unwrap();
        assert_eq!(
            instructions,
            [
                UnwindInstruction::PopCoreRange { last: 4, lr: true },
                UnwindInstruction::Finish
            ]
        );
        assert!(compact.descriptors().unwrap().is_none());

        assert_eq!(exidx.find(0x0fff, &bases).unwrap(), None);
        assert_eq!(
            exidx.find(0x1000, &bases).unwrap().unwrap().offset(),
            ExIdxOffset(0)
        );
        assert_eq!(
            exidx.find(0x10ff, &bases).unwrap().unwrap().offset(),
            ExIdxOffset(0)
        );
        assert_eq!(
            exidx.find(0x1100, &bases).unwrap().unwrap().offset(),
            ExIdxOffset(8)
        );
        assert_eq!(
            exidx.find(0xffff, &bases).unwrap().unwrap().offset(),
            ExIdxOffset(16)
        );
    }

    #[test]
    fn test_inline_reserved_personality() {
        // An inline entry for reserved personality routine 3. Its instructions
        // cannot be decoded, but it has no descriptors either.
        let data = words_le(&[0, 0x8300_b0b0]);
        let exidx = ExIdx::new(&data, LittleEndian);
        let ExIdxEntryData::Inline(compact) = exidx.entry(0).unwrap().data().clone() else {
            panic!("expected inline entry");
        };
        assert_eq!(compact.personality(), crate::PersonalityIndex(3));
        assert!(compact.descriptors().unwrap().is_none());
        assert_eq!(
            compact.instructions().err(),
            Some(Error::UnsupportedPersonality(crate::PersonalityIndex(3)))
        );
    }

    #[test]
    fn test_big_endian() {
        let data = [0x00, 0x00, 0x01, 0x00, 0x80, 0x97, 0xb0, 0xb0];
        let exidx = ExIdx::new(&data, BigEndian);
        let entry = exidx.entry(0).unwrap();
        let bases = BaseAddresses::default().set_exidx(0);
        assert_eq!(entry.function_address(&bases), Ok(0x100));
        let ExIdxEntryData::Inline(compact) = entry.data() else {
            panic!("expected inline entry");
        };
        assert_eq!(
            compact.instructions().unwrap().next(),
            Ok(Some(UnwindInstruction::SetVsp(7)))
        );
    }

    #[test]
    fn test_find_thumb_bit() {
        // exidx at 0x2000: f at 0x0f00, then a Thumb function g at 0x1000
        // recorded with bit 0 set, as the EHABI suggests.
        let data = words_le(&[
            0x0f00u32.wrapping_sub(0x2000) & 0x7fff_ffff,
            1,
            0x1001u32.wrapping_sub(0x2008) & 0x7fff_ffff,
            1,
        ]);
        let exidx = ExIdx::new(&data, LittleEndian);
        let bases = BaseAddresses::default().set_exidx(0x2000);
        let entry = exidx.find(0x1000, &bases).unwrap().unwrap();
        assert_eq!(entry.offset(), ExIdxOffset(8));
        assert_eq!(entry.function_address(&bases), Ok(0x1001));
        assert_eq!(
            exidx.find(0x0fff, &bases).unwrap().unwrap().offset(),
            ExIdxOffset(0)
        );
    }

    #[test]
    fn test_errors() {
        let data = words_le(&[0x8000_0000, 1, 0]);
        let exidx = ExIdx::new(&data, LittleEndian);
        let mut entries = exidx.entries();
        assert_eq!(
            entries.next(),
            Err(Error::InvalidExIdxFunctionWord(0x8000_0000))
        );
        assert_eq!(entries.next(), Ok(None));

        let data = words_le(&[0, 1, 0]);
        let exidx = ExIdx::new(&data, LittleEndian);
        let mut entries = exidx.entries();
        assert!(entries.next().unwrap().is_some());
        assert_eq!(entries.next(), Err(Error::InvalidExIdxLength(12)));
        assert_eq!(entries.next(), Ok(None));
        assert_eq!(
            exidx
                .entry(0)
                .unwrap()
                .function_address(&BaseAddresses::default()),
            Err(Error::MissingBaseAddress(SectionId::ArmExidx))
        );
    }
}
