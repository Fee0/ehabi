use crate::common::{BaseAddresses, ExIdxOffset, ExTabOffset, SectionId};
use crate::constants;
use crate::endianity::Endianity;
use crate::read::{
    CompactEntry, EndianSlice, Error, ExTab, ExTabEntry, Prel31, Reader, Result, Section,
    UnwindEntry,
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
    pub fn entry(&self, index: usize) -> Result<ExIdxEntry<R>> {
        if index >= self.len() {
            return Err(Error::OffsetOutOfBounds);
        }
        let mut input = self.section.range_from(index * 8)?;
        ExIdxEntry::parse(&mut input, &self.section)
    }

    /// Parse the entry at the given section offset.
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
    /// `bases.exidx` must be set.
    pub fn find(&self, address: u32, bases: &BaseAddresses) -> Result<Option<ExIdxEntry<R>>> {
        let mut low = 0;
        let mut high = self.len();
        let mut found = None;
        while low < high {
            let mid = low + (high - low) / 2;
            let entry = self.entry(mid)?;
            if entry.function_address(bases)? <= address {
                found = Some(entry);
                low = mid + 1;
            } else {
                high = mid;
            }
        }
        Ok(found)
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
        let function_word = input.read_relocatable_u32()?;
        if function_word & 0x8000_0000 != 0 {
            return Err(Error::InvalidExIdxFunctionWord(function_word));
        }
        let function = Prel31::from_word(offset, function_word);
        let word = input.read_relocatable_u32()?;
        let data = if word == constants::EXIDX_CANTUNWIND {
            ExIdxEntryData::CantUnwind
        } else if word & constants::EHT_COMPACT_MODEL != 0 {
            let mut empty = section.clone();
            empty.empty();
            ExIdxEntryData::Inline(CompactEntry::new(None, word, empty, section.clone()))
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
    /// `bases.exidx` must be set.
    pub fn function_address(&self, bases: &BaseAddresses) -> Result<u32> {
        let exidx = bases
            .exidx
            .ok_or(Error::MissingBaseAddress(SectionId::ArmExidx))?;
        Ok(self.function.address(exidx))
    }

    /// Return the unwinding data for the function.
    #[inline]
    pub fn data(&self) -> &ExIdxEntryData<R> {
        &self.data
    }

    /// Return the offset of the `.ARM.extab` entry, if this entry refers to one.
    ///
    /// `bases.exidx` and `bases.extab` must be set.
    pub fn extab_offset(&self, bases: &BaseAddresses) -> Result<Option<ExTabOffset>> {
        let ExIdxEntryData::ExTab(reference) = self.data else {
            return Ok(None);
        };
        let exidx = bases
            .exidx
            .ok_or(Error::MissingBaseAddress(SectionId::ArmExidx))?;
        let extab = bases
            .extab
            .ok_or(Error::MissingBaseAddress(SectionId::ArmExtab))?;
        let address = reference.address(exidx);
        Ok(Some(ExTabOffset(address.wrapping_sub(extab) as usize)))
    }

    /// Return the unwinding information for this function, following the
    /// reference into `.ARM.extab` if necessary.
    ///
    /// `bases.exidx` and `bases.extab` must be set if the entry refers to
    /// `.ARM.extab`.
    pub fn resolve(&self, extab: &ExTab<R>, bases: &BaseAddresses) -> Result<UnwindEntry<R>> {
        Ok(match &self.data {
            ExIdxEntryData::CantUnwind => UnwindEntry::CantUnwind,
            ExIdxEntryData::Inline(entry) => UnwindEntry::Compact(entry.clone()),
            ExIdxEntryData::ExTab(_) => {
                let offset = self.extab_offset(bases)?.ok_or(Error::OffsetOutOfBounds)?;
                match extab.entry_at(offset)? {
                    ExTabEntry::Compact(entry) => UnwindEntry::Compact(entry),
                    ExTabEntry::Generic(entry) => UnwindEntry::Generic(entry),
                }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::{BigEndian, LittleEndian};
    use crate::unwind::UnwindInstruction;
    use alloc::vec::Vec;

    fn words_le(words: &[u32]) -> Vec<u8> {
        words.iter().flat_map(|w| w.to_le_bytes()).collect()
    }

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
