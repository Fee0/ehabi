use alloc::borrow::Cow;
use core::fmt;

use crate::read::{Reader, Result};

/// Trait for relocating words while reading a section.
///
/// In a relocatable object, the `prel31` references in the EHABI tables are
/// emitted as `R_ARM_PREL31` relocations (and `type_info` references as
/// `R_ARM_TARGET2`). Arm ELF uses REL relocations, so the addend is stored in
/// the word itself. An implementation of this trait computes what the word
/// would contain after linking, for some layout of the sections chosen by the
/// caller.
///
/// For `R_ARM_PREL31` the result is
/// `(word & 0x8000_0000) | ((S + A - P) & 0x7fff_ffff)`, where `A` is the
/// sign-extended low 31 bits of `word`, `S` is the address of the target
/// symbol and `P` is the address of the word. Use the same layout for
/// [`BaseAddresses`](crate::BaseAddresses).
pub trait Relocate {
    /// Relocate a word which was read from the given section offset.
    ///
    /// Return the word unchanged if there is no relocation at this offset.
    fn relocate_word(&self, offset: usize, word: u32) -> Result<u32>;
}

impl<T: Relocate + ?Sized> Relocate for &T {
    fn relocate_word(&self, offset: usize, word: u32) -> Result<u32> {
        (**self).relocate_word(offset, word)
    }
}

/// A [`Reader`] which applies relocations to relocatable words.
///
/// This is useful for reading sections in a relocatable object file. It is
/// generally not needed for executables and shared libraries.
#[derive(Clone)]
pub struct RelocateReader<R: Reader, T: Relocate> {
    section: R,
    reader: R,
    relocate: T,
}

impl<R: Reader, T: Relocate> RelocateReader<R, T> {
    /// Create a new `RelocateReader` which applies relocations to the given
    /// section reader.
    pub fn new(section: R, relocate: T) -> Self {
        let reader = section.clone();
        RelocateReader {
            section,
            reader,
            relocate,
        }
    }

    /// Get a reference to the underlying section reader.
    pub fn inner(&self) -> &R {
        &self.reader
    }
}

impl<R: Reader, T: Relocate> fmt::Debug for RelocateReader<R, T> {
    fn fmt(&self, fmt: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt.debug_tuple("RelocateReader")
            .field(&self.reader)
            .finish()
    }
}

impl<R, T> Reader for RelocateReader<R, T>
where
    R: Reader,
    T: Relocate + Clone,
{
    type Endian = R::Endian;

    fn read_relocatable_u32(&mut self) -> Result<u32> {
        let offset = self.reader.offset_from(&self.section);
        let word = self.reader.read_u32()?;
        self.relocate.relocate_word(offset, word)
    }

    #[inline]
    fn endian(&self) -> Self::Endian {
        self.reader.endian()
    }

    #[inline]
    fn len(&self) -> usize {
        self.reader.len()
    }

    #[inline]
    fn empty(&mut self) {
        self.reader.empty()
    }

    #[inline]
    fn truncate(&mut self, len: usize) -> Result<()> {
        self.reader.truncate(len)
    }

    #[inline]
    fn offset_from(&self, base: &Self) -> usize {
        self.reader.offset_from(&base.reader)
    }

    #[inline]
    fn skip(&mut self, len: usize) -> Result<()> {
        self.reader.skip(len)
    }

    #[inline]
    fn split(&mut self, len: usize) -> Result<Self> {
        let mut other = self.clone();
        other.reader.truncate(len)?;
        self.reader.skip(len)?;
        Ok(other)
    }

    #[inline]
    fn to_slice(&self) -> Result<Cow<'_, [u8]>> {
        self.reader.to_slice()
    }

    #[inline]
    fn read_slice(&mut self, buf: &mut [u8]) -> Result<()> {
        self.reader.read_slice(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::LittleEndian;
    use crate::read::EndianSlice;

    #[derive(Debug, Clone)]
    struct AddAtFour;

    impl Relocate for AddAtFour {
        fn relocate_word(&self, offset: usize, word: u32) -> Result<u32> {
            Ok(if offset == 4 { word + 0x100 } else { word })
        }
    }

    #[test]
    fn test_relocate_reader() {
        let buf = [1, 0, 0, 0, 2, 0, 0, 0];
        let mut reader = RelocateReader::new(EndianSlice::new(&buf, LittleEndian), AddAtFour);
        assert_eq!(reader.read_relocatable_u32(), Ok(1));
        let mut tail = reader.split(4).unwrap();
        assert_eq!(tail.read_relocatable_u32(), Ok(0x102));
    }
}
