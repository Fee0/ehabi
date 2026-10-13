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
/// For `R_ARM_PREL31` use [`relocate_prel31`]. Use the same layout for
/// [`BaseAddresses`](crate::BaseAddresses).
pub trait Relocate {
    /// Relocate a word which was read from the given section offset.
    ///
    /// Return the word unchanged if there is no relocation at this offset.
    ///
    /// # Errors
    ///
    /// Returns an error if the relocation at `offset` cannot be applied.
    fn relocate_word(&self, offset: usize, word: u32) -> Result<u32>;
}

/// Apply an `R_ARM_PREL31` relocation to `word`, as a linker would.
///
/// The result is `(word & 0x8000_0000) | ((S + A - P) & 0x7fff_ffff)`, where
/// `S` is `symbol`, `P` is `place` (the address of the word), and the addend
/// `A` is the sign-extended low 31 bits of `word`.
#[must_use]
pub fn relocate_prel31(word: u32, symbol: u32, place: u32) -> u32 {
    let addend = crate::common::prel31_value(word).cast_unsigned();
    let value = symbol.wrapping_add(addend).wrapping_sub(place);
    (word & 0x8000_0000) | (value & 0x7fff_ffff)
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
///
/// ```
/// use ehabi::read::{EndianSlice, ExIdx, Relocate, RelocateReader, Result, relocate_prel31};
/// use ehabi::{BaseAddresses, LittleEndian};
///
/// /// The relocations of `.ARM.exidx`, for a layout that places the section
/// /// at `exidx_address` and the function `f` at 0x1000.
/// #[derive(Clone)]
/// struct Relocations {
///     exidx_address: u32,
/// }
///
/// impl Relocate for Relocations {
///     fn relocate_word(&self, offset: usize, word: u32) -> Result<u32> {
///         Ok(match offset {
///             // R_ARM_PREL31 against `f`.
///             0 => relocate_prel31(word, 0x1000, self.exidx_address + offset as u32),
///             _ => word,
///         })
///     }
/// }
///
/// # fn main() -> Result<()> {
/// // One index entry: a function word holding only the addend (0), and
/// // EXIDX_CANTUNWIND.
/// let data = [0, 0, 0, 0, 1, 0, 0, 0];
/// let exidx_address = 0x2000;
/// let exidx = ExIdx::from(RelocateReader::new(
///     EndianSlice::new(&data, LittleEndian),
///     Relocations { exidx_address },
/// ));
///
/// let bases = BaseAddresses::default().set_exidx(exidx_address);
/// assert_eq!(exidx.entry(0)?.function_address(&bases)?, 0x1000);
/// # Ok(())
/// # }
/// ```
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
        self.reader.empty();
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
    fn test_relocate_prel31() {
        // Addend -4, bit 31 preserved.
        assert_eq!(relocate_prel31(0xffff_fffc, 0x1000, 0x2000), 0xffff_effc);
        assert_eq!(relocate_prel31(0x0000_0010, 0x2000, 0x1000), 0x0000_1010);
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
