use alloc::borrow::Cow;
use core::fmt::Debug;

use crate::endianity::Endianity;
use crate::read::Result;

/// A trait for reading the data from an EHABI section.
///
/// All read operations advance the offset of the reader unless specified
/// otherwise. The EHABI tables are always 32-bit and word oriented, so
/// offsets are `usize` and there are no address-size parameters.
#[allow(clippy::len_without_is_empty)]
pub trait Reader: Debug + Clone {
    /// The endianity of bytes that are read.
    type Endian: Endianity;

    /// Return the endianity of bytes that are read.
    fn endian(&self) -> Self::Endian;

    /// Return the number of bytes remaining.
    fn len(&self) -> usize;

    /// Set the number of bytes remaining to zero.
    fn empty(&mut self);

    /// Set the number of bytes remaining to the specified length.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `len` bytes remain.
    fn truncate(&mut self, len: usize) -> Result<()>;

    /// Return the offset of this reader's data relative to the start of the
    /// given base reader's data.
    ///
    /// May panic if this reader's data is not contained within the given base
    /// reader's data.
    fn offset_from(&self, base: &Self) -> usize;

    /// Discard the specified number of bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `len` bytes remain.
    fn skip(&mut self, len: usize) -> Result<()>;

    /// Split a reader in two.
    ///
    /// A new reader is returned that can be used to read the next `len` bytes,
    /// and `self` is advanced so that it reads the remainder.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `len` bytes remain.
    fn split(&mut self, len: usize) -> Result<Self>;

    /// Return all remaining data as a clone-on-write slice.
    ///
    /// Does not advance the reader.
    ///
    /// # Errors
    ///
    /// Returns an error if the data cannot be provided as a slice.
    fn to_slice(&self) -> Result<Cow<'_, [u8]>>;

    /// Read exactly `buf.len()` bytes into `buf`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than `buf.len()` bytes remain.
    fn read_slice(&mut self, buf: &mut [u8]) -> Result<()>;

    /// Read a word that may be the target of a relocation (`R_ARM_PREL31`
    /// or `R_ARM_TARGET2`).
    ///
    /// The default implementation reads the word as-is, which is correct for
    /// linked images. [`RelocateReader`](crate::read::RelocateReader)
    /// overrides it to apply relocations in relocatable objects.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 4 bytes remain, or if relocating the word
    /// fails.
    #[inline]
    fn read_relocatable_u32(&mut self) -> Result<u32> {
        self.read_u32()
    }

    /// Return true if there are no bytes remaining.
    #[inline]
    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read a `u8`.
    ///
    /// # Errors
    ///
    /// Returns an error if no bytes remain.
    #[inline]
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0; 1];
        self.read_slice(&mut buf)?;
        Ok(buf[0])
    }

    /// Read a `u16`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 2 bytes remain.
    #[inline]
    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0; 2];
        self.read_slice(&mut buf)?;
        Ok(self.endian().read_u16(&buf))
    }

    /// Read a `u32`.
    ///
    /// # Errors
    ///
    /// Returns an error if fewer than 4 bytes remain.
    #[inline]
    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0; 4];
        self.read_slice(&mut buf)?;
        Ok(self.endian().read_u32(&buf))
    }

    /// Return a reader for the data starting at `offset`, without changing
    /// this reader.
    ///
    /// # Errors
    ///
    /// Returns an error if `offset` is greater than the number of bytes
    /// remaining.
    #[inline]
    fn range_from(&self, offset: usize) -> Result<Self> {
        let mut reader = self.clone();
        reader.skip(offset)?;
        Ok(reader)
    }
}
