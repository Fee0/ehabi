use crate::common::{BaseAddresses, SectionId, prel31_encode};
use crate::endianity::Endianity;
use crate::write::{Address, Error, Reference, Result};

/// A trait for writing the data to an EHABI section.
///
/// All write operations append to the section unless otherwise specified.
#[allow(clippy::len_without_is_empty)]
pub trait Writer {
    /// The endianity of bytes that are written.
    type Endian: Endianity;

    /// Return the endianity of bytes that are written.
    fn endian(&self) -> Self::Endian;

    /// Return the current section length.
    ///
    /// This may be used as an offset for future `write_at` calls.
    fn len(&self) -> usize;

    /// Write a slice.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer cannot store the bytes.
    fn write(&mut self, bytes: &[u8]) -> Result<()>;

    /// Write a slice at a given offset.
    ///
    /// The write must not extend past the current section length.
    ///
    /// # Errors
    ///
    /// Returns [`Error::OffsetOutOfBounds`] if the write extends past the
    /// current section length.
    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<()>;

    /// Write a `prel31` reference, with `high_bit` stored in bit 31.
    ///
    /// `place` identifies the section being written, so that its address can
    /// be found in `bases`.
    ///
    /// If the writer supports relocations, then it must provide its own
    /// implementation of this method.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingBaseAddress`] if a section address needed to
    /// resolve the reference is not in `bases`, [`Error::InvalidAddress`] for a
    /// symbol target if the writer does not support relocations, and
    /// [`Error::Prel31OutOfRange`] if the displacement does not fit in 31 bits.
    fn write_prel31(
        &mut self,
        place: SectionId,
        target: Reference,
        high_bit: bool,
        bases: &BaseAddresses,
    ) -> Result<()> {
        let word = resolve_prel31(self.len(), place, target, high_bit, bases)?;
        self.write_u32(word)
    }

    /// Write a reference to a `type_info` object, as initialized by an
    /// `R_ARM_TARGET2` relocation.
    ///
    /// A constant is written as-is, since its encoding is platform-specific.
    ///
    /// If the writer supports relocations, then it must provide its own
    /// implementation of this method.
    ///
    /// # Errors
    ///
    /// Returns [`Error::InvalidAddress`] for a symbol target if the writer does
    /// not support relocations.
    fn write_target2(&mut self, target: Address) -> Result<()> {
        match target {
            Address::Constant(value) => self.write_u32(value),
            Address::Symbol { .. } => Err(Error::InvalidAddress),
        }
    }

    /// Record a dependency on a symbol at the current offset, as indicated by
    /// an `R_ARM_NONE` relocation. Nothing is written.
    ///
    /// The default implementation does nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if the writer cannot record the dependency.
    fn write_dependency(&mut self, _symbol: usize) -> Result<()> {
        Ok(())
    }

    /// Write a u8.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write`](Self::write).
    fn write_u8(&mut self, val: u8) -> Result<()> {
        self.write(&[val])
    }

    /// Write a u16.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write`](Self::write).
    fn write_u16(&mut self, val: u16) -> Result<()> {
        let mut bytes = [0; 2];
        self.endian().write_u16(&mut bytes, val);
        self.write(&bytes)
    }

    /// Write a u32.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write`](Self::write).
    fn write_u32(&mut self, val: u32) -> Result<()> {
        let mut bytes = [0; 4];
        self.endian().write_u32(&mut bytes, val);
        self.write(&bytes)
    }

    /// Write a u32 at the given offset.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write_at`](Self::write_at).
    fn write_u32_at(&mut self, offset: usize, val: u32) -> Result<()> {
        let mut bytes = [0; 4];
        self.endian().write_u32(&mut bytes, val);
        self.write_at(offset, &bytes)
    }

    /// Write zero bytes until the length is a multiple of 4.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`write`](Self::write).
    fn align_to_word(&mut self) -> Result<()> {
        let padding = self.len().wrapping_neg() % 4;
        self.write(&[0; 3][..padding])
    }
}

/// Compute the word for a `prel31` reference with a constant target, written
/// at `offset` in section `place`.
pub(crate) fn resolve_prel31(
    offset: usize,
    place: SectionId,
    target: Reference,
    high_bit: bool,
    bases: &BaseAddresses,
) -> Result<u32> {
    let target = match target {
        Reference::Address(Address::Constant(address)) => address,
        Reference::Address(Address::Symbol { .. }) => return Err(Error::InvalidAddress),
        Reference::Section { section, offset } => bases
            .get(section)
            .ok_or(Error::MissingBaseAddress(section))?
            .wrapping_add(offset as u32),
    };
    let place = bases
        .get(place)
        .ok_or(Error::MissingBaseAddress(place))?
        .wrapping_add(offset as u32);
    let displacement = i64::from(target.wrapping_sub(place).cast_signed());
    let word = prel31_encode(displacement).ok_or(Error::Prel31OutOfRange(displacement))?;
    Ok(word | (u32::from(high_bit) << 31))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::LittleEndian;
    use crate::write::EndianVec;

    #[test]
    fn test_write_prel31() {
        let bases = BaseAddresses::default().set_exidx(0x1000).set_extab(0x2000);
        let mut w = EndianVec::new(LittleEndian);
        w.write_u32(0).unwrap();
        w.write_prel31(
            SectionId::ArmExidx,
            Reference::Address(Address::Constant(0x0ff8)),
            false,
            &bases,
        )
        .unwrap();
        w.write_prel31(
            SectionId::ArmExidx,
            Reference::Section {
                section: SectionId::ArmExtab,
                offset: 8,
            },
            true,
            &bases,
        )
        .unwrap();
        assert_eq!(
            w.slice()[4..8],
            ((-12i32).cast_unsigned() & 0x7fff_ffff).to_le_bytes()
        );
        assert_eq!(w.slice()[8..12], (0x8000_0000u32 | 0x1000).to_le_bytes());

        assert_eq!(
            w.write_prel31(
                SectionId::ArmExtab,
                Reference::Address(Address::Constant(0)),
                false,
                &BaseAddresses::default()
            ),
            Err(Error::MissingBaseAddress(SectionId::ArmExtab))
        );
        assert_eq!(
            w.write_prel31(
                SectionId::ArmExidx,
                Reference::Address(Address::Constant(0x8000_0000)),
                false,
                &bases
            ),
            Err(Error::Prel31OutOfRange(0x8000_0000 - 0x100c))
        );
    }

    #[test]
    fn test_align() {
        let mut w = EndianVec::new(LittleEndian);
        w.align_to_word().unwrap();
        assert_eq!(w.len(), 0);
        w.write_u8(1).unwrap();
        w.align_to_word().unwrap();
        assert_eq!(w.slice(), [1, 0, 0, 0]);
    }
}
