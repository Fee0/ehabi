//! Writing the LSDA of generic-model entries with the `lsda` crate.

use crate::common::{BaseAddresses, SectionId};
use crate::endianity::lsda_endian;
use crate::write::{Address, Error, Result, Writer};

/// A writer of this crate, as a writer of the `lsda` crate.
///
/// The LSDA is written at the position of the underlying writer, plus
/// `start`, so that pc-relative values and the type table alignment are
/// computed from its place in `.ARM.extab`. Symbol references to `type_info`
/// objects become `R_ARM_TARGET2` relocations, if the underlying writer
/// records relocations.
struct LsdaWriter<'a, W: Writer> {
    w: &'a mut W,
    start: usize,
    /// The first error of the underlying writer, which the `lsda` crate only
    /// sees as an `lsda` error.
    error: Option<Error>,
}

impl<W: Writer> LsdaWriter<'_, W> {
    fn fail(&mut self, error: Error) -> lsda::write::Error {
        self.error.get_or_insert(error);
        match error {
            Error::InvalidAddress => lsda::write::Error::InvalidAddress,
            _ => lsda::write::Error::OffsetOutOfBounds,
        }
    }
}

impl<W: Writer> lsda::write::Writer for LsdaWriter<'_, W> {
    type Endian = lsda::RunTimeEndian;

    fn endian(&self) -> Self::Endian {
        lsda_endian(self.w.endian())
    }

    fn len(&self) -> usize {
        self.start + self.w.len()
    }

    fn write(&mut self, bytes: &[u8]) -> lsda::write::Result<()> {
        self.w.write(bytes).map_err(|e| self.fail(e))
    }

    fn write_type_info(
        &mut self,
        encoding: lsda::Encoding,
        address: lsda::write::Address,
        format: lsda::Format,
        bases: &lsda::BaseAddresses,
    ) -> lsda::write::Result<()> {
        match address {
            lsda::write::Address::Symbol { symbol, addend } => {
                // The addend is stored in the word, as Arm REL relocations
                // require.
                let addend = i32::try_from(addend)
                    .map_err(|_| lsda::write::Error::ValueOutOfRange(addend.cast_unsigned()))?;
                let result = self.w.write_target2(Address::Symbol { symbol, addend });
                result.map_err(|e| self.fail(e))
            }
            constant @ lsda::write::Address::Constant(_) => {
                self.write_pointer(encoding, constant, format, bases)
            }
        }
    }
}

/// Write an LSDA at the position of `w`, plus `start`, in `.ARM.extab`.
///
/// Pointers are resolved against the `.ARM.extab` address in `bases`.
pub(crate) fn write_lsda<W: Writer>(
    w: &mut W,
    start: usize,
    lsda: &lsda::write::Lsda,
    bases: &BaseAddresses,
) -> Result<()> {
    let mut lsda_bases = lsda::BaseAddresses::default();
    if let Some(extab) = bases.extab {
        lsda_bases = lsda_bases.set_section(u64::from(extab));
    }
    let mut writer = LsdaWriter {
        w,
        start,
        error: None,
    };
    match lsda.write(&mut writer, lsda::Format::arm_ehabi(), &lsda_bases) {
        Ok(()) => Ok(()),
        Err(e) => Err(writer.error.unwrap_or(match e {
            lsda::write::Error::MissingBaseAddress(lsda::Base::Section) => {
                Error::MissingBaseAddress(SectionId::ArmExtab)
            }
            // A symbol in a pointer other than a type reference, such as
            // @LPStart, which would need a relocation that is not recorded.
            lsda::write::Error::InvalidAddress => Error::InvalidAddress,
            e => Error::Lsda(e),
        })),
    }
}
