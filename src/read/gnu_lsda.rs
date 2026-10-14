//! Reading the LSDA of generic-model entries with the `lsda` crate.

use alloc::borrow::Cow;

use crate::endianity::lsda_endian;
use crate::read::{Error, GenericEntry, Reader};

/// A reader of this crate, as a reader of the `lsda` crate.
///
/// The `lsda` crate decodes the language-specific data area (LSDA) at the
/// end of a generic-model `.ARM.extab` entry. This adapter lets it read the
/// LSDA in place, from the `.ARM.extab` reader.
///
/// Words that may be relocated (the `R_ARM_TARGET2` references to
/// `type_info` objects) are read with [`Reader::read_relocatable_u32`], so a
/// [`RelocateReader`](crate::read::RelocateReader) relocates them in the
/// LSDA as in the rest of the entry.
///
/// Errors are reported as `lsda` errors. An error of a
/// [`Relocate`](crate::read::Relocate) implementation other than
/// [`Error::UnexpectedEof`] is reported as
/// [`lsda::read::Error::OffsetOutOfBounds`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsdaReader<R>(R);

impl<R: Reader> LsdaReader<R> {
    /// Wrap a reader.
    #[inline]
    pub fn new(reader: R) -> Self {
        LsdaReader(reader)
    }

    /// Return the wrapped reader.
    #[inline]
    pub fn get_ref(&self) -> &R {
        &self.0
    }

    /// Unwrap the reader.
    #[inline]
    pub fn into_inner(self) -> R {
        self.0
    }
}

/// Report an error of this crate as an error of the `lsda` crate.
fn lsda_error(error: Error) -> lsda::read::Error {
    match error {
        Error::UnexpectedEof => lsda::read::Error::UnexpectedEof,
        Error::BadUnsignedLeb128 => lsda::read::Error::BadUnsignedLeb128,
        _ => lsda::read::Error::OffsetOutOfBounds,
    }
}

impl<R: Reader> lsda::read::Reader for LsdaReader<R> {
    type Endian = lsda::RunTimeEndian;

    #[inline]
    fn endian(&self) -> Self::Endian {
        lsda_endian(self.0.endian())
    }

    #[inline]
    fn len(&self) -> usize {
        self.0.len()
    }

    #[inline]
    fn empty(&mut self) {
        self.0.empty();
    }

    #[inline]
    fn truncate(&mut self, len: usize) -> lsda::read::Result<()> {
        self.0.truncate(len).map_err(lsda_error)
    }

    #[inline]
    fn offset_from(&self, base: &Self) -> usize {
        self.0.offset_from(&base.0)
    }

    #[inline]
    fn skip(&mut self, len: usize) -> lsda::read::Result<()> {
        self.0.skip(len).map_err(lsda_error)
    }

    #[inline]
    fn split(&mut self, len: usize) -> lsda::read::Result<Self> {
        self.0.split(len).map(LsdaReader).map_err(lsda_error)
    }

    #[inline]
    fn to_slice(&self) -> lsda::read::Result<Cow<'_, [u8]>> {
        self.0.to_slice().map_err(lsda_error)
    }

    #[inline]
    fn read_slice(&mut self, buf: &mut [u8]) -> lsda::read::Result<()> {
        self.0.read_slice(buf).map_err(lsda_error)
    }

    fn read_relocatable(&mut self, size: u8) -> lsda::read::Result<u64> {
        // Arm relocations apply to words.
        if size == 4 {
            self.0
                .read_relocatable_u32()
                .map(u64::from)
                .map_err(lsda_error)
        } else {
            lsda::read::Reader::read_sized(self, size)
        }
    }
}

impl<R: Reader> GenericEntry<R> {
    /// Parse the language-specific data area with the `lsda` crate, using
    /// the GCC/LLVM layout (see [`gnu_lsda`](Self::gnu_lsda)).
    ///
    /// This is the LSDA of `__gxx_personality_v0` (C++) and
    /// `__gcc_personality_v0` (C cleanups). It is read in place in
    /// `.ARM.extab`, so its offsets are offsets in `.ARM.extab`: resolve its
    /// pointers with [`lsda::BaseAddresses`] whose section address is that of
    /// `.ARM.extab`. Its type references are `R_ARM_TARGET2` values, whose
    /// interpretation is platform-specific.
    ///
    /// # Errors
    ///
    /// Returns [`lsda::read::Error::UnexpectedEof`] if the entry is shorter
    /// than its word count requires, and the errors of
    /// [`lsda::read::GccExceptTable::lsda_at`].
    pub fn parse_gnu_lsda(&self) -> lsda::read::Result<lsda::read::Lsda<LsdaReader<R>>> {
        let offset = self.gnu_lsda_offset().map_err(lsda_error)?;
        lsda::read::GccExceptTable::from_reader(
            LsdaReader::new(self.section().clone()),
            lsda::Format::arm_ehabi(),
        )
        .lsda_at(lsda::LsdaOffset(offset.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::ExTabOffset;
    use crate::endianity::{LittleEndian, RunTimeEndian};
    use crate::read::{EndianSlice, ExTab, ExTabEntry, Relocate, RelocateReader, Result};
    use alloc::vec::Vec;

    /// A generic entry with no extra unwinding words, and an LSDA at 8 for
    /// `try { ... } catch (T) { ... }` with one type reference at 20.
    fn entry(big: bool) -> Vec<u8> {
        let word = |w: u32| {
            if big {
                w.to_be_bytes()
            } else {
                w.to_le_bytes()
            }
        };
        let mut data = Vec::new();
        data.extend(word(0x7fff_ff00)); // personality
        data.extend(word(0x00b0_b0b0)); // finish
        data.extend([
            0xff, // @LPStart omitted
            0x00, // @TType: absptr
            0x0d, // @TType base offset: 11 + 0x0d = 0x18
            0x01, // call sites: uleb128
            0x04, // call-site table length
            0x00, 0x04, 0x08, 0x01, // call site, action 1
            0x01, 0x00, // action: catch type 1
            0x00, // padding
        ]);
        data.extend(word(0x2000)); // type 1
        data
    }

    fn parse<R: Reader>(extab: &ExTab<R>) -> lsda::read::Lsda<LsdaReader<R>> {
        let ExTabEntry::Generic(entry) = extab.entry_at(ExTabOffset(0)).unwrap() else {
            panic!("expected a generic entry");
        };
        entry.parse_gnu_lsda().unwrap()
    }

    #[test]
    fn test_parse_gnu_lsda() {
        for big in [false, true] {
            let data = entry(big);
            let endian = if big {
                RunTimeEndian::Big
            } else {
                RunTimeEndian::Little
            };
            let lsda = parse(&ExTab::new(&data, endian));
            assert_eq!(lsda.offset(), lsda::LsdaOffset(8));
            let tables = lsda.parse_tables().unwrap();
            assert_eq!(tables.call_sites.len(), 1);
            assert_eq!(tables.types.len(), 1);
            assert_eq!(tables.types[0].offset(), 0x14);
            assert_eq!(tables.types[0].value(), 0x2000);
            assert_eq!(tables.end, data.len());
        }
    }

    #[test]
    fn test_relocated_lsda() {
        #[derive(Debug, Clone)]
        struct AddToType;
        impl Relocate for AddToType {
            fn relocate_word(&self, offset: usize, word: u32) -> Result<u32> {
                Ok(if offset == 0x14 { word + 0x1000 } else { word })
            }
        }
        let data = entry(false);
        let reader = RelocateReader::new(EndianSlice::new(&data, LittleEndian), AddToType);
        let lsda = parse(&ExTab::from(reader));
        assert_eq!(lsda.type_entry(1).unwrap().value(), 0x3000);
    }

    #[test]
    fn test_errors() {
        // One extra unwinding word is missing.
        let data = [0x00, 0xff, 0xff, 0x7f, 0xb0, 0xb0, 0xb0, 0x01];
        let extab = ExTab::new(&data, LittleEndian);
        let ExTabEntry::Generic(entry) = extab.entry_at(ExTabOffset(0)).unwrap() else {
            panic!("expected a generic entry");
        };
        assert_eq!(
            entry.parse_gnu_lsda().err(),
            Some(lsda::read::Error::UnexpectedEof)
        );
    }
}
