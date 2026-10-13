//! Read the `.ARM.exidx` and `.ARM.extab` sections.
//!
//! ## Example Usage
//!
//! Look up the unwinding instructions for an address in a linked image:
//!
//! ```rust
//! use ehabi::read::{ExIdx, ExTab, UnwindEntry};
//! use ehabi::{BaseAddresses, LittleEndian};
//!
//! # fn example() -> ehabi::read::Result<()> {
//! // `.ARM.exidx` at 0x4 with one entry: the function at 0x1000 (prel31
//! // offset 0xffc) has an inline compact entry 0x80a8b0b0, which pops
//! // {r4, lr} (0xa8) and then finishes (0xb0).
//! let exidx_data = [0xfc, 0x0f, 0x00, 0x00, 0xb0, 0xb0, 0xa8, 0x80];
//! let exidx = ExIdx::new(&exidx_data, LittleEndian);
//! let extab = ExTab::new(&[], LittleEndian);
//! let bases = BaseAddresses::default().set_exidx(0x4).set_extab(0x0);
//!
//! let entry = exidx.find(0x1010, &bases)?.expect("address is covered");
//! assert_eq!(entry.function_address(&bases)?, 0x1000);
//! match entry.resolve(&extab, &bases)? {
//!     UnwindEntry::Compact(compact) => {
//!         let mut instructions = compact.instructions()?;
//!         while let Some(instruction) = instructions.next()? {
//!             println!("{instruction}");
//!         }
//!     }
//!     UnwindEntry::Generic(_) => { /* personality-specific data */ }
//!     UnwindEntry::CantUnwind => { /* the frame cannot be unwound */ }
//! }
//! # Ok(())
//! # }
//! # example().unwrap();
//! ```
//!
//! ## API Structure
//!
//! * [`ExIdx`] is the index table. Its entries map a function start address
//!   to unwinding information, which is one of: "cannot unwind", a compact
//!   entry stored inline, or a reference into `.ARM.extab`.
//!
//! * [`ExTab`] holds the out-of-line exception-handling table entries. These
//!   are not self-delimiting, so they are reached by offset from the index
//!   table rather than iterated.
//!
//! * [`CompactEntry`] is the Arm-defined compact model (personality routines
//!   0-2). It gives access to the [`UnwindInstruction`](crate::UnwindInstruction)s
//!   and the [`Descriptor`]s (cleanups, catches, exception specifications).
//!
//! * [`GenericEntry`] is the generic model: a `prel31` reference to a
//!   personality routine followed by data that only that routine understands.
//!   Helpers decode the layout used by GCC and LLVM for
//!   `__gxx_personality_v0` and friends.
//!
//! * Every place-relative reference is returned as a [`Prel31`], which
//!   records where in the section it was read so it can be resolved against
//!   [`BaseAddresses`](crate::BaseAddresses).
//!
//! * For relocatable objects, wrap the section data in a [`RelocateReader`]
//!   so that relocated words are seen as they would be after linking.

use core::fmt;
use core::result;

use crate::common::{PersonalityIndex, SectionId};

/// Implement `Iterator` (and `FallibleIterator`) for a type with an inherent
/// `fn next(&mut self) -> Result<Option<Item>>` that stops after an error.
macro_rules! impl_iterators {
    ($name:ident, $item:ty) => {
        impl<R: $crate::read::Reader> Iterator for $name<R> {
            type Item = $crate::read::Result<$item>;

            fn next(&mut self) -> Option<Self::Item> {
                $name::next(self).transpose()
            }
        }

        #[cfg(feature = "fallible-iterator")]
        impl<R: $crate::read::Reader> fallible_iterator::FallibleIterator for $name<R> {
            type Item = $item;
            type Error = $crate::read::Error;

            fn next(&mut self) -> $crate::read::Result<Option<Self::Item>> {
                $name::next(self)
            }
        }
    };
}

mod reader;
pub use self::reader::*;

mod endian_slice;
pub use self::endian_slice::*;

mod relocate;
pub use self::relocate::*;

mod unwind;
pub use self::unwind::*;

mod exidx;
pub use self::exidx::*;

mod extab;
pub use self::extab::*;

mod descriptors;
pub use self::descriptors::*;

/// An error that occurred when parsing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The input ended before the expected data.
    UnexpectedEof,
    /// An unsigned LEB128 value was truncated or too large.
    BadUnsignedLeb128,
    /// A multi-byte unwinding instruction was truncated.
    TruncatedUnwindInstruction,
    /// The length of the `.ARM.exidx` section is not a multiple of 8.
    InvalidExIdxLength(usize),
    /// The first word of an index table entry had bit 31 set.
    InvalidExIdxFunctionWord(u32),
    /// An offset or index was outside the section.
    OffsetOutOfBounds,
    /// An `.ARM.extab` offset was not a multiple of 4.
    UnalignedExTabOffset(usize),
    /// The address of the given section is needed but was not provided.
    MissingBaseAddress(SectionId),
    /// The data layout of this personality routine is not defined by the EHABI.
    UnsupportedPersonality(PersonalityIndex),
    /// A compact entry stored inline in the index table claimed extra words of
    /// unwinding instructions.
    InlineEntryHasExtraWords(u8),
    /// A descriptor had both kind bits set in its scope.
    InvalidDescriptorKind,
    /// A descriptor scope had a zero length but was not the terminator.
    InvalidScope,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::UnexpectedEof => f.write_str("unexpected end of input"),
            Error::BadUnsignedLeb128 => f.write_str("invalid unsigned LEB128 value"),
            Error::TruncatedUnwindInstruction => f.write_str("truncated unwinding instruction"),
            Error::InvalidExIdxLength(len) => {
                write!(f, ".ARM.exidx length {len} is not a multiple of 8")
            }
            Error::InvalidExIdxFunctionWord(word) => {
                write!(f, "index entry function word 0x{word:08x} has bit 31 set")
            }
            Error::OffsetOutOfBounds => f.write_str("offset out of bounds"),
            Error::UnalignedExTabOffset(offset) => {
                write!(f, ".ARM.extab offset 0x{offset:x} is not word aligned")
            }
            Error::MissingBaseAddress(section) => {
                write!(f, "the address of {} is required", section.name())
            }
            Error::UnsupportedPersonality(index) => {
                write!(f, "unsupported personality routine index {}", index.0)
            }
            Error::InlineEntryHasExtraWords(count) => {
                write!(f, "inline compact entry claims {count} extra words")
            }
            Error::InvalidDescriptorKind => f.write_str("invalid descriptor kind"),
            Error::InvalidScope => f.write_str("invalid descriptor scope"),
        }
    }
}

impl core::error::Error for Error {}

/// The result of a parse.
pub type Result<T> = result::Result<T, Error>;

/// A convenience trait for loading the EHABI sections from object files.
///
/// ```
/// use ehabi::read::{EndianSlice, ExIdx, Section};
/// use ehabi::LittleEndian;
///
/// let buf = [0u8; 8];
/// let loader = |_id| -> Result<_, ()> { Ok(EndianSlice::new(&buf, LittleEndian)) };
/// let exidx: ExIdx<_> = Section::load(loader).unwrap();
/// assert_eq!(exidx.len(), 1);
/// ```
pub trait Section<R>: From<R> {
    /// Returns the section id for this type.
    fn id() -> SectionId;

    /// Returns the ELF section name for this type.
    fn section_name() -> &'static str {
        Self::id().name()
    }

    /// Try to load the section using the given loader function.
    fn load<F, E>(f: F) -> result::Result<Self, E>
    where
        F: FnOnce(SectionId) -> result::Result<R, E>,
    {
        f(Self::id()).map(From::from)
    }

    /// Returns the `Reader` for this section.
    fn reader(&self) -> &R
    where
        R: Reader;
}

/// A place-relative reference, as encoded by an `R_ARM_PREL31` relocation.
///
/// The low 31 bits of the word are a signed offset from the address of the
/// word itself. Bit 31 is not part of the reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Prel31 {
    /// The offset of the word within its section.
    pub offset: usize,
    /// The sign-extended 31-bit displacement.
    pub value: i32,
}

impl Prel31 {
    pub(crate) fn from_word(offset: usize, word: u32) -> Self {
        Prel31 {
            offset,
            value: crate::common::prel31_value(word),
        }
    }

    /// Resolve the reference, given the address of the section it was read
    /// from.
    #[inline]
    pub fn address(&self, section_address: u32) -> u32 {
        section_address
            .wrapping_add(self.offset as u32)
            .wrapping_add(self.value as u32)
    }
}

/// A word initialized by an `R_ARM_TARGET2` relocation.
///
/// This refers to a `type_info` object. Its interpretation is
/// platform-specific: on bare metal it is an absolute address, while other
/// platforms define it as a GOT-relative or place-relative reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Target2 {
    /// The offset of the word within its section.
    pub offset: usize,
    /// The raw value of the word.
    pub value: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_prel31_address() {
        let reference = Prel31::from_word(8, 0x7fff_fff8);
        assert_eq!(reference.value, -8);
        assert_eq!(reference.address(0x1000), 0x1000);
    }
}
