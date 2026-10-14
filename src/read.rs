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
//!   [`BaseAddresses`].
//!
//! * For relocatable objects, wrap the section data in a [`RelocateReader`]
//!   so that relocated words are seen as they would be after linking.

use core::result;

use crate::common::{BaseAddresses, SectionId};

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

mod error;
pub use self::error::*;

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

#[cfg(feature = "lsda")]
mod gnu_lsda;
#[cfg(feature = "lsda")]
pub use self::gnu_lsda::*;

/// Return the address of `section`, or an error if it is not known.
pub(crate) fn base_address(bases: &BaseAddresses, section: SectionId) -> Result<u32> {
    bases.get(section).ok_or(Error::MissingBaseAddress(section))
}

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
    #[must_use]
    fn section_name() -> &'static str {
        Self::id().name()
    }

    /// Try to load the section using the given loader function.
    ///
    /// # Errors
    ///
    /// Returns the error from `f`.
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
    #[must_use]
    pub fn address(&self, section_address: u32) -> u32 {
        section_address
            .wrapping_add(self.offset as u32)
            .wrapping_add(self.value.cast_unsigned())
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
