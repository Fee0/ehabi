//! Write the `.ARM.exidx` and `.ARM.extab` sections.
//!
//! ## API Structure
//!
//! This module works by building up a representation of the tables in memory
//! with [`UnwindTable`], and then writing it all at once to a pair of
//! [`Sections`].
//!
//! * An [`IndexEntry`] maps a function to its unwinding information: "cannot
//!   unwind", a [`CompactEntry`] stored inline, or an [`ExTabEntry`] added
//!   with [`UnwindTable::add_extab_entry`].
//!
//! * Addresses are [`Address`] values: either constants, which are encoded
//!   relative to the section addresses in [`BaseAddresses`](crate::BaseAddresses), or symbols, which
//!   require a writer that records relocations (see [`RelocateWriter`]).
//!
//! * [`UnwindInstruction`] has helpers such as
//!   [`UnwindInstruction::pop_core`](crate::UnwindInstruction::pop_core) and
//!   [`UnwindInstruction::vsp_add`](crate::UnwindInstruction::vsp_add) that
//!   choose the shortest encoding.
//!
//! * With the `read` feature, [`UnwindTable::from_read`] converts parsed
//!   tables so they can be modified and written again.
//!
//! ## Example Usage
//!
//! ```rust
//! use ehabi::write::{
//!     Address, CompactEntry, EndianVec, IndexEntry, IndexEntryData, Sections, UnwindTable,
//! };
//! use ehabi::{BaseAddresses, LittleEndian, PersonalityIndex, UnwindInstruction};
//!
//! # fn example() -> ehabi::write::Result<()> {
//! let mut table = UnwindTable::new();
//!
//! // push {r4-r7, lr}; sub sp, sp, #16
//! let mut entry = CompactEntry::new(PersonalityIndex::SU16);
//! entry.instructions.extend(UnwindInstruction::vsp_add(16)?);
//! entry.instructions.extend(UnwindInstruction::pop_core(0x40f0)?);
//! table.add_index_entry(IndexEntry {
//!     function: Address::Constant(0x8000),
//!     data: IndexEntryData::Inline(entry),
//! });
//!
//! let mut sections = Sections::new(EndianVec::new(LittleEndian));
//! let bases = BaseAddresses::default().set_exidx(0x9000).set_extab(0x9100);
//! table.write(&mut sections, &bases)?;
//! assert_eq!(
//!     sections.exidx.slice(),
//!     [0x00, 0xf0, 0xff, 0x7f, 0xb0, 0xab, 0x03, 0x80]
//! );
//! # Ok(())
//! # }
//! # example().unwrap();
//! ```

use core::fmt;
use core::result;

use crate::common::{PersonalityIndex, Scope, SectionId};
use crate::unwind::UnwindInstruction;

mod writer;
pub use self::writer::*;

mod endian_vec;
pub use self::endian_vec::*;

mod relocate;
pub use self::relocate::*;

mod section;
pub use self::section::*;

mod unwind;
pub use self::unwind::*;

mod table;
pub use self::table::*;

#[cfg(feature = "read")]
mod convert;
#[cfg(feature = "read")]
pub use self::convert::*;

/// An error that occurred when writing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A symbol address was used with a writer that does not support
    /// relocations.
    InvalidAddress,
    /// The address of the given section is needed but was not provided.
    MissingBaseAddress(SectionId),
    /// A place-relative displacement does not fit in 31 bits.
    Prel31OutOfRange(i64),
    /// The instruction cannot be encoded: an operand is out of range.
    InvalidUnwindInstruction(UnwindInstruction),
    /// A value passed to an instruction helper cannot be represented.
    InvalidUnwindOperand(u64),
    /// The unwinding instructions do not fit in the entry: the encoded
    /// length in bytes is given.
    TooManyUnwindBytes(usize),
    /// The personality routine's format is not defined by the EHABI.
    UnsupportedPersonality(PersonalityIndex),
    /// An entry stored inline in `.ARM.exidx` has descriptors.
    InlineEntryHasDescriptors,
    /// A descriptor scope is not encodable: offset and length must be even,
    /// length must be non-zero, and both must fit in the scope width.
    InvalidScope(Scope),
    /// An exception specification has too many types.
    TooManyTypeInfos(usize),
    /// An `ExTabEntryId` does not belong to this table.
    InvalidExTabEntryId,
    /// A write was attempted beyond the end of the section.
    OffsetOutOfBounds,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::InvalidAddress => {
                f.write_str("symbol address used with a writer that does not support relocations")
            }
            Error::MissingBaseAddress(section) => {
                write!(f, "the address of {} is required", section.name())
            }
            Error::Prel31OutOfRange(value) => {
                write!(f, "displacement {value} does not fit in a prel31 field")
            }
            Error::InvalidUnwindInstruction(instruction) => {
                write!(f, "cannot encode unwinding instruction {instruction:?}")
            }
            Error::InvalidUnwindOperand(value) => {
                write!(f, "cannot encode unwinding operand {value}")
            }
            Error::TooManyUnwindBytes(len) => {
                write!(
                    f,
                    "{len} bytes of unwinding instructions do not fit in the entry"
                )
            }
            Error::UnsupportedPersonality(index) => {
                write!(f, "unsupported personality routine index {}", index.0)
            }
            Error::InlineEntryHasDescriptors => {
                f.write_str("an inline .ARM.exidx entry cannot have descriptors")
            }
            Error::InvalidScope(scope) => write!(
                f,
                "invalid descriptor scope: offset 0x{:x}, length 0x{:x}",
                scope.offset, scope.length
            ),
            Error::TooManyTypeInfos(count) => {
                write!(f, "too many types in exception specification: {count}")
            }
            Error::InvalidExTabEntryId => f.write_str("invalid .ARM.extab entry id"),
            Error::OffsetOutOfBounds => f.write_str("offset out of bounds"),
        }
    }
}

impl core::error::Error for Error {}

/// The result of a write.
pub type Result<T> = result::Result<T, Error>;

/// An address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Address {
    /// A fixed address that does not require relocation.
    Constant(u32),
    /// An address that is relative to a symbol which may be relocated.
    Symbol {
        /// The symbol that the address is relative to.
        ///
        /// The meaning of this value is decided by the writer, but will
        /// typically be an index into a symbol table.
        symbol: usize,
        /// The offset of the address relative to the symbol.
        ///
        /// This will typically be used as the addend in a relocation.
        addend: i32,
    },
}

/// The target of a `prel31` reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reference {
    /// An address.
    Address(Address),
    /// An offset within one of the EHABI sections.
    Section {
        /// The section.
        section: SectionId,
        /// The offset within the section.
        offset: usize,
    },
}
