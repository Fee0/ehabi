use core::fmt;
use core::result;

use crate::common::{PersonalityIndex, Scope, SectionId};
use crate::unwind::UnwindInstruction;

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
