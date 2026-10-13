use core::fmt;
use core::result;

use crate::common::{PersonalityIndex, SectionId};

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
