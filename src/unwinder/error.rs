use core::fmt;
use core::result;

use crate::read;
use crate::unwind::UnwindInstruction;

/// An error that occurred when unwinding a frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The unwinding tables could not be parsed.
    Read(read::Error),
    /// No index table entry covers the address.
    NoUnwindInfo(u32),
    /// The function's index table entry is `EXIDX_CANTUNWIND`.
    CantUnwind,
    /// The unwinding instructions refuse to unwind the frame.
    RefuseToUnwind,
    /// A spare or reserved encoding, or an instruction naming registers that
    /// the EHABI reserves.
    ReservedInstruction(UnwindInstruction),
    /// The value of a core register is needed but is not known.
    MissingRegister(u8),
    /// Memory at the address could not be read.
    MemoryRead(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Error::Read(e) => write!(f, "invalid unwinding tables: {e}"),
            Error::NoUnwindInfo(address) => {
                write!(f, "no unwinding information for address 0x{address:08x}")
            }
            Error::CantUnwind => f.write_str("the function cannot be unwound (EXIDX_CANTUNWIND)"),
            Error::RefuseToUnwind => f.write_str("the unwinding instructions refuse to unwind"),
            Error::ReservedInstruction(instruction) => {
                write!(f, "reserved unwinding instruction: {instruction}")
            }
            Error::MissingRegister(n) => write!(f, "the value of r{n} is not known"),
            Error::MemoryRead(address) => {
                write!(f, "cannot read memory at address 0x{address:08x}")
            }
        }
    }
}

impl core::error::Error for Error {}

impl From<read::Error> for Error {
    fn from(e: read::Error) -> Self {
        Error::Read(e)
    }
}

/// The result of an unwinding operation.
pub type Result<T> = result::Result<T, Error>;
