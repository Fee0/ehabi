//! `ehabi` is a library for reading and writing the exception-handling tables
//! of the 32-bit Arm architecture: `.ARM.exidx` and `.ARM.extab`.
//!
//! The format is specified by the *Exception Handling ABI for the Arm
//! Architecture* (EHABI32), part of the Arm ABI specifications at
//! <https://github.com/ARM-software/abi-aa>. This crate follows release
//! 2025Q4 of that document, including the PACBTI-M unwinding instructions.
//!
//! The API is organised as follows:
//!
//! * The [`read`] module parses sections through the [`Reader`](read::Reader)
//!   trait, with zero-copy [`EndianSlice`](read::EndianSlice) as the usual
//!   implementation. Each section has its own type ([`read::ExIdx`] and
//!   [`read::ExTab`]), and iterators return `Result<Option<T>>`.
//!
//! * The [`write`](mod@write) module builds an in-memory [`UnwindTable`](write::UnwindTable)
//!   and writes it to a [`Writer`](write::Writer) such as
//!   [`EndianVec`](write::EndianVec), optionally recording relocations.
//!
//! * The [`unwinder`] module executes the instructions to unwind stack frames
//!   of a stopped program, as a debugger or profiler does.
//!
//! * [`UnwindInstruction`] is shared by all of them. Each variant maps to exactly one
//!   encoding, so instructions survive a read/write round trip byte for byte
//!   (except that a non-minimal uleb128 operand is re-encoded minimally).
//!
//! The [`read`] and [`write`](mod@write) module documentation each start with
//! a complete example.
//!
//! ## Cargo features
//!
//! * `read` (default): the [`read`] module.
//! * `write` (default): the [`write`](mod@write) module.
//! * `unwinder` (default): the [`unwinder`] module, a virtual unwinder. It
//!   implies `read`.
//! * `fallible-iterator`: implement `fallible_iterator::FallibleIterator`
//!   for the iterators.
//! * `lsda`: read and write the language-specific data area (LSDA) of
//!   generic-model entries with the [`lsda`](https://docs.rs/lsda) crate:
//!   `GenericEntry::parse_gnu_lsda` and `LsdaReader` when reading,
//!   `GenericData::GnuLsda` when writing, and
//!   `UnwindTable::from_read_with_lsdas` to convert. The byte order types also
//!   implement `lsda::Endianity`.
//!
//! The crate is `no_std` and requires `alloc`. The error types implement
//! `core::error::Error`.
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![warn(elided_lifetimes_in_paths)]
// Iterators have an inherent `next` returning `Result<Option<T>>`, so that
// errors propagate with `?`; they also implement `Iterator`.
#![allow(clippy::should_implement_trait)]
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

mod common;
pub use crate::common::*;

pub mod constants;

mod endianity;
pub use crate::endianity::*;

pub mod leb128;

mod unwind;
pub use crate::unwind::*;

#[cfg(feature = "read")]
pub mod read;

#[cfg(feature = "write")]
pub mod write;

#[cfg(feature = "unwinder")]
pub mod unwinder;

#[cfg(all(test, any(feature = "read", feature = "write")))]
mod test_util;
