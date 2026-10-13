//! `ehabi` is a library for reading and writing the exception-handling tables
//! of the 32-bit Arm architecture: `.ARM.exidx` and `.ARM.extab`.
//!
//! The format is specified by the *Exception Handling ABI for the Arm
//! Architecture* (EHABI32), part of the Arm ABI specifications at
//! <https://github.com/ARM-software/abi-aa>. This crate follows release
//! 2025Q4 of that document, including the PACBTI-M unwinding instructions.
//!
//! The API is modelled on the [`gimli`](https://docs.rs/gimli) crate:
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
//! * [`UnwindInstruction`] is shared by both. Each variant maps to exactly one
//!   encoding, so instructions survive a read/write round trip byte for byte
//!   (except that a non-minimal uleb128 operand is re-encoded minimally).
//!
//! ## Cargo features
//!
//! * `read` (default): the [`read`] module.
//! * `write` (default): the [`write`](mod@write) module.
//! * `fallible-iterator`: implement `fallible_iterator::FallibleIterator`
//!   for the iterators.
//!
//! The crate is `no_std` and requires `alloc`. The error types implement
//! `core::error::Error`.
#![deny(missing_docs)]
#![deny(missing_debug_implementations)]
#![warn(elided_lifetimes_in_paths)]
// Iterators have an inherent `next` returning `Result<Option<T>>`, as in gimli.
#![allow(clippy::should_implement_trait)]
#![no_std]

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
