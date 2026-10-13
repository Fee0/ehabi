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
//! * [`UnwindInstruction`](crate::UnwindInstruction) has helpers such as
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

use crate::common::SectionId;

mod error;
pub use self::error::*;

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
