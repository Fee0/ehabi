use crate::common::{BaseAddresses, SectionId, prel31_encode};
use crate::write::{Address, Error, Reference, Result, Writer, resolve_prel31};

/// A relocation to be applied to a section.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Relocation {
    /// The offset within the section where the relocation should be applied.
    pub offset: usize,
    /// The kind of relocation.
    pub kind: RelocationKind,
    /// The target of the relocation.
    pub target: RelocationTarget,
    /// The addend to be applied to the relocated value.
    pub addend: i64,
}

/// The kind of a [`Relocation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationKind {
    /// `R_ARM_PREL31`: a 31-bit place-relative offset. Bit 31 of the word is
    /// preserved.
    Prel31,
    /// `R_ARM_TARGET2`: a platform-specific reference to a `type_info` object.
    Target2,
    /// `R_ARM_NONE`: a dependency on the target, such as a personality
    /// routine. Nothing is relocated.
    None,
}

/// The target of a [`Relocation`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RelocationTarget {
    /// The relocation target is a symbol.
    ///
    /// The meaning of this value is decided by the writer, but will typically
    /// be an index into a symbol table.
    Symbol(usize),
    /// The relocation target is the start of one of the EHABI sections.
    Section(SectionId),
}

/// A [`Writer`] which also records relocations.
///
/// Symbol addresses and references between the two sections are recorded as
/// relocations. Arm ELF uses REL relocations, so the addend is also stored in
/// the relocated word (in the low 31 bits for `R_ARM_PREL31`). Consumers that
/// emit RELA relocations can ignore those bits.
pub trait RelocateWriter {
    /// The type of the writer being used to write the section data.
    type Writer: Writer;

    /// Get the writer being used to write the section data.
    fn writer(&self) -> &Self::Writer;

    /// Get the writer being used to write the section data.
    fn writer_mut(&mut self) -> &mut Self::Writer;

    /// Record a relocation.
    fn relocate(&mut self, relocation: Relocation);
}

impl<T: RelocateWriter> Writer for T {
    type Endian = <<T as RelocateWriter>::Writer as Writer>::Endian;

    fn endian(&self) -> Self::Endian {
        self.writer().endian()
    }

    fn len(&self) -> usize {
        self.writer().len()
    }

    fn write(&mut self, bytes: &[u8]) -> Result<()> {
        self.writer_mut().write(bytes)
    }

    fn write_at(&mut self, offset: usize, bytes: &[u8]) -> Result<()> {
        self.writer_mut().write_at(offset, bytes)
    }

    fn write_prel31(
        &mut self,
        place: SectionId,
        target: Reference,
        high_bit: bool,
        bases: &BaseAddresses,
    ) -> Result<()> {
        let (target, addend) = match target {
            Reference::Address(Address::Constant(_)) => {
                let word = resolve_prel31(self.len(), place, target, high_bit, bases)?;
                return self.writer_mut().write_u32(word);
            }
            Reference::Address(Address::Symbol { symbol, addend }) => {
                (RelocationTarget::Symbol(symbol), i64::from(addend))
            }
            Reference::Section { section, offset } => (
                RelocationTarget::Section(section),
                i64::try_from(offset).unwrap_or(i64::MAX),
            ),
        };
        // The addend is stored in place, where the linker sign-extends the
        // low 31 bits, so it must fit.
        let addend_bits = prel31_encode(addend).ok_or(Error::Prel31OutOfRange(addend))?;
        // Record the relocation only once its word has been written.
        let offset = self.len();
        self.writer_mut()
            .write_u32(addend_bits | (u32::from(high_bit) << 31))?;
        self.relocate(Relocation {
            offset,
            kind: RelocationKind::Prel31,
            target,
            addend,
        });
        Ok(())
    }

    fn write_target2(&mut self, target: Address) -> Result<()> {
        match target {
            Address::Constant(value) => self.writer_mut().write_u32(value),
            Address::Symbol { symbol, addend } => {
                let offset = self.len();
                self.writer_mut().write_u32(addend.cast_unsigned())?;
                self.relocate(Relocation {
                    offset,
                    kind: RelocationKind::Target2,
                    target: RelocationTarget::Symbol(symbol),
                    addend: i64::from(addend),
                });
                Ok(())
            }
        }
    }

    fn write_dependency(&mut self, symbol: usize) -> Result<()> {
        self.relocate(Relocation {
            offset: self.len(),
            kind: RelocationKind::None,
            target: RelocationTarget::Symbol(symbol),
            addend: 0,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::LittleEndian;
    use crate::write::EndianVec;
    use alloc::vec::Vec;

    struct Section<W> {
        writer: W,
        relocations: Vec<Relocation>,
    }

    impl<W: Writer> RelocateWriter for Section<W> {
        type Writer = W;

        fn writer(&self) -> &Self::Writer {
            &self.writer
        }

        fn writer_mut(&mut self) -> &mut Self::Writer {
            &mut self.writer
        }

        fn relocate(&mut self, relocation: Relocation) {
            self.relocations.push(relocation);
        }
    }

    /// A writer with no room left.
    struct Full;

    impl Writer for Full {
        type Endian = LittleEndian;

        fn endian(&self) -> LittleEndian {
            LittleEndian
        }

        fn len(&self) -> usize {
            0
        }

        fn write(&mut self, _bytes: &[u8]) -> Result<()> {
            Err(Error::OffsetOutOfBounds)
        }

        fn write_at(&mut self, _offset: usize, _bytes: &[u8]) -> Result<()> {
            Err(Error::OffsetOutOfBounds)
        }
    }

    #[test]
    fn test_failed_write_records_no_relocation() {
        let mut w = Section {
            writer: Full,
            relocations: Vec::new(),
        };
        let symbol = Address::Symbol {
            symbol: 1,
            addend: 0,
        };
        let bases = BaseAddresses::default();
        assert!(
            w.write_prel31(
                SectionId::ArmExidx,
                Reference::Address(symbol),
                false,
                &bases
            )
            .is_err()
        );
        assert!(w.write_target2(symbol).is_err());
        assert_eq!(w.relocations, []);
    }

    #[test]
    fn test_relocate_writer() {
        let mut w = Section {
            writer: EndianVec::new(LittleEndian),
            relocations: Vec::new(),
        };
        let bases = BaseAddresses::default();
        w.write_dependency(7).unwrap();
        w.write_prel31(
            SectionId::ArmExidx,
            Reference::Address(Address::Symbol {
                symbol: 1,
                addend: -4,
            }),
            false,
            &bases,
        )
        .unwrap();
        w.write_prel31(
            SectionId::ArmExidx,
            Reference::Section {
                section: SectionId::ArmExtab,
                offset: 0x10,
            },
            true,
            &bases,
        )
        .unwrap();
        w.write_target2(Address::Symbol {
            symbol: 2,
            addend: 0,
        })
        .unwrap();

        // An addend that does not fit in 31 bits is an error, not truncated.
        let len = w.writer.len();
        for target in [
            Reference::Address(Address::Symbol {
                symbol: 1,
                addend: 0x4000_0000,
            }),
            Reference::Section {
                section: SectionId::ArmExtab,
                offset: 0x4000_0000,
            },
        ] {
            assert_eq!(
                w.write_prel31(SectionId::ArmExidx, target, false, &bases),
                Err(Error::Prel31OutOfRange(0x4000_0000))
            );
        }
        assert_eq!(w.writer.len(), len);

        assert_eq!(
            w.writer.slice(),
            [
                0xfc, 0xff, 0xff, 0x7f, //
                0x10, 0x00, 0x00, 0x80, //
                0x00, 0x00, 0x00, 0x00,
            ]
        );
        assert_eq!(
            w.relocations,
            [
                Relocation {
                    offset: 0,
                    kind: RelocationKind::None,
                    target: RelocationTarget::Symbol(7),
                    addend: 0,
                },
                Relocation {
                    offset: 0,
                    kind: RelocationKind::Prel31,
                    target: RelocationTarget::Symbol(1),
                    addend: -4,
                },
                Relocation {
                    offset: 4,
                    kind: RelocationKind::Prel31,
                    target: RelocationTarget::Section(SectionId::ArmExtab),
                    addend: 0x10,
                },
                Relocation {
                    offset: 8,
                    kind: RelocationKind::Target2,
                    target: RelocationTarget::Symbol(2),
                    addend: 0,
                },
            ]
        );
    }
}
