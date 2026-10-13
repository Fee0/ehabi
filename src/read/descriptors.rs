use crate::common::Scope;
use crate::constants;
use crate::read::{Error, Prel31, Reader, Result, Target2};

/// An iterator over the descriptors of a compact-model entry.
///
/// Descriptors are listed in depth-first block order and terminated by a zero
/// word.
#[derive(Debug, Clone)]
pub struct DescriptorIter<R: Reader> {
    input: R,
    section: R,
    wide: bool,
    done: bool,
}

impl<R: Reader> DescriptorIter<R> {
    pub(crate) fn new(input: R, section: R, wide: bool) -> Self {
        DescriptorIter {
            input,
            section,
            wide,
            done: false,
        }
    }

    /// Return true if the scopes are 32 bits wide (personality routine 2).
    #[inline]
    pub fn has_wide_scopes(&self) -> bool {
        self.wide
    }

    /// Return the remaining input, which follows the terminator once the
    /// iterator has returned `Ok(None)`.
    #[inline]
    pub fn remaining(&self) -> &R {
        &self.input
    }

    /// Advance the iterator and return the next descriptor.
    ///
    /// # Errors
    ///
    /// Returns [`Error::UnexpectedEof`] if the list is not terminated within
    /// the section, [`Error::InvalidScope`] for a descriptor with a zero-length
    /// scope, and [`Error::InvalidDescriptorKind`] for the reserved descriptor
    /// kind. After an error, the iterator returns `Ok(None)`.
    pub fn next(&mut self) -> Result<Option<Descriptor<R>>> {
        if self.done {
            return Ok(None);
        }
        let result = self.parse();
        if !matches!(result, Ok(Some(_))) {
            self.done = true;
        }
        result
    }

    fn parse(&mut self) -> Result<Option<Descriptor<R>>> {
        let (length, offset) = if self.wide {
            let length = self.input.read_u32()?;
            if length == 0 {
                return Ok(None);
            }
            (length, self.input.read_u32()?)
        } else {
            let length = u32::from(self.input.read_u16()?);
            let offset = u32::from(self.input.read_u16()?);
            // Only a whole zero word terminates the list; other zero lengths
            // are rejected below.
            if length == 0 && offset == 0 {
                return Ok(None);
            }
            (length, offset)
        };
        let scope = Scope {
            offset: offset & !1,
            length: length & !1,
        };
        // The EHABI requires a non-zero length. This also rejects a length
        // field of 1, which is a catch descriptor with an empty scope.
        if scope.length == 0 {
            return Err(Error::InvalidScope);
        }

        let descriptor = match (length & 1, offset & 1) {
            (0, 0) => {
                let landing_pad = self.read_prel31()?;
                Descriptor::Cleanup { scope, landing_pad }
            }
            (1, 0) => {
                let (place, word) = self.read_word()?;
                let landing_pad = Prel31::from_word(place, word);
                let catches_reference = word & 0x8000_0000 != 0;
                let (place, word) = self.read_word()?;
                let catch_type = match word {
                    constants::CATCH_ANY => CatchType::Any,
                    constants::CATCH_ANY_AND_FAIL => CatchType::AnyAndFail,
                    value => CatchType::TypeInfo(Target2 {
                        offset: place,
                        value,
                    }),
                };
                Descriptor::Catch {
                    scope,
                    landing_pad,
                    catches_reference,
                    catch_type,
                }
            }
            (0, 1) => {
                let word = self.input.read_u32()?;
                let count = word & 0x7fff_ffff;
                let len = (count as usize)
                    .checked_mul(4)
                    .ok_or(Error::UnexpectedEof)?;
                let type_infos = self.input.split(len)?;
                let landing_pad = if word & 0x8000_0000 != 0 {
                    Some(self.read_prel31()?)
                } else {
                    None
                };
                Descriptor::ExceptionSpec(ExceptionSpec {
                    scope,
                    type_infos,
                    landing_pad,
                    section: self.section.clone(),
                })
            }
            _ => return Err(Error::InvalidDescriptorKind),
        };
        Ok(Some(descriptor))
    }

    /// Read a relocatable word, returning its section offset and value.
    fn read_word(&mut self) -> Result<(usize, u32)> {
        let place = self.input.offset_from(&self.section);
        Ok((place, self.input.read_relocatable_u32()?))
    }

    fn read_prel31(&mut self) -> Result<Prel31> {
        let (place, word) = self.read_word()?;
        Ok(Prel31::from_word(place, word))
    }
}

impl_iterators!(DescriptorIter, Descriptor<R>);

/// A descriptor in a compact-model exception-handling table entry.
///
/// Scope offsets are relative to the start of the function, and landing pad
/// references are relative to the `.ARM.extab` section.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Descriptor<R: Reader> {
    /// A cleanup: in phase 2, if the return address is within the scope, the
    /// landing pad is entered.
    Cleanup {
        /// The region of the function covered by this descriptor.
        scope: Scope,
        /// The landing pad.
        landing_pad: Prel31,
    },
    /// A catch handler.
    Catch {
        /// The region of the function covered by this descriptor.
        scope: Scope,
        /// The landing pad. For [`CatchType::AnyAndFail`] this should be zero.
        landing_pad: Prel31,
        /// Whether the handler catches a reference type (bit 31 of the
        /// landing pad word).
        catches_reference: bool,
        /// The type caught by the handler.
        catch_type: CatchType,
    },
    /// A function exception specification.
    ExceptionSpec(ExceptionSpec<R>),
}

impl<R: Reader> Descriptor<R> {
    /// Return the region of the function covered by this descriptor.
    pub fn scope(&self) -> Scope {
        match self {
            Descriptor::Cleanup { scope, .. } | Descriptor::Catch { scope, .. } => *scope,
            Descriptor::ExceptionSpec(spec) => spec.scope,
        }
    }
}

/// The type caught by a catch descriptor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CatchType {
    /// `0xffffffff`: any type, as in `catch(...)`.
    Any,
    /// `0xfffffffe`: any type, and the personality routine immediately
    /// returns `_URC_FAILURE`. This prevents exceptions propagating out of
    /// the scope.
    AnyAndFail,
    /// A reference to a `type_info` object.
    TypeInfo(Target2),
}

/// A function exception specification descriptor.
///
/// If the thrown type matches none of the listed types, the exception
/// specification is violated: control passes to the landing pad if there is
/// one, or otherwise to `__cxa_call_unexpected`. A count of zero corresponds
/// to `throw()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExceptionSpec<R: Reader> {
    scope: Scope,
    type_infos: R,
    landing_pad: Option<Prel31>,
    section: R,
}

impl<R: Reader> ExceptionSpec<R> {
    /// Return the region of the function covered by this descriptor.
    #[inline]
    pub fn scope(&self) -> Scope {
        self.scope
    }

    /// Return the number of types that may be thrown.
    #[inline]
    pub fn count(&self) -> u32 {
        (self.type_infos.len() / 4) as u32
    }

    /// Return an iterator over the `type_info` references for the types that
    /// may be thrown.
    pub fn type_infos(&self) -> TypeInfoIter<R> {
        TypeInfoIter {
            input: self.type_infos.clone(),
            section: self.section.clone(),
        }
    }

    /// Return the landing pad to enter when no type matches, if present.
    #[inline]
    pub fn landing_pad(&self) -> Option<Prel31> {
        self.landing_pad
    }
}

/// An iterator over the `type_info` references of an [`ExceptionSpec`].
#[derive(Debug, Clone)]
pub struct TypeInfoIter<R: Reader> {
    input: R,
    section: R,
}

impl<R: Reader> TypeInfoIter<R> {
    /// Advance the iterator and return the next reference.
    ///
    /// # Errors
    ///
    /// Returns an error if a reference cannot be read or relocated. After an
    /// error, the iterator returns `Ok(None)`.
    pub fn next(&mut self) -> Result<Option<Target2>> {
        if self.input.is_empty() {
            return Ok(None);
        }
        let offset = self.input.offset_from(&self.section);
        match self.input.read_relocatable_u32() {
            Ok(value) => Ok(Some(Target2 { offset, value })),
            Err(e) => {
                self.input.empty();
                Err(e)
            }
        }
    }
}

impl_iterators!(TypeInfoIter, Target2);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::LittleEndian;
    use crate::read::EndianSlice;
    use crate::test_util::words_le;
    use alloc::vec::Vec;

    fn parse(data: &[u8], wide: bool) -> Result<Vec<Descriptor<EndianSlice<'_, LittleEndian>>>> {
        let section = EndianSlice::new(data, LittleEndian);
        DescriptorIter::new(section, section, wide).collect()
    }

    #[test]
    fn test_narrow() {
        // 16-bit scopes are halfwords: length at the lower address.
        let data = words_le(&[
            // cleanup [0x10, 0x18)
            0x0010_0008,
            0x0000_0100,
            // catch [0x20, 0x24), by reference, type_info
            0x0020_0005,
            0x8000_0040,
            0x0000_1234,
            // catch(...) fail
            0x0000_0003,
            0,
            constants::CATCH_ANY_AND_FAIL,
            // exception spec with 2 types and a landing pad
            0x0001_0010,
            0x8000_0002,
            0xaaaa_aaaa,
            0xbbbb_bbbb,
            0x0000_0080,
            // spec throw()
            0x0001_0010,
            0,
            // terminator
            0,
        ]);
        let descriptors = parse(&data, false).unwrap();
        assert_eq!(descriptors.len(), 5);

        assert_eq!(
            descriptors[0],
            Descriptor::Cleanup {
                scope: Scope {
                    offset: 0x10,
                    length: 8
                },
                landing_pad: Prel31 {
                    offset: 4,
                    value: 0x100
                },
            }
        );
        assert_eq!(
            descriptors[1],
            Descriptor::Catch {
                scope: Scope {
                    offset: 0x20,
                    length: 4
                },
                landing_pad: Prel31 {
                    offset: 12,
                    value: 0x40
                },
                catches_reference: true,
                catch_type: CatchType::TypeInfo(Target2 {
                    offset: 16,
                    value: 0x1234
                }),
            }
        );
        assert!(matches!(
            descriptors[2],
            Descriptor::Catch {
                catch_type: CatchType::AnyAndFail,
                catches_reference: false,
                ..
            }
        ));
        let Descriptor::ExceptionSpec(spec) = &descriptors[3] else {
            panic!("expected exception spec");
        };
        assert_eq!(spec.count(), 2);
        assert_eq!(
            spec.scope(),
            Scope {
                offset: 0,
                length: 0x10
            }
        );
        let types: Vec<_> = spec.type_infos().map(|t| t.unwrap().value).collect();
        assert_eq!(types, [0xaaaa_aaaa, 0xbbbb_bbbb]);
        assert_eq!(
            spec.landing_pad(),
            Some(Prel31 {
                offset: 48,
                value: 0x80
            })
        );
        let Descriptor::ExceptionSpec(spec) = &descriptors[4] else {
            panic!("expected exception spec");
        };
        assert_eq!(spec.count(), 0);
        assert_eq!(spec.landing_pad(), None);
    }

    #[test]
    fn test_wide() {
        let data = words_le(&[0x0001_0001, 0x0002_0000, 0, constants::CATCH_ANY, 0]);
        let descriptors = parse(&data, true).unwrap();
        assert_eq!(
            descriptors,
            [Descriptor::Catch {
                scope: Scope {
                    offset: 0x20000,
                    length: 0x10000
                },
                landing_pad: Prel31 {
                    offset: 8,
                    value: 0
                },
                catches_reference: false,
                catch_type: CatchType::Any,
            }]
        );
    }

    #[test]
    fn test_errors() {
        assert_eq!(
            parse(&words_le(&[0x0001_0003]), false),
            Err(Error::InvalidDescriptorKind)
        );
        assert_eq!(
            parse(&words_le(&[0x0002_0000]), false),
            Err(Error::InvalidScope)
        );
        // A catch descriptor (length field 1) with an empty scope.
        assert_eq!(
            parse(&words_le(&[0x0000_0001]), false),
            Err(Error::InvalidScope)
        );
        assert_eq!(
            parse(&words_le(&[0x0000_0001, 0]), true),
            Err(Error::InvalidScope)
        );
        assert_eq!(
            parse(&words_le(&[0x0000_0002]), false),
            Err(Error::UnexpectedEof)
        );
        assert_eq!(parse(&[], false), Err(Error::UnexpectedEof));
    }
}
