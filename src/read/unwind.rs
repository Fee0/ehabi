use crate::read::{Error, Reader, Result};
use crate::unwind::{DecodeError, UnwindInstruction};

/// The bytes of a frame unwinding description, in execution order.
///
/// Unwinding instructions are packed into words and executed most
/// significant byte first within each word, and in increasing word address
/// order. This iterator undoes that packing for either endianity.
///
/// Trailing padding (normally *Finish* instructions) is included.
#[derive(Debug, Clone)]
pub struct UnwindBytes<R: Reader> {
    head: u32,
    head_len: u8,
    words: R,
}

impl<R: Reader> UnwindBytes<R> {
    /// Create an iterator over the low `head_len` bytes of `head`, followed by
    /// the bytes of each complete word in `words`.
    pub(crate) fn new(head: u32, head_len: u8, words: R) -> Self {
        debug_assert!(head_len <= 4);
        UnwindBytes {
            head,
            head_len,
            words,
        }
    }

    /// Return the number of bytes remaining.
    pub fn remaining(&self) -> usize {
        usize::from(self.head_len) + self.words.len() / 4 * 4
    }
}

impl<R: Reader> Iterator for UnwindBytes<R> {
    type Item = u8;

    fn next(&mut self) -> Option<u8> {
        if self.head_len == 0 {
            if self.words.len() < 4 {
                return None;
            }
            self.head = self.words.read_u32().ok()?;
            self.head_len = 4;
        }
        self.head_len -= 1;
        Some((self.head >> (8 * self.head_len)) as u8)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let len = self.remaining();
        (len, Some(len))
    }
}

/// An iterator over the [`UnwindInstruction`]s of a frame unwinding
/// description.
///
/// Iteration stops after the first [`UnwindInstruction::Finish`], since no
/// further instructions are processed for the frame. Use [`UnwindBytes`]
/// directly to see any bytes after it.
#[derive(Debug, Clone)]
pub struct UnwindInstructionIter<R: Reader> {
    bytes: UnwindBytes<R>,
    done: bool,
}

impl<R: Reader> UnwindInstructionIter<R> {
    pub(crate) fn new(bytes: UnwindBytes<R>) -> Self {
        UnwindInstructionIter { bytes, done: false }
    }

    /// Advance the iterator and return the next instruction.
    ///
    /// Returns `Ok(None)` when there are no more instructions. An implicit
    /// *Finish* follows the last instruction; it is not returned.
    pub fn next(&mut self) -> Result<Option<UnwindInstruction>> {
        if self.done {
            return Ok(None);
        }
        let result = decode_unwind_instruction(&mut self.bytes);
        if !matches!(result, Ok(Some(instruction)) if instruction != UnwindInstruction::Finish) {
            self.done = true;
        }
        result
    }
}

impl_iterators!(UnwindInstructionIter, UnwindInstruction);

/// Decode one unwinding instruction from a byte stream.
///
/// Returns `Ok(None)` at the end of the stream.
pub fn decode_unwind_instruction<I>(bytes: &mut I) -> Result<Option<UnwindInstruction>>
where
    I: Iterator<Item = u8>,
{
    UnwindInstruction::decode(bytes).map_err(|e| match e {
        DecodeError::Truncated => Error::TruncatedUnwindInstruction,
        DecodeError::BadUleb128 => Error::BadUnsignedLeb128,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::{BigEndian, LittleEndian};
    use crate::read::EndianSlice;
    use UnwindInstruction::*;
    use alloc::vec::Vec;

    fn decode_all(bytes: &[u8]) -> Result<Vec<UnwindInstruction>> {
        let mut iter = bytes.iter().copied();
        let mut out = Vec::new();
        while let Some(instruction) = decode_unwind_instruction(&mut iter)? {
            out.push(instruction);
        }
        Ok(out)
    }

    #[test]
    fn test_unwind_bytes_order() {
        // Long format: 2 bytes in the first word, then one more word.
        let words = [0x11, 0x22, 0x33, 0x44];
        let le = UnwindBytes::new(0x8101_aabb, 2, EndianSlice::new(&words, LittleEndian));
        assert_eq!(le.collect::<Vec<_>>(), [0xaa, 0xbb, 0x44, 0x33, 0x22, 0x11]);
        let be = UnwindBytes::new(0x8101_aabb, 2, EndianSlice::new(&words, BigEndian));
        assert_eq!(be.collect::<Vec<_>>(), [0xaa, 0xbb, 0x11, 0x22, 0x33, 0x44]);
    }

    #[test]
    fn test_decode() {
        assert_eq!(
            decode_all(&[0x00, 0x3f, 0x40, 0x7f]),
            Ok(alloc::vec![
                IncrementVsp(4),
                IncrementVsp(0x100),
                DecrementVsp(4),
                DecrementVsp(0x100)
            ])
        );
        assert_eq!(decode_all(&[0x80, 0x00]), Ok(alloc::vec![RefuseToUnwind]));
        assert_eq!(
            decode_all(&[0x84, 0x01]),
            Ok(alloc::vec![PopCore {
                mask: (1 << 14) | (1 << 4)
            }])
        );
        assert_eq!(decode_all(&[0x97]), Ok(alloc::vec![SetVsp(7)]));
        assert_eq!(
            decode_all(&[0xab]),
            Ok(alloc::vec![PopCoreRange { last: 7, lr: true }])
        );
        assert_eq!(
            decode_all(&[0xb1, 0x0f, 0xb1, 0x10, 0xb1, 0x00]),
            Ok(alloc::vec![
                PopCore { mask: 0xf },
                Spare {
                    opcode: 0xb1,
                    operand: Some(0x10)
                },
                Spare {
                    opcode: 0xb1,
                    operand: Some(0x00)
                },
            ])
        );
        assert_eq!(
            decode_all(&[0xb2, 0x00]),
            Ok(alloc::vec![IncrementVspLarge(0x204)])
        );
        assert_eq!(
            decode_all(&[0xb2, 0x81, 0x01]),
            Ok(alloc::vec![IncrementVspLarge(0x204 + (0x81 << 2))])
        );
        assert_eq!(
            decode_all(&[0xc8, 0x23]),
            Ok(alloc::vec![PopVfpVpush {
                first: 18,
                count: 4
            }])
        );
        assert_eq!(
            decode_all(&[0xd7, 0xbf, 0xb4, 0xb5]),
            Ok(alloc::vec![
                PopVfpVpushD8 { count: 8 },
                PopVfpFstmxD8 { count: 8 },
                PopRaAuthCode,
                UseVspAsRaAuthModifier,
            ])
        );
    }

    #[test]
    fn test_decode_truncated() {
        assert_eq!(decode_all(&[0x80]), Err(Error::TruncatedUnwindInstruction));
        assert_eq!(decode_all(&[0xb2, 0x80]), Err(Error::BadUnsignedLeb128));
    }

    #[test]
    fn test_iter_stops_at_finish() {
        let bytes = UnwindBytes::new(0x00a8_b097, 3, EndianSlice::new(&[], LittleEndian));
        let mut iter = UnwindInstructionIter::new(bytes);
        assert_eq!(iter.next(), Ok(Some(PopCoreRange { last: 4, lr: true })));
        assert_eq!(iter.next(), Ok(Some(Finish)));
        assert_eq!(iter.next(), Ok(None));
    }
}
