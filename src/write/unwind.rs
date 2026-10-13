use alloc::vec::Vec;

use crate::unwind::UnwindInstruction;
use crate::write::{Error, Result};

impl UnwindInstruction {
    /// Append the encoding of this instruction to `out`.
    ///
    /// Returns an error if an operand cannot be represented by the
    /// instruction's encoding. Operands that are representable but name
    /// registers outside the architecture (for example `D[15]-D[18]` with
    /// FSTMFDX) are encoded as-is; the EHABI defines these as reserved.
    pub fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        use UnwindInstruction::*;

        let invalid = || Error::InvalidUnwindInstruction(*self);
        let range = |first: u8, count: u8| {
            if first < 16 && (1..=16).contains(&count) {
                Ok((first << 4) | (count - 1))
            } else {
                Err(invalid())
            }
        };
        let short_count = |count: u8, max: u8| {
            if (1..=max).contains(&count) {
                Ok(count - 1)
            } else {
                Err(invalid())
            }
        };
        let vsp = |bytes: u32| {
            if (4..=0x100).contains(&bytes) && bytes.is_multiple_of(4) {
                Ok(((bytes - 4) >> 2) as u8)
            } else {
                Err(invalid())
            }
        };

        match *self {
            IncrementVsp(bytes) => out.push(vsp(bytes)?),
            DecrementVsp(bytes) => out.push(0x40 | vsp(bytes)?),
            IncrementVspLarge(bytes) => {
                if bytes < 0x204 || bytes % 4 != 0 {
                    return Err(invalid());
                }
                out.push(0xb2);
                crate::leb128::write_unsigned((bytes - 0x204) >> 2, |b| out.push(b));
            }
            RefuseToUnwind => out.extend_from_slice(&[0x80, 0x00]),
            PopCore { mask } => {
                if mask != 0 && mask & 0xfff0 == 0 {
                    out.extend_from_slice(&[0xb1, mask as u8]);
                } else if mask != 0 && mask & 0xf == 0 {
                    out.extend_from_slice(&[0x80 | (mask >> 12) as u8, (mask >> 4) as u8]);
                } else {
                    return Err(invalid());
                }
            }
            PopCoreRange { last, lr } => {
                if !(4..=11).contains(&last) {
                    return Err(invalid());
                }
                out.push(if lr { 0xa8 } else { 0xa0 } | (last - 4));
            }
            SetVsp(reg) => {
                if reg >= 16 || reg == 13 || reg == 15 {
                    return Err(invalid());
                }
                out.push(0x90 | reg);
            }
            Finish => out.push(0xb0),
            PopVfpFstmx { first, count } => out.extend_from_slice(&[0xb3, range(first, count)?]),
            PopVfpFstmxD8 { count } => out.push(0xb8 | short_count(count, 8)?),
            PopVfpVpush { first, count } => {
                if first < 16 {
                    out.extend_from_slice(&[0xc9, range(first, count)?]);
                } else {
                    out.extend_from_slice(&[0xc8, range(first - 16, count)?]);
                }
            }
            PopVfpVpushD8 { count } => out.push(0xd0 | short_count(count, 8)?),
            PopRaAuthCode => out.push(0xb4),
            UseVspAsRaAuthModifier => out.push(0xb5),
            PopWmmxWr10 { count } => out.push(0xc0 | short_count(count, 6)?),
            PopWmmx { first, count } => out.extend_from_slice(&[0xc6, range(first, count)?]),
            PopWmmxControl { mask } => {
                if mask == 0 || mask & 0xf0 != 0 {
                    return Err(invalid());
                }
                out.extend_from_slice(&[0xc7, mask]);
            }
            Spare { opcode, operand } => {
                // Only accept encodings that decode back to `Spare`.
                let valid = match (opcode, operand) {
                    (0x9d | 0x9f | 0xb6 | 0xb7 | 0xca..=0xcf | 0xd8..=0xff, None) => true,
                    (0xb1 | 0xc7, Some(operand)) => operand == 0 || operand & 0xf0 != 0,
                    _ => false,
                };
                if !valid {
                    return Err(invalid());
                }
                out.push(opcode);
                out.extend(operand);
            }
        }
        Ok(())
    }

    /// Return the instructions for `vsp = vsp + bytes`, using the shortest
    /// encoding.
    ///
    /// `bytes` must be a multiple of 4. Returns no instructions for zero.
    pub fn vsp_add(bytes: u64) -> Result<Vec<UnwindInstruction>> {
        if !bytes.is_multiple_of(4) {
            return Err(Error::InvalidUnwindOperand(bytes));
        }
        Ok(match bytes {
            0 => Vec::new(),
            4..=0x100 => alloc::vec![UnwindInstruction::IncrementVsp(bytes as u32)],
            0x104..=0x200 => alloc::vec![
                UnwindInstruction::IncrementVsp(0x100),
                UnwindInstruction::IncrementVsp(bytes as u32 - 0x100),
            ],
            _ => alloc::vec![UnwindInstruction::IncrementVspLarge(bytes)],
        })
    }

    /// Return the instructions for `vsp = vsp - bytes`.
    ///
    /// `bytes` must be a multiple of 4. Returns no instructions for zero.
    pub fn vsp_sub(bytes: u32) -> Result<Vec<UnwindInstruction>> {
        if !bytes.is_multiple_of(4) {
            return Err(Error::InvalidUnwindOperand(u64::from(bytes)));
        }
        let mut out = Vec::new();
        let mut remaining = bytes;
        while remaining > 0 {
            let step = remaining.min(0x100);
            out.push(UnwindInstruction::DecrementVsp(step));
            remaining -= step;
        }
        Ok(out)
    }

    /// Return the instructions to pop the core registers in `mask` (bit `n`
    /// for `rN`), as saved by a single `push`, using the shortest encoding.
    ///
    /// Registers r0-r3 are at the lowest addresses, so they are popped first.
    pub fn pop_core(mask: u16) -> Result<Vec<UnwindInstruction>> {
        let mut out = Vec::new();
        let low = mask & 0xf;
        if low != 0 {
            out.push(UnwindInstruction::PopCore { mask: low });
        }
        let high = mask & 0xfff0;
        if high != 0 {
            let lr = high & (1 << 14) != 0;
            let rest = high & !(1 << 14);
            let last = 15u8.saturating_sub(rest.leading_zeros() as u8);
            let is_r4_range = (4..=11).contains(&last) && rest == ((1u16 << (last + 1)) - (1 << 4));
            out.push(if is_r4_range {
                UnwindInstruction::PopCoreRange { last, lr }
            } else {
                UnwindInstruction::PopCore { mask: high }
            });
        }
        Ok(out)
    }

    /// Return the instructions to pop VFP registers `D[first]..D[first +
    /// count - 1]` saved by `VPUSH`, using the shortest encoding.
    ///
    /// The registers must be within D0-D31. Returns no instructions for a zero
    /// count.
    pub fn pop_vfp(first: u8, count: u8) -> Result<Vec<UnwindInstruction>> {
        if u32::from(first) + u32::from(count) > 32 {
            return Err(Error::InvalidUnwindOperand(
                u64::from(first) + u64::from(count),
            ));
        }
        let mut out = Vec::new();
        let (mut first, mut count) = (first, count);
        while count > 0 {
            // A single VPUSH saves at most 16 registers.
            let step = count.min(16);
            out.push(if first == 8 && step <= 8 {
                UnwindInstruction::PopVfpVpushD8 { count: step }
            } else {
                UnwindInstruction::PopVfpVpush { first, count: step }
            });
            first += step;
            count -= step;
        }
        Ok(out)
    }
}

/// The packed form of a frame unwinding description.
pub(crate) struct PackedUnwindBytes {
    /// The first `head_len` bytes, in the low bits of a word.
    pub head: u32,
    /// The remaining bytes, packed into whole words.
    pub words: Vec<u32>,
}

/// Return the number of words needed after the first `head_len` bytes to
/// hold `len` bytes.
pub(crate) fn extra_unwind_words(len: usize, head_len: usize) -> usize {
    len.saturating_sub(head_len).div_ceil(4)
}

/// Pack instruction bytes into words, most significant byte first, padding
/// with *Finish*. The first `head_len` bytes go in the low bits of `head`.
pub(crate) fn pack_unwind_bytes(bytes: &[u8], head_len: usize) -> PackedUnwindBytes {
    let extra = extra_unwind_words(bytes.len(), head_len);
    let mut bytes = bytes
        .iter()
        .copied()
        .chain(core::iter::repeat(crate::constants::UNWIND_OPCODE_FINISH));
    let mut pack = |len: usize| {
        (0..len).fold(0u32, |word, _| {
            (word << 8) | u32::from(bytes.next().unwrap_or(0))
        })
    };
    let head = pack(head_len);
    let words = (0..extra).map(|_| pack(4)).collect();
    PackedUnwindBytes { head, words }
}

/// Encode a sequence of unwinding instructions.
pub fn encode_unwind_instructions(instructions: &[UnwindInstruction]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for instruction in instructions {
        instruction.encode(&mut out)?;
    }
    Ok(out)
}

#[cfg(all(test, feature = "read"))]
mod tests {
    use super::*;
    use crate::read::decode_unwind_instruction;
    use UnwindInstruction::*;

    /// Every one- and two-byte sequence decodes to an instruction that encodes
    /// back to the same bytes.
    #[test]
    fn test_roundtrip_exhaustive() {
        for op in 0..=0xffu8 {
            for operand in 0..=0xffu8 {
                let bytes = [op, operand];
                let mut iter = bytes.iter().copied();
                let Ok(Some(instruction)) = decode_unwind_instruction(&mut iter) else {
                    // Only a multi-byte uleb128 can be truncated here.
                    assert!(op == 0xb2 && operand & 0x80 != 0);
                    continue;
                };
                let consumed = 2 - iter.count();
                let mut out = Vec::new();
                instruction.encode(&mut out).unwrap();
                assert_eq!(out, bytes[..consumed], "{instruction:?}");
                if consumed == 1 {
                    break;
                }
            }
        }
    }

    #[test]
    fn test_roundtrip_uleb() {
        for bytes in [0x204u64, 0x208, 0x400, 0x10_0000, 0x1_0000_0000] {
            let mut out = Vec::new();
            IncrementVspLarge(bytes).encode(&mut out).unwrap();
            let instruction = decode_unwind_instruction(&mut out.iter().copied())
                .unwrap()
                .unwrap();
            assert_eq!(instruction, IncrementVspLarge(bytes));
        }
    }

    #[test]
    fn test_encode_invalid() {
        for instruction in [
            IncrementVsp(0),
            IncrementVsp(6),
            IncrementVsp(0x104),
            IncrementVspLarge(0x200),
            PopCore { mask: 0 },
            PopCore { mask: 0x0011 },
            PopCoreRange {
                last: 12,
                lr: false,
            },
            SetVsp(13),
            PopVfpVpush {
                first: 32,
                count: 1,
            },
            PopVfpFstmxD8 { count: 9 },
            PopWmmxWr10 { count: 7 },
            PopWmmxControl { mask: 0x10 },
            Spare {
                opcode: 0xb0,
                operand: None,
            },
            Spare {
                opcode: 0xb1,
                operand: Some(0x01),
            },
        ] {
            assert_eq!(
                instruction.encode(&mut Vec::new()),
                Err(Error::InvalidUnwindInstruction(instruction))
            );
        }
    }

    #[test]
    fn test_helpers() {
        assert_eq!(UnwindInstruction::vsp_add(0), Ok(alloc::vec![]));
        assert_eq!(
            UnwindInstruction::vsp_add(8),
            Ok(alloc::vec![IncrementVsp(8)])
        );
        assert_eq!(
            UnwindInstruction::vsp_add(0x180),
            Ok(alloc::vec![IncrementVsp(0x100), IncrementVsp(0x80)])
        );
        assert_eq!(
            UnwindInstruction::vsp_add(0x204),
            Ok(alloc::vec![IncrementVspLarge(0x204)])
        );
        assert_eq!(
            UnwindInstruction::vsp_add(5),
            Err(Error::InvalidUnwindOperand(5))
        );
        assert_eq!(
            UnwindInstruction::vsp_sub(0x104),
            Ok(alloc::vec![DecrementVsp(0x100), DecrementVsp(4)])
        );

        assert_eq!(
            UnwindInstruction::pop_core(0x4ff0),
            Ok(alloc::vec![PopCoreRange { last: 11, lr: true }])
        );
        assert_eq!(
            UnwindInstruction::pop_core(0x00f0),
            Ok(alloc::vec![PopCoreRange { last: 7, lr: false }])
        );
        assert_eq!(
            UnwindInstruction::pop_core(0x4000),
            Ok(alloc::vec![PopCore { mask: 0x4000 }])
        );
        assert_eq!(
            UnwindInstruction::pop_core(0x5f0f),
            Ok(alloc::vec![PopCore { mask: 0xf }, PopCore { mask: 0x5f00 }])
        );

        assert_eq!(
            UnwindInstruction::pop_vfp(8, 8),
            Ok(alloc::vec![PopVfpVpushD8 { count: 8 }])
        );
        assert_eq!(
            UnwindInstruction::pop_vfp(0, 32),
            Ok(alloc::vec![
                PopVfpVpush {
                    first: 0,
                    count: 16
                },
                PopVfpVpush {
                    first: 16,
                    count: 16
                }
            ])
        );
        assert!(UnwindInstruction::pop_vfp(30, 3).is_err());
    }
}
