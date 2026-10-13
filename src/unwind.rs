//! Frame unwinding instructions.
//!
//! The instructions used by the Arm-defined personality routines (and, by
//! convention, by the GNU and LLVM generic-model entries) are described in
//! EHABI32 section "Frame unwinding instructions".
//!
//! [`UnwindInstruction`] is shared between reading and writing. Each variant
//! corresponds to exactly one encoding, so decoding and re-encoding an
//! instruction reproduces the original bytes. The one exception is the
//! uleb128 operand of [`UnwindInstruction::IncrementVspLarge`], which is
//! re-encoded in its minimal form. Where the EHABI provides both a
//! short and a general encoding for the same operation (for example `pop
//! {r4-r7}` can be encoded as `0xa3` or as `0x80 0x0f`), there are separate
//! variants for each.

use core::fmt;

/// A single frame unwinding instruction.
///
/// "vsp" is the virtual stack pointer of the frame being unwound. Register
/// masks use bit `n` for core register `rN`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UnwindInstruction {
    /// `00xxxxxx`: `vsp = vsp + bytes`.
    ///
    /// `bytes` is a multiple of 4 in the range `0x04..=0x100`.
    IncrementVsp(u32),
    /// `01xxxxxx`: `vsp = vsp - bytes`.
    ///
    /// `bytes` is a multiple of 4 in the range `0x04..=0x100`.
    DecrementVsp(u32),
    /// `10110010 uleb128`: `vsp = vsp + bytes`.
    ///
    /// `bytes` is `0x204 + (uleb128 << 2)`, so it is at least `0x204`. For
    /// increments of `0x104..=0x200`, two [`IncrementVsp`](Self::IncrementVsp)
    /// instructions are used instead.
    IncrementVspLarge(u64),
    /// `10000000 00000000`: refuse to unwind.
    ///
    /// The personality routine returns `_URC_FAILURE`, which prevents
    /// throwing out of the function. Unlike `EXIDX_CANTUNWIND`, descriptors
    /// may still be present.
    RefuseToUnwind,
    /// Pop the core registers in `mask`, lowest numbered register at the
    /// lowest stack address.
    ///
    /// Encoded as `1000iiii iiiiiiii` when only r4-r15 are present, or as
    /// `10110001 0000iiii` when only r0-r3 are present. A mask containing
    /// registers from both groups cannot be encoded in one instruction.
    ///
    /// When r13 is popped, the loaded value is written to vsp after the whole
    /// instruction has completed.
    PopCore {
        /// Bit `n` set pops `rN`.
        mask: u16,
    },
    /// `10100nnn` / `10101nnn`: pop r4-r`last`, and also r14 if `lr` is set.
    ///
    /// `last` is in the range `4..=11`.
    PopCoreRange {
        /// The highest register in the r4-based range.
        last: u8,
        /// Whether r14 is also popped.
        lr: bool,
    },
    /// `1001nnnn`: `vsp = r[reg]`, where `reg` is not 13 or 15.
    SetVsp(u8),
    /// `10110000`: finish.
    ///
    /// Copies r14 to r15 if r15 has not been updated, and terminates the
    /// sequence. An implicit finish follows the last instruction.
    Finish,
    /// `10110011 sssscccc`: pop VFP double-precision registers
    /// `D[first]..D[first + count - 1]` saved (as if) by FSTMFDX.
    ///
    /// vsp is incremented by `8 * count + 4`.
    PopVfpFstmx {
        /// The first register.
        first: u8,
        /// The number of registers, `1..=16`.
        count: u8,
    },
    /// `10111nnn`: pop VFP double-precision registers `D[8]..D[8 + count - 1]`
    /// saved (as if) by FSTMFDX.
    PopVfpFstmxD8 {
        /// The number of registers, `1..=8`.
        count: u8,
    },
    /// Pop VFP double-precision registers `D[first]..D[first + count - 1]`
    /// saved (as if) by VPUSH.
    ///
    /// Encoded as `11001001 sssscccc` when `first < 16`, or as
    /// `11001000 sssscccc` (with `ssss = first - 16`) otherwise.
    /// vsp is incremented by `8 * count`.
    PopVfpVpush {
        /// The first register, `0..=31`.
        first: u8,
        /// The number of registers, `1..=16`.
        count: u8,
    },
    /// `11010nnn`: pop VFP double-precision registers `D[8]..D[8 + count - 1]`
    /// saved (as if) by VPUSH.
    PopVfpVpushD8 {
        /// The number of registers, `1..=8`.
        count: u8,
    },
    /// `10110100`: pop the Return Address Authentication Code pseudo-register
    /// (PACBTI-M).
    PopRaAuthCode,
    /// `10110101`: use the current vsp as the modifier for Return Address
    /// Authentication, instead of the CFA (PACBTI-M).
    UseVspAsRaAuthModifier,
    /// `11000nnn` (nnn != 6, 7): pop Intel Wireless MMX registers
    /// `wR[10]..wR[10 + count - 1]`.
    PopWmmxWr10 {
        /// The number of registers, `1..=6`.
        count: u8,
    },
    /// `11000110 sssscccc`: pop Intel Wireless MMX registers
    /// `wR[first]..wR[first + count - 1]`.
    PopWmmx {
        /// The first register, `0..=15`.
        first: u8,
        /// The number of registers, `1..=16`.
        count: u8,
    },
    /// `11000111 0000iiii`: pop Intel Wireless MMX wCGR registers under mask
    /// {wCGR3, wCGR2, wCGR1, wCGR0}.
    PopWmmxControl {
        /// Bit `n` set pops `wCGRn`; non-zero and at most `0xf`.
        mask: u8,
    },
    /// A spare or reserved encoding.
    ///
    /// A personality routine returns `_URC_FAILURE` when it encounters one.
    /// Spare encodings in the two-byte instruction classes (`0xb1`, `0xc7`)
    /// consume their operand byte; all others are a single byte.
    Spare {
        /// The opcode byte.
        opcode: u8,
        /// The operand byte, for two-byte spare encodings.
        operand: Option<u8>,
    },
}

impl UnwindInstruction {
    /// Returns true if this is a spare or reserved encoding.
    #[inline]
    pub fn is_spare(&self) -> bool {
        matches!(self, UnwindInstruction::Spare { .. })
    }

    /// Returns the core register mask popped by this instruction, if any.
    ///
    /// Returns `None` for a [`PopCoreRange`](Self::PopCoreRange) whose `last`
    /// is outside `4..=11`, which cannot be encoded.
    pub fn popped_core_registers(&self) -> Option<u16> {
        match *self {
            UnwindInstruction::PopCore { mask } => Some(mask),
            UnwindInstruction::PopCoreRange { last, lr } => {
                if !(4..=11).contains(&last) {
                    return None;
                }
                let range = ((1u32 << (last + 1)) - (1 << 4)) as u16;
                Some(if lr { range | (1 << 14) } else { range })
            }
            _ => None,
        }
    }
}

/// Why an unwinding instruction could not be decoded.
#[cfg(any(feature = "read", feature = "write"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DecodeError {
    /// A multi-byte instruction was truncated.
    Truncated,
    /// The uleb128 operand was truncated or too large.
    BadUleb128,
}

#[cfg(any(feature = "read", feature = "write"))]
impl UnwindInstruction {
    /// Decode one instruction from a byte stream, returning `Ok(None)` at the
    /// end of the stream.
    ///
    /// This is the single definition of the opcode table: the writer
    /// validates [`Spare`](Self::Spare) encodings against it.
    pub(crate) fn decode<I>(bytes: &mut I) -> Result<Option<Self>, DecodeError>
    where
        I: Iterator<Item = u8>,
    {
        use crate::constants::*;
        use UnwindInstruction::*;

        let Some(op) = bytes.next() else {
            return Ok(None);
        };
        let mut operand = || bytes.next().ok_or(DecodeError::Truncated);
        let range = |byte: u8, base: u8| (base + (byte >> 4), (byte & 0xf) + 1);
        let count = (op & 0x7) + 1;
        let spare = Spare {
            opcode: op,
            operand: None,
        };

        let instruction = match op {
            UNWIND_OPCODE_INC_VSP..=0x3f => IncrementVsp((u32::from(op & 0x3f) << 2) + 4),
            UNWIND_OPCODE_DEC_VSP..=0x7f => DecrementVsp((u32::from(op & 0x3f) << 2) + 4),
            UNWIND_OPCODE_POP_REG_MASK_R4..=0x8f => {
                let low = operand()?;
                match (u16::from(op & 0xf) << 12) | (u16::from(low) << 4) {
                    0 => RefuseToUnwind,
                    mask => PopCore { mask },
                }
            }
            UNWIND_OPCODE_RESERVED_ARM_MOVE | UNWIND_OPCODE_RESERVED_WMMX_MOVE => spare,
            UNWIND_OPCODE_SET_VSP..=0x9f => SetVsp(op & 0xf),
            UNWIND_OPCODE_POP_REG_RANGE_R4..=0xa7 => PopCoreRange {
                last: 4 + (op & 0x7),
                lr: false,
            },
            UNWIND_OPCODE_POP_REG_RANGE_R4_R14..=0xaf => PopCoreRange {
                last: 4 + (op & 0x7),
                lr: true,
            },
            UNWIND_OPCODE_FINISH => Finish,
            UNWIND_OPCODE_POP_REG_MASK => match operand()? {
                mask @ 0x01..=0x0f => PopCore {
                    mask: u16::from(mask),
                },
                operand => Spare {
                    opcode: op,
                    operand: Some(operand),
                },
            },
            UNWIND_OPCODE_INC_VSP_ULEB128 => {
                let value = crate::leb128::read_unsigned(bytes).ok_or(DecodeError::BadUleb128)?;
                let increment = value
                    .checked_mul(4)
                    .and_then(|v| v.checked_add(0x204))
                    .ok_or(DecodeError::BadUleb128)?;
                IncrementVspLarge(increment)
            }
            UNWIND_OPCODE_POP_VFP_REG_RANGE_FSTMFDX => {
                let (first, count) = range(operand()?, 0);
                PopVfpFstmx { first, count }
            }
            UNWIND_OPCODE_POP_RA_AUTH_CODE => PopRaAuthCode,
            UNWIND_OPCODE_RA_AUTH_MODIFIER_VSP => UseVspAsRaAuthModifier,
            0xb6 | 0xb7 => spare,
            UNWIND_OPCODE_POP_VFP_REG_RANGE_FSTMFDX_D8..=0xbf => PopVfpFstmxD8 { count },
            UNWIND_OPCODE_POP_WIRELESS_MMX_REG_RANGE_WR10..=0xc5 => PopWmmxWr10 { count },
            UNWIND_OPCODE_POP_WIRELESS_MMX_REG_RANGE => {
                let (first, count) = range(operand()?, 0);
                PopWmmx { first, count }
            }
            UNWIND_OPCODE_POP_WIRELESS_MMX_REG_MASK => match operand()? {
                mask @ 0x01..=0x0f => PopWmmxControl { mask },
                operand => Spare {
                    opcode: op,
                    operand: Some(operand),
                },
            },
            UNWIND_OPCODE_POP_VFP_REG_RANGE_VPUSH_D16 => {
                let (first, count) = range(operand()?, 16);
                PopVfpVpush { first, count }
            }
            UNWIND_OPCODE_POP_VFP_REG_RANGE_VPUSH => {
                let (first, count) = range(operand()?, 0);
                PopVfpVpush { first, count }
            }
            UNWIND_OPCODE_POP_VFP_REG_RANGE_VPUSH_D8..=0xd7 => PopVfpVpushD8 { count },
            0xca..=0xcf | 0xd8..=0xff => spare,
        };
        Ok(Some(instruction))
    }
}

/// Write the registers whose bits are set in `mask` as `{a, b, ...}`.
fn write_register_list(
    f: &mut fmt::Formatter<'_>,
    mask: u16,
    name: impl Fn(&mut fmt::Formatter<'_>, u32) -> fmt::Result,
) -> fmt::Result {
    f.write_str("{")?;
    let mut first = true;
    for reg in (0..16).filter(|reg| mask & (1 << reg) != 0) {
        if !first {
            f.write_str(", ")?;
        }
        first = false;
        name(f, reg)?;
    }
    f.write_str("}")
}

fn write_core_register(f: &mut fmt::Formatter<'_>, reg: u32) -> fmt::Result {
    match reg {
        13 => f.write_str("sp"),
        14 => f.write_str("lr"),
        15 => f.write_str("pc"),
        _ => write!(f, "r{reg}"),
    }
}

struct RegisterRange(&'static str, u8, u8);

impl fmt::Display for RegisterRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let RegisterRange(prefix, first, count) = *self;
        if count <= 1 {
            write!(f, "{{{prefix}{first}}}")
        } else {
            let last = u32::from(first) + u32::from(count) - 1;
            write!(f, "{{{prefix}{first}-{prefix}{last}}}")
        }
    }
}

impl fmt::Display for UnwindInstruction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use UnwindInstruction::*;
        match *self {
            IncrementVsp(bytes) => write!(f, "vsp = vsp + {bytes}"),
            DecrementVsp(bytes) => write!(f, "vsp = vsp - {bytes}"),
            IncrementVspLarge(bytes) => write!(f, "vsp = vsp + {bytes}"),
            RefuseToUnwind => f.write_str("refuse to unwind"),
            PopCore { mask } => {
                f.write_str("pop ")?;
                write_register_list(f, mask, write_core_register)
            }
            PopCoreRange { last, lr } => match self.popped_core_registers() {
                Some(mask) => {
                    f.write_str("pop ")?;
                    write_register_list(f, mask, write_core_register)
                }
                None => {
                    let lr = if lr { ", lr" } else { "" };
                    write!(f, "pop {{r4-r{last}{lr}}} (invalid range)")
                }
            },
            SetVsp(reg) => write!(f, "vsp = r{reg}"),
            Finish => f.write_str("finish"),
            PopVfpFstmx { first, count } => {
                write!(f, "pop {} (fstmx)", RegisterRange("d", first, count))
            }
            PopVfpFstmxD8 { count } => write!(f, "pop {} (fstmx)", RegisterRange("d", 8, count)),
            PopVfpVpush { first, count } => write!(f, "pop {}", RegisterRange("d", first, count)),
            PopVfpVpushD8 { count } => write!(f, "pop {}", RegisterRange("d", 8, count)),
            PopRaAuthCode => f.write_str("pop {ra_auth_code}"),
            UseVspAsRaAuthModifier => f.write_str("use vsp as modifier for ra_auth_code"),
            PopWmmxWr10 { count } => write!(f, "pop {}", RegisterRange("wR", 10, count)),
            PopWmmx { first, count } => write!(f, "pop {}", RegisterRange("wR", first, count)),
            PopWmmxControl { mask } => {
                f.write_str("pop ")?;
                write_register_list(f, u16::from(mask), |f, reg| write!(f, "wCGR{reg}"))
            }
            Spare {
                opcode,
                operand: None,
            } => write!(f, "spare 0x{opcode:02x}"),
            Spare {
                opcode,
                operand: Some(operand),
            } => write!(f, "spare 0x{opcode:02x} 0x{operand:02x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::string::ToString;

    #[test]
    fn test_display() {
        use UnwindInstruction::*;
        assert_eq!(IncrementVsp(16).to_string(), "vsp = vsp + 16");
        assert_eq!(
            PopCore {
                mask: (1 << 4) | (1 << 11) | (1 << 14)
            }
            .to_string(),
            "pop {r4, r11, lr}"
        );
        assert_eq!(
            PopCoreRange { last: 7, lr: true }.to_string(),
            "pop {r4, r5, r6, r7, lr}"
        );
        assert_eq!(
            PopVfpVpush {
                first: 16,
                count: 4
            }
            .to_string(),
            "pop {d16-d19}"
        );
        assert_eq!(PopVfpFstmxD8 { count: 1 }.to_string(), "pop {d8} (fstmx)");
        assert_eq!(
            PopWmmxControl { mask: 0b101 }.to_string(),
            "pop {wCGR0, wCGR2}"
        );
    }

    #[test]
    fn test_display_out_of_range() {
        use UnwindInstruction::*;
        // Hand-built instructions with out-of-range fields must not panic.
        assert_eq!(
            PopCoreRange { last: 2, lr: false }.popped_core_registers(),
            None
        );
        assert_eq!(
            PopCoreRange {
                last: 255,
                lr: true
            }
            .to_string(),
            "pop {r4-r255, lr} (invalid range)"
        );
        assert_eq!(
            PopVfpVpush {
                first: 255,
                count: 255
            }
            .to_string(),
            "pop {d255-d509}"
        );
    }
}
