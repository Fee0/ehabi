//! Constant definitions from the EHABI and the Arm ELF specification.
//!
//! The opcode constants are the first byte of each unwinding instruction
//! (EHABI32, "Frame unwinding instructions"). Where an instruction carries an
//! operand in its low bits, the constant has those bits clear.

/// ELF section type of `.ARM.exidx` sections.
pub const SHT_ARM_EXIDX: u32 = 0x7000_0001;

/// No relocation; used to record a dependency on a personality routine.
pub const R_ARM_NONE: u32 = 0;
/// 32-bit absolute relocation.
pub const R_ARM_ABS32: u32 = 2;
/// Platform-specific reference to a `type_info` object.
pub const R_ARM_TARGET2: u32 = 41;
/// 31-bit place-relative offset; bit 31 of the place is preserved.
pub const R_ARM_PREL31: u32 = 42;

/// The second word of an index table entry for a function that cannot be unwound.
pub const EXIDX_CANTUNWIND: u32 = 0x1;

/// Bit 31 of the first word of an exception-handling table entry selects the
/// Arm-defined compact model.
pub const EHT_COMPACT_MODEL: u32 = 0x8000_0000;

/// Catch type that matches any exception, as in `catch(...)`.
pub const CATCH_ANY: u32 = 0xffff_ffff;
/// Catch type that matches any exception and makes the personality routine
/// return `_URC_FAILURE`, preventing propagation out of the scope.
pub const CATCH_ANY_AND_FAIL: u32 = 0xffff_fffe;

/// `00xxxxxx`: `vsp = vsp + (xxxxxx << 2) + 4`.
pub const UNWIND_OPCODE_INC_VSP: u8 = 0x00;
/// `01xxxxxx`: `vsp = vsp - (xxxxxx << 2) - 4`.
pub const UNWIND_OPCODE_DEC_VSP: u8 = 0x40;
/// `1000iiii iiiiiiii`: pop integer registers under mask {r15-r12}, {r11-r4}.
/// With a zero mask this is "refuse to unwind".
pub const UNWIND_OPCODE_POP_REG_MASK_R4: u8 = 0x80;
/// `1001nnnn`: `vsp = r[nnnn]`.
pub const UNWIND_OPCODE_SET_VSP: u8 = 0x90;
/// `10011101`: reserved as prefix for Arm register to register moves.
pub const UNWIND_OPCODE_RESERVED_ARM_MOVE: u8 = 0x9d;
/// `10011111`: reserved as prefix for Intel Wireless MMX register to register moves.
pub const UNWIND_OPCODE_RESERVED_WMMX_MOVE: u8 = 0x9f;
/// `10100nnn`: pop `r4-r[4+nnn]`.
pub const UNWIND_OPCODE_POP_REG_RANGE_R4: u8 = 0xa0;
/// `10101nnn`: pop `r4-r[4+nnn]`, r14.
pub const UNWIND_OPCODE_POP_REG_RANGE_R4_R14: u8 = 0xa8;
/// `10110000`: finish.
pub const UNWIND_OPCODE_FINISH: u8 = 0xb0;
/// `10110001 0000iiii`: pop integer registers under mask {r3, r2, r1, r0}.
pub const UNWIND_OPCODE_POP_REG_MASK: u8 = 0xb1;
/// `10110010 uleb128`: `vsp = vsp + 0x204 + (uleb128 << 2)`.
pub const UNWIND_OPCODE_INC_VSP_ULEB128: u8 = 0xb2;
/// `10110011 sssscccc`: pop VFP `D[ssss]-D[ssss+cccc]` saved by FSTMFDX.
pub const UNWIND_OPCODE_POP_VFP_REG_RANGE_FSTMFDX: u8 = 0xb3;
/// `10110100`: pop the Return Address Authentication Code pseudo-register.
pub const UNWIND_OPCODE_POP_RA_AUTH_CODE: u8 = 0xb4;
/// `10110101`: use the current vsp as modifier in Return Address Authentication.
pub const UNWIND_OPCODE_RA_AUTH_MODIFIER_VSP: u8 = 0xb5;
/// `10111nnn`: pop VFP `D[8]-D[8+nnn]` saved by FSTMFDX.
pub const UNWIND_OPCODE_POP_VFP_REG_RANGE_FSTMFDX_D8: u8 = 0xb8;
/// `11000nnn` (nnn != 6, 7): pop Intel Wireless MMX `wR[10]-wR[10+nnn]`.
pub const UNWIND_OPCODE_POP_WIRELESS_MMX_REG_RANGE_WR10: u8 = 0xc0;
/// `11000110 sssscccc`: pop Intel Wireless MMX `wR[ssss]-wR[ssss+cccc]`.
pub const UNWIND_OPCODE_POP_WIRELESS_MMX_REG_RANGE: u8 = 0xc6;
/// `11000111 0000iiii`: pop Intel Wireless MMX wCGR registers under mask {wCGR3-0}.
pub const UNWIND_OPCODE_POP_WIRELESS_MMX_REG_MASK: u8 = 0xc7;
/// `11001000 sssscccc`: pop VFP `D[16+ssss]-D[16+ssss+cccc]` saved by VPUSH.
pub const UNWIND_OPCODE_POP_VFP_REG_RANGE_VPUSH_D16: u8 = 0xc8;
/// `11001001 sssscccc`: pop VFP `D[ssss]-D[ssss+cccc]` saved by VPUSH.
pub const UNWIND_OPCODE_POP_VFP_REG_RANGE_VPUSH: u8 = 0xc9;
/// `11010nnn`: pop VFP `D[8]-D[8+nnn]` saved by VPUSH.
pub const UNWIND_OPCODE_POP_VFP_REG_RANGE_VPUSH_D8: u8 = 0xd0;
