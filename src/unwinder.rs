//! Unwind stack frames using the `.ARM.exidx` and `.ARM.extab` sections.
//!
//! This is a *virtual* unwinder: given the registers of a frame and a way to
//! read the stack, it computes the registers of the caller without running
//! any code in the target. It suits debuggers, profilers and crash-dump
//! analysis, where the stack belongs to another process, a core file or a
//! halted microcontroller.
//!
//! * [`execute`] runs a sequence of [`UnwindInstruction`]s against a
//!   [`Registers`] set, reading saved registers through [`Memory`].
//! * [`Module`] holds the tables of one image and unwinds one frame at a
//!   time: it finds the index entry for the program counter, resolves it and
//!   executes its instructions.
//!
//! Instructions are executed as specified by the EHABI and as libgcc's
//! `__gnu_unwind_execute` does. Generic-model entries are assumed to use the
//! GCC/LLVM layout, which every common personality routine uses.
//!
//! ## Example
//!
//! ```rust
//! use ehabi::read::{ExIdx, ExTab};
//! use ehabi::unwinder::{Module, Registers};
//! use ehabi::{BaseAddresses, LittleEndian};
//!
//! # fn main() -> ehabi::unwinder::Result<()> {
//! // `.ARM.exidx` at 0x4 with one entry: the function at 0x1000 has the
//! // inline compact entry 0x80a8b0b0, `pop {r4, lr}; finish`.
//! let exidx_data = [0xfc, 0x0f, 0x00, 0x00, 0xb0, 0xb0, 0xa8, 0x80];
//! let module = Module::new(
//!     ExIdx::new(&exidx_data, LittleEndian),
//!     ExTab::new(&[], LittleEndian),
//!     BaseAddresses::default().set_exidx(0x4).set_extab(0x0),
//! );
//!
//! // The frame is stopped at 0x1010, after saving r4 and lr at 0x8000.
//! let mut regs = Registers::new();
//! regs.set_core(Registers::PC, 0x1010);
//! regs.set_core(Registers::SP, 0x8000);
//! let mut memory = |address| match address {
//!     0x8000 => Some(0x4444),     // r4
//!     0x8004 => Some(0x2000_0101), // lr
//!     _ => None,
//! };
//!
//! let caller = module.unwind_frame(&regs, true, &mut memory)?;
//! assert_eq!(caller.pc(), Some(0x2000_0101));
//! assert_eq!(caller.sp(), Some(0x8008));
//! assert_eq!(caller.core(4), Some(0x4444));
//! # Ok(())
//! # }
//! ```

use crate::common::BaseAddresses;
use crate::endianity::Endianity;
use crate::read::{self, ExIdx, ExTab, Reader, Section, UnwindEntry};
use crate::unwind::UnwindInstruction;

mod error;
pub use self::error::*;

mod registers;
pub use self::registers::*;

/// Read access to the memory of the target, usually its stack.
///
/// It is implemented for closures `FnMut(u32) -> Option<u32>`.
pub trait Memory {
    /// Read the word at `address`, as the target would load it with `LDR`
    /// (that is, in the target's byte order).
    ///
    /// Returns `None` if the memory cannot be read.
    fn read_u32(&mut self, address: u32) -> Option<u32>;
}

impl<F: FnMut(u32) -> Option<u32>> Memory for F {
    #[inline]
    fn read_u32(&mut self, address: u32) -> Option<u32> {
        self(address)
    }
}

/// Execute frame unwinding instructions, turning the registers of a frame
/// into those of its caller.
///
/// vsp starts at the stack pointer in `regs`. When the instructions finish
/// (with an explicit *Finish* or at the end of the sequence), the stack
/// pointer is set to vsp and, unless an instruction popped r15, the link
/// register is copied to r15. `endian` gives the order in which the two
/// words of a VFP register are stored.
///
/// Registers popped by iWMMXt instructions are skipped over but not
/// tracked.
///
/// # Errors
///
/// Returns [`Error::MissingRegister`] if the stack pointer, or the source of a
/// `vsp = r[n]` instruction, is unknown; [`Error::MemoryRead`] if a saved
/// register cannot be read; [`Error::RefuseToUnwind`];
/// [`Error::ReservedInstruction`] for spare and reserved encodings; and
/// [`Error::Read`] for errors from `instructions`. On error, `regs` may be
/// partially updated.
pub fn execute<I, M, E>(
    instructions: I,
    regs: &mut Registers,
    memory: &mut M,
    endian: E,
) -> Result<()>
where
    I: IntoIterator<Item = read::Result<UnwindInstruction>>,
    M: Memory + ?Sized,
    E: Endianity,
{
    let mut machine = Machine {
        vsp: regs.sp().ok_or(Error::MissingRegister(Registers::SP))?,
        set_pc: false,
        ra_auth_code: None,
        ra_auth_modifier: None,
        regs,
        memory,
        big_endian: endian.is_big_endian(),
    };
    for instruction in instructions {
        let instruction = instruction?;
        if instruction == UnwindInstruction::Finish {
            break;
        }
        machine.step(instruction)?;
    }
    machine.finish();
    Ok(())
}

/// The state of [`execute`].
struct Machine<'a, M: ?Sized> {
    vsp: u32,
    set_pc: bool,
    ra_auth_code: Option<u32>,
    ra_auth_modifier: Option<u32>,
    regs: &'a mut Registers,
    memory: &'a mut M,
    big_endian: bool,
}

impl<M: Memory + ?Sized> Machine<'_, M> {
    fn step(&mut self, instruction: UnwindInstruction) -> Result<()> {
        use UnwindInstruction::*;

        let reserved = || Error::ReservedInstruction(instruction);
        match instruction {
            IncrementVsp(bytes) => self.vsp = self.vsp.wrapping_add(bytes),
            // The arithmetic is modulo 2^32, as on the target.
            IncrementVspLarge(bytes) => self.vsp = self.vsp.wrapping_add(bytes as u32),
            DecrementVsp(bytes) => self.vsp = self.vsp.wrapping_sub(bytes),
            RefuseToUnwind => return Err(Error::RefuseToUnwind),
            PopCore { .. } | PopCoreRange { .. } => {
                let mask = instruction.popped_core_registers().ok_or_else(reserved)?;
                self.pop_core(mask)?;
            }
            SetVsp(n) if n != Registers::SP && n < Registers::PC => {
                self.vsp = self.regs.core(n).ok_or(Error::MissingRegister(n))?;
            }
            Finish => {}
            // FSTMX saves D0-D15 only, with a format word after them.
            PopVfpFstmx { first, count } if fits(first, count, 16) => {
                self.pop_fstmx(first, count)?;
            }
            PopVfpFstmxD8 { count } if fits(8, count, 16) => self.pop_fstmx(8, count)?,
            PopVfpVpush { first, count } if fits(first, count, 32) => self.pop_vfp(first, count)?,
            PopVfpVpushD8 { count } if fits(8, count, 32) => self.pop_vfp(8, count)?,
            PopRaAuthCode => {
                self.ra_auth_code = Some(self.read(self.vsp)?);
                self.vsp = self.vsp.wrapping_add(4);
            }
            UseVspAsRaAuthModifier => self.ra_auth_modifier = Some(self.vsp),
            // iWMMXt registers are skipped over, not tracked.
            PopWmmxWr10 { count } if fits(10, count, 16) => {
                self.vsp = self.vsp.wrapping_add(8 * u32::from(count));
            }
            PopWmmx { first, count } if fits(first, count, 16) => {
                self.vsp = self.vsp.wrapping_add(8 * u32::from(count));
            }
            PopWmmxControl { mask } if (1..=0xf).contains(&mask) => {
                self.vsp = self.vsp.wrapping_add(4 * mask.count_ones());
            }
            // Registers beyond the architecture are reserved.
            SetVsp(_)
            | PopVfpFstmx { .. }
            | PopVfpFstmxD8 { .. }
            | PopVfpVpush { .. }
            | PopVfpVpushD8 { .. }
            | PopWmmxWr10 { .. }
            | PopWmmx { .. }
            | PopWmmxControl { .. }
            | Spare { .. } => return Err(reserved()),
        }
        Ok(())
    }

    fn read(&mut self, address: u32) -> Result<u32> {
        self.memory
            .read_u32(address)
            .ok_or(Error::MemoryRead(address))
    }

    /// Pop the core registers in `mask`, lowest numbered at the lowest
    /// address. A popped r13 replaces vsp after the whole pop.
    fn pop_core(&mut self, mask: u16) -> Result<()> {
        let mut address = self.vsp;
        let mut sp = None;
        for n in (0..16u8).filter(|n| mask & (1 << n) != 0) {
            let value = self.read(address)?;
            address = address.wrapping_add(4);
            if n == Registers::SP {
                sp = Some(value);
            } else {
                self.regs.set_core(n, value);
            }
        }
        if mask & (1 << Registers::PC) != 0 {
            self.set_pc = true;
        }
        self.vsp = sp.unwrap_or(address);
        Ok(())
    }

    /// Pop `D[first]..D[first + count - 1]`, lowest numbered at the lowest
    /// address.
    fn pop_vfp(&mut self, first: u8, count: u8) -> Result<()> {
        for n in first..first + count {
            let first_word = self.read(self.vsp)?;
            let second_word = self.read(self.vsp.wrapping_add(4))?;
            // The high word is stored first on big-endian targets.
            let (high, low) = if self.big_endian {
                (first_word, second_word)
            } else {
                (second_word, first_word)
            };
            self.regs
                .set_vfp(n, (u64::from(high) << 32) | u64::from(low));
            self.vsp = self.vsp.wrapping_add(8);
        }
        Ok(())
    }

    /// Pop `D[first]..D[first + count - 1]` saved by FSTMX, which stores a
    /// format word after the registers.
    fn pop_fstmx(&mut self, first: u8, count: u8) -> Result<()> {
        self.pop_vfp(first, count)?;
        self.vsp = self.vsp.wrapping_add(4);
        Ok(())
    }

    fn finish(self) {
        if !self.set_pc {
            match self.regs.lr() {
                Some(lr) => self.regs.set_core(Registers::PC, lr),
                None => self.regs.clear_core(Registers::PC),
            }
        }
        self.regs.set_core(Registers::SP, self.vsp);
        let modifier = self
            .ra_auth_code
            .map(|_| self.ra_auth_modifier.unwrap_or(self.vsp));
        self.regs.set_ra_auth(self.ra_auth_code, modifier);
    }
}

/// Return true if registers `first..first + count` are below `limit`.
fn fits(first: u8, count: u8, limit: u32) -> bool {
    u32::from(first) + u32::from(count) <= limit
}

/// The unwinding tables of one loaded image.
///
/// `bases` must give the addresses at which the sections are loaded, in the
/// same address space as the program counters that are unwound.
#[derive(Debug, Clone, Copy)]
pub struct Module<R: Reader> {
    exidx: ExIdx<R>,
    extab: ExTab<R>,
    bases: BaseAddresses,
}

impl<R: Reader> Module<R> {
    /// Create a module from its sections and their addresses.
    pub fn new(exidx: ExIdx<R>, extab: ExTab<R>, bases: BaseAddresses) -> Self {
        Module {
            exidx,
            extab,
            bases,
        }
    }

    /// Return the `.ARM.exidx` section.
    #[inline]
    pub fn exidx(&self) -> &ExIdx<R> {
        &self.exidx
    }

    /// Return the `.ARM.extab` section.
    #[inline]
    pub fn extab(&self) -> &ExTab<R> {
        &self.extab
    }

    /// Return the section addresses.
    #[inline]
    pub fn bases(&self) -> &BaseAddresses {
        &self.bases
    }

    /// Unwind one frame, returning the registers of the caller.
    ///
    /// `is_first_frame` is true for the frame in which execution stopped,
    /// whose program counter is the address of the next instruction to
    /// execute. For every other frame the program counter is a return
    /// address, which may lie just past the end of the calling function, so
    /// the entry is looked up for the address before it. Bit 0 (the Thumb
    /// bit) of the program counter is ignored for the lookup.
    ///
    /// The result is not checked for progress; a caller walking the stack
    /// should stop when the stack pointer does not increase.
    ///
    /// # Errors
    ///
    /// Returns [`Error::MissingRegister`] if the program counter is unknown,
    /// [`Error::NoUnwindInfo`] if no index entry covers it,
    /// [`Error::CantUnwind`] for an `EXIDX_CANTUNWIND` entry, [`Error::Read`]
    /// if the entry cannot be parsed, and the errors of [`execute`].
    pub fn unwind_frame<M: Memory + ?Sized>(
        &self,
        regs: &Registers,
        is_first_frame: bool,
        memory: &mut M,
    ) -> Result<Registers> {
        let pc = regs.pc().ok_or(Error::MissingRegister(Registers::PC))?;
        let address = if is_first_frame {
            pc & !1
        } else {
            (pc & !1).wrapping_sub(1)
        };
        let entry = self
            .exidx
            .find(address, &self.bases)?
            .ok_or(Error::NoUnwindInfo(pc))?;
        let instructions = match entry.resolve(&self.extab, &self.bases)? {
            UnwindEntry::CantUnwind => return Err(Error::CantUnwind),
            UnwindEntry::Compact(entry) => entry.instructions()?,
            UnwindEntry::Generic(entry) => entry.gnu_instructions()?,
        };
        let mut caller = regs.clone();
        execute(
            instructions,
            &mut caller,
            memory,
            self.exidx.reader().endian(),
        )?;
        Ok(caller)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endianity::{BigEndian, LittleEndian};
    use crate::test_util::words_le;
    use UnwindInstruction::*;

    /// Memory holding `words` from `base` upwards.
    fn stack(base: u32, words: &[u32]) -> impl FnMut(u32) -> Option<u32> + '_ {
        move |address| {
            let index = address.checked_sub(base)? / 4;
            if address % 4 != 0 {
                return None;
            }
            words.get(index as usize).copied()
        }
    }

    fn run(
        instructions: &[UnwindInstruction],
        regs: &mut Registers,
        memory: &mut impl Memory,
    ) -> Result<()> {
        execute(
            instructions.iter().copied().map(Ok),
            regs,
            memory,
            LittleEndian,
        )
    }

    fn frame(sp: u32, lr: u32) -> Registers {
        let mut regs = Registers::new();
        regs.set_core(Registers::SP, sp);
        regs.set_core(Registers::LR, lr);
        regs.set_core(Registers::PC, 0x1234);
        regs
    }

    #[test]
    fn test_pop_and_finish() {
        let mut regs = frame(0x1000, 0xdead);
        let mut memory = stack(0x1000, &[0, 0, 0x44, 0x55, 0x2001]);
        run(
            &[IncrementVsp(8), PopCoreRange { last: 5, lr: true }, Finish],
            &mut regs,
            &mut memory,
        )
        .unwrap();
        assert_eq!(regs.core(4), Some(0x44));
        assert_eq!(regs.core(5), Some(0x55));
        assert_eq!(regs.lr(), Some(0x2001));
        // Finish copies lr to pc.
        assert_eq!(regs.pc(), Some(0x2001));
        assert_eq!(regs.sp(), Some(0x1014));
        assert_eq!(regs.ra_auth_code(), None);
    }

    #[test]
    fn test_implicit_finish_and_leaf() {
        // A leaf function with no instructions returns to lr.
        let mut regs = frame(0x1000, 0x3000);
        run(&[], &mut regs, &mut stack(0, &[])).unwrap();
        assert_eq!(regs.pc(), Some(0x3000));
        assert_eq!(regs.sp(), Some(0x1000));
    }

    #[test]
    fn test_pop_pc() {
        // pop {r4, pc}: Finish must not overwrite the popped pc.
        let mut regs = frame(0x1000, 0xdead);
        run(
            &[PopCore { mask: 0x8010 }],
            &mut regs,
            &mut stack(0x1000, &[0x44, 0x4001]),
        )
        .unwrap();
        assert_eq!(regs.pc(), Some(0x4001));
        assert_eq!(regs.lr(), Some(0xdead));
        assert_eq!(regs.sp(), Some(0x1008));
    }

    #[test]
    fn test_pop_sp() {
        // pop {r12, sp, lr}: the loaded sp replaces vsp after the whole
        // pop, so lr is still read from the original stack.
        let mut regs = frame(0x1000, 0);
        run(
            &[PopCore { mask: 0x7000 }],
            &mut regs,
            &mut stack(0x1000, &[0xcc, 0x9000, 0x5001]),
        )
        .unwrap();
        assert_eq!(regs.core(12), Some(0xcc));
        assert_eq!(regs.lr(), Some(0x5001));
        assert_eq!(regs.sp(), Some(0x9000));
    }

    #[test]
    fn test_set_vsp() {
        // A frame-pointer frame: vsp = r11; vsp -= 4; pop {r11, lr}.
        let mut regs = frame(0x1000, 0);
        regs.set_core(11, 0x1104);
        run(
            &[SetVsp(11), DecrementVsp(4), PopCore { mask: 0x4800 }],
            &mut regs,
            &mut stack(0x1100, &[0x2000, 0x6001]),
        )
        .unwrap();
        assert_eq!(regs.core(11), Some(0x2000));
        assert_eq!(regs.pc(), Some(0x6001));
        assert_eq!(regs.sp(), Some(0x1108));

        let mut regs = frame(0x1000, 0);
        assert_eq!(
            run(&[SetVsp(7)], &mut regs, &mut stack(0, &[])),
            Err(Error::MissingRegister(7))
        );
    }

    #[test]
    fn test_vfp() {
        let words = [0x1111_1111, 0x2222_2222, 0x3333_3333, 0x4444_4444, 0];
        let mut regs = frame(0x1000, 0);
        run(
            &[PopVfpVpushD8 { count: 2 }],
            &mut regs,
            &mut stack(0x1000, &words),
        )
        .unwrap();
        assert_eq!(regs.vfp(8), Some(0x2222_2222_1111_1111));
        assert_eq!(regs.vfp(9), Some(0x4444_4444_3333_3333));
        assert_eq!(regs.sp(), Some(0x1010));

        // FSTMX has an extra format word; big-endian stores the high word
        // first.
        let mut regs = frame(0x1000, 0);
        execute(
            [Ok(PopVfpFstmx { first: 0, count: 2 })],
            &mut regs,
            &mut stack(0x1000, &words),
            BigEndian,
        )
        .unwrap();
        assert_eq!(regs.vfp(0), Some(0x1111_1111_2222_2222));
        assert_eq!(regs.vfp(1), Some(0x3333_3333_4444_4444));
        assert_eq!(regs.sp(), Some(0x1014));
    }

    #[test]
    fn test_ra_auth_code() {
        // pop {ra_auth_code}; use vsp as modifier; pop {r4}.
        let mut regs = frame(0x1000, 0x7001);
        run(
            &[
                PopRaAuthCode,
                UseVspAsRaAuthModifier,
                PopCore { mask: 0x0010 },
            ],
            &mut regs,
            &mut stack(0x1000, &[0xaaaa, 0x44]),
        )
        .unwrap();
        assert_eq!(regs.ra_auth_code(), Some(0xaaaa));
        assert_eq!(regs.ra_auth_modifier(), Some(0x1004));

        // Without 0xb5, the modifier is the CFA.
        let mut regs = frame(0x1000, 0x7001);
        run(
            &[PopRaAuthCode, IncrementVsp(8)],
            &mut regs,
            &mut stack(0x1000, &[0xaaaa]),
        )
        .unwrap();
        assert_eq!(regs.ra_auth_modifier(), Some(0x100c));
    }

    #[test]
    fn test_wmmx() {
        let mut regs = frame(0x1000, 0);
        run(
            &[PopWmmxWr10 { count: 2 }, PopWmmxControl { mask: 0b1011 }],
            &mut regs,
            &mut stack(0, &[]),
        )
        .unwrap();
        assert_eq!(regs.sp(), Some(0x1000 + 16 + 12));
    }

    #[test]
    fn test_errors() {
        let mut memory = stack(0x1000, &[0x44]);
        let mut regs = frame(0x1000, 0);
        assert_eq!(
            run(&[RefuseToUnwind], &mut regs, &mut memory),
            Err(Error::RefuseToUnwind)
        );
        let spare = Spare {
            opcode: 0xb6,
            operand: None,
        };
        assert_eq!(
            run(&[spare], &mut regs, &mut memory),
            Err(Error::ReservedInstruction(spare))
        );
        let beyond_d15 = PopVfpFstmx {
            first: 12,
            count: 5,
        };
        assert_eq!(
            run(&[beyond_d15], &mut regs, &mut memory),
            Err(Error::ReservedInstruction(beyond_d15))
        );
        let mut regs = frame(0x1000, 0);
        assert_eq!(
            run(&[PopCore { mask: 0x30 }], &mut regs, &mut memory),
            Err(Error::MemoryRead(0x1004))
        );
        let mut regs = Registers::new();
        assert_eq!(
            run(&[], &mut regs, &mut memory),
            Err(Error::MissingRegister(Registers::SP))
        );
        // Instructions after Finish are not executed.
        let mut regs = frame(0x1000, 0);
        run(&[Finish, RefuseToUnwind], &mut regs, &mut memory).unwrap();
    }

    #[test]
    fn test_module() {
        // `.ARM.exidx` at 0x2000: f at 0x1000 with `pop {r4, lr}` inline,
        // g at 0x1100 referring to `.ARM.extab` (at 0x3000), and an
        // EXIDX_CANTUNWIND terminator at 0x1200.
        let exidx_data = words_le(&[
            0x7fff_f000,
            0x80a8_b0b0,
            0x7fff_f0f8,
            0x0000_0ff4,
            0x7fff_f1f0,
            0x0000_0001,
        ]);
        // g: generic entry in the GCC layout, `vsp += 4; pop {r4-r5, lr}`.
        let extab_data = words_le(&[0x7fff_f000, 0x0000_a9b0]);
        let module = Module::new(
            ExIdx::new(&exidx_data, LittleEndian),
            ExTab::new(&extab_data, LittleEndian),
            BaseAddresses::default().set_exidx(0x2000).set_extab(0x3000),
        );
        // The stack: g's frame at 0x8000 (4 bytes of locals, r4, r5, lr into
        // f), then f's frame (r4, lr into its caller at 0x1300).
        let words = [0, 0x4, 0x5, 0x1081, 0x44, 0x1301];
        let mut memory = stack(0x8000, &words);

        let mut regs = Registers::new();
        regs.set_core(Registers::PC, 0x1110);
        regs.set_core(Registers::SP, 0x8000);
        let f = module.unwind_frame(&regs, true, &mut memory).unwrap();
        assert_eq!(f.pc(), Some(0x1081));
        assert_eq!(f.sp(), Some(0x8010));
        assert_eq!((f.core(4), f.core(5)), (Some(0x4), Some(0x5)));

        let caller = module.unwind_frame(&f, false, &mut memory).unwrap();
        assert_eq!(caller.pc(), Some(0x1301));
        assert_eq!(caller.sp(), Some(0x8018));
        assert_eq!(caller.core(4), Some(0x44));

        // The caller is covered by the EXIDX_CANTUNWIND entry.
        assert_eq!(
            module.unwind_frame(&caller, false, &mut memory),
            Err(Error::CantUnwind)
        );

        // A return address just past the end of f is looked up in f.
        let mut at_end = f.clone();
        at_end.set_core(Registers::PC, 0x1101);
        let caller = module.unwind_frame(&at_end, false, &mut memory).unwrap();
        assert_eq!(caller.pc(), Some(0x1301));
        // As the first frame, the same address is in g.
        let mut at_start = regs.clone();
        at_start.set_core(Registers::PC, 0x1100);
        let f = module.unwind_frame(&at_start, true, &mut memory).unwrap();
        assert_eq!(f.pc(), Some(0x1081));

        let mut before = Registers::new();
        before.set_core(Registers::PC, 0x0ff0);
        assert_eq!(
            module.unwind_frame(&before, true, &mut memory),
            Err(Error::NoUnwindInfo(0x0ff0))
        );
    }
}
