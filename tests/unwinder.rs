//! The unwinder against simulated call stacks.
//!
//! Each case builds a table of functions with random prologues, writes it
//! with the `write` module, then simulates a chain of calls into those
//! functions: every prologue saves registers on a simulated stack exactly as
//! the instructions describe, and every function then clobbers the registers
//! it saved. Unwinding the stack from the innermost frame must restore the
//! registers of each caller, and stop at the `EXIDX_CANTUNWIND` entry of
//! the outermost one.
//!
//! Set `EHABI_UNWINDER_ITERATIONS` to run longer than the default.

use std::collections::HashMap;

use ehabi::read::{ExIdx, ExTab};
use ehabi::unwinder::{Error, Module, Registers};
use ehabi::write::{
    Address, CompactEntry, EndianVec, ExTabEntry, GenericData, GenericEntry, IndexEntry,
    IndexEntryData, Sections, UnwindTable,
};
use ehabi::{BaseAddresses, PersonalityIndex, RunTimeEndian, UnwindInstruction};

mod rng;
use rng::{Rng, iterations};

const SP: usize = Registers::SP as usize;
const LR: usize = Registers::LR as usize;
const PC: usize = Registers::PC as usize;

const FUNCTION_SIZE: u32 = 0x100;
const TEXT: u32 = 0x1_0000;
const EXIDX: u32 = 0x4_0000;
const EXTAB: u32 = 0x5_0000;

/// One step of a prologue, in execution order.
#[derive(Debug, Clone, Copy)]
enum Step {
    /// `push {mask}`, never including sp or pc.
    Push(u16),
    /// `vpush {d[first]-d[first + count - 1]}`.
    Vpush { first: u8, count: u8 },
    /// `fstmfdx sp!, {d[first]-d[first + count - 1]}`.
    Fstmx { first: u8, count: u8 },
    /// `sub sp, sp, #bytes`.
    Sub(u32),
}

#[derive(Debug)]
struct Function {
    prologue: Vec<Step>,
}

impl Function {
    fn random(rng: &mut Rng, leaf: bool) -> Self {
        let mut prologue = Vec::new();
        let mut saves_lr = false;
        for _ in 0..rng.below(4) {
            prologue.push(match rng.below(4) {
                0 => {
                    let mask = (rng.next() as u16 & 0x5fff) | 1 << (4 + rng.below(8));
                    saves_lr |= mask & (1 << 14) != 0;
                    Step::Push(mask)
                }
                1 => {
                    let first = rng.below(32) as u8;
                    let count = 1 + rng.below(u64::from(16.min(32 - first))) as u8;
                    Step::Vpush { first, count }
                }
                2 => {
                    let first = rng.below(16) as u8;
                    let count = 1 + rng.below(u64::from(16 - first)) as u8;
                    Step::Fstmx { first, count }
                }
                _ => {
                    let max = if rng.chance(10) { 0x4000 } else { 0x200 };
                    Step::Sub(4 * (1 + rng.below(max) as u32))
                }
            });
        }
        // A function that calls another must save the return address.
        if !leaf && !saves_lr {
            prologue.insert(0, Step::Push(1 << 14 | 1 << 4));
        }
        Function { prologue }
    }

    /// The VFP registers that the prologue saves.
    fn saved_vfp(&self) -> Vec<u8> {
        self.prologue
            .iter()
            .flat_map(|step| match *step {
                Step::Vpush { first, count } | Step::Fstmx { first, count } => first..first + count,
                _ => 0..0,
            })
            .collect()
    }

    /// The unwinding instructions, which undo the prologue in reverse.
    fn instructions(&self) -> Vec<UnwindInstruction> {
        let mut out = Vec::new();
        for step in self.prologue.iter().rev() {
            match *step {
                Step::Push(mask) => out.extend(UnwindInstruction::pop_core(mask)),
                Step::Vpush { first, count } => {
                    out.extend(UnwindInstruction::pop_vfp(first, count).unwrap());
                }
                Step::Fstmx { first: 8, count } if count <= 8 => {
                    out.push(UnwindInstruction::PopVfpFstmxD8 { count });
                }
                Step::Fstmx { first, count } => {
                    out.push(UnwindInstruction::PopVfpFstmx { first, count });
                }
                Step::Sub(bytes) => {
                    out.extend(UnwindInstruction::vsp_add(u64::from(bytes)).unwrap());
                }
            }
        }
        out
    }
}

/// Add an index entry for a function, in a randomly chosen representation.
fn add_entry(rng: &mut Rng, table: &mut UnwindTable, address: u32, function: &Function) {
    let instructions = function.instructions();
    let compact = |personality| CompactEntry {
        personality,
        instructions: instructions.clone(),
        descriptors: Vec::new(),
    };
    let su16 = compact(PersonalityIndex::SU16);
    let data = match rng.below(3) {
        0 if su16.can_inline() => IndexEntryData::Inline(su16),
        0 | 1 => {
            let entry = if rng.chance(50) && su16.can_inline() {
                su16
            } else {
                compact(PersonalityIndex::LU16)
            };
            IndexEntryData::ExTab(table.add_extab_entry(ExTabEntry::Compact(entry)))
        }
        _ => IndexEntryData::ExTab(table.add_extab_entry(ExTabEntry::Generic(GenericEntry {
            personality: Address::Constant(TEXT - 0x100),
            data: GenericData::Gnu {
                instructions,
                lsda: vec![0xff; rng.below(8) as usize],
            },
        }))),
    };
    table.add_index_entry(IndexEntry {
        function: Address::Constant(address),
        data,
    });
}

/// The simulated machine.
struct Machine {
    core: [u32; 16],
    vfp: [u64; 32],
    memory: HashMap<u32, u32>,
    big_endian: bool,
}

impl Machine {
    fn push_word(&mut self, value: u32) {
        self.core[SP] -= 4;
        self.memory.insert(self.core[SP], value);
    }

    /// Store D registers from sp upwards, lowest numbered at the lowest
    /// address, as VSTM does.
    fn store_vfp(&mut self, first: u8, count: u8, base: u32) {
        for (i, n) in (first..first + count).enumerate() {
            let value = self.vfp[usize::from(n)];
            let (low, high) = (value as u32, (value >> 32) as u32);
            let (first_word, second_word) = if self.big_endian {
                (high, low)
            } else {
                (low, high)
            };
            let address = base + 8 * i as u32;
            self.memory.insert(address, first_word);
            self.memory.insert(address + 4, second_word);
        }
    }

    /// Run a prologue, then clobber every register it saved.
    fn enter(&mut self, rng: &mut Rng, function: &Function) {
        for step in &function.prologue {
            match *step {
                Step::Push(mask) => {
                    for n in (0..16).rev().filter(|n| mask & (1 << n) != 0) {
                        self.push_word(self.core[n]);
                    }
                }
                Step::Vpush { first, count } => {
                    self.core[SP] -= 8 * u32::from(count);
                    self.store_vfp(first, count, self.core[SP]);
                }
                Step::Fstmx { first, count } => {
                    // The format word is stored above the registers.
                    self.push_word(rng.word());
                    self.core[SP] -= 8 * u32::from(count);
                    self.store_vfp(first, count, self.core[SP]);
                }
                // The unwinder never reads locals, so they are not stored.
                Step::Sub(bytes) => self.core[SP] -= bytes,
            }
        }
        for step in &function.prologue {
            match *step {
                Step::Push(mask) => {
                    for n in (0..16).filter(|n| mask & (1 << n) != 0) {
                        self.core[n] = rng.word();
                    }
                }
                Step::Vpush { first, count } | Step::Fstmx { first, count } => {
                    for n in first..first + count {
                        self.vfp[usize::from(n)] = rng.next();
                    }
                }
                Step::Sub(_) => {}
            }
        }
    }
}

/// What unwinding a frame must produce: the caller's state at the call.
struct Expected {
    core: [u32; 16],
    vfp: [u64; 32],
    /// The VFP registers that the callee saved, and so must be restored.
    saved_vfp: Vec<u8>,
}

/// The address of function `index`; the outermost function follows the
/// others.
fn function_address(index: u32) -> u32 {
    TEXT + index * FUNCTION_SIZE
}

/// Write the table for `functions`, laid out from `TEXT`, followed by an
/// `EXIDX_CANTUNWIND` entry for the outermost function.
fn write_table(
    rng: &mut Rng,
    functions: &[Function],
    endian: RunTimeEndian,
    bases: &BaseAddresses,
) -> Sections<EndianVec<RunTimeEndian>> {
    let mut table = UnwindTable::new();
    for (i, function) in (0..).zip(functions) {
        add_entry(rng, &mut table, function_address(i), function);
    }
    table.add_index_entry(IndexEntry {
        function: Address::Constant(function_address(functions.len() as u32)),
        data: IndexEntryData::CantUnwind,
    });
    let mut sections = Sections::new(EndianVec::new(endian));
    table.write(&mut sections, bases).unwrap();
    sections
}

fn run_case(seed: u64) {
    let mut rng = Rng(seed);
    let endian = if rng.chance(50) {
        RunTimeEndian::Big
    } else {
        RunTimeEndian::Little
    };

    // The table: random functions, then the outermost function, which is
    // covered by an EXIDX_CANTUNWIND entry.
    let count = 1 + rng.below(8) as u32;
    let depth = 1 + rng.below(6) as usize;
    let chain: Vec<u32> = (0..depth)
        .map(|_| rng.below(u64::from(count)) as u32)
        .collect();
    let functions: Vec<Function> = (0..count)
        .map(|i| {
            // Only the innermost frame may be a leaf.
            let leaf = chain.last() == Some(&i) && !chain[..depth - 1].contains(&i);
            Function::random(&mut rng, leaf)
        })
        .collect();
    let bases = BaseAddresses::default().set_exidx(EXIDX).set_extab(EXTAB);
    let sections = write_table(&mut rng, &functions, endian, &bases);
    let module = Module::new(
        ExIdx::new(sections.exidx.slice(), endian),
        ExTab::new(sections.extab.slice(), endian),
        bases,
    );

    // Simulate the calls.
    let mut machine = Machine {
        core: std::array::from_fn(|_| rng.word()),
        vfp: std::array::from_fn(|_| rng.next()),
        memory: HashMap::new(),
        big_endian: endian == RunTimeEndian::Big,
    };
    machine.core[SP] = 0x7fff_0000;
    let mut caller = function_address(count);
    let mut expected = Vec::new();
    for &index in &chain {
        // A return address anywhere after the first instruction of the
        // caller, up to and including its end; Thumb or Arm.
        let return_address = (caller + 4 + rng.below(u64::from(FUNCTION_SIZE - 3)) as u32) & !1
            | rng.below(2) as u32;
        machine.core[LR] = return_address;
        machine.core[PC] = return_address;
        let function = &functions[index as usize];
        expected.push(Expected {
            core: machine.core,
            vfp: machine.vfp,
            saved_vfp: function.saved_vfp(),
        });
        machine.enter(&mut rng, function);
        caller = function_address(index);
    }

    // Unwind from a random point in the innermost function.
    let mut regs = Registers::from_core(machine.core);
    regs.set_core(
        Registers::PC,
        caller + rng.below(u64::from(FUNCTION_SIZE)) as u32,
    );
    let mut memory = |address| machine.memory.get(&address).copied();
    for (level, expected) in expected.iter().enumerate().rev() {
        let context = || format!("seed {seed:#x}, {endian:?}, level {level}, chain {chain:?}");
        let first = level == depth - 1;
        regs = module
            .unwind_frame(&regs, first, &mut memory)
            .unwrap_or_else(|e| panic!("{}: {e}", context()));
        for n in (4..=11).chain([Registers::SP, Registers::PC]) {
            assert_eq!(
                regs.core(n),
                Some(expected.core[usize::from(n)]),
                "{}: r{n}",
                context()
            );
        }
        for &n in &expected.saved_vfp {
            assert_eq!(
                regs.vfp(n),
                Some(expected.vfp[usize::from(n)]),
                "{}: d{n}",
                context()
            );
        }
    }
    assert_eq!(
        module.unwind_frame(&regs, false, &mut memory),
        Err(Error::CantUnwind),
        "seed {seed:#x}"
    );
}

#[test]
fn simulated_call_stacks() {
    let base = 0x9e37_79b9_7f4a_7c15u64;
    for i in 0..iterations("EHABI_UNWINDER_ITERATIONS", 2_000) {
        run_case(base.wrapping_mul(i + 1) | 1);
    }
}
