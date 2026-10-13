//! Comparison with LLVM's EHABI decoder, `llvm-readobj --unwind`.
//!
//! Shared by the `llvm_oracle` and `corpus` tests. See `tests/llvm_oracle.rs`
//! for the known deviations of `llvm-readobj` from the EHABI.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;

use ehabi::read::{ExIdx, ExIdxEntryData, ExTab, ExTabEntry, Reader, decode_unwind_instruction};
use ehabi::{BaseAddresses, ExTabOffset, LittleEndian, UnwindInstruction};

// ---------------------------------------------------------------------------
// Locating and running llvm-readobj
// ---------------------------------------------------------------------------

pub fn llvm_readobj() -> Option<PathBuf> {
    if let Some(path) = std::env::var_os("LLVM_READOBJ") {
        return Some(PathBuf::from(path));
    }
    let exe = if cfg!(windows) {
        "llvm-readobj.exe"
    } else {
        "llvm-readobj"
    };
    let rustc = |args: &[&str]| -> Option<String> {
        let output = Command::new("rustc").args(args).output().ok()?;
        Some(String::from_utf8(output.stdout).ok()?.trim().to_string())
    };
    if let (Some(sysroot), Some(version)) = (rustc(&["--print", "sysroot"]), rustc(&["-vV"]))
        && let Some(host) = version.lines().find_map(|l| l.strip_prefix("host: "))
    {
        let path = Path::new(&sysroot)
            .join("lib/rustlib")
            .join(host)
            .join("bin")
            .join(exe);
        if path.exists() {
            return Some(path);
        }
    }
    Command::new(exe)
        .arg("--version")
        .output()
        .ok()
        .map(|_| PathBuf::from(exe))
}

/// One `Entry { ... }` block of `llvm-readobj --unwind`.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Entry {
    pub function_address: u64,
    pub model: String,
    pub personality_index: Option<u32>,
    pub extab_address: Option<u64>,
    pub personality_address: Option<u64>,
    /// `(bytes, meaning)`, e.g. `("0xB2 0x3F", "vsp = vsp + 768")`.
    pub opcodes: Vec<(String, String)>,
}

fn hex(value: &str) -> u64 {
    u64::from_str_radix(value.trim().trim_start_matches("0x"), 16).unwrap()
}

/// Run `llvm-readobj --unwind` and parse its entries.
pub fn readobj(tool: &Path, file: &Path) -> Vec<Entry> {
    let output = Command::new(tool)
        .arg("--unwind")
        .arg(file)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "llvm-readobj failed on {}",
        file.display()
    );
    let text = String::from_utf8(output.stdout).unwrap();

    let mut entries = Vec::new();
    let mut current: Option<Entry> = None;
    let mut in_opcodes = false;
    for line in text.lines().map(str::trim) {
        if line == "Entry {" {
            current = Some(Entry::default());
            continue;
        }
        let Some(entry) = current.as_mut() else {
            continue;
        };
        if line == "Opcodes [" {
            in_opcodes = true;
        } else if in_opcodes {
            if line == "]" {
                in_opcodes = false;
            } else {
                let (bytes, meaning) = line.split_once(" ; ").expect(line);
                entry
                    .opcodes
                    .push((bytes.trim().to_string(), meaning.to_string()));
            }
        } else if line == "}" {
            entries.push(current.take().unwrap());
        } else if let Some((key, value)) = line.split_once(": ") {
            match key {
                "FunctionAddress" => entry.function_address = hex(value),
                "Model" => entry.model = value.to_string(),
                "PersonalityIndex" => entry.personality_index = Some(value.parse().unwrap()),
                "TableEntryAddress" | "TableEntryOffset" => entry.extab_address = Some(hex(value)),
                "PersonalityRoutineAddress" => entry.personality_address = Some(hex(value)),
                _ => {}
            }
        }
    }
    entries
}

// ---------------------------------------------------------------------------
// The same information, from ehabi, rendered the way llvm-readobj prints it
// ---------------------------------------------------------------------------

fn llvm_gpr_list(mask: u16) -> String {
    const NAMES: [&str; 16] = [
        "r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "fp", "ip", "sp", "lr",
        "pc",
    ];
    let names: Vec<&str> = (0..16)
        .filter(|r| mask & (1 << r) != 0)
        .map(|r| NAMES[r])
        .collect();
    format!("{{{}}}", names.join(", "))
}

fn llvm_range(prefix: &str, first: u8, count: u8) -> String {
    let names: Vec<String> = (first..first + count)
        .map(|r| format!("{prefix}{r}"))
        .collect();
    format!("{{{}}}", names.join(", "))
}

fn llvm_meaning(instruction: UnwindInstruction) -> String {
    use UnwindInstruction::*;
    match instruction {
        IncrementVsp(n) => format!("vsp = vsp + {n}"),
        IncrementVspLarge(n) => format!("vsp = vsp + {n}"),
        DecrementVsp(n) => format!("vsp = vsp - {n}"),
        RefuseToUnwind => "refuse to unwind".into(),
        PopCore { .. } | PopCoreRange { .. } => {
            format!(
                "pop {}",
                llvm_gpr_list(instruction.popped_core_registers().unwrap())
            )
        }
        SetVsp(reg) => format!("vsp = r{reg}"),
        Finish => "finish".into(),
        PopVfpFstmx { first, count } | PopVfpVpush { first, count } => {
            format!("pop {}", llvm_range("d", first, count))
        }
        PopVfpFstmxD8 { count } | PopVfpVpushD8 { count } => {
            format!("pop {}", llvm_range("d", 8, count))
        }
        PopRaAuthCode => "pop ra_auth_code".into(),
        PopWmmxWr10 { count } => format!("pop {}", llvm_range("wR", 10, count)),
        PopWmmx { first, count } => format!("pop {}", llvm_range("wR", first, count)),
        PopWmmxControl { mask } => {
            let names: Vec<String> = (0..4)
                .filter(|r| mask & (1 << r) != 0)
                .map(|r| format!("wCGR{r}"))
                .collect();
            format!("pop {{{}}}", names.join(", "))
        }
        Spare { opcode: 0x9d, .. } => "reserved (ARM MOVrr)".into(),
        Spare { opcode: 0x9f, .. } => "reserved (WiMMX MOVrr)".into(),
        // llvm-readobj predates 0xb5 and prints it as spare.
        Spare { .. } | UseVspAsRaAuthModifier => "spare".into(),
    }
}

/// Decode every byte of an unwinding description, as llvm-readobj does
/// (it does not stop at the first *Finish*).
pub fn llvm_opcodes<R: Reader>(bytes: ehabi::read::UnwindBytes<R>) -> Vec<(String, String)> {
    let all: Vec<u8> = bytes.collect();
    let mut rest = &all[..];
    let mut opcodes = Vec::new();
    while !rest.is_empty() {
        let mut iter = rest.iter().copied();
        let instruction = decode_unwind_instruction(&mut iter).unwrap().unwrap();
        let used = rest.len() - iter.len();
        let bytes: Vec<String> = rest[..used].iter().map(|b| format!("0x{b:02X}")).collect();
        opcodes.push((bytes.join(" "), llvm_meaning(instruction)));
        rest = &rest[used..];
    }
    opcodes
}

/// How llvm-readobj computes addresses.
pub enum Layout {
    /// Linked image: references are place-relative to section addresses.
    Linked(BaseAddresses),
    /// Relocatable object: llvm-readobj takes the REL addends as the values.
    Relocatable,
}

pub fn ehabi_entries(exidx_data: &[u8], extab_data: &[u8], layout: &Layout) -> Vec<Entry> {
    let exidx = ExIdx::new(exidx_data, LittleEndian);
    let extab = ExTab::new(extab_data, LittleEndian);
    let extab_base = match layout {
        // Files without `.ARM.extab` only have inline and CANTUNWIND entries.
        Layout::Linked(bases) => bases.extab.map_or(0, u64::from),
        Layout::Relocatable => 0,
    };
    let signed = |value: i32| i64::from(value).cast_unsigned();

    let mut entries = Vec::new();
    let mut iter = exidx.entries();
    while let Some(entry) = iter.next().unwrap() {
        let mut out = Entry {
            function_address: match layout {
                Layout::Linked(bases) => u64::from(entry.function_address(bases).unwrap()),
                Layout::Relocatable => signed(entry.function().value),
            },
            ..Entry::default()
        };
        let compact = match entry.data() {
            ExIdxEntryData::CantUnwind => {
                out.model = "CantUnwind".into();
                None
            }
            ExIdxEntryData::Inline(compact) => {
                out.model = "Compact (Inline)".into();
                Some(compact.clone())
            }
            ExIdxEntryData::ExTab(reference) => {
                let offset = match layout {
                    Layout::Linked(bases) => entry.extab_offset(bases).unwrap().unwrap().0,
                    Layout::Relocatable => usize::try_from(reference.value).unwrap(),
                };
                out.extab_address = Some(extab_base + offset as u64);
                match extab.entry_at(ExTabOffset(offset)).unwrap() {
                    ExTabEntry::Compact(compact) => {
                        out.model = "Compact".into();
                        Some(compact)
                    }
                    ExTabEntry::Generic(generic) => {
                        out.model = "Generic".into();
                        out.personality_address = Some(match layout {
                            Layout::Linked(bases) => {
                                u64::from(generic.personality_address(bases).unwrap())
                            }
                            Layout::Relocatable => signed(generic.personality().value),
                        });
                        None
                    }
                }
            }
        };
        if let Some(compact) = compact {
            let personality = compact.personality();
            out.personality_index = Some(u32::from(personality.0));
            if personality.is_defined() {
                if compact.is_inline() && personality.is_long() {
                    // Known deviation: llvm-readobj decodes the count byte
                    // (always 0 for inline entries) as the opcode 0x00.
                    assert_eq!(compact.word() & 0x00ff_0000, 0);
                    out.opcodes.push(("0x00".into(), "vsp = vsp + 4".into()));
                }
                out.opcodes
                    .extend(llvm_opcodes(compact.unwind_bytes().unwrap()));
            }
        }
        entries.push(out);
    }
    entries
}

/// Compare with llvm-readobj, returning a description of the first
/// difference, if any.
pub fn diff(tool: &Path, file: &Path, expected: &[Entry]) -> Option<String> {
    let actual = readobj(tool, file);
    if actual.len() != expected.len() {
        return Some(format!(
            "llvm-readobj has {} entries, ehabi {}",
            actual.len(),
            expected.len()
        ));
    }
    let (index, (llvm, ours)) = actual
        .iter()
        .zip(expected)
        .enumerate()
        .find(|(_, (llvm, ours))| llvm != ours)?;
    Some(format!(
        "entry {index} differs:
  llvm:  {llvm:?}
  ehabi: {ours:?}"
    ))
}

/// Compare with llvm-readobj, panicking on any difference. Returns the
/// number of entries compared.
pub fn compare(tool: &Path, file: &Path, expected: &[Entry]) -> usize {
    if let Some(difference) = diff(tool, file, expected) {
        panic!("{}: {difference}", file.display());
    }
    expected.len()
}
