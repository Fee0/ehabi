//! Checks ehabi against a corpus of real 32-bit Arm ELF files.
//!
//! Set `EHABI_CORPUS` to a directory of ELF files, for example one created by
//! `scripts/fetch_corpus.py`. Without it, the test prints a notice and passes.
//! For every file with an `.ARM.exidx` section it checks that:
//!
//! 1. every index entry parses and resolves, its unwinding instructions
//!    decode, and its descriptors (compact model) or GCC/LLVM layout
//!    (generic model) parse;
//! 2. for linked files, `UnwindTable::from_read` followed by `write`
//!    reproduces both sections byte for byte;
//! 3. for linked little-endian files, the decoding matches
//!    `llvm-readobj --unwind`, when it is available.
//!
//! Run it in release mode: `cargo test --release --test corpus -- --nocapture`.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use ehabi::RunTimeEndian;
use ehabi::read::UnwindEntry;
use ehabi::write::{EndianVec, Sections, UnwindTable};
use object::Object;

mod elf;
mod llvm;

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

#[derive(Default)]
struct Stats {
    files: usize,
    relocatable: usize,
    entries: usize,
    models: BTreeMap<&'static str, usize>,
    instructions: usize,
    descriptors: usize,
    gnu_generic: usize,
    identical: usize,
    llvm_checked: usize,
}

/// Check that every entry parses, returning a description of each failure.
fn check_entries(s: &elf::EhSections<'_>, stats: &mut Stats) -> Vec<String> {
    let mut errors = Vec::new();
    let mut entries = s.exidx.entries();
    loop {
        let entry = match entries.next() {
            Ok(Some(entry)) => entry,
            Ok(None) => break,
            Err(e) => {
                errors.push(format!("index entry: {e}"));
                break;
            }
        };
        stats.entries += 1;
        let at = entry.offset().0;
        let resolved = match entry.resolve(&s.extab, &s.bases) {
            Ok(resolved) => resolved,
            Err(e) => {
                errors.push(format!("entry 0x{at:x}: resolve: {e}"));
                continue;
            }
        };
        match resolved {
            UnwindEntry::CantUnwind => *stats.models.entry("cantunwind").or_default() += 1,
            UnwindEntry::Compact(compact) => {
                let model = if compact.is_inline() {
                    "compact inline"
                } else {
                    "compact"
                };
                *stats.models.entry(model).or_default() += 1;
                match compact.instructions() {
                    Ok(iter) => {
                        for instruction in iter {
                            match instruction {
                                Ok(_) => stats.instructions += 1,
                                Err(e) => {
                                    errors.push(format!("entry 0x{at:x}: instruction: {e}"));
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => errors.push(format!("entry 0x{at:x}: instructions: {e}")),
                }
                match compact.descriptors() {
                    Ok(Some(iter)) => {
                        for descriptor in iter {
                            match descriptor {
                                Ok(_) => stats.descriptors += 1,
                                Err(e) => {
                                    errors.push(format!("entry 0x{at:x}: descriptor: {e}"));
                                    break;
                                }
                            }
                        }
                    }
                    Ok(None) => {}
                    Err(e) => errors.push(format!("entry 0x{at:x}: descriptors: {e}")),
                }
            }
            UnwindEntry::Generic(generic) => {
                *stats.models.entry("generic").or_default() += 1;
                let gnu = generic.gnu_instructions().and_then(|iter| {
                    let count = iter.count();
                    generic.gnu_lsda_offset().map(|_| count)
                });
                match gnu {
                    Ok(count) => {
                        stats.instructions += count;
                        stats.gnu_generic += 1;
                    }
                    Err(e) => errors.push(format!("entry 0x{at:x}: generic (GCC layout): {e}")),
                }
            }
        }
    }
    errors
}

/// Check the byte-exact round trip, returning a description of a failure.
fn check_round_trip(s: &elf::EhSections<'_>) -> Option<String> {
    let table = match UnwindTable::from_read(&s.exidx, &s.extab, &s.bases) {
        Ok(table) => table,
        Err(e) => return Some(format!("from_read: {e}")),
    };
    let mut sections = Sections::new(EndianVec::new(s.endian));
    if let Err(e) = table.write(&mut sections, &s.bases) {
        return Some(format!("write: {e}"));
    }
    let first_difference = |written: &[u8], original: &[u8]| {
        written
            .iter()
            .zip(original)
            .position(|(a, b)| a != b)
            .or((written.len() != original.len()).then_some(written.len().min(original.len())))
    };
    for (name, written, original) in [
        (".ARM.exidx", sections.exidx.slice(), s.exidx_data),
        (".ARM.extab", sections.extab.slice(), s.extab_data),
    ] {
        if let Some(offset) = first_difference(written, original) {
            return Some(format!(
                "round trip: {name} differs at 0x{offset:x} (written {} bytes, original {})",
                written.len(),
                original.len()
            ));
        }
    }
    None
}

#[test]
fn corpus() {
    let Some(dir) = std::env::var_os("EHABI_CORPUS") else {
        eprintln!("EHABI_CORPUS not set; skipping (see scripts/fetch_corpus.py)");
        return;
    };
    let tool = llvm::llvm_readobj();
    if tool.is_none() {
        eprintln!("llvm-readobj not found; skipping the comparison with LLVM");
    }

    let mut paths = Vec::new();
    files(Path::new(&dir), &mut paths);
    paths.sort();

    let mut stats = Stats::default();
    let mut failures = Vec::new();
    for path in &paths {
        let data = std::fs::read(path).unwrap();
        let Ok(file) = object::File::parse(&*data) else {
            continue;
        };
        if file.architecture() != object::Architecture::Arm {
            continue;
        }
        let Some(s) = elf::load(&file) else {
            continue;
        };
        stats.files += 1;
        let name = path
            .strip_prefix(&dir)
            .unwrap_or(path)
            .display()
            .to_string();

        for error in check_entries(&s, &mut stats) {
            failures.push(format!("{name}: {error}"));
        }
        if s.relocatable {
            // The tables of relocatable objects hold REL addends, which a
            // write with resolved addresses does not reproduce.
            stats.relocatable += 1;
            continue;
        }
        match check_round_trip(&s) {
            Some(error) => failures.push(format!("{name}: {error}")),
            None => stats.identical += 1,
        }
        if let (Some(tool), RunTimeEndian::Little) = (&tool, s.endian) {
            let expected =
                llvm::ehabi_entries(s.exidx_data, s.extab_data, &llvm::Layout::Linked(s.bases));
            match llvm::diff(tool, path, &expected) {
                Some(difference) => failures.push(format!("{name}: llvm-readobj: {difference}")),
                None => stats.llvm_checked += 1,
            }
        }
    }

    eprintln!(
        "{} files with .ARM.exidx ({} relocatable), {} index entries",
        stats.files, stats.relocatable, stats.entries
    );
    for (model, count) in &stats.models {
        eprintln!("  {model}: {count}");
    }
    eprintln!(
        "  {} unwinding instructions, {} descriptors, {} generic entries in GCC layout",
        stats.instructions, stats.descriptors, stats.gnu_generic
    );
    eprintln!(
        "  byte-identical round trip: {} of {} linked files",
        stats.identical,
        stats.files - stats.relocatable
    );
    eprintln!("  identical to llvm-readobj: {} files", stats.llvm_checked);

    for failure in failures.iter().take(50) {
        eprintln!("FAIL {failure}");
    }
    assert!(failures.is_empty(), "{} failures", failures.len());
    assert!(
        stats.files > 0,
        "no ELF files with .ARM.exidx in {}",
        Path::new(&dir).display()
    );
}
