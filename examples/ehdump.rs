//! Dump the `.ARM.exidx` and `.ARM.extab` sections of an ELF file.
//!
//! Usage: `cargo run --example ehdump -- <file>`
//!
//! Relocatable objects are shown with a synthetic layout in which each
//! section has its own address.

use std::{env, fs, process};

use ehabi::UnwindInstruction;
use ehabi::read::{
    CatchType, Descriptor, Reader, UnwindBytes, UnwindEntry, decode_unwind_instruction,
};

#[path = "../tests/elf/mod.rs"]
mod elf;

fn main() {
    let Some(path) = env::args().nth(1) else {
        eprintln!("Usage: ehdump <file>");
        process::exit(2);
    };
    let data = fs::read(&path).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        process::exit(1);
    });
    let file = object::File::parse(&*data).unwrap_or_else(|e| {
        eprintln!("{path}: {e}");
        process::exit(1);
    });
    let Some(sections) = elf::load(&file) else {
        eprintln!("{path}: no .ARM.exidx section");
        process::exit(1);
    };
    if let Err(e) = dump(&sections) {
        eprintln!("{path}: {e}");
        process::exit(1);
    }
}

fn dump(s: &elf::EhSections<'_>) -> ehabi::read::Result<()> {
    println!(
        ".ARM.exidx at 0x{:08x}, {} entries; .ARM.extab at 0x{:08x}, {} bytes{}",
        s.bases.exidx.unwrap_or(0),
        s.exidx.len(),
        s.bases.extab.unwrap_or(0),
        s.extab_data.len(),
        if s.relocatable {
            " (synthetic layout)"
        } else {
            ""
        },
    );

    let mut entries = s.exidx.entries();
    while let Some(entry) = entries.next()? {
        println!();
        println!(
            "[0x{:04x}] function {}",
            entry.offset().0,
            s.describe(entry.function_address(&s.bases)?)
        );
        match entry.resolve(&s.extab, &s.bases)? {
            UnwindEntry::CantUnwind => println!("  EXIDX_CANTUNWIND"),
            UnwindEntry::Compact(compact) => {
                match compact.offset() {
                    Some(offset) => print!("  .ARM.extab+0x{:x}: ", offset.0),
                    None => print!("  inline "),
                }
                println!(
                    "compact model, word 0x{:08x}, {}",
                    compact.word(),
                    compact.personality()
                );
                print_instructions(compact.unwind_bytes());
                if let Some(mut descriptors) = compact.descriptors()? {
                    while let Some(descriptor) = descriptors.next()? {
                        print_descriptor(s, &descriptor)?;
                    }
                }
            }
            UnwindEntry::Generic(generic) => {
                println!(
                    "  .ARM.extab+0x{:x}: generic model, personality {}",
                    generic.offset().0,
                    s.describe(generic.personality_address(&s.bases)?)
                );
                print_instructions(generic.gnu_unwind_bytes());
                if let Ok(offset) = generic.gnu_lsda_offset() {
                    println!("    LSDA at .ARM.extab+0x{:x}", offset.0);
                }
            }
        }
    }
    Ok(())
}

/// Print the bytes of an unwinding description and the instructions they
/// decode to, up to the first *Finish*. Each instruction is shown with the
/// bytes it was decoded from.
fn print_instructions<R: Reader>(bytes: ehabi::read::Result<UnwindBytes<R>>) {
    let Ok(bytes) = bytes else {
        println!("    (unwinding instructions not decodable)");
        return;
    };
    let hex = |bytes: &[u8], prefix: &str| -> String {
        let hex: Vec<String> = bytes.iter().map(|b| format!("{prefix}{b:02x}")).collect();
        hex.join(" ")
    };
    let all: Vec<u8> = bytes.collect();
    println!("    bytes: {}", hex(&all, ""));
    let mut rest = &all[..];
    loop {
        let mut iter = rest.iter().copied();
        match decode_unwind_instruction(&mut iter) {
            Ok(Some(instruction)) => {
                let used = rest.len() - iter.len();
                println!("    {:<16} ; {instruction}", hex(&rest[..used], "0x"));
                rest = &rest[used..];
                if instruction == UnwindInstruction::Finish {
                    break;
                }
            }
            Ok(None) => break,
            Err(e) => {
                println!("    error: {e}");
                break;
            }
        }
    }
}

fn print_descriptor<R: Reader>(
    s: &elf::EhSections<'_>,
    descriptor: &Descriptor<R>,
) -> ehabi::read::Result<()> {
    let extab = s.bases.extab.unwrap_or(0);
    let scope = descriptor.scope();
    // 32-bit scopes from untrusted input can extend past 4 GiB.
    let end = u64::from(scope.offset) + u64::from(scope.length);
    let range = format!("[0x{:x}, 0x{end:x})", scope.offset);
    match descriptor {
        Descriptor::Cleanup { landing_pad, .. } => {
            println!(
                "    cleanup {range} -> landing pad 0x{:08x}",
                landing_pad.address(extab)
            );
        }
        Descriptor::Catch {
            landing_pad,
            catches_reference,
            catch_type,
            ..
        } => {
            let caught = match catch_type {
                CatchType::Any => "...".to_string(),
                CatchType::AnyAndFail => "... (fail)".to_string(),
                CatchType::TypeInfo(t) => s.describe(t.value),
            };
            let reference = if *catches_reference { "&" } else { "" };
            if landing_pad.value == 0 {
                println!("    catch {range} {caught}{reference} -> no landing pad");
            } else {
                println!(
                    "    catch {range} {caught}{reference} -> landing pad 0x{:08x}",
                    landing_pad.address(extab)
                );
            }
        }
        Descriptor::ExceptionSpec(spec) => {
            let mut types = Vec::new();
            let mut iter = spec.type_infos();
            while let Some(t) = iter.next()? {
                types.push(s.describe(t.value));
            }
            print!("    exception spec {range} throw({})", types.join(", "));
            match spec.landing_pad() {
                Some(pad) => println!(" -> landing pad 0x{:08x}", pad.address(extab)),
                None => println!(" -> __cxa_call_unexpected"),
            }
        }
    }
    Ok(())
}
