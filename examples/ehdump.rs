//! Dump the `.ARM.exidx` and `.ARM.extab` sections of an ELF file.
//!
//! Usage: `cargo run --example ehdump -- <file>`
//!
//! Relocatable objects are shown with a synthetic layout in which each
//! section has its own address.

use std::{env, fs, process};

use ehabi::read::{
    CatchType, Descriptor, ExIdxEntryData, Reader, UnwindBytes, UnwindEntry, UnwindInstructionIter,
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
    let name = |address: u32| match s.symbol_name(address) {
        Some(name) => format!("0x{address:08x} ({name})"),
        None => format!("0x{address:08x}"),
    };
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
            name(entry.function_address(&s.bases)?)
        );
        let location = match entry.data() {
            ExIdxEntryData::CantUnwind => "",
            ExIdxEntryData::Inline(_) => "inline ",
            ExIdxEntryData::ExTab(_) => "",
        };
        match entry.resolve(&s.extab, &s.bases)? {
            UnwindEntry::CantUnwind => println!("  EXIDX_CANTUNWIND"),
            UnwindEntry::Compact(compact) => {
                match compact.offset() {
                    Some(offset) => print!("  .ARM.extab+0x{:x}: ", offset.0),
                    None => print!("  "),
                }
                println!(
                    "{location}compact model, word 0x{:08x}, {}",
                    compact.word(),
                    compact.personality()
                );
                print_instructions(compact.unwind_bytes(), compact.instructions());
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
                    name(generic.personality_address(&s.bases)?)
                );
                print_instructions(generic.gnu_unwind_bytes(), generic.gnu_instructions());
                if let Ok(offset) = generic.gnu_lsda_offset() {
                    println!("    LSDA at .ARM.extab+0x{:x}", offset.0);
                }
            }
        }
    }
    Ok(())
}

fn print_instructions<R: Reader>(
    bytes: ehabi::read::Result<UnwindBytes<R>>,
    instructions: ehabi::read::Result<UnwindInstructionIter<R>>,
) {
    let (Ok(bytes), Ok(mut instructions)) = (bytes, instructions) else {
        println!("    (unwinding instructions not decodable)");
        return;
    };
    let raw: Vec<String> = bytes.map(|b| format!("{b:02x}")).collect();
    println!("    bytes: {}", raw.join(" "));
    loop {
        match instructions.next() {
            Ok(Some(instruction)) => {
                let mut encoded = Vec::new();
                instruction.encode(&mut encoded).unwrap();
                let encoded: Vec<String> = encoded.iter().map(|b| format!("0x{b:02x}")).collect();
                println!("    {:<16} ; {instruction}", encoded.join(" "));
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
    let range = format!(
        "[0x{:x}, 0x{:x})",
        scope.offset,
        scope.offset + scope.length
    );
    let type_info = |value: u32| match s.symbol_name(value) {
        Some(name) => format!("0x{value:08x} ({name})"),
        None => format!("0x{value:08x}"),
    };
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
                CatchType::TypeInfo(t) => type_info(t.value),
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
                types.push(type_info(t.value));
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
