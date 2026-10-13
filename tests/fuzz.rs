//! Robustness: every read path must return `Ok` or `Err` on arbitrary input,
//! never panic or loop forever.
//!
//! Inputs are random sections and mutations of the sections in the clang
//! fixtures, read in both byte orders with arbitrary base addresses.
//! Set `EHABI_FUZZ_ITERATIONS` to run longer than the default.

use ehabi::read::{
    CatchType, Descriptor, EndianSlice, ExIdx, ExIdxEntryData, ExTab, Reader, UnwindEntry,
};
use ehabi::write::{EndianVec, Sections, UnwindTable};
use ehabi::{BaseAddresses, Endianity, ExIdxOffset, ExTabOffset, LittleEndian, RunTimeEndian};
use object::{Object, ObjectSection};

/// xorshift64*, so failures are reproducible from the printed seed.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next() as u8).collect()
    }
}

/// Words that are likely to reach interesting paths when used as table data.
const SPECIAL_WORDS: [u32; 12] = [
    0,
    1,
    0x7fff_ffff,
    0x8000_0000,
    0x80b0_b0b0,
    0x81ff_b0b0,
    0x82ff_0000,
    0x8f00_0000,
    0xffff_ffff,
    0xffff_fffe,
    0x0000_ffff,
    0x4000_0000,
];

fn mutate(rng: &mut Rng, data: &mut Vec<u8>) {
    for _ in 0..1 + rng.below(8) {
        match rng.below(6) {
            0 if !data.is_empty() => {
                let i = rng.below(data.len() as u64) as usize;
                data[i] ^= 1 << rng.below(8);
            }
            1 if !data.is_empty() => {
                let i = rng.below(data.len() as u64) as usize;
                data[i] = rng.next() as u8;
            }
            2 if data.len() >= 4 => {
                let i = rng.below(data.len() as u64 / 4) as usize * 4;
                let word = SPECIAL_WORDS[rng.below(SPECIAL_WORDS.len() as u64) as usize];
                data[i..i + 4].copy_from_slice(&word.to_le_bytes());
            }
            3 => {
                let len = rng.below(data.len() as u64 + 1) as usize;
                data.truncate(len);
            }
            4 => {
                let len = rng.below(16) as usize;
                let extra = rng.bytes(len);
                data.extend(extra);
            }
            _ if data.len() >= 8 => {
                // Duplicate a word-aligned chunk elsewhere.
                let from = rng.below(data.len() as u64 / 4) as usize * 4;
                let to = rng.below(data.len() as u64 / 4) as usize * 4;
                let len = 4.min(data.len() - from).min(data.len() - to);
                let chunk = data[from..from + len].to_vec();
                data[to..to + len].copy_from_slice(&chunk);
            }
            _ => {}
        }
    }
}

fn random_bases(rng: &mut Rng, exidx_len: usize) -> BaseAddresses {
    match rng.below(4) {
        // Near the top of the address space, so addresses wrap.
        0 => BaseAddresses::default()
            .set_exidx(u32::MAX - rng.below(64) as u32)
            .set_extab(u32::MAX - rng.below(64) as u32),
        // Missing bases.
        1 => BaseAddresses::default(),
        // extab right after exidx, as linkers place them.
        2 => {
            let exidx = rng.next() as u32;
            BaseAddresses::default()
                .set_exidx(exidx)
                .set_extab(exidx.wrapping_add(exidx_len as u32))
        }
        _ => BaseAddresses::default()
            .set_exidx(rng.next() as u32)
            .set_extab(rng.next() as u32),
    }
}

/// Walk everything reachable from the tables. Errors are fine; panics are not.
fn exercise<E: Endianity>(rng: &mut Rng, exidx_data: &[u8], extab_data: &[u8], endian: E) {
    let exidx = ExIdx::new(exidx_data, endian);
    let extab = ExTab::new(extab_data, endian);
    let bases = random_bases(rng, exidx_data.len());

    let mut entries = exidx.entries();
    let mut count = 0;
    while let Ok(Some(entry)) = entries.next() {
        count += 1;
        assert!(count <= exidx.len(), "entries() yielded too many entries");
        let _ = entry.function_address(&bases);
        let _ = entry.extab_offset(&bases);
        if let ExIdxEntryData::Inline(compact) = entry.data() {
            exercise_entry(UnwindEntry::Compact(compact.clone()));
        }
        if let Ok(resolved) = entry.resolve(&extab, &bases) {
            exercise_entry(resolved);
        }
    }
    for _ in 0..4 {
        let _ = exidx.find(rng.next() as u32, &bases);
        let _ = exidx.entry_at(ExIdxOffset(rng.below(exidx_data.len() as u64 + 16) as usize));
        if let Ok(entry) =
            extab.entry_at(ExTabOffset(rng.below(extab_data.len() as u64 + 8) as usize))
        {
            exercise_entry(match entry {
                ehabi::read::ExTabEntry::Compact(c) => UnwindEntry::Compact(c),
                ehabi::read::ExTabEntry::Generic(g) => UnwindEntry::Generic(g),
            });
        }
    }

    // Convert and write back whatever converts.
    if let Ok(table) = UnwindTable::from_read(&exidx, &extab, &bases) {
        let mut sections = Sections::new(EndianVec::new(LittleEndian));
        let _ = table.write(&mut sections, &bases);
        for entry in table.index_entries() {
            let _ = format!("{entry:?}");
        }
    }
}

fn exercise_entry<R: Reader>(entry: UnwindEntry<R>) {
    match entry {
        UnwindEntry::CantUnwind => {}
        UnwindEntry::Compact(compact) => {
            if let Ok(instructions) = compact.instructions() {
                for instruction in instructions.take(2000) {
                    let Ok(instruction) = instruction else { break };
                    let _ = instruction.to_string();
                    let mut out = Vec::new();
                    // Everything the decoder produces must re-encode.
                    instruction.encode(&mut out).unwrap();
                }
            }
            if let Ok(bytes) = compact.unwind_bytes() {
                assert!(bytes.count() <= 3 + 255 * 4);
            }
            if let Ok(Some(descriptors)) = compact.descriptors() {
                for descriptor in descriptors.take(100_000) {
                    let Ok(descriptor) = descriptor else { break };
                    exercise_descriptor(descriptor);
                }
            }
        }
        UnwindEntry::Generic(generic) => {
            if let Ok(instructions) = generic.gnu_instructions() {
                for instruction in instructions.take(2000) {
                    if instruction.is_err() {
                        break;
                    }
                }
            }
            let _ = generic.gnu_lsda().map(|lsda| lsda.len());
            let _ = generic.gnu_lsda_offset();
        }
    }
}

fn exercise_descriptor<R: Reader>(descriptor: Descriptor<R>) {
    let scope = descriptor.scope();
    let _ = scope.contains(scope.offset);
    match descriptor {
        Descriptor::Cleanup { landing_pad, .. } => {
            let _ = landing_pad.address(u32::MAX);
        }
        Descriptor::Catch { catch_type, .. } => {
            let _ = matches!(catch_type, CatchType::TypeInfo(_));
        }
        Descriptor::ExceptionSpec(spec) => {
            let _ = spec.count();
            let _ = spec.landing_pad();
            for type_info in spec.type_infos().take(100_000) {
                if type_info.is_err() {
                    break;
                }
            }
        }
    }
}

fn fixture_sections() -> Vec<(Vec<u8>, Vec<u8>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data");
    let mut out = Vec::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        let Ok(data) = std::fs::read(&path) else {
            continue;
        };
        let Ok(file) = object::File::parse(&*data) else {
            continue;
        };
        let section = |name: &str| {
            file.section_by_name(name)
                .and_then(|s| s.data().ok())
                .unwrap_or(&[])
                .to_vec()
        };
        out.push((section(".ARM.exidx"), section(".ARM.extab")));
    }
    assert!(!out.is_empty());
    out
}

fn iterations() -> u64 {
    std::env::var("EHABI_FUZZ_ITERATIONS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(20_000)
}

#[test]
fn random_sections_do_not_panic() {
    for seed in 0..iterations() {
        let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
        let exidx_len = rng.below(12) as usize * 8 + rng.below(2) as usize * 3;
        let exidx = rng.bytes(exidx_len);
        let extab_len = rng.below(64) as usize;
        let mut extab = rng.bytes(extab_len);
        // Seed some structure: compact headers and terminators.
        for chunk in extab.chunks_mut(4).filter(|c| c.len() == 4) {
            if rng.below(3) == 0 {
                let word = SPECIAL_WORDS[rng.below(SPECIAL_WORDS.len() as u64) as usize];
                chunk.copy_from_slice(&word.to_le_bytes());
            }
        }
        let endian = if seed % 2 == 0 {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        exercise(&mut rng, &exidx, &extab, endian);
    }
}

#[test]
fn mutated_fixtures_do_not_panic() {
    let fixtures = fixture_sections();
    for seed in 0..iterations() {
        let mut rng = Rng(seed.wrapping_mul(0xd1b5_4a32_d192_ed03) | 1);
        let (exidx, extab) = &fixtures[rng.below(fixtures.len() as u64) as usize];
        let (mut exidx, mut extab) = (exidx.clone(), extab.clone());
        match rng.below(3) {
            0 => mutate(&mut rng, &mut exidx),
            1 => mutate(&mut rng, &mut extab),
            _ => {
                mutate(&mut rng, &mut exidx);
                mutate(&mut rng, &mut extab);
            }
        }
        let endian = if rng.below(4) == 0 {
            RunTimeEndian::Big
        } else {
            RunTimeEndian::Little
        };
        exercise(&mut rng, &exidx, &extab, endian);
        let _ = EndianSlice::new(&exidx, endian).len();
    }
}
