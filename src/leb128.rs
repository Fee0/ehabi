//! Unsigned LEB128 encoding, as used by the `0xb2` unwinding instruction.

/// Decode an unsigned LEB128 value from a byte iterator.
///
/// Returns `None` if the iterator ends before the value does, or if the value
/// does not fit in a `u64`.
pub fn read_unsigned<I: Iterator<Item = u8>>(bytes: &mut I) -> Option<u64> {
    let mut result = 0u64;
    let mut shift = 0u32;
    loop {
        let byte = bytes.next()?;
        let low = u64::from(byte & 0x7f);
        if shift >= 64 || (shift == 63 && low > 1) {
            return None;
        }
        result |= low << shift;
        if byte & 0x80 == 0 {
            return Some(result);
        }
        shift += 7;
    }
}

/// Encode an unsigned LEB128 value, passing each byte to `out`.
pub fn write_unsigned(mut value: u64, mut out: impl FnMut(u8)) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out(byte);
            return;
        }
        out(byte | 0x80);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    #[test]
    fn test_roundtrip() {
        for value in [
            0,
            1,
            0x7f,
            0x80,
            0x3fff,
            0x4000,
            u64::from(u32::MAX),
            u64::MAX,
        ] {
            let mut buf = Vec::new();
            write_unsigned(value, |b| buf.push(b));
            assert_eq!(read_unsigned(&mut buf.iter().copied()), Some(value));
        }
    }

    #[test]
    fn test_errors() {
        assert_eq!(read_unsigned(&mut [0x80u8].iter().copied()), None);
        let overflow = [0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02];
        assert_eq!(read_unsigned(&mut overflow.iter().copied()), None);
    }
}
