//! Helpers shared by the unit tests.

use alloc::vec::Vec;

/// Encode words as little-endian bytes.
#[cfg(feature = "read")]
pub(crate) fn words_le(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Decode little-endian bytes into words.
#[cfg(feature = "write")]
pub(crate) fn words(data: &[u8]) -> Vec<u32> {
    data.chunks(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect()
}
