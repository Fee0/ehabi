use core::fmt;

/// An identifier for one of the two EHABI sections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SectionId {
    /// The `.ARM.exidx` section: the binary-searchable exception index table.
    ArmExidx,
    /// The `.ARM.extab` section: the exception-handling table.
    ArmExtab,
}

impl SectionId {
    /// Returns the ELF section name for this kind.
    ///
    /// Object producers may append further characters to these names, for
    /// example `.ARM.exidx.text.foo`.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            SectionId::ArmExidx => ".ARM.exidx",
            SectionId::ArmExtab => ".ARM.extab",
        }
    }
}

/// An offset into the `.ARM.exidx` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExIdxOffset<T = usize>(pub T);

/// An offset into the `.ARM.extab` section.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExTabOffset<T = usize>(pub T);

/// The addresses at which the EHABI sections are located.
///
/// Every reference in these tables is a place-relative `prel31` offset, so the
/// section addresses are needed to resolve them to absolute addresses (when
/// reading), or to compute them from absolute addresses (when writing).
///
/// For a linked image these are the sections' virtual addresses. For a
/// relocatable object, any consistent layout may be used.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct BaseAddresses {
    /// The address of the `.ARM.exidx` section.
    pub exidx: Option<u32>,
    /// The address of the `.ARM.extab` section.
    pub extab: Option<u32>,
}

impl BaseAddresses {
    /// Set the `.ARM.exidx` section address.
    #[inline]
    #[must_use]
    pub fn set_exidx(mut self, address: u32) -> Self {
        self.exidx = Some(address);
        self
    }

    /// Set the `.ARM.extab` section address.
    #[inline]
    #[must_use]
    pub fn set_extab(mut self, address: u32) -> Self {
        self.extab = Some(address);
        self
    }

    /// Return the address for the given section, if known.
    #[inline]
    #[must_use]
    pub fn get(&self, section: SectionId) -> Option<u32> {
        match section {
            SectionId::ArmExidx => self.exidx,
            SectionId::ArmExtab => self.extab,
        }
    }
}

/// The index of an Arm-defined personality routine, used by the compact model.
///
/// Bits 24-27 of the first word of a compact entry select one of 16
/// personality routines. Indices 0, 1 and 2 are defined by the EHABI for C and
/// C++; indices 3-15 are reserved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PersonalityIndex(pub u8);

impl PersonalityIndex {
    /// `__aeabi_unwind_cpp_pr0`: short frame unwinding description, 16-bit scopes.
    pub const SU16: PersonalityIndex = PersonalityIndex(0);
    /// `__aeabi_unwind_cpp_pr1`: long frame unwinding description, 16-bit scopes.
    pub const LU16: PersonalityIndex = PersonalityIndex(1);
    /// `__aeabi_unwind_cpp_pr2`: long frame unwinding description, 32-bit scopes.
    pub const LU32: PersonalityIndex = PersonalityIndex(2);

    /// Returns true if the format of this personality routine's data is defined
    /// by the EHABI (indices 0, 1 and 2).
    #[inline]
    #[must_use]
    pub fn is_defined(self) -> bool {
        self.0 <= 2
    }

    /// Returns true if this routine uses the long unwinding description format.
    #[inline]
    #[must_use]
    pub fn is_long(self) -> bool {
        self == Self::LU16 || self == Self::LU32
    }

    /// Returns the number of unwinding instruction bytes in the first word of
    /// an entry: 3 for the short format, 2 for the long format.
    #[inline]
    #[must_use]
    pub fn unwind_head_len(self) -> usize {
        if self.is_long() { 2 } else { 3 }
    }

    /// Returns true if this routine uses 32-bit scopes in its descriptors.
    #[inline]
    #[must_use]
    pub fn has_wide_scopes(self) -> bool {
        self == Self::LU32
    }

    /// Returns the symbol name of the personality routine, if it is defined.
    #[must_use]
    pub fn routine_name(self) -> Option<&'static str> {
        match self.0 {
            0 => Some("__aeabi_unwind_cpp_pr0"),
            1 => Some("__aeabi_unwind_cpp_pr1"),
            2 => Some("__aeabi_unwind_cpp_pr2"),
            _ => None,
        }
    }
}

impl fmt::Display for PersonalityIndex {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.routine_name() {
            Some(name) => f.write_str(name),
            None => write!(f, "<reserved personality {}>", self.0),
        }
    }
}

/// The region of a function covered by a descriptor.
///
/// Maps to the half-open interval `[offset, offset + length)` relative to the
/// start of the function. Both values are multiples of 2, and `length` is
/// non-zero.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Scope {
    /// The offset within the function at which the scope starts.
    pub offset: u32,
    /// The length of the scope in bytes.
    pub length: u32,
}

impl Scope {
    /// Returns true if the given function-relative offset is within the scope.
    #[inline]
    #[must_use]
    pub fn contains(self, offset: u32) -> bool {
        offset >= self.offset && offset - self.offset < self.length
    }
}

/// Sign-extend the low 31 bits of a `prel31` word.
#[cfg(feature = "read")]
#[inline]
pub(crate) fn prel31_value(word: u32) -> i32 {
    (word << 1).cast_signed() >> 1
}

/// Encode a signed displacement into the low 31 bits of a word, if it fits.
#[cfg(feature = "write")]
#[inline]
pub(crate) fn prel31_encode(value: i64) -> Option<u32> {
    if (-(1 << 30)..(1 << 30)).contains(&value) {
        Some(value.cast_unsigned() as u32 & 0x7fff_ffff)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(all(feature = "read", feature = "write"))]
    fn test_prel31() {
        assert_eq!(prel31_value(0x0000_0004), 4);
        assert_eq!(prel31_value(0x7fff_fffc), -4);
        assert_eq!(prel31_value(0xffff_fffc), -4);
        assert_eq!(prel31_value(0x4000_0000), -(1 << 30));
        assert_eq!(prel31_encode(-4), Some(0x7fff_fffc));
        assert_eq!(prel31_encode(1 << 30), None);
        assert_eq!(prel31_encode(-(1 << 30)), Some(0x4000_0000));
    }

    #[test]
    fn test_scope() {
        let scope = Scope {
            offset: 8,
            length: 4,
        };
        assert!(!scope.contains(6));
        assert!(scope.contains(8));
        assert!(scope.contains(11));
        assert!(!scope.contains(12));
    }
}
