/// The register state of a frame, as far as it is known.
///
/// This is the virtual register set of the EHABI: the core registers r0-r15,
/// the VFP registers D0-D31 and the Return Address Authentication Code
/// pseudo-register of PACBTI-M. Each register is either known or unknown.
///
/// Unwinding restores the registers that the frame saved and leaves the
/// others unchanged. Callee-saved registers that were not saved therefore
/// keep their correct values, but the caller-saved registers (r0-r3, r12)
/// still hold the values from the frame that was unwound.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Registers {
    core: [Option<u32>; 16],
    vfp: [Option<u64>; 32],
    ra_auth_code: Option<u32>,
    ra_auth_modifier: Option<u32>,
}

impl Registers {
    /// The register number of the stack pointer, r13.
    pub const SP: u8 = 13;
    /// The register number of the link register, r14.
    pub const LR: u8 = 14;
    /// The register number of the program counter, r15.
    pub const PC: u8 = 15;

    /// Create a register set in which every register is unknown.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a register set from the values of the core registers r0-r15.
    #[must_use]
    pub fn from_core(core: [u32; 16]) -> Self {
        Registers {
            core: core.map(Some),
            ..Self::default()
        }
    }

    /// Return the value of core register `rN`, if it is known.
    ///
    /// Returns `None` for `n >= 16`.
    #[inline]
    #[must_use]
    pub fn core(&self, n: u8) -> Option<u32> {
        self.core.get(usize::from(n)).copied().flatten()
    }

    /// Set the value of core register `rN`.
    ///
    /// # Panics
    ///
    /// Panics if `n >= 16`.
    #[inline]
    pub fn set_core(&mut self, n: u8, value: u32) {
        self.core[usize::from(n)] = Some(value);
    }

    /// Mark core register `rN` as unknown.
    ///
    /// # Panics
    ///
    /// Panics if `n >= 16`.
    #[inline]
    pub fn clear_core(&mut self, n: u8) {
        self.core[usize::from(n)] = None;
    }

    /// Return the stack pointer, r13, if it is known.
    #[inline]
    #[must_use]
    pub fn sp(&self) -> Option<u32> {
        self.core(Self::SP)
    }

    /// Return the link register, r14, if it is known.
    #[inline]
    #[must_use]
    pub fn lr(&self) -> Option<u32> {
        self.core(Self::LR)
    }

    /// Return the program counter, r15, if it is known.
    ///
    /// After unwinding, this is the return address into the caller. Bit 0 is
    /// set if the caller executes in Thumb state.
    #[inline]
    #[must_use]
    pub fn pc(&self) -> Option<u32> {
        self.core(Self::PC)
    }

    /// Return the value of VFP register `D[n]`, if it is known.
    ///
    /// Returns `None` for `n >= 32`.
    #[inline]
    #[must_use]
    pub fn vfp(&self, n: u8) -> Option<u64> {
        self.vfp.get(usize::from(n)).copied().flatten()
    }

    /// Set the value of VFP register `D[n]`.
    ///
    /// # Panics
    ///
    /// Panics if `n >= 32`.
    #[inline]
    pub fn set_vfp(&mut self, n: u8, value: u64) {
        self.vfp[usize::from(n)] = Some(value);
    }

    /// Return the Return Address Authentication Code popped while unwinding
    /// the last frame, if any (PACBTI-M).
    #[inline]
    #[must_use]
    pub fn ra_auth_code(&self) -> Option<u32> {
        self.ra_auth_code
    }

    /// Return the modifier with which [`ra_auth_code`](Self::ra_auth_code)
    /// authenticates the return address in [`pc`](Self::pc).
    ///
    /// This is the vsp at the `0xb5` instruction if there was one, and
    /// otherwise the CFA (the stack pointer after unwinding). It is `None`
    /// when no authentication code was popped.
    #[inline]
    #[must_use]
    pub fn ra_auth_modifier(&self) -> Option<u32> {
        self.ra_auth_modifier
    }

    pub(crate) fn set_ra_auth(&mut self, code: Option<u32>, modifier: Option<u32>) {
        self.ra_auth_code = code;
        self.ra_auth_modifier = modifier;
    }
}
