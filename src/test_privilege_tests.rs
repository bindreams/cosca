//! Unit tests for [`super`].

#[cfg(target_os = "linux")]
mod bypasses_dac_tests {
    use super::super::bypasses_dac;
    use rustix::thread::CapabilitySet;

    /// The precondition is a capability, not uid 0: a uid-1000 caller with an ambient
    /// `CAP_DAC_OVERRIDE` bypasses DAC, and a root caller stripped of both capabilities does not.
    #[skuld::test]
    fn either_dac_capability_counts_and_nothing_else_does() {
        assert!(bypasses_dac(CapabilitySet::DAC_OVERRIDE));
        assert!(bypasses_dac(CapabilitySet::DAC_READ_SEARCH));
        assert!(bypasses_dac(CapabilitySet::CHOWN | CapabilitySet::DAC_OVERRIDE));
        assert!(!bypasses_dac(CapabilitySet::empty()));
        assert!(!bypasses_dac(CapabilitySet::CHOWN | CapabilitySet::SETUID));
    }
}
