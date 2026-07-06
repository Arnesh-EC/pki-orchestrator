mod cert_verify;
mod exec_arbitrary;
mod hostname_rename;

use crate::registry::CommandRegistry;

/// The v0 command surface: 3 handlers chosen to exercise every point on the
/// role spectrum (guest-eligible read, operator-only write, guest-forbidden
/// escape hatch). See the README's command-catalog table for the planned
/// ADCS catalog this will grow into.
pub fn build_default_registry() -> CommandRegistry {
    let mut registry = CommandRegistry::new();
    registry.register(Box::new(hostname_rename::HostnameRename));
    registry.register(Box::new(cert_verify::CertVerify));
    registry.register(Box::new(exec_arbitrary::ExecArbitrary));
    registry
}
