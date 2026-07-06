//! The core run-loop body, shared by both the console dev/CI path and the
//! real Windows-Service-invoked path (see `service::scm`). There is exactly
//! one control-flow implementation, not two.
//!
//! v0 has no backend connection yet, so this just proves the registry/config
//! wiring is sound and returns; the networking phase will replace this with
//! a phone-home + command-listen loop.

use anyhow::Result;

use crate::{commands::build_default_registry, config::OrchestratorConfig};

pub fn run_loop(config: &OrchestratorConfig) -> Result<()> {
    let registry = build_default_registry();
    tracing::info!(
        vm_id = %config.identity.vm_id,
        role = ?config.identity.role,
        command_count = registry.len(),
        "orchestrator started (v0: idle — no backend connection yet)"
    );
    Ok(())
}
