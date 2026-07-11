//! Helpers shared by command handlers: dispatch-param access, validation
//! errors, and the non-zero-exit check every shell-backed handler performs.
//! Extracted once the Phase L catalog grew past a handful of files — the
//! per-file copies in the original handlers (`ca.rs`, `ip.rs`) predate this.

use crate::{
    powershell::{PowerShellError, PowerShellOutput},
    registry::{CommandContext, CommandError}
};

/// Read one dispatch param as `&str`. The backend supplies these — for
/// plan-driven provisioning it dispatches each command with resolved params,
/// so a handler never reads config directly (backend-driven provisioning).
pub fn param<'a>(ctx: &'a CommandContext, key: &str) -> Option<&'a str> {
    ctx.params.get(key).map(String::as_str)
}

/// Like [`param`], but a missing key is a `MissingParam` error.
pub fn required<'a>(
    ctx: &'a CommandContext,
    key: &str
) -> Result<&'a str, CommandError> {
    param(ctx, key).ok_or_else(|| CommandError::MissingParam(key.into()))
}

pub fn invalid(name: &str, reason: &str) -> CommandError {
    CommandError::InvalidParam {
        name: name.into(),
        reason: reason.into()
    }
}

/// Pass a successful shell run through; map a non-zero exit to
/// `CommandError::Shell` carrying the exit code and stderr.
pub fn require_success(
    output: PowerShellOutput
) -> Result<PowerShellOutput, CommandError> {
    if output.succeeded() {
        Ok(output)
    } else {
        Err(CommandError::Shell(PowerShellError::NonZeroExit {
            exit_code: output.exit_code,
            stderr: output.stderr
        }))
    }
}

/// Best-effort JSON parse of `ConvertTo-Json` output — `Null` when the
/// output isn't valid JSON (callers keep the raw text alongside).
pub fn parse_json(stdout: &str) -> serde_json::Value {
    serde_json::from_str(stdout.trim()).unwrap_or(serde_json::Value::Null)
}
