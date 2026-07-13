//! System-level commands (Phase L).
//!
//! `system.reboot` is the one command whose *success* looks like a dropped
//! connection: rebooting cmdlets in this catalog never self-reboot
//! (`Install-ADDSForest -NoRebootOnCompletion`, `Add-Computer` without
//! `-Restart`) — the backend sequence engine dispatches this as a separate
//! step it marks `expects_disconnect`, then waits for the agent's next
//! phone-home. The `shutdown /r /t <delay>` grace window is what lets the
//! done-frame flush over the socket before the OS goes down.

use serde_json::{Value, json};

use crate::{
    authz::Capability,
    commands::util::{invalid, param, parse_json, require_success},
    registry::{CommandContext, CommandError, CommandHandler},
};

/// `shutdown /r /t <delaySeconds>` — schedule a reboot and report done.
pub struct SystemReboot;

impl CommandHandler for SystemReboot {
    fn name(&self) -> &'static str {
        "system.reboot"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let delay = param(ctx, "delaySeconds").unwrap_or("10");
        match delay.parse::<u32>() {
            Ok(d) if (5..=120).contains(&d) => {}
            _ => {
                return Err(invalid(
                    "delaySeconds",
                    "must be an integer in 5-120",
                ));
            }
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "scheduling reboot",
            50.0,
        ));

        let script = "param([string]$Delay) \
            shutdown /r /t $Delay /c 'pki-orchestrator plan reboot'; \
            exit $LASTEXITCODE";
        let output =
            require_success(ctx.shell.run(script, &[delay.to_string()])?)?;
        drop(output);

        let result = json!({ "rebooting": true, "delay_seconds": delay });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

/// One-shot boot snapshot: uptime plus whether the base image's
/// `FirstBootFinalize` scheduled task still exists (and is currently
/// running). The backend's boot-settle gate probes this to tell the
/// intermediate firstboot boot (finalize reboot still pending) from the
/// final settled boot, instead of inferring it from connection-stability
/// heuristics. Read tier — reveals nothing a guest couldn't already see.
pub struct SystemBootInfo;

impl CommandHandler for SystemBootInfo {
    fn name(&self) -> &'static str {
        "system.boot_info"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "reading boot info",
            50.0,
        ));

        let script = "$ErrorActionPreference = 'Stop'; \
            $os = Get-CimInstance Win32_OperatingSystem; \
            $task = Get-ScheduledTask -TaskName 'FirstBootFinalize' -ErrorAction SilentlyContinue; \
            [pscustomobject]@{ \
                uptimeS = [int]((Get-Date) - $os.LastBootUpTime).TotalSeconds; \
                finalizePending = ($null -ne $task); \
                finalizeRunning = ($null -ne $task -and $task.State -eq 'Running') \
            } | ConvertTo-Json -Compress";
        let output = require_success(ctx.shell.run(script, &[])?)?;

        let info = parse_json(&output.stdout);
        let result = json!({
            "uptimeS": info.get("uptimeS").cloned().unwrap_or(Value::Null),
            "finalizePending":
                info.get("finalizePending").cloned().unwrap_or(Value::Null),
            "finalizeRunning":
                info.get("finalizeRunning").cloned().unwrap_or(Value::Null),
            "raw": output.stdout,
        });
        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{powershell::MockPowerShell, report::NullProgressSink};
    use std::{collections::HashMap, sync::Arc};

    fn ctx_params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn reboot_defaults_to_ten_seconds() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = SystemReboot.execute(&ctx).unwrap();
        assert_eq!(result["rebooting"], true);
        assert_eq!(result["delay_seconds"], "10");
    }

    #[test]
    fn reboot_rejects_out_of_range_delay() {
        for delay in ["0", "3", "300", "-1", "ten"] {
            let params = ctx_params(&[("delaySeconds", delay)]);
            let sink = NullProgressSink;
            let ctx = CommandContext {
                params: &params,
                progress: &sink,
                shell: Arc::new(MockPowerShell::new()),
            };
            assert!(matches!(
                SystemReboot.execute(&ctx),
                Err(CommandError::InvalidParam { .. })
            ));
        }
    }

    #[test]
    fn reboot_propagates_shutdown_failure() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "Access is denied.(5)");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            SystemReboot.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }

    #[test]
    fn boot_info_parses_a_settled_boot() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"uptimeS":412,"finalizePending":false,"finalizeRunning":false}"#,
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = SystemBootInfo.execute(&ctx).unwrap();
        assert_eq!(result["uptimeS"], 412);
        assert_eq!(result["finalizePending"], false);
        assert_eq!(result["finalizeRunning"], false);
    }

    #[test]
    fn boot_info_reports_finalize_pending() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"uptimeS":38,"finalizePending":true,"finalizeRunning":true}"#,
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = SystemBootInfo.execute(&ctx).unwrap();
        assert_eq!(result["finalizePending"], true);
        assert_eq!(result["finalizeRunning"], true);
    }

    #[test]
    fn boot_info_keeps_raw_when_unparseable() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("not json");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        let result = SystemBootInfo.execute(&ctx).unwrap();
        assert!(result["uptimeS"].is_null());
        assert!(result["finalizePending"].is_null());
        assert_eq!(result["raw"], "not json");
    }

    #[test]
    fn boot_info_propagates_shell_failure() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "boom");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell,
        };
        assert!(matches!(
            SystemBootInfo.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }

    #[test]
    fn boot_info_is_read_tier() {
        assert_eq!(SystemBootInfo.required_capability(), Capability::VmRead);
    }
}
