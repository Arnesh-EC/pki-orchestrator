//! Online Responder (OCSP) commands (Phase L).
//!
//! `ocsp.install` puts the Online Responder role service on the web host —
//! deliberately *only* that role service (no Certification Authority on
//! SRV1). Idempotent: an already-configured responder is a success, so
//! converging plans re-run clean. The revocation-configuration step lives in
//! a separate command (`ocsp.configure_revocation`, the CertAdm COM canary).

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::require_success,
    registry::{CommandContext, CommandError, CommandHandler}
};

/// `Install-WindowsFeature ADCS-Online-Cert` + `Install-AdcsOnlineResponder`.
pub struct OcspInstall;

impl CommandHandler for OcspInstall {
    fn name(&self) -> &'static str {
        "ocsp.install"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmProvision
    }

    fn execute(
        &self,
        ctx: &CommandContext
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "installing Online Responder",
            20.0
        ));

        let script = "$ErrorActionPreference = 'Stop'; \
            Install-WindowsFeature ADCS-Online-Cert -IncludeManagementTools | Out-Null; \
            Import-Module ADCSDeployment; \
            try { Install-AdcsOnlineResponder -Force | Out-Null } \
            catch { if ($_.Exception.Message -notmatch 'already') { throw } }; \
            (Get-Service ocspsvc).Status.ToString()";
        let output = require_success(ctx.shell.run(script, &[])?)?;

        let result = json!({
            "installed": true,
            "service": output.stdout.trim()
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

    #[test]
    fn install_reports_service_status() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("Running\n");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = OcspInstall.execute(&ctx).unwrap();
        assert_eq!(result["installed"], true);
        assert_eq!(result["service"], "Running");
    }

    #[test]
    fn install_propagates_role_failure() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(1, "Install-WindowsFeature failed");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        assert!(matches!(
            OcspInstall.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }
}
