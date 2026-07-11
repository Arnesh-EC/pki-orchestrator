//! Domain-controller commands (Phase L).
//!
//! `dc.verify` is the post-promotion readiness probe: `Get-ADDomain` keeps
//! failing until AD Web Services is up, which can lag the post-promotion
//! reboot by minutes. The handler is deliberately single-shot — the backend
//! sequence engine owns the retry/backoff window, so a failure here is a
//! normal "not ready yet" signal, not a fault.

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{parse_json, require_success},
    registry::{CommandContext, CommandError, CommandHandler}
};

/// `Get-ADDomain` — proves the forest is up and ADWS is answering.
pub struct DcVerify;

impl CommandHandler for DcVerify {
    fn name(&self) -> &'static str {
        "dc.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "verifying directory",
            50.0
        ));

        let script = "$ErrorActionPreference = 'Stop'; \
            Import-Module ActiveDirectory; \
            Get-ADDomain | Select-Object DNSRoot, NetBIOSName, DomainMode | ConvertTo-Json";
        let output = require_success(ctx.shell.run(script, &[])?)?;

        let domain = parse_json(&output.stdout);
        let result = json!({ "domain": domain, "raw": output.stdout });
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
    fn verify_parses_domain_facts() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"DNSRoot":"EncryptionConsulting.com","NetBIOSName":"ENCRYPTIONCONSU","DomainMode":"Windows2016Domain"}"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = DcVerify.execute(&ctx).unwrap();
        assert_eq!(result["domain"]["DNSRoot"], "EncryptionConsulting.com");
        assert_eq!(result["domain"]["NetBIOSName"], "ENCRYPTIONCONSU");
    }

    #[test]
    fn verify_fails_while_adws_is_still_down() {
        // Backend engine treats this as "retry later", not a fault.
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_failure(
            1,
            "Unable to contact the server. This may be because this server does not exist"
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        assert!(matches!(
            DcVerify.execute(&ctx),
            Err(CommandError::Shell(_))
        ));
    }

    #[test]
    fn verify_keeps_raw_output_when_unparseable() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("not json");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = DcVerify.execute(&ctx).unwrap();
        assert!(result["domain"].is_null());
        assert_eq!(result["raw"], "not json");
    }
}
