//! Domain-membership commands (Phase L).
//!
//! `domain.verify` is the post-join probe (`Win32_ComputerSystem.PartOfDomain`)
//! the backend sequence engine polls after the join reboot. It reports facts —
//! `part_of_domain: false` is a successful read of an unjoined machine, and
//! the engine's per-step predicate decides whether that means "retry".

use serde_json::json;

use crate::{
    authz::Capability,
    commands::util::{parse_json, require_success},
    registry::{CommandContext, CommandError, CommandHandler}
};

/// `Win32_ComputerSystem` — domain membership, domain name, hostname.
pub struct DomainVerify;

impl CommandHandler for DomainVerify {
    fn name(&self) -> &'static str {
        "domain.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext
    ) -> Result<serde_json::Value, CommandError> {
        ctx.progress.report(crate::report::OpRunState::running(
            "verifying membership",
            50.0
        ));

        let script = "$ErrorActionPreference = 'Stop'; \
            Get-CimInstance Win32_ComputerSystem | Select-Object PartOfDomain, Domain, DNSHostName | ConvertTo-Json";
        let output = require_success(ctx.shell.run(script, &[])?)?;

        let system = parse_json(&output.stdout);
        let result = json!({
            "part_of_domain": system["PartOfDomain"] == true,
            "domain": system["Domain"],
            "raw": output.stdout
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
    fn verify_reports_joined_machine() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"PartOfDomain":true,"Domain":"EncryptionConsulting.com","DNSHostName":"ca02"}"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = DomainVerify.execute(&ctx).unwrap();
        assert_eq!(result["part_of_domain"], true);
        assert_eq!(result["domain"], "EncryptionConsulting.com");
    }

    #[test]
    fn verify_reports_workgroup_machine_as_not_joined() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            r#"{"PartOfDomain":false,"Domain":"WORKGROUP","DNSHostName":"win11"}"#
        );
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = DomainVerify.execute(&ctx).unwrap();
        assert_eq!(result["part_of_domain"], false);
        assert_eq!(result["domain"], "WORKGROUP");
    }

    #[test]
    fn verify_treats_unparseable_output_as_not_joined() {
        let params = HashMap::new();
        let sink = NullProgressSink;
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success("garbage");
        let ctx = CommandContext {
            params: &params,
            progress: &sink,
            shell
        };
        let result = DomainVerify.execute(&ctx).unwrap();
        assert_eq!(result["part_of_domain"], false);
        assert_eq!(result["raw"], "garbage");
    }
}
