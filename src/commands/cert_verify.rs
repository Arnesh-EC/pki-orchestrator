use crate::{
    authz::Capability,
    commands::util::{
        invalid, param, parse_json, require_success, required,
        valid_windows_path,
    },
    registry::{CommandContext, CommandError, CommandHandler},
};

const ML_DSA_87_OID: &str = "2.16.840.1.101.3.4.3.19";

fn valid_oid(value: &str) -> bool {
    value.split('.').count() >= 2
        && value.split('.').all(|part| {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_digit())
        })
}

/// Run the guide's URL-fetch verification and return separate, machine-readable
/// chain, AIA, CDP, OCSP, ML-DSA, validity, and freshness facts.
pub struct CertVerify;

impl CommandHandler for CertVerify {
    fn name(&self) -> &'static str {
        "cert.verify"
    }

    fn required_capability(&self) -> Capability {
        Capability::VmRead
    }

    fn execute(
        &self,
        ctx: &CommandContext,
    ) -> Result<serde_json::Value, CommandError> {
        let path = required(ctx, "path")?;
        let root_path = param(ctx, "rootPath").unwrap_or_default();
        let issuing_path = param(ctx, "issuingPath").unwrap_or_default();
        for (name, value) in [
            ("path", path),
            ("rootPath", root_path),
            ("issuingPath", issuing_path),
        ] {
            if !value.is_empty() && !valid_windows_path(value) {
                return Err(invalid(name, "must be an absolute Windows path"));
            }
        }
        let expected_oid =
            param(ctx, "expectedSignatureOid").unwrap_or(ML_DSA_87_OID);
        if !valid_oid(expected_oid) {
            return Err(invalid(
                "expectedSignatureOid",
                "must be a dotted-decimal object identifier",
            ));
        }

        ctx.progress.report(crate::report::OpRunState::running(
            "verifying chain and revocation paths",
            50.0,
        ));

        let script = "param([string]$Path,[string]$RootPath,[string]$IssuingPath,[string]$ExpectedOid) \
            $ErrorActionPreference = 'Stop'; \
            $raw = (certutil -verify -urlfetch $Path 2>&1) -join \"`n\"; \
            $verifyExit = $LASTEXITCODE; \
            $chainOk = ($verifyExit -eq 0) -and ($raw -match 'CertUtil: -verify command completed successfully'); \
            $aiaCount = [regex]::Matches($raw, '(?im)^\\s*Verified\\s+\"Certificate\\s*\\(').Count; \
            $baseCrlCount = [regex]::Matches($raw, '(?im)^\\s*Verified\\s+\"Base CRL\\s*\\(').Count; \
            $deltaCrlCount = [regex]::Matches($raw, '(?im)^\\s*Verified\\s+\"Delta CRL\\s*\\(').Count; \
            $ocspCount = [regex]::Matches($raw, '(?im)^\\s*Verified\\s+\"OCSP').Count; \
            $urls = @([regex]::Matches($raw, 'https?://[^\\s\"<>]+') | ForEach-Object { $_.Value.TrimEnd('.', ',', ')') } | Sort-Object -Unique); \
            $now = [DateTime]::UtcNow; \
            $certificates = @(); \
            foreach ($item in @(@{ role = 'probe'; path = $Path }, @{ role = 'issuing'; path = $IssuingPath }, @{ role = 'root'; path = $RootPath })) { \
                if (-not $item.path) { continue }; \
                $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($item.path); \
                $validNow = $now -ge $cert.NotBefore.ToUniversalTime() -and $now -le $cert.NotAfter.ToUniversalTime(); \
                $certificates += @{ role = $item.role; subject = $cert.Subject; thumbprint = $cert.Thumbprint; signature_oid = $cert.SignatureAlgorithm.Value; not_before = $cert.NotBefore.ToUniversalTime().ToString('o'); not_after = $cert.NotAfter.ToUniversalTime().ToString('o'); valid_now = $validNow } \
            }; \
            $expectedCertCount = 1 + [int][bool]$IssuingPath + [int][bool]$RootPath; \
            $mlDsaOk = $certificates.Count -eq $expectedCertCount -and @($certificates | Where-Object { $_.signature_oid -ne $ExpectedOid }).Count -eq 0; \
            $validityOk = $certificates.Count -eq $expectedCertCount -and @($certificates | Where-Object { -not $_.valid_now }).Count -eq 0; \
            $aiaOk = $aiaCount -ge 2; \
            $cdpOk = $baseCrlCount -ge 2 -and $deltaCrlCount -ge 1; \
            $ocspOk = $ocspCount -ge 1; \
            $fresh = $chainOk -and $cdpOk -and $ocspOk; \
            @{ healthy = ($chainOk -and $aiaOk -and $cdpOk -and $ocspOk -and $mlDsaOk -and $validityOk -and $fresh); chain_ok = $chainOk; chain = @{ ok = $chainOk }; aia = @{ ok = $aiaOk; verified_certificates = $aiaCount }; cdp = @{ ok = $cdpOk; verified_base_crls = $baseCrlCount; verified_delta_crls = $deltaCrlCount }; ocsp = @{ ok = $ocspOk; verified_responses = $ocspCount }; ml_dsa = @{ ok = $mlDsaOk; expected_oid = $ExpectedOid }; validity = @{ ok = $validityOk }; revocation_freshness = @{ ok = $fresh }; certificates = $certificates; urls = $urls; raw = $raw } | ConvertTo-Json -Depth 6 -Compress";
        let output = require_success(ctx.shell.run(
            script,
            &[
                path.to_string(),
                root_path.to_string(),
                issuing_path.to_string(),
                expected_oid.to_string(),
            ],
        )?)?;
        let result = parse_json(&output.stdout);
        if !result.is_object() {
            return Err(CommandError::Shell(
                crate::powershell::PowerShellError::NonZeroExit {
                    exit_code: 1,
                    stderr: "cert.verify returned invalid JSON".into(),
                },
            ));
        }

        ctx.progress
            .report(crate::report::OpRunState::done(result.clone()));
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{powershell::MockPowerShell, report::NullProgressSink};
    use serde_json::json;
    use std::{collections::HashMap, sync::Arc};

    fn params(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    #[test]
    fn reports_structured_pki_health() {
        let params = params(&[
            ("path", "C:\\Transfer\\lab-health.cer"),
            ("rootPath", "C:\\CertEnroll\\root.crt"),
            ("issuingPath", "C:\\CertEnroll\\issuing.crt"),
        ]);
        let shell = Arc::new(MockPowerShell::new());
        shell.push_success(
            json!({
                "healthy": true,
                "chain_ok": true,
                "chain": {"ok": true},
                "aia": {"ok": true, "verified_certificates": 2},
                "cdp": {"ok": true, "verified_base_crls": 2, "verified_delta_crls": 1},
                "ocsp": {"ok": true, "verified_responses": 1},
                "ml_dsa": {"ok": true, "expected_oid": ML_DSA_87_OID},
                "validity": {"ok": true},
                "revocation_freshness": {"ok": true},
                "certificates": [],
                "urls": [],
                "raw": "CertUtil: -verify command completed successfully."
            })
            .to_string(),
        );
        let ctx = CommandContext {
            params: &params,
            progress: &NullProgressSink,
            shell,
        };

        let result = CertVerify.execute(&ctx).unwrap();

        assert_eq!(result["healthy"], true);
        assert_eq!(result["aia"]["verified_certificates"], 2);
        assert_eq!(result["ml_dsa"]["expected_oid"], ML_DSA_87_OID);
    }

    #[test]
    fn rejects_invalid_certificate_path() {
        let params = params(&[("path", "relative.cer")]);
        let ctx = CommandContext {
            params: &params,
            progress: &NullProgressSink,
            shell: Arc::new(MockPowerShell::new()),
        };

        assert!(matches!(
            CertVerify.execute(&ctx),
            Err(CommandError::InvalidParam { .. })
        ));
    }

    #[test]
    fn missing_path_param_is_reported() {
        let params = HashMap::new();
        let ctx = CommandContext {
            params: &params,
            progress: &NullProgressSink,
            shell: Arc::new(MockPowerShell::new()),
        };

        assert!(matches!(
            CertVerify.execute(&ctx),
            Err(CommandError::MissingParam(_))
        ));
    }
}
