use anyhow::Result;
use clap::Parser;
use pki_orchestrator::cli::{Cli, Command};
use tracing_subscriber::EnvFilter;

fn main() -> Result<()> {
    // rustls 0.23 requires a process-level crypto provider chosen before the
    // first TLS handshake. tokio-tungstenite's `rustls-tls-webpki-roots` feature
    // pulls rustls without enabling its `ring`/`aws-lc-rs` feature, so the
    // provider isn't auto-selected and `connect_async` panics on its first use.
    // Install it here — the single entry point for both the CLI `connect` path
    // and the SCM `service run` path. Ignore the error the second call would
    // return if a provider is somehow already installed.
    let _ = rustls::crypto::ring::default_provider().install_default();

    let cli = Cli::parse();

    // Console-path logging only — `service run` sets up its own file-based
    // subscriber in `service::scm` (a Windows Service has no attached
    // console to write to), and must be the only one to call `.init()`.
    if !matches!(cli.command, Command::Service { .. }) {
        tracing_subscriber::fmt()
            .with_env_filter(
                EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| EnvFilter::new("info")),
            )
            .init();
    }

    pki_orchestrator::cli::run(cli)
}
