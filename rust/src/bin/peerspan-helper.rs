//! `peerspan-helper`: the optional transport-only mailbox and relay operator.
use clap::{Parser, Subcommand, error::ErrorKind};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "peerspan-helper",
    about = "Optional encrypted transport resources"
)]
struct Cli {
    /// Private helper state directory
    #[arg(long, global = true)]
    state: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Serve mailboxes and the relay
    Serve {
        /// Explicit TCP bind address HOST:PORT
        #[arg(long)]
        listen: String,
        /// Protected resource credential configuration
        #[arg(long)]
        tokens_file: Option<PathBuf>,
    },
    /// Print the transport public key and protocols
    Info,
}

/// Only bounded operator diagnostics: never resource credentials, packet
/// contents, ciphertext or private key material.
fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1)
}
const FAILED: &str = "helper failed; check flags, private state and resource configuration";

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) => {
            e.exit()
        }
        Err(_) => fail(FAILED),
    };
    let Some(state) = cli.state.or_else(peerspan_helper_state) else {
        fail(FAILED)
    };
    match cli.command {
        Command::Info => match peerspan_host::helper::info(&state, &mut std::io::stdout()) {
            Ok(()) => {}
            Err(peerspan_host::helper::InfoError::NotFound) => fail("not_found"),
            Err(peerspan_host::helper::InfoError::Failed) => fail(FAILED),
        },
        Command::Serve {
            listen,
            tokens_file,
        } => {
            let runtime = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .unwrap_or_else(|_| fail(FAILED));
            let result = runtime.block_on(async {
                let shutdown = async {
                    let Ok(mut terminate) =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    else {
                        return std::future::pending().await;
                    };
                    tokio::select! {
                        _ = terminate.recv() => {}
                        _ = tokio::signal::ctrl_c() => {}
                    }
                };
                peerspan_host::helper::serve(
                    &state,
                    &listen,
                    tokens_file.as_deref(),
                    &mut std::io::stdout(),
                    shutdown,
                )
                .await
            });
            runtime.shutdown_timeout(std::time::Duration::from_secs(5));
            if result.is_err() {
                fail(FAILED)
            }
        }
    }
}
fn peerspan_helper_state() -> Option<PathBuf> {
    peerspan_host::helper::default_state()
}
