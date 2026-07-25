use std::process::Command;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
enum Cli {
    Build { name: Option<String> },
    Run,
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli {
        Cli::Build { name } => {
            let target = format!("{}-unknown-none", std::env::consts::ARCH);

            if let Some(ref n) = name {
                eprintln!("building eBPF prog: {n}");
            } else {
                eprintln!("building all eBPF progs for {target}");
            }

            let status = Command::new("cargo")
                .args(["build", "-Z", "build-std=core", "--target", &target])
                .env("CARGO_ENCODED_RUSTFLAGS", "")
                .arg(
                    name.as_ref()
                        .map(|n| format!("-p={n}"))
                        .as_deref()
                        .unwrap_or("-p=ring0-ebpf"),
                )
                .status()
                .context("failed to run cargo build for eBPF")?;

            if !status.success() {
                anyhow::bail!("eBPF build failed");
            }
            println!("eBPF build OK");
        }
        Cli::Run => {
            let status = Command::new("cargo")
                .args(["run", "-p=ring0d"])
                .status()
                .context("failed to run ring0d")?;
            if !status.success() {
                anyhow::bail!("ring0d run failed");
            }
        }
    }

    Ok(())
}
