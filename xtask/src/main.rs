use std::process::Command;

use anyhow::{Context, Result};
use clap::Parser;

#[derive(Parser)]
#[command(name = "cargo", bin_name = "cargo")]
enum Cargo {
    #[command(subcommand)]
    Xtask(Cli),
}

#[derive(clap::Subcommand)]
enum Cli {
    Build { name: Option<String> },
    Run,
}

fn main() -> Result<()> {
    let Cargo::Xtask(cli) = Cargo::parse();

    match cli {
        Cli::Build { name } => {
            let target = "bpfel-unknown-none";

            if let Some(n) = &name {
                eprintln!("building eBPF prog: {n}");
            } else {
                eprintln!("building all eBPF progs for {target}");
            }

            let pkg_arg = match name {
                Some(n) => format!("-p={n}"),
                None => "-p=ring0-ebpf".to_string(),
            };
            let status = Command::new("cargo")
                .args(["build", "-Z", "build-std=core", "--target", target])
                .env("CARGO_ENCODED_RUSTFLAGS", "-Cpanic=abort")
                .env("RUSTUP_TOOLCHAIN", "nightly")
                .arg(pkg_arg)
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
