use std::path::PathBuf;
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

const BPF_TARGET: &str = "bpfel-unknown-none";
// Pinned nightly for eBPF builds. Bleeding-edge nightlies (LLVM >= 21/22,
// e.g. 1.99.x) generate BPF instructions the kernel verifier rejects
// ("R5 bitwise operator ^= on pointer prohibited", "last insn is not an exit
// or jmp", inlined panic loops). nightly-2025-05-01 (rustc 1.88, LLVM 20)
// produces objects that verify cleanly with aya-ebpf 0.2.
const BPF_TOOLCHAIN: &str = "nightly-2025-05-01";

fn main() -> Result<()> {
    let Cargo::Xtask(cli) = Cargo::parse();

    match cli {
        Cli::Build { name } => {
            if let Some(n) = &name {
                eprintln!("building eBPF prog: {n}");
            } else {
                eprintln!("building all eBPF progs for {BPF_TARGET}");
            }

            let pkg_arg = match name {
                Some(n) => format!("-p={n}"),
                None => "-p=ring0-ebpf".to_string(),
            };
            let output = Command::new("cargo")
                .args([
                    "build",
                    "-Z",
                    "build-std=core",
                    "--target",
                    BPF_TARGET,
                    "--message-format=json-render-diagnostics",
                ])
                // The eBPF crate builds in the debug profile by default; the
                // dev profile enables overflow-checks AND debug-assertions.
                // With debug-assertions on, `ptr::copy_nonoverlapping` (used
                // internally by probe-read/copy helpers) emits an "unsafe
                // precondition violated" panic check  -  the resulting panic
                // stubs get merged into the tail of every program and the
                // kernel rejects them with "last insn is not an exit or jmp /
                // processed 0 insns". Network math is intentionally wrapping,
                // so disable both for the BPF build.
                // (\x1f separates encoded rustflags args.)
                .env(
                    "CARGO_ENCODED_RUSTFLAGS",
                    "-Cpanic=abort\x1f-Coverflow-checks=no\x1f-Cdebug-assertions=no",
                )
                .env("RUSTUP_TOOLCHAIN", BPF_TOOLCHAIN)
                .arg(pkg_arg)
                .output()
                .context("failed to run cargo build for eBPF")?;

            // Forward cargo's rendered diagnostics to our stderr.
            use std::io::Write;
            std::io::stderr().write_all(&output.stderr)?;

            if !output.status.success() {
                anyhow::bail!("eBPF build failed");
            }

            // Locate the executable cargo claims to have produced. A stale
            // `cargo-xtask` installed on PATH (or a build that silently skips
            // relinking) can report success while the object file is stale or
            // missing  -  the daemon then loads the wrong code. Verify the real
            // artifact instead of trusting the exit code.
            let mut exe: Option<PathBuf> = None;
            for line in String::from_utf8_lossy(&output.stdout).lines() {
                let v: serde_json::Value = match serde_json::from_str(line) {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                if v.get("reason").and_then(|r| r.as_str()) != Some("compiler-artifact") {
                    continue;
                }
                let is_bin = v
                    .get("target")
                    .and_then(|t| t.get("kind"))
                    .and_then(|k| k.as_array())
                    .map(|kinds| kinds.iter().any(|k| k.as_str() == Some("bin")))
                    .unwrap_or(false);
                if is_bin {
                    if let Some(e) = v.get("executable").and_then(|e| e.as_str()) {
                        exe = Some(PathBuf::from(e));
                    }
                }
            }

            let exe = exe.context(
                "cargo completed without reporting the eBPF binary artifact  -  \
                 refusing to report success for a missing object (is a stale \
                 cargo-xtask shadowing this one?)",
            )?;
            if !exe.exists() {
                anyhow::bail!(
                    "cargo reported artifact {} but the file does not exist",
                    exe.display()
                );
            }
            let meta = std::fs::metadata(&exe)
                .with_context(|| format!("cannot stat eBPF object {}", exe.display()))?;
            if meta.len() == 0 {
                anyhow::bail!("eBPF object {} is empty", exe.display());
            }
            println!("eBPF build OK: {}", exe.display());
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
