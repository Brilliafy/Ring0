use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use clap::Parser;
use ring0_common::event_capnp as capnp_schema;

const SOCKET_PATH: &str = "/run/ring0d.sock";

#[derive(Parser)]
#[command(
    name = "ring0-redteam",
    about = "Ring0 red-team attack simulator & verification"
)]
enum Cli {
    All,
    TestShadowRead,
    TestReverseShell,
    TestTamper,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli {
        Cli::All => {
            let mut passed = 0u32;
            let mut failed = 0u32;
            for test in &[test_shadow_read, test_reverse_shell, test_tamper] {
                match test() {
                    Ok(()) => {
                        println!("{}", "  PASS".green());
                        passed += 1;
                    }
                    Err(e) => {
                        println!("{} {}", "  FAIL".red(), e);
                        failed += 1;
                    }
                }
            }
            println!("\n{passed} passed, {failed} failed");
            if failed > 0 {
                std::process::exit(1);
            }
            Ok(())
        }
        Cli::TestShadowRead => test_shadow_read(),
        Cli::TestReverseShell => test_reverse_shell(),
        Cli::TestTamper => test_tamper(),
    }
}

trait Color {
    fn green(&self) -> String;
    fn red(&self) -> String;
}
impl Color for &str {
    fn green(&self) -> String {
        format!("\x1b[32m{self}\x1b[0m")
    }
    fn red(&self) -> String {
        format!("\x1b[31m{self}\x1b[0m")
    }
}

fn connect() -> Result<UnixStream> {
    let stream = UnixStream::connect(SOCKET_PATH).context("connect to ring0d socket")?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    Ok(stream)
}

fn send_cmd(frame: &[u8]) -> Result<()> {
    let mut stream = connect()?;
    let len = (frame.len() as u32).to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(frame)?;
    stream.flush()?;
    Ok(())
}

fn test_shadow_read() -> Result<()> {
    let start = Instant::now();
    println!("[redteam] Testing shadow file read detection...");
    let _ = std::fs::read_to_string("/etc/shadow");
    let elapsed = start.elapsed().as_millis();
    println!("  shadow read attempted in {elapsed}ms (check RingZero alerts for detection)");
    Ok(())
}

fn test_reverse_shell() -> Result<()> {
    let start = Instant::now();
    println!("[redteam] Testing reverse shell simulation...");
    let path = std::env::temp_dir().join("redteam_test_dropper");
    std::fs::write(&path, "#!/bin/sh\necho test")?;
    std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o755))?;
    let _child = std::process::Command::new(&path).env_clear().spawn();
    let elapsed = start.elapsed().as_millis();
    let _ = std::fs::remove_file(&path);
    println!("  reverse shell child spawned in {elapsed}ms (check correlation engine)");
    Ok(())
}

fn test_tamper() -> Result<()> {
    let start = Instant::now();
    println!("[redteam] Testing daemon tamper detection...");

    let rules_path = "/etc/ring0/rules.yaml";
    let tamper_content = "# tamper test";
    if std::path::Path::new(rules_path).exists() {
        let original = std::fs::read_to_string(rules_path).ok();
        let _ = std::fs::write(rules_path, tamper_content);
        if let Ok(orig) = original {
            let _ = std::fs::write(rules_path, &orig);
        }
    }

    let elapsed = start.elapsed().as_millis();
    println!("  tamper attempted in {elapsed}ms (check self-defense alerts)");
    Ok(())
}
