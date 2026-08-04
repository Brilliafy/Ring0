use std::process::Command;

/// These integration tests talk to a running `ring0d` daemon over the Unix
/// socket. When the daemon is not reachable they are skipped rather than
/// failed, so `cargo test` passes on machines without the daemon running.
fn daemon_socket_available() -> bool {
    std::path::Path::new("/run/ring0d.sock").exists()
        || std::env::var("RING0_SOCKET")
            .map(|p| std::path::Path::new(&p).exists())
            .unwrap_or(false)
}

fn run_ring0ctl(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_ring0ctl"))
        .args(args)
        .output()
        .expect("ring0ctl failed to start")
}

#[test]
fn test_ring0ctl_block_unblock() {
    if !daemon_socket_available() {
        eprintln!("skipping: ring0d daemon socket not present");
        return;
    }
    let output = run_ring0ctl(&["block", "10.0.0.1"]);
    assert!(
        output.status.success(),
        "block failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let output = run_ring0ctl(&["unblock", "10.0.0.1"]);
    assert!(
        output.status.success(),
        "unblock failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_ring0ctl_kill_invalid_pid() {
    if !daemon_socket_available() {
        eprintln!("skipping: ring0d daemon socket not present");
        return;
    }
    let output = run_ring0ctl(&["kill", "999999999"]);
    assert!(output.status.success());
}

#[test]
fn test_ring0ctl_rejects_invalid_ip() {
    // This command must fail fast with a parse error, daemon or not.
    let output = run_ring0ctl(&["block", "not-an-ip"]);
    assert!(
        !output.status.success(),
        "block with an invalid IP should fail: {}",
        String::from_utf8_lossy(&output.stdout)
    );
}
