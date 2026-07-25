use std::process::Command;

#[test]
fn test_ring0ctl_block_unblock() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "ring0ctl", "--", "block", "10.0.0.1"])
        .output()
        .expect("ring0ctl block failed");
    assert!(output.status.success(), "block failed: {}", String::from_utf8_lossy(&output.stderr));

    let output = Command::new("cargo")
        .args(["run", "--bin", "ring0ctl", "--", "unblock", "10.0.0.1"])
        .output()
        .expect("ring0ctl unblock failed");
    assert!(output.status.success(), "unblock failed: {}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn test_ring0ctl_kill_invalid_pid() {
    let output = Command::new("cargo")
        .args(["run", "--bin", "ring0ctl", "--", "kill", "999999999"])
        .output()
        .expect("ring0ctl kill failed");
    assert!(output.status.success());
}
