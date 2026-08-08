use std::fs;
use std::path::Path;

use tracing::{error, info, warn};

pub struct ContainmentManager;

fn cgroup_v2_available() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

impl ContainmentManager {
    pub fn quarantine_pid(pid: u32) -> bool {
        // F1: pid_t is signed 32-bit; u32 pids >= 0x8000_0000 would cast to a
        // negative pid_t and signal a process group (or 0xFFFF_FFFF == -1,
        // which signals every process the daemon may signal).
        if i32::try_from(pid).map(|p| p > 0).unwrap_or(false) {
            if cgroup_v2_available() {
                Self::cgroup_freeze(pid)
            } else {
                warn!("cgroup v2 not mounted, using SIGSTOP fallback for PID {pid}");
                Self::sigstop_fallback(pid)
            }
        } else {
            warn!("refusing to quarantine invalid PID {pid}");
            false
        }
    }

    /// Quarantine a PID only if it still matches the starttime captured when
    /// the triggering event was observed. A mismatch means the PID was reused
    /// (or the process died) since the event  -  freezing it would hit an
    /// innocent process, so we refuse and log.
    pub fn quarantine_pid_checked(pid: u32, expected_starttime: Option<u64>) -> bool {
        if let Some(expected) = expected_starttime {
            match crate::process::ProcessResolver::starttime(pid) {
                Some(actual) if actual != expected => {
                    warn!(
                        "refusing to quarantine PID {pid}: starttime changed since event (PID reuse?)  -  expected {expected}, got {actual}"
                    );
                    return false;
                }
                None => {
                    warn!("refusing to quarantine PID {pid}: process already gone");
                    return false;
                }
                _ => {}
            }
        }
        Self::quarantine_pid(pid)
    }

    fn cgroup_freeze(pid: u32) -> bool {
        let cg_path = "/sys/fs/cgroup/ring0-quarantine";
        if !Path::new(cg_path).exists() {
            if let Err(e) = fs::create_dir_all(cg_path) {
                error!("failed to create {cg_path}: {e}");
                return Self::sigstop_fallback(pid);
            }
            if let Err(e) = fs::write(format!("{cg_path}/cgroup.procs"), "") {
                error!("failed to init cgroup procs: {e}");
            }
        }
        if let Err(e) = fs::write(format!("{cg_path}/cgroup.procs"), pid.to_string()) {
            error!("failed to move PID {pid} to quarantine cgroup: {e}");
            return Self::sigstop_fallback(pid);
        }
        if let Err(e) = fs::write(format!("{cg_path}/cgroup.freeze"), "1") {
            error!("failed to freeze cgroup: {e}");
            return Self::sigstop_fallback(pid);
        }
        info!("PID {pid} frozen via cgroup v2 quarantine");
        true
    }

    fn sigstop_fallback(pid: u32) -> bool {
        // F1: never pass a wrapped/negative pid_t to kill(2)  -  kill(-1, ...)
        // would stop every process on the host.
        let pid_i = match i32::try_from(pid) {
            Ok(p) if p > 0 => p,
            _ => {
                error!("sigstop_fallback: refusing invalid PID {pid}");
                return false;
            }
        };
        let ret = unsafe { libc::kill(pid_i, libc::SIGSTOP) };
        if ret == 0 {
            info!("PID {pid} stopped via SIGSTOP fallback");
            true
        } else {
            let e = std::io::Error::last_os_error();
            error!("failed to SIGSTOP PID {pid}: {e}");
            false
        }
    }

    pub fn kill_tree(root_pid: u32) -> u32 {
        // F1: refuse pids that would wrap to negative pid_t in kill(2).
        if i32::try_from(root_pid).map(|p| p > 0).unwrap_or(false) == false {
            error!("kill_tree: refusing invalid root PID {root_pid}");
            return 0;
        }
        let mut killed = 0u32;
        let proc = Path::new("/proc");
        let dir = match fs::read_dir(proc) {
            Ok(d) => d,
            Err(e) => {
                error!("kill_tree: cannot read /proc: {e}");
                return 0;
            }
        };
        let children: Vec<u32> = dir
            .filter_map(|e| e.ok())
            .filter_map(|e| {
                e.file_name()
                    .to_str()
                    .map(|s| s.parse::<u32>())
                    .and_then(|r| r.ok())
            })
            .filter(|pid| {
                // E14: compare the *parsed* PPid numerically  -  a substring
                // match (`"PPid: 7"` containing "7") also matched PPid 70,
                // 107, … and could mass-kill unrelated process trees.
                let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
                status.lines().any(|l| {
                    l.trim_start()
                        .strip_prefix("PPid:")
                        .and_then(|v| v.trim().parse::<u32>().ok())
                        == Some(root_pid)
                })
            })
            .collect();

        for child in &children {
            let ret = unsafe { libc::kill(*child as i32, libc::SIGKILL) };
            if ret == 0 {
                killed += 1;
            }
        }
        let root_pid_i = root_pid as i32; // guarded above: 1..=i32::MAX
        let ret = unsafe { libc::kill(root_pid_i, libc::SIGKILL) };
        if ret == 0 {
            killed += 1;
        }
        info!(
            "kill_tree({root_pid}): killed {killed} processes ({} children + root)",
            children.len()
        );
        killed
    }
}
