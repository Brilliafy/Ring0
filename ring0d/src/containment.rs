use std::fs;
use std::path::Path;

use tracing::{error, info, warn};

pub struct ContainmentManager;

fn cgroup_v2_available() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

impl ContainmentManager {
    pub fn quarantine_pid(pid: u32) -> bool {
        if cgroup_v2_available() {
            Self::cgroup_freeze(pid)
        } else {
            warn!("cgroup v2 not mounted, using SIGSTOP fallback for PID {pid}");
            Self::sigstop_fallback(pid)
        }
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
        let ret = unsafe { libc::kill(pid as i32, libc::SIGSTOP) };
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
                let status = fs::read_to_string(format!("/proc/{pid}/status")).unwrap_or_default();
                status
                    .lines()
                    .any(|l| l.starts_with("PPid:") && l.contains(&root_pid.to_string()))
            })
            .collect();

        for child in &children {
            let ret = unsafe { libc::kill(*child as i32, libc::SIGKILL) };
            if ret == 0 {
                killed += 1;
            }
        }
        let ret = unsafe { libc::kill(root_pid as i32, libc::SIGKILL) };
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
