use std::collections::{HashMap, HashSet};
use std::fs;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use parking_lot::RwLock;
use tracing::{info, warn};

/// How long a forked PID is considered "recent" and therefore checked against
/// the /proc view.
const HIDDEN_PID_WINDOW: Duration = Duration::from_secs(60);
/// Prune connector entries older than this to keep the map bounded.
const CONNECTOR_PRUNE: Duration = Duration::from_secs(300);

// netlink connector protocol constants (include/linux/connector.h, cn_proc.h).
const NETLINK_CONNECTOR: libc::c_int = 11;
const CN_IDX_PROC: u32 = 0x1;
const CN_VAL_PROC: u32 = 0x1;
const PROC_CN_MCAST_LISTEN: u32 = 0x1;
const PROC_EVENT_FORK: u32 = 0x1;
const PROC_EVENT_EXEC: u32 = 0x2;
// NOTE: PROC_EVENT_EXIT is 0x80000000 (bit 31) — 0x4 is PROC_EVENT_UID.
const PROC_EVENT_EXIT: u32 = 0x8000_0000;

/// Kernel-truth PID set maintained from the kernel's process-events
/// notification (netlink connector / CN_PROC). fork/exit events are delivered
/// by the kernel itself, so a userspace rootkit that hides processes by
/// hooking `getdents64` cannot remove a PID from this set — the daemon diffs it
/// against the /proc (VFS) view to find hidden processes.
pub struct ProcConnector {
    pids: Arc<RwLock<HashMap<u32, Instant>>>,
    _handle: Option<std::thread::JoinHandle<()>>,
    running: Arc<AtomicBool>,
}

impl ProcConnector {
    pub fn new() -> Option<Arc<Self>> {
        let pids = Arc::new(RwLock::new(HashMap::new()));
        let running = Arc::new(AtomicBool::new(true));
        let listener_pids = pids.clone();
        let listener_running = running.clone();
        let handle = std::thread::Builder::new()
            .name("ring0-proc-connector".into())
            .spawn(move || Self::listen(listener_pids, listener_running))
            .ok()?;
        Some(Arc::new(Self {
            pids,
            _handle: Some(handle),
            running,
        }))
    }

    /// Snapshot the (tgid, last-event-time) entries newer than `window`.
    fn recent(&self, now: Instant, window: Duration) -> Vec<(u32, Instant)> {
        self.pids
            .read()
            .iter()
            .filter(|(_, t)| now.duration_since(**t) <= window)
            .map(|(pid, t)| (*pid, *t))
            .collect()
    }

    fn prune(&self, now: Instant) {
        let mut pids = self.pids.write();
        pids.retain(|_, t| now.duration_since(*t) < CONNECTOR_PRUNE);
    }

    fn listen(pids: Arc<RwLock<HashMap<u32, Instant>>>, running: Arc<AtomicBool>) {
        let fd = unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_DGRAM, NETLINK_CONNECTOR) };
        if fd < 0 {
            warn!("proc connector: cannot open NETLINK_CONNECTOR socket (CONFIG_PROC_EVENTS?)");
            return;
        }
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as u16;
        addr.nl_groups = CN_IDX_PROC;
        let rc = unsafe {
            libc::bind(
                fd,
                &addr as *const libc::sockaddr_nl as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            warn!(
                "proc connector: bind failed: {}",
                std::io::Error::last_os_error()
            );
            unsafe { libc::close(fd) };
            return;
        }
        if !Self::subscribe(fd) {
            unsafe { libc::close(fd) };
            return;
        }
        info!("proc connector: subscribed to kernel process events");

        let mut buf = [0u8; 4096];
        while running.load(Ordering::Relaxed) {
            let n = unsafe { libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), 0) };
            if n <= 0 {
                // EINTR or no data; keep polling.
                std::thread::sleep(Duration::from_millis(50));
                continue;
            }
            let data = &buf[..n as usize];
            if let Some((what, pid)) = Self::parse_proc_event(data) {
                let now = Instant::now();
                let mut map = pids.write();
                match what {
                    PROC_EVENT_FORK | PROC_EVENT_EXEC => {
                        map.insert(pid, now);
                    }
                    PROC_EVENT_EXIT => {
                        map.remove(&pid);
                    }
                    _ => {}
                }
                if map.len() > 65536 {
                    map.retain(|_, t| now.duration_since(*t) < CONNECTOR_PRUNE);
                }
            }
        }
        unsafe { libc::close(fd) };
    }

    fn subscribe(fd: libc::c_int) -> bool {
        let mut buf = [0u8; 64];
        let nl_len = 16usize; // nlmsghdr
        let cn_len = 20usize; // cn_msg
        let data_len = 4usize; // PROC_CN_MCAST_LISTEN
        let total = nl_len + cn_len + data_len;

        // nlmsghdr
        buf[0..4].copy_from_slice(&(total as u32).to_le_bytes()); // nlmsg_len
        buf[4..6].copy_from_slice(&(libc::NLMSG_DONE as u16).to_le_bytes());
        buf[6..8].copy_from_slice(&(libc::NLM_F_REQUEST as u16).to_le_bytes());
        // nlmsg_seq / nlmsg_pid stay 0

        // cn_msg
        buf[16..20].copy_from_slice(&CN_IDX_PROC.to_le_bytes()); // id.idx
        buf[20..24].copy_from_slice(&CN_VAL_PROC.to_le_bytes()); // id.val
                                                                 // seq=0, ack=0
        buf[32..36].copy_from_slice(&(data_len as u32).to_le_bytes()); // len

        // data
        buf[36..40].copy_from_slice(&PROC_CN_MCAST_LISTEN.to_le_bytes());

        let rc = unsafe { libc::send(fd, buf.as_ptr() as *const libc::c_void, total, 0) };
        if rc < 0 {
            warn!(
                "proc connector: subscribe failed: {}",
                std::io::Error::last_os_error()
            );
            return false;
        }
        true
    }

    /// Parse a received netlink/connector frame and return (event, tgid).
    fn parse_proc_event(data: &[u8]) -> Option<(u32, u32)> {
        if data.len() < 16 + 20 + 24 {
            return None;
        }
        // proc_event starts at 16 (nlmsghdr) + 20 (cn_msg) = 36.
        let what = u32::from_le_bytes(data[36..40].try_into().ok()?);
        // union starts at 36 + 16 = 52.
        let pid = match what {
            // fork: parent_pid(52) parent_tgid(56) child_pid(60) child_tgid(64)
            // Use child_tgid: child_pid is the thread id, which for pthread
            // creation is never a /proc directory and would create false
            // "hidden process" reports.
            PROC_EVENT_FORK => u32::from_le_bytes(data[64..68].try_into().ok()?),
            // exec/exit: process_pid(52) process_tgid(56)
            PROC_EVENT_EXEC | PROC_EVENT_EXIT => u32::from_le_bytes(data[56..60].try_into().ok()?),
            _ => return None,
        };
        if pid == 0 {
            return None;
        }
        Some((what, pid))
    }
}

pub struct RootkitDetector {
    known_pids: Arc<RwLock<HashSet<u32>>>,
    scan_count: Arc<RwLock<u64>>,
    proc_connector: Option<Arc<ProcConnector>>,
}

#[derive(Debug, Clone)]
pub struct RootkitFinding {
    pub alert_type: String,
    pub description: String,
    pub pid: u32,
    pub hidden: bool,
    pub module_name: String,
    pub timestamp: u64,
}

impl RootkitDetector {
    pub fn new() -> Self {
        let proc_connector = ProcConnector::new();
        if proc_connector.is_none() {
            warn!("RootkitDetector: kernel process-events connector unavailable");
        }
        Self {
            known_pids: Arc::new(RwLock::new(HashSet::new())),
            scan_count: Arc::new(RwLock::new(0)),
            proc_connector,
        }
    }

    pub fn scan_hidden_pids(&self) -> Vec<RootkitFinding> {
        let mut findings = Vec::new();
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;

        let proc_pids: HashSet<u32> = match self.enumerate_proc_pids() {
            Ok(pids) => pids,
            Err(e) => {
                warn!("Rootkit scan failed to enumerate /proc: {e:?}");
                return findings;
            }
        };

        *self.scan_count.write() += 1;

        {
            let mut known = self.known_pids.write();
            known.extend(proc_pids.iter().copied());
            known.retain(|pid| proc_pids.contains(pid));
        }

        // Differential audit: PIDs that the kernel reported as forked/exec'd
        // but that never appear in the /proc (VFS) view are hidden processes.
        if let Some(connector) = &self.proc_connector {
            let now_instant = Instant::now();
            for (pid, _last_seen) in connector.recent(now_instant, HIDDEN_PID_WINDOW) {
                if !proc_pids.contains(&pid) {
                    findings.push(RootkitFinding {
                        alert_type: "HiddenProcess".into(),
                        description: format!(
                            "PID {} forked in the kernel but is hidden from /proc",
                            pid
                        ),
                        pid,
                        hidden: true,
                        module_name: String::new(),
                        timestamp: now,
                    });
                }
            }
            connector.prune(now_instant);
        }

        // Suspicious stopped/orphaned processes (unchanged heuristic).
        for &pid in &proc_pids {
            if let Ok(status) = fs::read_to_string(format!("/proc/{pid}/status")) {
                let name = status
                    .lines()
                    .find(|l| l.starts_with("Name:"))
                    .unwrap_or("")
                    .to_string();
                let state = status
                    .lines()
                    .find(|l| l.starts_with("State:"))
                    .unwrap_or("")
                    .to_string();
                if state.contains("T (stopped)") || state.contains("Z (zombie)") {
                    let ppid = status
                        .lines()
                        .find(|l| l.starts_with("PPid:"))
                        .and_then(|l| l.split_whitespace().nth(1))
                        .and_then(|v| v.parse::<u32>().ok())
                        .unwrap_or(0);
                    if ppid == 1 {
                        continue;
                    }
                    let exe_path = match fs::read_link(format!("/proc/{pid}/exe")) {
                        Ok(p) => p.display().to_string(),
                        Err(_) => "unknown".into(),
                    };
                    if exe_path.contains("(deleted)") || !proc_pids.contains(&ppid) {
                        findings.push(RootkitFinding {
                            alert_type: "SuspiciousProcess".into(),
                            description: format!(
                                "Suspicious stopped/orphaned process: {} {} ppid={}",
                                pid, name, ppid
                            ),
                            pid,
                            hidden: false,
                            module_name: name,
                            timestamp: now,
                        });
                    }
                }
            }
        }

        findings
    }

    fn enumerate_proc_pids(&self) -> Result<HashSet<u32>> {
        let mut pids = HashSet::new();
        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            if let Some(pid) = entry
                .file_name()
                .to_str()
                .and_then(|s| s.parse::<u32>().ok())
            {
                pids.insert(pid);
            }
        }
        Ok(pids)
    }

    pub fn ingest_memfd_event(
        &self,
        _pid: u32,
        _name: &str,
        _flags: u32,
    ) -> Option<RootkitFinding> {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        Some(RootkitFinding {
            alert_type: "FilelessExec".into(),
            description: format!(
                "memfd_create by PID {}: name={} flags=0x{:x}",
                _pid, _name, _flags
            ),
            pid: _pid,
            hidden: false,
            module_name: _name.to_string(),
            timestamp: now,
        })
    }

    pub fn ingest_wx_mmap_event(
        &self,
        _pid: u32,
        _prot: u32,
        _flags: u32,
        _len: u64,
    ) -> Option<RootkitFinding> {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let prot_write = 2;
        let prot_exec = 4;
        let is_wx = (_prot & prot_write) != 0 && (_prot & prot_exec) != 0;
        Some(RootkitFinding {
            alert_type: if is_wx {
                "WXMemoryMapping".into()
            } else {
                "AnonymousExecMapping".into()
            },
            description: format!(
                "Process {} mapped {} memory: prot=0x{:x} flags=0x{:x} len={}",
                _pid,
                if is_wx { "W+X" } else { "anonymous executable" },
                _prot,
                _flags,
                _len
            ),
            pid: _pid,
            hidden: false,
            module_name: String::new(),
            timestamp: now,
        })
    }

    pub fn ingest_module_event(
        &self,
        _pid: u32,
        _name: &str,
        _flags: u32,
    ) -> Option<RootkitFinding> {
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let binary =
            crate::process::ProcessResolver::binary_path(_pid).unwrap_or_else(|| "unknown".into());
        Some(RootkitFinding {
            alert_type: "KernelModuleLoad".into(),
            description: format!(
                "Process {} ({}) loaded kernel module: {} flags=0x{:x}",
                _pid, binary, _name, _flags
            ),
            pid: _pid,
            hidden: false,
            module_name: _name.to_string(),
            timestamp: now,
        })
    }

    pub fn scan_count(&self) -> u64 {
        *self.scan_count.read()
    }
}
