use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Mutex;

use tracing::warn;

#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub uid: u32,
    pub ppid: u32,
    pub binary_path: String,
    pub cmdline: String,
}

#[derive(Debug, Clone)]
pub struct SocketEntry {
    pub pid: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
}

pub struct ProcessResolver;

static INODE_CACHE: std::sync::LazyLock<Mutex<HashMap<u64, CachedPid>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::with_capacity(4096)));
static SOCKET_CACHE: std::sync::LazyLock<Mutex<Vec<SocketEntry>>> =
    std::sync::LazyLock::new(|| Mutex::new(Vec::with_capacity(4096)));

struct CachedPid {
    pid: u32,
    stamp: std::time::Instant,
}

impl ProcessResolver {
    pub fn resolve_for_socket(src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Option<ProcessInfo> {
        let inode = Self::inode_from_proc_net(src_port, dst_ip, dst_port)?;
        let pid = Self::pid_from_inode_cached(inode)?;
        let uid = Self::uid(pid).unwrap_or(0);
        let ppid = Self::ppid(pid).unwrap_or(0);
        let binary_path = Self::binary_path(pid).unwrap_or_else(|| "unknown".into());
        let cmdline = Self::cmdline(pid).unwrap_or_else(|| "unknown".into());
        Some(ProcessInfo {
            pid,
            uid,
            ppid,
            binary_path,
            cmdline,
        })
    }

    fn inode_from_proc_net(src_port: u16, dst_ip: IpAddr, dst_port: u16) -> Option<u64> {
        let content_v4 = std::fs::read_to_string("/proc/net/tcp");
        let content_v6 = std::fs::read_to_string("/proc/net/tcp6");

        let dst_hex = match dst_ip {
            IpAddr::V4(v4) => {
                let ip = u32::from(v4);
                format!("{:08X}:{:04X}", ip.to_be(), dst_port)
            }
            IpAddr::V6(v6) => {
                let octets = v6.octets();
                let pairs: Vec<String> = octets
                    .chunks(2)
                    .map(|c| format!("{:02X}{:02X}", c[0] as u32, c[1] as u32))
                    .collect();
                format!("{}:{:04X}", pairs.join(""), dst_port)
            }
        };
        let src_hex = format!("{:04X}", src_port);

        if let Ok(content) = content_v4 {
            if let Some(inode) = Self::parse_proc_net(&content, &src_hex, &dst_hex) {
                return Some(inode);
            }
        }
        if let Ok(content) = content_v6 {
            if let Some(inode) = Self::parse_proc_net(&content, &src_hex, &dst_hex) {
                return Some(inode);
            }
        }
        None
    }

    fn parse_proc_net(content: &str, src_hex: &str, dst_hex: &str) -> Option<u64> {
        for line in content.lines().skip(1) {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let parts: Vec<&str> = trimmed.split_whitespace().collect();
            if parts.len() < 10 {
                continue;
            }
            let local_fields: Vec<&str> = parts[1].split(':').collect();
            if local_fields.len() != 2 {
                continue;
            }
            if local_fields[1] != src_hex {
                continue;
            }
            if parts[2] == dst_hex {
                return parts[9].parse::<u64>().ok();
            }
        }
        None
    }

    fn pid_from_inode_cached(inode: u64) -> Option<u32> {
        {
            let cache = INODE_CACHE.lock().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = cache.get(&inode) {
                if entry.stamp.elapsed().as_secs() < 5 {
                    return Some(entry.pid);
                }
            }
        }
        let pid = Self::pid_from_inode(inode)?;
        let mut cache = INODE_CACHE.lock().unwrap_or_else(|e| e.into_inner());
        cache.insert(
            inode,
            CachedPid {
                pid,
                stamp: std::time::Instant::now(),
            },
        );
        if cache.len() > 16384 {
            cache.clear();
        }
        Some(pid)
    }

    pub fn pid_from_inode(inode: u64) -> Option<u32> {
        let proc = Path::new("/proc");
        let dir = match std::fs::read_dir(proc) {
            Ok(d) => d,
            Err(e) => {
                warn!("cannot read /proc: {e}");
                return None;
            }
        };
        for entry in dir {
            let entry = match entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            let pid_str = entry.file_name();
            let pid: u32 = match pid_str.to_str().and_then(|s| s.parse().ok()) {
                Some(p) => p,
                None => continue,
            };
            let fd_dir = entry.path().join("fd");
            let fds = match std::fs::read_dir(&fd_dir) {
                Ok(d) => d,
                Err(_) => continue,
            };
            for fd_entry in fds {
                let fd_entry = match fd_entry {
                    Ok(e) => e,
                    Err(_) => continue,
                };
                match std::fs::read_link(fd_entry.path()) {
                    Ok(target) => {
                        let target_str = target.to_string_lossy();
                        if target_str.contains(&format!("socket:[{inode}]")) {
                            return Some(pid);
                        }
                    }
                    Err(_) => continue,
                }
            }
        }
        None
    }

    pub fn uid(pid: u32) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(uid_str) = line.strip_prefix("Uid:") {
                return uid_str.split_whitespace().next()?.parse().ok();
            }
        }
        None
    }

    pub fn ppid(pid: u32) -> Option<u32> {
        let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
        for line in status.lines() {
            if let Some(ppid_str) = line.strip_prefix("PPid:") {
                return ppid_str.trim().parse().ok();
            }
        }
        None
    }

    pub fn binary_path(pid: u32) -> Option<String> {
        std::fs::read_link(format!("/proc/{pid}/exe"))
            .ok()
            .map(|p| p.to_string_lossy().to_string())
    }

    pub fn cmdline(pid: u32) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/cmdline"))
            .ok()
            .map(|s| s.replace('\0', " "))
    }

    pub fn push_socket(pid: u32, dst_ip: u32, dst_port: u16, protocol: u8) {
        if let Ok(mut cache) = SOCKET_CACHE.lock() {
            cache.push(SocketEntry {
                pid,
                dst_ip,
                dst_port,
                protocol,
            });
            if cache.len() > 16384 {
                cache.drain(0..8192);
            }
        }
    }

    pub fn lookup_socket(dst_ip: u32, dst_port: u16) -> Option<u32> {
        if let Ok(cache) = SOCKET_CACHE.lock() {
            for entry in cache.iter().rev() {
                if entry.dst_ip == dst_ip && entry.dst_port == dst_port {
                    return Some(entry.pid);
                }
            }
        }
        None
    }

    pub fn socket_tree() -> Vec<SocketEntry> {
        if let Ok(cache) = SOCKET_CACHE.lock() {
            cache.clone()
        } else {
            Vec::new()
        }
    }
}
