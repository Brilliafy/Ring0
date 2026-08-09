//! On-demand /proc snapshots for the GUI: live process list (for the process
//! tree view) and active socket list (for the network view). These are
//! read-only, unprivileged queries answered directly by the IPC connection
//! handler - they never touch the kernel maps or the event pipeline.

use std::collections::HashMap;
use std::io::Read;

/// A single live process, as shown in the GUI process tree.
#[derive(Debug, Clone)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub binary: String,
    pub cmdline: String,
    pub state: String,
}

/// A single active TCP/UDP socket with its owning process (when resolvable).
#[derive(Debug, Clone)]
pub struct SocketInfo {
    pub local_ip: String,
    pub local_port: u16,
    pub remote_ip: String,
    pub remote_port: u16,
    pub proto: String,
    pub state: String,
    pub pid: u32,
    pub binary: String,
}

const MAX_PROCS: usize = 2048;
const MAX_SOCKETS: usize = 4096;

/// Snapshot of every live process (bounded). Returns sorted by pid.
pub fn list_processes() -> Vec<ProcessInfo> {
    let mut out = Vec::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else { continue };
        let base = format!("/proc/{pid}");
        // stat: pid (comm) state ppid ...
        let mut stat = String::new();
        let _ = std::fs::File::open(format!("{base}/stat"))
            .and_then(|mut f| f.read_to_string(&mut stat));
        let fields: Vec<&str> = stat.split_whitespace().collect();
        // comm may contain spaces/parens; find the last ')' instead of using
        // field indices.
        let Some(close) = stat.rfind(')') else { continue };
        let tail: Vec<&str> = stat[close + 1..].split_whitespace().collect();
        if tail.len() < 3 {
            continue;
        }
        let state = tail[0].to_string();
        let ppid = tail[1].parse::<u32>().unwrap_or(0);

        let mut uid = 0u32;
        if let Ok(status_txt) = std::fs::read_to_string(format!("{base}/status")) {
            for line in status_txt.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    uid = rest
                        .split_whitespace()
                        .next()
                        .and_then(|v| v.parse().ok())
                        .unwrap_or(0);
                    break;
                }
            }
        }

        let mut cmdline = String::new();
        let _ = std::fs::read_to_string(format!("{base}/cmdline")).map(|c| {
            cmdline = c.replace('\0', " ").trim().to_string();
        });
        if cmdline.is_empty() {
            // Kernel threads have empty cmdline - use the comm in parens.
            if let Some(open) = stat.find('(') {
                cmdline = stat[open + 1..close].to_string();
            }
        }

        let mut binary = String::new();
        let _ = std::fs::read_link(format!("{base}/exe")).map(|p| {
            binary = p.to_string_lossy().to_string();
        });
        if binary.is_empty() {
            binary = fields.get(1).copied().unwrap_or("?").trim_matches('(').trim_end_matches(')').to_string();
        }

        out.push(ProcessInfo {
            pid,
            ppid,
            uid,
            binary,
            cmdline,
            state,
        });
        if out.len() >= MAX_PROCS {
            break;
        }
    }
    out.sort_by_key(|p| p.pid);
    out
}

/// Map socket-inode -> (pid, binary) by scanning /proc/*/fd.
fn inode_to_pid() -> HashMap<u64, (u32, String)> {
    let mut map = HashMap::new();
    let Ok(proc_dir) = std::fs::read_dir("/proc") else {
        return map;
    };
    for entry in proc_dir.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<u32>() else { continue };
        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = std::fs::read_dir(&fd_dir) else { continue };
        let mut binary = String::new();
        let _ = std::fs::read_link(format!("/proc/{pid}/exe")).map(|p| {
            binary = p.to_string_lossy().to_string();
        });
        for fd in fds.flatten() {
            let Ok(target) = std::fs::read_link(fd.path()) else { continue };
            let t = target.to_string_lossy();
            if let Some(rest) = t.strip_prefix("socket:[") {
                if let Some(inode) = rest.trim_end_matches(']').parse::<u64>().ok() {
                    map.insert(inode, (pid, binary.clone()));
                }
            }
        }
    }
    map
}

/// Parse a /proc/net file line: `local_ip:port remote_ip:port st ... inode`.
fn parse_net_file(
    path: &str,
    proto: &str,
    map: &HashMap<u64, (u32, String)>,
    out: &mut Vec<SocketInfo>,
) {
    let Ok(content) = std::fs::read_to_string(path) else { return };
    for line in content.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let (local, remote, state_hex) = (fields[1], fields[2], fields[3]);
        let Some(inode) = fields.get(9).and_then(|v| v.parse::<u64>().ok()) else {
            continue;
        };
        let Some((local_ip, local_port)) = parse_addr(local) else { continue };
        let Some((remote_ip, remote_port)) = parse_addr(remote) else { continue };
        let (pid, binary) = map.get(&inode).cloned().unwrap_or((0, String::new()));
        out.push(SocketInfo {
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            proto: proto.to_string(),
            state: tcp_state_name(state_hex).to_string(),
            pid,
            binary,
        });
        if out.len() >= MAX_SOCKETS {
            return;
        }
    }
}

/// `0100007F:1F90` -> ("127.0.0.1", 8080). v6 lines are 32 hex chars + port.
fn parse_addr(s: &str) -> Option<(String, u16)> {
    let (ip_hex, port_hex) = s.rsplit_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    if ip_hex.len() == 8 {
        // v4 little-endian: 0100007F -> 127.0.0.1
        let raw = u32::from_str_radix(ip_hex, 16).ok()?;
        let ip = format!("{}.{}.{}.{}", raw & 0xff, (raw >> 8) & 0xff, (raw >> 16) & 0xff, (raw >> 24) & 0xff);
        Some((ip, port))
    } else if ip_hex.len() == 32 {
        // /proc/net/tcp6 prints each 32-bit group as a host-byte-order (LE on
        // x86) u32; un-reverse each quad to recover the network-order address.
        let mut quads = [0u32; 4];
        for (i, g) in ip_hex.as_bytes().chunks(8).enumerate() {
            let h = u32::from_str_radix(std::str::from_utf8(g).ok()?, 16).ok()?;
            quads[i] = u32::from_be(h);
        }
        let ip = std::net::Ipv6Addr::new(
            ((quads[0] >> 16) & 0xffff) as u16,
            (quads[0] & 0xffff) as u16,
            ((quads[1] >> 16) & 0xffff) as u16,
            (quads[1] & 0xffff) as u16,
            ((quads[2] >> 16) & 0xffff) as u16,
            (quads[2] & 0xffff) as u16,
            ((quads[3] >> 16) & 0xffff) as u16,
            (quads[3] & 0xffff) as u16,
        )
        .to_string();
        Some((ip, port))
    } else {
        None
    }
}

fn tcp_state_name(hex: &str) -> &'static str {
    match u8::from_str_radix(hex, 16).unwrap_or(0) {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        0x0C => "NEW_SYN_RECV",
        _ => "?",
    }
}

/// Snapshot of active TCP/UDP sockets with owning processes (bounded).
pub fn list_sockets() -> Vec<SocketInfo> {
    let map = inode_to_pid();
    let mut out = Vec::new();
    parse_net_file("/proc/net/tcp", "TCP", &map, &mut out);
    parse_net_file("/proc/net/tcp6", "TCP6", &map, &mut out);
    parse_net_file("/proc/net/udp", "UDP", &map, &mut out);
    parse_net_file("/proc/net/udp6", "UDP6", &map, &mut out);
    out.sort_by(|a, b| b.pid.cmp(&a.pid).then(a.local_port.cmp(&b.local_port)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_v4_addr() {
        assert_eq!(parse_addr("0100007F:1F90"), Some(("127.0.0.1".into(), 8080)));
    }

    #[test]
    fn parse_v6_addr() {
        // 2606:4700::6812:273 (a Cloudflare-style address as /proc/net stores it)
        // stored group-swapped: 0626 0047 0000 0000 6812 0273 -> reversed groups
        let hex = "00470626000000000000000073022681";
        let (ip, port) = parse_addr(&format!("{hex}:01BB")).unwrap();
        assert_eq!(ip, "2606:4700::8126:273");
        assert_eq!(port, 443);
    }

    #[test]
    fn tcp_states() {
        assert_eq!(tcp_state_name("0A"), "LISTEN");
        assert_eq!(tcp_state_name("01"), "ESTABLISHED");
    }
}
