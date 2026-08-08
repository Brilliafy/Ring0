use std::net::IpAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::{HashMap, LpmTrie, MapData, RingBuf};
use aya::programs::{BtfTracePoint, Lsm, SchedClassifier, TcAttachType, Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};
use tokio::sync::broadcast;
use tracing::{info, warn};

// Event kinds — canonical definitions live in the ring0-abi crate (shared with
// ring0-ebpf); re-exported here for convenience.
pub use ring0_abi::{
    KIND_CAP, KIND_CONNECT, KIND_DPI, KIND_FILE_ACCESS, KIND_KILL, KIND_LSM, KIND_MEMFD, KIND_MMAP,
    KIND_MODULE, KIND_PACKET, KIND_PROCESS_EXEC, KIND_PTRACE, KIND_SETUID, KIND_TLS, KIND_UNLINK,
};

/// Literal DPI signatures synced into the kernel DPI_PATTERNS map.
///
/// The kernel scanner probes keys `0..N` (see `dpi_scan_packet` in
/// ring0-ebpf), so the *map key* is the sequential index here — NOT the rule
/// id. The parallel `BPF_DPI_RULE_IDS` array maps index → real signature rule
/// id, which the daemon uses to look up the signature name. (Previously the
/// rule ids themselves were used as keys, so the kernel scan range 0..64 never
/// matched any pattern and the fast path was dead.)
pub const BPF_DPI_SIGNATURES: &[(u32, &[u8])] = &[
    (5001, b"/bin/sh"),
    (5008, b"/etc/passwd"),
    (5009, b"/etc/shadow"),
    (5010, b"powershell"),
    (5013, b"beacon"),
    (5017, b"UPX!"),
    (5018, b"mimikatz"),
    (5005, b"sqlmap"),
    (5006, b"nikto"),
    (5007, b"nmap"),
];

/// Real signature rule id for each sequential kernel DPI pattern key above.
/// Must stay index-aligned with `BPF_DPI_SIGNATURES`.
pub const BPF_DPI_RULE_IDS: &[u32] = &[5001, 5008, 5009, 5010, 5013, 5017, 5018, 5005, 5006, 5007];

#[derive(Clone, Copy)]
#[repr(C)]
struct DpiPattern {
    len: u8,
    data: [u8; 32],
}

// Plain old data: all fields are byte arrays/ints, so this is sound.
unsafe impl aya::Pod for DpiPattern {}

// aya::Pod cannot be implemented for the shared (external) FlowKey type
// (orphan rule); a repr(transparent) local wrapper has identical layout, which
// is all the kernel map key contract requires.
#[repr(transparent)]
#[derive(Clone, Copy)]
struct KernelFlowKey(ring0_abi::FlowKey);
unsafe impl aya::Pod for KernelFlowKey {}

/// Looks for the compiled eBPF object produced by `cargo xtask build`.
fn find_bpf_object() -> Option<String> {
    let candidates = [
        format!(
            "{}/../target/bpfel-unknown-none/debug/ring0-ebpf",
            env!("CARGO_MANIFEST_DIR")
        ),
        format!(
            "{}/target/bpfel-unknown-none/debug/ring0-ebpf",
            env!("CARGO_MANIFEST_DIR")
        ),
        format!(
            "{}/../target/bpfel-unknown-none/release/ring0-ebpf",
            env!("CARGO_MANIFEST_DIR")
        ),
    ];
    for c in &candidates {
        if std::path::Path::new(c).exists() {
            return Some(c.clone());
        }
    }
    None
}

/// Picks the default network interface (first IPv4 route).
fn default_interface() -> Option<String> {
    let route = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in route.lines().skip(1) {
        let mut fields = line.split_whitespace();
        if let Some(iface) = fields.next() {
            let dest = fields.next().unwrap_or("");
            if dest == "00000000" {
                return Some(iface.to_string());
            }
        }
    }
    None
}

pub struct EbpfManager {
    ring_tx: broadcast::Sender<Vec<u8>>,
    lsm_tx: broadcast::Sender<Vec<u8>>,
    rootkit_tx: broadcast::Sender<Vec<u8>>,
    privesc_tx: broadcast::Sender<Vec<u8>>,
    ebpf: Option<Ebpf>,
    loaded: Arc<AtomicBool>,
    lsm_attached: Arc<AtomicBool>,
    /// Interfaces XDP/TC have been attached to (for periodic re-scan when new
    /// interfaces appear or the default route moves).
    attached_interfaces: parking_lot::Mutex<Vec<String>>,
    // software fallback for when the kernel maps are unavailable
    fallback_blocked_ips: parking_lot::Mutex<Vec<String>>,
    fallback_blocked_ports: parking_lot::Mutex<Vec<u16>>,
    fallback_dns_domains: parking_lot::Mutex<Vec<String>>,
    /// Stop flags + join handles for the ring-buffer reader threads so
    /// `detach()` can terminate them instead of leaving them spinning.
    ring_stops: Vec<Arc<AtomicBool>>,
    ring_handles: Vec<std::thread::JoinHandle<()>>,
}

fn make_channels() -> (
    broadcast::Sender<Vec<u8>>,
    broadcast::Sender<Vec<u8>>,
    broadcast::Sender<Vec<u8>>,
    broadcast::Sender<Vec<u8>>,
) {
    let (ring_tx, _) = broadcast::channel(4096);
    let (lsm_tx, _) = broadcast::channel(1024);
    let (rootkit_tx, _) = broadcast::channel(1024);
    let (privesc_tx, _) = broadcast::channel(1024);
    (ring_tx, lsm_tx, rootkit_tx, privesc_tx)
}

impl EbpfManager {
    pub fn load(lsm_enforce: bool) -> Result<Self> {
        let (ring_tx, lsm_tx, rootkit_tx, privesc_tx) = make_channels();

        match Self::load_real(
            ring_tx.clone(),
            lsm_tx.clone(),
            rootkit_tx.clone(),
            privesc_tx.clone(),
            lsm_enforce,
        ) {
            Ok(mgr) => {
                info!("eBPF manager initialized — real programs loaded");
                Ok(mgr)
            }
            Err(e) => {
                warn!("eBPF load failed: {e:?} — continuing with fallback enforcement");
                Ok(Self {
                    ring_tx,
                    lsm_tx,
                    rootkit_tx,
                    privesc_tx,
                    ebpf: None,
                    loaded: Arc::new(AtomicBool::new(false)),
                    lsm_attached: Arc::new(AtomicBool::new(false)),
                    attached_interfaces: parking_lot::Mutex::new(Vec::new()),
                    fallback_blocked_ips: parking_lot::Mutex::new(Vec::new()),
                    fallback_blocked_ports: parking_lot::Mutex::new(Vec::new()),
                    fallback_dns_domains: parking_lot::Mutex::new(Vec::new()),
                    ring_stops: Vec::new(),
                    ring_handles: Vec::new(),
                })
            }
        }
    }

    fn load_real(
        ring_tx: broadcast::Sender<Vec<u8>>,
        lsm_tx: broadcast::Sender<Vec<u8>>,
        rootkit_tx: broadcast::Sender<Vec<u8>>,
        privesc_tx: broadcast::Sender<Vec<u8>>,
        lsm_enforce: bool,
    ) -> Result<Self> {
        let path =
            find_bpf_object().context("eBPF object not found — run `cargo xtask build` first")?;
        info!("loading eBPF object: {path}");

        let btf = aya::Btf::from_sys_fs().context("failed to load kernel BTF")?;
        let mut loader = EbpfLoader::new();
        loader.btf(Some(&btf));
        let mut ebpf = loader
            .load_file(&path)
            .context("failed to load BPF program")?;

        let attached_interfaces = parking_lot::Mutex::new(Vec::new());

        // ── Attach XDP + TC to the default interface ──
        if let Some(iface) = default_interface() {
            match attach_xdp(&mut ebpf, &iface) {
                Ok(()) => info!("XDP attached on {iface}"),
                Err(e) => warn!("XDP attach failed on {iface}: {e}"),
            }
            match attach_tc(&mut ebpf, &iface) {
                Ok(()) => info!("TC classifier attached on {iface}"),
                Err(e) => warn!("TC attach failed on {iface}: {e}"),
            }
            attached_interfaces.lock().push(iface);
        } else {
            warn!("no default interface found — XDP not attached");
        }
        // F7: the XDP/TC fast path filters IPv4 (incl. stacked 802.1Q VLAN)
        // only. IPv6 (0x86dd) traffic is passed without IP/port/DNS/DPI checks,
        // and block_ip ignores V6 addresses — document the gap explicitly so
        // it is not mistaken for a working IPv6 blocklist.
        warn!(
            "IPv6 traffic is NOT filtered by the XDP/TC fast path — IPv6-blocked hosts remain reachable (IPv4 + VLAN filtering is active)"
        );

        // ── Attach BTF tracepoints (looked up by ELF section name) ──
        //
        // Per-syscall `sys_enter_<name>` events are not real kernel tracepoints
        // (they are dynamically layered on the generic `sys_enter` tracepoint),
        // so raw/btf tracepoint programs can only attach to `sys_enter`. The
        // eBPF program dispatches on the syscall number internally.
        // sched_process_exec (on every exec) stays attached — it is cheap and
        // feeds the process lineage tree.
        match attach_tracepoint(&mut ebpf, "tp_btf/sched_process_exec", &btf) {
            Ok(()) => {}
            Err(e) => warn!("tracepoint tp_btf/sched_process_exec attach failed: {e}"),
        }
        // The generic `sys_enter` tracepoint fires on EVERY syscall
        // system-wide; its dispatcher + handlers (openat/connect/kill/mmap/
        // setuid/memfd/finit_module probes) ran on every process and was the
        // prime suspect for the system-wide slowdowns and lock-screen hangs
        // (every syscall pays the dispatch + probe cost, and a hiccup in any
        // handler stalls the whole machine). Gated behind
        // RING0_SYSCALL_MONITOR=1 (opt-in) — the XDP/TC blocklist, TLS
        // uprobes and exec tracepoint still provide the core protection
        // without a per-syscall hook.
        if std::env::var("RING0_SYSCALL_MONITOR").as_deref() == Ok("1") {
            match attach_tracepoint(&mut ebpf, "tp_btf/sys_enter", &btf) {
                Ok(()) => info!("sys_enter syscall monitor attached (RING0_SYSCALL_MONITOR=1)"),
                Err(e) => warn!("tracepoint tp_btf/sys_enter attach failed: {e}"),
            }
        } else {
            info!("sys_enter syscall monitor NOT attached (opt-in: RING0_SYSCALL_MONITOR=1)");
        }

        // ── Attach LSM programs (by section name) ──
        // NOTE: lsm/file_open is a compile-time no-op and is eliminated from
        // the object entirely — do not request it here.
        // `lsm/capable` and `lsm/ptrace_access_check` run on system-wide hot
        // paths (every capability check, every ptrace access check) and emit a
        // ring event per hit even in audit mode. Under normal operation that
        // is a runaway event source (each event is written to storage by the
        // daemon), so they are only attached when the user explicitly enables
        // enforcement. `socket_connect` is fully audit-gated (returns 0 before
        // doing any work) and stays attached for blocklist enforcement.
        let mut lsm_ok = false;
        let mut lsm_names: Vec<&str> = vec!["lsm/bprm_check", "lsm/socket_connect"];
        if lsm_enforce {
            lsm_names.extend(["lsm/ptrace_access_check", "lsm/capable"]);
        } else {
            info!("LSM ptrace/capable hooks not attached (audit storm risk) — set RING0_LSM_ENFORCE=1 to enable");
        }
        for name in lsm_names {
            match attach_lsm(&mut ebpf, name, &btf) {
                Ok(()) => lsm_ok = true,
                Err(e) => warn!("LSM {name} attach failed: {e}"),
            }
        }

        // ── Attach TLS uprobes (libssl) ──
        match attach_uprobes(&mut ebpf) {
            Ok(()) => info!("TLS uprobes attached"),
            Err(e) => warn!("TLS uprobe attach failed: {e}"),
        }

        // ── Spawn ring buffer readers ──
        let mut ring_stops = Vec::new();
        let mut ring_handles = Vec::new();
        for (map_name, tx) in [
            ("RING_BUF", ring_tx.clone()),
            ("LSM_EVENTS", lsm_tx.clone()),
            ("ROOTKIT_EVENTS", rootkit_tx.clone()),
            ("PRIVESC_EVENTS", privesc_tx.clone()),
        ] {
            if let Some((stop, handle)) = spawn_ring_reader(&mut ebpf, map_name, tx) {
                ring_stops.push(stop);
                ring_handles.push(handle);
            }
        }

        Ok(Self {
            ring_tx,
            lsm_tx: lsm_tx.clone(),
            rootkit_tx: rootkit_tx.clone(),
            privesc_tx: privesc_tx.clone(),
            ebpf: Some(ebpf),
            loaded: Arc::new(AtomicBool::new(true)),
            lsm_attached: Arc::new(AtomicBool::new(lsm_ok)),
            attached_interfaces,
            fallback_blocked_ips: parking_lot::Mutex::new(Vec::new()),
            fallback_blocked_ports: parking_lot::Mutex::new(Vec::new()),
            fallback_dns_domains: parking_lot::Mutex::new(Vec::new()),
            ring_stops,
            ring_handles,
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.ring_tx.subscribe()
    }
    pub fn subscribe_lsm(&self) -> broadcast::Receiver<Vec<u8>> {
        self.lsm_tx.subscribe()
    }
    pub fn subscribe_rootkit(&self) -> broadcast::Receiver<Vec<u8>> {
        self.rootkit_tx.subscribe()
    }
    pub fn subscribe_privesc(&self) -> broadcast::Receiver<Vec<u8>> {
        self.privesc_tx.subscribe()
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Relaxed)
    }

    pub fn lsm_available(&self) -> bool {
        self.lsm_attached.load(Ordering::Relaxed)
    }

    pub fn enable_lsm_enforcement(&mut self) {
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("LSM_ENFORCE") {
                if let Ok(mut map) = HashMap::<&mut MapData, u32, u8>::try_from(map) {
                    let _ = map.insert(&1, &1, 0);
                }
            }
            info!("LSM enforcement enabled");
        } else {
            warn!("LSM enforcement unavailable");
        }
    }

    pub fn block_binary(&mut self, name: &str) -> Result<()> {
        if let Some(ebpf) = self.ebpf.as_mut() {
            // Insert BOTH the full path (matched by the userspace exec
            // handler via `binary_blocked`) AND the basename (matched by
            // the kernel LSM `bprm_check`, which only has the 16-byte
            // `comm` — a full path can never match a comm prefix).
            for key_name in [
                name,
                Path::new(name)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(name),
            ] {
                let mut key = [0u8; 64];
                let b = key_name.as_bytes();
                let n = b.len().min(63);
                key[..n].copy_from_slice(&b[..n]);
                if let Some(map) = ebpf.map_mut("BLOCKED_BINARIES") {
                    if let Ok(mut map) = HashMap::<&mut MapData, [u8; 64], u8>::try_from(map) {
                        map.insert(&key, &1, 0)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn unblock_binary(&mut self, name: &str) -> Result<()> {
        if let Some(ebpf) = self.ebpf.as_mut() {
            for key_name in [
                name,
                Path::new(name)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or(name),
            ] {
                let mut key = [0u8; 64];
                let b = key_name.as_bytes();
                let n = b.len().min(63);
                key[..n].copy_from_slice(&b[..n]);
                if let Some(map) = ebpf.map_mut("BLOCKED_BINARIES") {
                    if let Ok(mut map) = HashMap::<&mut MapData, [u8; 64], u8>::try_from(map) {
                        let _ = map.remove(&key);
                    }
                }
            }
        }
        Ok(())
    }

    pub fn block_ip(&mut self, ip: IpAddr) -> Result<()> {
        if let IpAddr::V4(v4) = ip {
            let inserted = if let Some(ebpf) = self.ebpf.as_mut() {
                if let Some(map) = ebpf.map_mut("BLOCKED_IPS") {
                    if let Ok(mut map) = LpmTrie::<&mut MapData, u32, u8>::try_from(map) {
                        let key = LpmTrieKey::new(32, u32::from_be(u32::from(v4)));
                        map.insert(&key, &1, 0)?;
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };
            // Mirror into the reporting list on BOTH outcomes so status views
            // (blocked_ips / DaemonStatus) reflect reality whether or not the
            // kernel map insert succeeded (previously the list was only
            // populated on kernel failure, making status under-report).
            let mut list = self.fallback_blocked_ips.lock();
            let s = ip.to_string();
            if !list.contains(&s) {
                list.push(s);
            }
            if !inserted {
                warn!("kernel BLOCKED_IPS insert failed for {ip} — enforcement degraded to userspace mirror only");
            }
            info!("blocked {ip}");
        } else {
            // IPv6 enforcement is not implemented in the XDP/TC fast path
            // (documented limitation). A silent no-op here would make an
            // administrator believe ::1/::ffff blocks are effective.
            warn!(
                "IPv6 address {ip}: blocking IPv6 is not supported by the XDP/TC fast path — request ignored"
            );
        }
        Ok(())
    }
    pub fn unblock_ip(&mut self, ip: IpAddr) -> Result<()> {
        if let IpAddr::V4(v4) = ip {
            let _removed = if let Some(ebpf) = self.ebpf.as_mut() {
                if let Some(map) = ebpf.map_mut("BLOCKED_IPS") {
                    if let Ok(mut map) = LpmTrie::<&mut MapData, u32, u8>::try_from(map) {
                        let key = LpmTrieKey::new(32, u32::from_be(u32::from(v4)));
                        let _ = map.remove(&key);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                }
            } else {
                false
            };
            // Always remove from the reporting mirror.
            let mut list = self.fallback_blocked_ips.lock();
            let s = ip.to_string();
            list.retain(|x| x != &s);
            info!("unblocked {ip}");
        } else {
            warn!("IPv6 address {ip}: IPv6 blocking is not supported — nothing to unblock");
        }
        Ok(())
    }
    pub fn block_port(&mut self, port: u16) -> Result<()> {
        let inserted = if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("BLOCKED_PORTS") {
                if let Ok(mut map) = HashMap::<&mut MapData, u16, u32>::try_from(map) {
                    map.insert(&port, &1, 0)?;
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        if !inserted {
            let mut list = self.fallback_blocked_ports.lock();
            if !list.contains(&port) {
                list.push(port);
            }
        }
        info!("blocked port {port}");
        Ok(())
    }
    pub fn unblock_port(&mut self, port: u16) -> Result<()> {
        let removed = if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("BLOCKED_PORTS") {
                if let Ok(mut map) = HashMap::<&mut MapData, u16, u32>::try_from(map) {
                    let _ = map.remove(&port);
                    true
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        if !removed {
            let mut list = self.fallback_blocked_ports.lock();
            list.retain(|x| x != &port);
        }
        Ok(())
    }

    /// List currently blocked IPs (from the kernel map or the fallback list).
    pub fn blocked_ips(&self) -> Vec<String> {
        let mut out = Vec::new();
        let list = self.fallback_blocked_ips.lock();
        out.extend(list.iter().cloned());
        out
    }

    /// Returns true if the given binary path is on the kernel blocklist.
    pub fn binary_blocked(&self, path: &str) -> bool {
        if let Some(ebpf) = self.ebpf.as_ref() {
            if let Some(map) = ebpf.map("BLOCKED_BINARIES") {
                let mut key = [0u8; 64];
                let b = path.as_bytes();
                let n = b.len().min(63);
                key[..n].copy_from_slice(&b[..n]);
                if let Ok(map) = HashMap::<&MapData, [u8; 64], u8>::try_from(map) {
                    return map.get(&key, 0).ok().is_some();
                }
            }
        }
        false
    }

    /// Batch-sync IP CIDRs into the kernel BLOCKED_IPS map.
    pub fn sync_blocked_cidrs(&mut self, cidrs: &[(u32, u8)]) -> usize {
        let mut added = 0;
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("BLOCKED_IPS") {
                if let Ok(mut map) = LpmTrie::<&mut MapData, u32, u8>::try_from(map) {
                    for (ip, prefix) in cidrs {
                        let key = LpmTrieKey::new(*prefix as u32, u32::from_be(*ip));
                        if map.insert(&key, &1, 0).is_ok() {
                            added += 1;
                        }
                    }
                }
            }
        }
        // Mirror into the reporting list on BOTH outcomes so status views
        // (blocked_ips / DaemonStatus) reflect reality whether or not the
        // kernel map insert succeeded (previously the list was only
        // populated on kernel failure, making status under-report).
        // Dedup via HashSet — `list.contains` per entry is O(n²) and a feed
        // with 100k CIDRs stalls the daemon for minutes.
        let mut list = self.fallback_blocked_ips.lock();
        let mut seen: std::collections::HashSet<String> = list.iter().cloned().collect();
        for (ip, prefix) in cidrs {
            let s = format!("{}/{}", std::net::Ipv4Addr::from(*ip), prefix);
            seen.insert(s);
        }
        *list = seen.into_iter().collect();
        added
    }

    /// Batch-sync hashed DNS domains into the kernel DNS_DOMAIN_BLOCK map.
    pub fn sync_dns_domains(&mut self, domains: &[String]) -> usize {
        let mut added = 0;
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("DNS_DOMAIN_BLOCK") {
                if let Ok(mut map) = HashMap::<&mut MapData, u64, u8>::try_from(map) {
                    for d in domains {
                        let h = crate::sucadara::fnv1a_hash(d);
                        if map.insert(&h, &1, 0).is_ok() {
                            added += 1;
                        }
                    }
                }
            }
        }
        let mut list = self.fallback_dns_domains.lock();
        let mut seen: std::collections::HashSet<String> = list.iter().cloned().collect();
        for d in domains {
            seen.insert(d.clone());
        }
        *list = seen.into_iter().collect();
        added
    }

    /// Batch-sync ports into the kernel BLOCKED_PORTS map.
    pub fn sync_blocked_ports(&mut self, ports: &[u16]) -> usize {
        let mut added = 0;
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("BLOCKED_PORTS") {
                if let Ok(mut map) = HashMap::<&mut MapData, u16, u32>::try_from(map) {
                    for p in ports {
                        if map.insert(p, &1, 0).is_ok() {
                            added += 1;
                        }
                    }
                }
            }
        }
        let mut list = self.fallback_blocked_ports.lock();
        let mut seen: std::collections::HashSet<u16> = list.iter().copied().collect();
        for p in ports {
            seen.insert(*p);
        }
        *list = seen.into_iter().collect();
        added
    }

    /// Number of domains in the kernel/fallback DNS blocklist.
    pub fn blocked_domain_count(&self) -> usize {
        self.fallback_dns_domains.lock().len()
    }

    /// Sync the literal DPI patterns into the kernel DPI_PATTERNS map.
    ///
    /// Patterns are stored under *sequential* keys 0..N because the kernel
    /// scanner iterates that range (see `dpi_scan_packet`). The real signature
    /// rule id for each index lives in `BPF_DPI_RULE_IDS`, index-aligned with
    /// `BPF_DPI_SIGNATURES`.
    pub fn sync_dpi_patterns(&mut self, patterns: &[(u32, &[u8])]) -> usize {
        debug_assert_eq!(
            patterns.len(),
            BPF_DPI_RULE_IDS.len(),
            "BPF_DPI_RULE_IDS must stay index-aligned with BPF_DPI_SIGNATURES"
        );
        let mut added = 0usize;
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("DPI_PATTERNS") {
                if let Ok(mut map) = HashMap::<&mut MapData, u32, DpiPattern>::try_from(map) {
                    for (idx, (_rule_id, bytes)) in patterns.iter().enumerate() {
                        let n = bytes.len().min(32);
                        let mut pat = DpiPattern {
                            len: n as u8,
                            data: [0u8; 32],
                        };
                        pat.data[..n].copy_from_slice(&bytes[..n]);
                        if map.insert(idx as u32, &pat, 0).is_ok() {
                            added += 1;
                        }
                    }
                }
            }
        }
        added
    }

    /// Set DPI enforcement (drop on match). Off by default = observe-only.
    pub fn set_dpi_enforce(&mut self, enforce: bool) {
        // Only act (map write + log) when the mode actually changes — the
        // governor tick used to call this every 5s, writing the map and
        // logging every time (17k+ log lines/day) regardless of state.
        let changed = if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("DPI_MODE") {
                if let Ok(mut map) = HashMap::<&mut MapData, u32, u8>::try_from(map) {
                    let current = map.get(&1, 0).ok().unwrap_or(0);
                    let next = if enforce { 1u8 } else { 0u8 };
                    if current == next {
                        false
                    } else {
                        let _ = map.insert(&1, &next, 0);
                        true
                    }
                } else {
                    false
                }
            } else {
                false
            }
        } else {
            false
        };
        if changed {
            if enforce {
                info!("DPI enforcement enabled — matching traffic will be dropped");
            } else {
                info!("DPI in observe mode — matching traffic is reported, not dropped");
            }
        }
    }

    /// Number of blocked ports.
    pub fn blocked_port_count(&self) -> usize {
        self.fallback_blocked_ports.lock().len()
    }

    /// Toggle per-packet event sampling in the kernel. `enabled=false`
    /// (governor critical) writes key 1 value 0 to SAMPLING_ENABLED, which
    /// suppresses PacketEvent emission while keeping all block checks active.
    pub fn set_sampling_enabled(&mut self, enabled: bool) {
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("SAMPLING_ENABLED") {
                if let Ok(mut map) = HashMap::<&mut MapData, u32, u8>::try_from(map) {
                    if enabled {
                        let _ = map.remove(&1);
                    } else {
                        let _ = map.insert(&1, &0, 0);
                    }
                }
            }
        }
    }

    /// Mark a 5-tuple as established/trusted in the kernel `ESTABLISHED_FLOWS`
    /// map so the XDP/TC fast path skips per-packet DPI + event emission for
    /// that flow. This is what makes "flow offloaded" real: previously the
    /// kernel map was never populated, so no flow was ever skipped.
    pub fn mark_flow_established(&mut self, key: &ring0_abi::FlowKey) -> Result<()> {
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("ESTABLISHED_FLOWS") {
                if let Ok(mut map) = HashMap::<&mut MapData, KernelFlowKey, u32>::try_from(map) {
                    map.insert(&KernelFlowKey(*key), &1, 0)?;
                    return Ok(());
                }
                anyhow::bail!("ESTABLISHED_FLOWS map type mismatch");
            }
            anyhow::bail!("ESTABLISHED_FLOWS map not found");
        }
        // Fallback mode (no kernel programs): nothing to mark; offload is a
        // userspace-only mirror.
        Ok(())
    }

    pub fn detach(&mut self) {
        // E22: signal the ring-reader threads and join them so they don't
        // spin forever after the programs are unloaded (they wake within ~1ms).
        for stop in &self.ring_stops {
            stop.store(true, Ordering::Relaxed);
        }
        for handle in self.ring_handles.drain(..) {
            let _ = handle.join();
        }
        // Dropping the Ebpf object detaches all programs.
        if let Some(ebpf) = self.ebpf.take() {
            drop(ebpf);
            info!("eBPF programs detached");
        }
    }

    /// Periodically re-scan the system for up, non-loopback interfaces and
    /// attach XDP/TC to any that are not yet covered. Previously enforcement
    /// was bound to the single default-route interface at startup, so a
    /// Wi-Fi→cellular/VPN route switch silently moved traffic onto an
    /// unattached interface.
    /// Reset all per-connection TLS scan budgets. Called on the periodic
    /// intel tick so the budget map cannot fill with spent connections
    /// forever (fresh connections would stop being scanned). A reset costs
    /// each live connection one more ~8KB of re-inspection per hour — a
    /// bounded, negligible re-scan of ongoing flows.
    /// Budget override for untrusted/suspicious processes (script hosts,
    /// /tmp binaries, unsigned builds). Must match TLS_UNTRUSTED_BUDGET in
    /// ring0-ebpf/src/main.rs.
    pub const TLS_UNTRUSTED_BUDGET: u32 = 32768;

    pub fn set_pid_budget(&mut self, pid: u32, budget: u32) {
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("TLS_PID_BUDGET") {
                if let Ok(mut map) = HashMap::<&mut MapData, u32, u32>::try_from(map) {
                    let _ = map.insert(pid, budget, 0);
                }
            }
        }
    }

    pub fn clear_pid_budgets(&mut self) {
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("TLS_PID_BUDGET") {
                if let Ok(mut map) = HashMap::<&mut MapData, u32, u32>::try_from(map) {
                    let keys: Vec<u32> = map.keys().filter_map(Result::ok).collect();
                    for k in keys {
                        let _ = map.remove(&k);
                    }
                }
            }
        }
    }

    pub fn clear_tls_budgets(&mut self) {
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("TLS_FLOW_BUDGET") {
                if let Ok(mut map) = HashMap::<&mut MapData, u64, u32>::try_from(map) {
                    let keys: Vec<u64> = map.keys().filter_map(Result::ok).collect();
                    let mut cleared = 0u32;
                    for k in keys {
                        if map.remove(&k).is_ok() {
                            cleared += 1;
                        }
                    }
                    if cleared > 0 {
                        info!("cleared {cleared} per-connection TLS scan budgets");
                    }
                }
            }
        }
    }

    pub fn scan_interfaces(&mut self) {
        if self.ebpf.is_none() {
            return;
        }
        let mut attached = self.attached_interfaces.lock();
        for iface in list_up_interfaces() {
            if attached.contains(&iface) {
                continue;
            }
            if let Some(ebpf) = self.ebpf.as_mut() {
                match attach_xdp(ebpf, &iface) {
                    Ok(()) => {
                        let _ = attach_tc(ebpf, &iface);
                        info!("XDP/TC attached on newly seen interface {iface}");
                        attached.push(iface.clone());
                    }
                    Err(e) => {
                        // Not every driver supports XDP; don't re-try forever,
                        // but remember it so we only warn once per interface.
                        attached.push(iface.clone());
                        warn!("XDP attach skipped on {iface}: {e}");
                    }
                }
            }
        }
    }
}

/// Enumerate up, non-loopback interfaces from /sys/class/net.
fn list_up_interfaces() -> Vec<String> {
    let mut out = Vec::new();
    let Ok(dir) = std::fs::read_dir("/sys/class/net") else {
        return out;
    };
    for entry in dir.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name == "lo" {
            continue;
        }
        let operstate =
            std::fs::read_to_string(format!("/sys/class/net/{name}/operstate")).unwrap_or_default();
        if operstate.trim() == "up" {
            out.push(name);
        }
    }
    out
}

type LpmTrieKey = aya::maps::lpm_trie::Key<u32>;

fn attach_xdp(ebpf: &mut Ebpf, iface: &str) -> Result<()> {
    // aya 0.14 names programs by their ELF symbol (the Rust fn name), NOT the
    // section name — `program_mut("xdp")` never matched and no program ever
    // attached, silently disabling all kernel enforcement.
    let program: &mut Xdp = ebpf
        .program_mut("ring0_xdp")
        .context("xdp program not found")?
        .try_into()?;
    program.load()?; // aya >= 0.13 requires an explicit load before attach
    program.attach(iface, XdpMode::default())?;
    Ok(())
}

fn attach_tc(ebpf: &mut Ebpf, iface: &str) -> Result<()> {
    use aya::programs::tc;
    // clsact is not idempotent to add: a daemon restart (or scan_interfaces
    // re-run) hits "Exclusivity flag on, cannot modify" because the qdisc
    // already exists — treat "already attached" as success.
    if let Err(e) = tc::qdisc_add_clsact(iface) {
        let already = matches!(&e, aya::programs::tc::TcError::AlreadyAttached)
            || e.to_string().contains("Exclusivity");
        if !already {
            return Err(e.into());
        }
    }
    let program: &mut SchedClassifier = ebpf
        .program_mut("ring0_tc")
        .context("tc classifier not found")?
        .try_into()?;
    program.load()?; // aya >= 0.13 requires an explicit load before attach
    program.attach(iface, TcAttachType::Ingress)?;
    Ok(())
}

fn attach_tracepoint(ebpf: &mut Ebpf, name: &str, btf: &aya::Btf) -> Result<()> {
    // Section name -> (program symbol, tracepoint name). aya 0.14 names
    // programs by symbol and BtfTracePoint::load requires the BTF id of the
    // kernel tracepoint.
    let (symbol, tp) = match name {
        "tp_btf/sched_process_exec" => ("ring0_sched_exec", "sched_process_exec"),
        "tp_btf/sys_enter" => ("ring0_sys_enter", "sys_enter"),
        other => (other, other),
    };
    let program: &mut BtfTracePoint = ebpf
        .program_mut(symbol)
        .context("program not found")?
        .try_into()?;
    program.load(tp, btf)?;
    program.attach()?;
    Ok(())
}

fn attach_lsm(ebpf: &mut Ebpf, name: &str, btf: &aya::Btf) -> Result<()> {
    // Section name -> (program symbol, LSM hook name). aya 0.14 names
    // programs by symbol and Lsm::load requires the bpf_lsm_* hook BTF id.
    let (symbol, hook) = match name {
        "lsm/file_open" => ("ring0_lsm_file_open", "file_open"),
        "lsm/bprm_check" => ("ring0_lsm_bprm_check", "bprm_check"),
        "lsm/socket_connect" => ("ring0_lsm_socket_connect", "socket_connect"),
        "lsm/ptrace_access_check" => ("ring0_lsm_ptrace", "ptrace_access_check"),
        "lsm/capable" => ("ring0_lsm_capable", "capable"),
        other => (other, other),
    };
    let program: &mut Lsm = ebpf
        .program_mut(symbol)
        .context("program not found")?
        .try_into()?;
    program.load(hook, btf)?;
    program.attach()?;
    Ok(())
}

fn attach_uprobes(ebpf: &mut Ebpf) -> Result<()> {
    use aya::programs::uprobe::UProbeScope;
    use aya::programs::UProbe;
    // Attach to EVERY libssl instance on the system, not just /usr/lib64:
    // conda/homebrew/etc. bundle their own libssl (e.g. anaconda's curl
    // loads ~/anaconda3/lib/libssl.so.3), which a single-path attach would
    // silently miss.
    let libssl_paths = find_libssl_paths();
    if libssl_paths.is_empty() {
        anyhow::bail!("no libssl found on the system");
    }
    info!(
        "attaching TLS uprobes to {} libssl path(s)",
        libssl_paths.len()
    );
    // Each #[uprobe] fn is its own program named by symbol (aya 0.14).
    // Attach both independently; a failure on one must not drop the others.
    let pairs = [
        ("ring0_ssl_write", "SSL_write"),
        ("ring0_ssl_read", "SSL_read"),
    ];
    // Each #[uprobe] fn is one program object: load it ONCE, then attach it
    // to every libssl path (aya supports multiple managed links per probe).
    for (symbol, fn_name) in pairs {
        let program: &mut UProbe = match ebpf
            .program_mut(symbol)
            .with_context(|| format!("uprobe program {symbol} not found"))?
            .try_into()
        {
            Ok(p) => p,
            Err(e) => {
                warn!("uprobe {symbol} load failed: {e}");
                continue;
            }
        };
        if let Err(e) = program.load() {
            warn!("uprobe {symbol} load failed: {e}");
            continue;
        }
        for libssl in &libssl_paths {
            match program.attach(fn_name, libssl, UProbeScope::AllProcesses) {
                Ok(_) => info!("uprobe {symbol} -> {fn_name} attached ({libssl})"),
                Err(e) => warn!("uprobe {symbol} attach failed on {libssl}: {e}"),
            }
        }
    }
    Ok(())
}

/// All libssl shared-library paths on the system: common fixed locations
/// plus every `libssl.so.3` listed by the dynamic linker cache (catches
/// conda/homebrew/user-installed copies).
fn find_libssl_paths() -> Vec<String> {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    let mut paths = Vec::new();
    let mut push = |p: &str| {
        if std::path::Path::new(p).exists() && seen.insert(p.to_string()) {
            paths.push(p.to_string());
        }
    };
    for p in [
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so",
        "/lib64/libssl.so.3",
    ] {
        push(p);
    }
    // User-space copies: conda/miniconda/venvs bundle their own libssl (e.g.
    // anaconda's curl resolves ~/anaconda3/lib/libssl.so.3, which ldconfig
    // does not list). The daemon may run as root, so probe /home/* rather
    // than $HOME, plus a root-local fallback.
    for sub in [
        "/anaconda3/lib/libssl.so.3",
        "/miniconda3/lib/libssl.so.3",
        "/miniconda/lib/libssl.so.3",
        "/.local/lib/libssl.so.3",
        "/.local/lib/x86_64-linux-gnu/libssl.so.3",
    ] {
        push(&format!("/root{sub}"));
        if let Ok(entries) = std::fs::read_dir("/home") {
            for e in entries.flatten() {
                push(&format!("{}{}", e.path().display(), sub));
            }
        }
    }
    // Dynamic linker cache: `ldconfig -p` lines look like
    //   libssl.so.3 (libc6,x86-64) => /path/to/libssl.so.3
    if let Ok(out) = std::process::Command::new("ldconfig").arg("-p").output() {
        let text = String::from_utf8_lossy(&out.stdout);
        for line in text.lines() {
            let line = line.trim();
            if line.contains("libssl.so") {
                if let Some(idx) = line.rfind("=> ") {
                    push(line[idx + 3..].trim());
                }
            }
        }
    }
    paths
}

fn spawn_ring_reader(
    ebpf: &mut Ebpf,
    map_name: &str,
    tx: broadcast::Sender<Vec<u8>>,
) -> Option<(Arc<AtomicBool>, std::thread::JoinHandle<()>)> {
    let map = ebpf.take_map(map_name)?;
    let mut ring = match RingBuf::try_from(map) {
        Ok(r) => r,
        Err(e) => {
            warn!("ring buffer {map_name} setup failed: {e}");
            return None;
        }
    };
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let handle = std::thread::Builder::new()
        .name(format!("ring0-{map_name}-reader"))
        .spawn(move || {
            while !stop_for_thread.load(Ordering::Relaxed) {
                while let Some(item) = ring.next() {
                    let bytes = item.to_vec();
                    // The broadcast channel drops messages when there are no
                    // receivers; a send error must NOT kill the reader. The
                    // daemon's run loop subscribes a moment after this reader
                    // starts (the attach phase races the subscription), and an
                    // exec/packet event in that window used to terminate the
                    // RING_BUF reader permanently — after which the daemon ran
                    // with zero live packet/process events while the "ring
                    // reader started" log said otherwise.
                    let _ = tx.send(bytes);
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        })
        .ok()?;
    info!("ring reader started for {map_name}");
    Some((stop, handle))
}
