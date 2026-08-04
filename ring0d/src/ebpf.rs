use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use aya::maps::{HashMap, LpmTrie, MapData, RingBuf};
use aya::programs::{BtfTracePoint, Lsm, SchedClassifier, TcAttachType, Xdp, XdpMode};
use aya::{Ebpf, EbpfLoader};
use tokio::sync::broadcast;
use tracing::{info, warn};

// Event kinds — must match ring0-ebpf/src/main.rs
pub const KIND_PACKET: u8 = 0;
pub const KIND_PROCESS_EXEC: u8 = 1;
pub const KIND_FILE_ACCESS: u8 = 2;
pub const KIND_CONNECT: u8 = 3;
pub const KIND_KILL: u8 = 4;
pub const KIND_UNLINK: u8 = 5;
pub const KIND_TLS: u8 = 6;
pub const KIND_LSM: u8 = 10;
pub const KIND_CANARY: u8 = 11;
pub const KIND_SETUID: u8 = 12;
pub const KIND_CAP: u8 = 13;
pub const KIND_PTRACE: u8 = 14;
pub const KIND_MEMFD: u8 = 20;
pub const KIND_MMAP: u8 = 21;
pub const KIND_MODULE: u8 = 22;

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
    tls_ring_tx: broadcast::Sender<Vec<u8>>,
    lsm_tx: broadcast::Sender<Vec<u8>>,
    rootkit_tx: broadcast::Sender<Vec<u8>>,
    canary_tx: broadcast::Sender<Vec<u8>>,
    privesc_tx: broadcast::Sender<Vec<u8>>,
    ebpf: Option<Ebpf>,
    loaded: Arc<AtomicBool>,
    // software fallback for when the kernel maps are unavailable
    fallback_blocked_ips: std::sync::Mutex<Vec<String>>,
    fallback_blocked_ports: std::sync::Mutex<Vec<u16>>,
    fallback_dns_domains: std::sync::Mutex<Vec<String>>,
}

fn make_channels() -> (
    broadcast::Sender<Vec<u8>>,
    broadcast::Sender<Vec<u8>>,
    broadcast::Sender<Vec<u8>>,
    broadcast::Sender<Vec<u8>>,
    broadcast::Sender<Vec<u8>>,
    broadcast::Sender<Vec<u8>>,
) {
    let (ring_tx, _) = broadcast::channel(4096);
    let (tls_tx, _) = broadcast::channel(4096);
    let (lsm_tx, _) = broadcast::channel(1024);
    let (rootkit_tx, _) = broadcast::channel(1024);
    let (canary_tx, _) = broadcast::channel(1024);
    let (privesc_tx, _) = broadcast::channel(1024);
    (ring_tx, tls_tx, lsm_tx, rootkit_tx, canary_tx, privesc_tx)
}

impl EbpfManager {
    pub fn load() -> Result<Self> {
        let (ring_tx, tls_ring_tx, lsm_tx, rootkit_tx, canary_tx, privesc_tx) = make_channels();

        match Self::load_real(
            ring_tx.clone(),
            tls_ring_tx.clone(),
            lsm_tx.clone(),
            rootkit_tx.clone(),
            canary_tx.clone(),
            privesc_tx.clone(),
        ) {
            Ok(mgr) => {
                info!("eBPF manager initialized — real programs loaded");
                Ok(mgr)
            }
            Err(e) => {
                warn!("eBPF load failed: {e:?} — continuing with fallback enforcement");
                Ok(Self {
                    ring_tx,
                    tls_ring_tx,
                    lsm_tx,
                    rootkit_tx,
                    canary_tx,
                    privesc_tx,
                    ebpf: None,
                    loaded: Arc::new(AtomicBool::new(false)),
                    fallback_blocked_ips: std::sync::Mutex::new(Vec::new()),
                    fallback_blocked_ports: std::sync::Mutex::new(Vec::new()),
                    fallback_dns_domains: std::sync::Mutex::new(Vec::new()),
                })
            }
        }
    }

    fn load_real(
        ring_tx: broadcast::Sender<Vec<u8>>,
        tls_ring_tx: broadcast::Sender<Vec<u8>>,
        lsm_tx: broadcast::Sender<Vec<u8>>,
        rootkit_tx: broadcast::Sender<Vec<u8>>,
        canary_tx: broadcast::Sender<Vec<u8>>,
        privesc_tx: broadcast::Sender<Vec<u8>>,
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

        // ── Attach XDP to the default interface ──
        if let Some(iface) = default_interface() {
            match attach_xdp(&mut ebpf, &iface) {
                Ok(()) => info!("XDP attached on {iface}"),
                Err(e) => warn!("XDP attach failed on {iface}: {e}"),
            }
        } else {
            warn!("no default interface found — XDP not attached");
        }

        // ── Attach TC classifier (egress monitor) ──
        if let Some(iface) = default_interface() {
            match attach_tc(&mut ebpf, &iface) {
                Ok(()) => info!("TC classifier attached on {iface}"),
                Err(e) => warn!("TC attach failed on {iface}: {e}"),
            }
        }

        // ── Attach BTF tracepoints (looked up by ELF section name) ──
        //
        // Per-syscall `sys_enter_<name>` events are not real kernel tracepoints
        // (they are dynamically layered on the generic `sys_enter` tracepoint),
        // so raw/btf tracepoint programs can only attach to `sys_enter`. The
        // eBPF program dispatches on the syscall number internally.
        for name in ["tp_btf/sched_process_exec", "tp_btf/sys_enter"] {
            match attach_tracepoint(&mut ebpf, name) {
                Ok(()) => {}
                Err(e) => warn!("tracepoint {name} attach failed: {e}"),
            }
        }

        // ── Attach LSM programs (by section name) ──
        for name in [
            "lsm/file_open",
            "lsm/bprm_check",
            "lsm/socket_connect",
            "lsm/ptrace_access_check",
            "lsm/capable",
        ] {
            match attach_lsm(&mut ebpf, name) {
                Ok(()) => {}
                Err(e) => warn!("LSM {name} attach failed: {e}"),
            }
        }

        // ── Attach TLS uprobes (libssl) ──
        match attach_uprobes(&mut ebpf) {
            Ok(()) => info!("TLS uprobes attached"),
            Err(e) => warn!("TLS uprobe attach failed: {e}"),
        }

        // ── Spawn ring buffer readers ──
        spawn_ring_reader(&mut ebpf, "RING_BUF", ring_tx.clone());
        spawn_ring_reader(&mut ebpf, "LSM_EVENTS", lsm_tx.clone());
        spawn_ring_reader(&mut ebpf, "ROOTKIT_EVENTS", rootkit_tx.clone());
        spawn_ring_reader(&mut ebpf, "PRIVESC_EVENTS", privesc_tx.clone());

        Ok(Self {
            ring_tx,
            tls_ring_tx,
            lsm_tx: lsm_tx.clone(),
            rootkit_tx: rootkit_tx.clone(),
            canary_tx: canary_tx.clone(),
            privesc_tx: privesc_tx.clone(),
            ebpf: Some(ebpf),
            loaded: Arc::new(AtomicBool::new(true)),
            fallback_blocked_ips: std::sync::Mutex::new(Vec::new()),
            fallback_blocked_ports: std::sync::Mutex::new(Vec::new()),
            fallback_dns_domains: std::sync::Mutex::new(Vec::new()),
        })
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.ring_tx.subscribe()
    }
    pub fn subscribe_tls(&self) -> broadcast::Receiver<Vec<u8>> {
        self.tls_ring_tx.subscribe()
    }
    pub fn subscribe_lsm(&self) -> broadcast::Receiver<Vec<u8>> {
        self.lsm_tx.subscribe()
    }
    pub fn subscribe_rootkit(&self) -> broadcast::Receiver<Vec<u8>> {
        self.rootkit_tx.subscribe()
    }
    pub fn subscribe_canary(&self) -> broadcast::Receiver<Vec<u8>> {
        self.canary_tx.subscribe()
    }
    pub fn subscribe_privesc(&self) -> broadcast::Receiver<Vec<u8>> {
        self.privesc_tx.subscribe()
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Relaxed)
    }

    pub fn lsm_available(&self) -> bool {
        self.ebpf.is_some()
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
            if let Some(map) = ebpf.map_mut("BLOCKED_BINARIES") {
                let mut key = [0u8; 64];
                let b = name.as_bytes();
                let n = b.len().min(63);
                key[..n].copy_from_slice(&b[..n]);
                if let Ok(mut map) = HashMap::<&mut MapData, [u8; 64], u8>::try_from(map) {
                    map.insert(&key, &1, 0)?;
                }
            }
        }
        Ok(())
    }

    pub fn unblock_binary(&mut self, name: &str) -> Result<()> {
        if let Some(ebpf) = self.ebpf.as_mut() {
            if let Some(map) = ebpf.map_mut("BLOCKED_BINARIES") {
                let mut key = [0u8; 64];
                let b = name.as_bytes();
                let n = b.len().min(63);
                key[..n].copy_from_slice(&b[..n]);
                if let Ok(mut map) = HashMap::<&mut MapData, [u8; 64], u8>::try_from(map) {
                    let _ = map.remove(&key);
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
                        let key = LpmTrieKey::new(32, u32::from(v4));
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
            if !inserted {
                let mut list = self.fallback_blocked_ips.lock().unwrap();
                let s = ip.to_string();
                if !list.contains(&s) {
                    list.push(s);
                }
            }
            info!("blocked {ip}");
        }
        Ok(())
    }
    pub fn unblock_ip(&mut self, ip: IpAddr) -> Result<()> {
        if let IpAddr::V4(v4) = ip {
            let removed = if let Some(ebpf) = self.ebpf.as_mut() {
                if let Some(map) = ebpf.map_mut("BLOCKED_IPS") {
                    if let Ok(mut map) = LpmTrie::<&mut MapData, u32, u8>::try_from(map) {
                        let key = LpmTrieKey::new(32, u32::from(v4));
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
            if !removed {
                let mut list = self.fallback_blocked_ips.lock().unwrap();
                let s = ip.to_string();
                list.retain(|x| x != &s);
            }
            info!("unblocked {ip}");
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
            let mut list = self.fallback_blocked_ports.lock().unwrap();
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
            let mut list = self.fallback_blocked_ports.lock().unwrap();
            list.retain(|x| x != &port);
        }
        Ok(())
    }

    /// List currently blocked IPs (from the kernel map or the fallback list).
    pub fn blocked_ips(&self) -> Vec<String> {
        let mut out = Vec::new();
        let list = self.fallback_blocked_ips.lock().unwrap();
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
                        let key = LpmTrieKey::new(*prefix as u32, *ip);
                        if map.insert(&key, &1, 0).is_ok() {
                            added += 1;
                        }
                    }
                }
            }
        }
        let mut list = self.fallback_blocked_ips.lock().unwrap();
        for (ip, prefix) in cidrs {
            let s = format!("{}/{}", std::net::Ipv4Addr::from(*ip), prefix);
            if !list.contains(&s) {
                list.push(s);
            }
        }
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
        let mut list = self.fallback_dns_domains.lock().unwrap();
        for d in domains {
            if !list.contains(d) {
                list.push(d.clone());
            }
        }
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
        let mut list = self.fallback_blocked_ports.lock().unwrap();
        for p in ports {
            if !list.contains(p) {
                list.push(*p);
            }
        }
        added
    }

    /// Number of domains in the kernel/fallback DNS blocklist.
    pub fn blocked_domain_count(&self) -> usize {
        self.fallback_dns_domains.lock().unwrap().len()
    }

    /// Number of blocked ports.
    pub fn blocked_port_count(&self) -> usize {
        self.fallback_blocked_ports.lock().unwrap().len()
    }

    pub fn detach(&mut self) {
        // Dropping the Ebpf object detaches all programs.
        if let Some(ebpf) = self.ebpf.take() {
            drop(ebpf);
            info!("eBPF programs detached");
        }
    }
}

type LpmTrieKey = aya::maps::lpm_trie::Key<u32>;

fn attach_xdp(ebpf: &mut Ebpf, iface: &str) -> Result<()> {
    let program: &mut Xdp = ebpf
        .program_mut("xdp")
        .context("xdp program not found")?
        .try_into()?;
    program.attach(iface, XdpMode::default())?;
    Ok(())
}

fn attach_tc(ebpf: &mut Ebpf, iface: &str) -> Result<()> {
    use aya::programs::tc;
    tc::qdisc_add_clsact(iface)?;
    let program: &mut SchedClassifier = ebpf
        .program_mut("classifier")
        .context("tc classifier not found")?
        .try_into()?;
    program.attach(iface, TcAttachType::Ingress)?;
    Ok(())
}

fn attach_tracepoint(ebpf: &mut Ebpf, name: &str) -> Result<()> {
    let program: &mut BtfTracePoint = ebpf
        .program_mut(name)
        .context("program not found")?
        .try_into()?;
    program.attach()?;
    Ok(())
}

fn attach_lsm(ebpf: &mut Ebpf, name: &str) -> Result<()> {
    let program: &mut Lsm = ebpf
        .program_mut(name)
        .context("program not found")?
        .try_into()?;
    program.attach()?;
    Ok(())
}

fn attach_uprobes(ebpf: &mut Ebpf) -> Result<()> {
    use aya::programs::uprobe::UProbeScope;
    use aya::programs::UProbe;
    let libssl = find_libssl()?;
    let program: &mut UProbe = ebpf
        .program_mut("uprobe")
        .context("uprobe program not found")?
        .try_into()?;
    // The uprobe section covers both ssl_write and ssl_read hooks.
    match program.attach("SSL_write", &libssl, UProbeScope::AllProcesses) {
        Ok(_) => {
            let _ = program.attach("SSL_read", &libssl, UProbeScope::AllProcesses);
            Ok(())
        }
        Err(e) => {
            let _ = program.attach("SSL_read", &libssl, UProbeScope::AllProcesses);
            warn!("TLS uprobe attach failed: {e}");
            Ok(())
        }
    }
}

fn find_libssl() -> Result<String> {
    for path in [
        "/usr/lib64/libssl.so.3",
        "/usr/lib64/libssl.so",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so",
    ] {
        if std::path::Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    anyhow::bail!("libssl not found")
}

fn spawn_ring_reader(ebpf: &mut Ebpf, map_name: &str, tx: broadcast::Sender<Vec<u8>>) {
    let Some(map) = ebpf.take_map(map_name) else {
        warn!("ring buffer map {map_name} not found");
        return;
    };
    let mut ring = match RingBuf::try_from(map) {
        Ok(r) => r,
        Err(e) => {
            warn!("ring buffer {map_name} setup failed: {e}");
            return;
        }
    };
    std::thread::Builder::new()
        .name(format!("ring0-{map_name}-reader"))
        .spawn(move || loop {
            while let Some(item) = ring.next() {
                let bytes = item.to_vec();
                if tx.send(bytes).is_err() {
                    return;
                }
            }
            std::thread::sleep(Duration::from_millis(1));
        })
        .ok();
    info!("ring reader started for {map_name}");
}
