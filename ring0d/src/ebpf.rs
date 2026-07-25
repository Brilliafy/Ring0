use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Context, Result};
use aya::{
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, LpmTrie as AyaLpmTrie, LruHashMap, RingBuf},
    programs::{BtfTracePoint, Tc, UProbe, Xdp},
    Bpf,
};
use tokio::sync::broadcast;
use tracing::{error, info, warn};

const SSL_PATHS: &[&str] = &[
    "/usr/lib64/libssl.so.3",
    "/usr/lib/x86_64-linux-gnu/libssl.so.3",
    "/usr/lib/aarch64-linux-gnu/libssl.so.3",
    "/usr/lib64/libssl.so.1.1",
    "/usr/lib/x86_64-linux-gnu/libssl.so.1.1",
    "/lib64/libssl.so.1.1",
];

fn find_libssl() -> Option<String> {
    SSL_PATHS
        .iter()
        .find(|p| Path::new(p).exists())
        .map(|p| p.to_string())
}

fn check_btf_availability() {
    let btf_path = "/sys/kernel/btf/vmlinux";
    if Path::new(btf_path).exists() {
        match fs::metadata(btf_path) {
            Ok(meta) if meta.len() > 0 => {
                info!(
                    "BTF vmlinux found at {btf_path} ({} bytes) — CO-RE relocations enabled",
                    meta.len()
                );
            }
            Ok(_) => {
                warn!(
                    "BTF vmlinux exists but is empty — CO-RE may fail, falling back to legacy mode"
                );
            }
            Err(e) => {
                warn!("BTF vmlinux stat failed: {e} — falling back to legacy tracepoint mode");
            }
        }
    } else {
        warn!("{btf_path} not found — kernel BTF unavailable, CO-RE disabled");
        warn!("eBPF programs will run in legacy mode without CO-RE relocations");
    }
}

pub struct EbpfManager {
    bpf: Option<Bpf>,
    ring_tx: broadcast::Sender<Vec<u8>>,
    tls_ring_tx: broadcast::Sender<Vec<u8>>,
    rootkit_tx: broadcast::Sender<Vec<u8>>,
    canary_tx: broadcast::Sender<Vec<u8>>,
    privesc_tx: broadcast::Sender<Vec<u8>>,
    rx_task: Option<tokio::task::JoinHandle<()>>,
    tls_rx_task: Option<tokio::task::JoinHandle<()>>,
    rootkit_rx_task: Option<tokio::task::JoinHandle<()>>,
    canary_rx_task: Option<tokio::task::JoinHandle<()>>,
    privesc_rx_task: Option<tokio::task::JoinHandle<()>>,
}

impl EbpfManager {
    pub fn load() -> Result<Self> {
        Self::check_btf_availability();

        let mut bpf = Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/ring0-ebpf"
        ))
        .context("failed to load eBPF object")?;

        let prog_xdp: &mut Xdp = bpf
            .program_mut("ring0_xdp")
            .context("ring0_xdp not found")?
            .try_into()
            .map_err(|e| anyhow::anyhow!("XDP program type mismatch: {e:?}"))?;
        prog_xdp.load().context("XDP load failed")?;
        prog_xdp.attach("lo").context("XDP attach to lo failed")?;
        info!("XDP program attached to lo");

        let prog_tc: &mut Tc = bpf
            .program_mut("ring0_tc")
            .context("ring0_tc not found")?
            .try_into()
            .map_err(|e| anyhow::anyhow!("TC program type mismatch: {e:?}"))?;
        prog_tc.load().context("TC load failed")?;
        prog_tc
            .attach("lo", aya::programs::TcAttachType::Ingress)
            .context("TC attach to lo failed")?;
        info!("TC classifier attached to lo");

        let tracepoints = ["ring0_sched_exec", "ring0_openat", "ring0_connect"];
        for name in &tracepoints {
            let prog: &mut BtfTracePoint = bpf
                .program_mut(name)
                .with_context(|| format!("{name} tracepoint not found"))?
                .try_into()
                .map_err(|e| anyhow::anyhow!("{name} type mismatch: {e:?}"))?;
            prog.load().with_context(|| format!("{name} load failed"))?;
            prog.attach()
                .with_context(|| format!("{name} attach failed"))?;
            info!("{name} tracepoint attached");
        }

        let rootkit_tps = ["ring0_memfd_create", "ring0_mmap", "ring0_finit_module"];
        for name in &rootkit_tps {
            if let Ok(prog) = bpf.program_mut(name) {
                let tp: &mut BtfTracePoint = match prog.try_into() {
                    Ok(p) => p,
                    Err(e) => {
                        warn!("{name} type mismatch: {e:?}");
                        continue;
                    }
                };
                if let Err(e) = tp.load() {
                    warn!("{name} load failed: {e:?}");
                    continue;
                }
                if let Err(e) = tp.attach() {
                    warn!("{name} attach failed: {e:?}");
                    continue;
                }
                info!("{name} rootkit tracepoint attached");
            } else {
                warn!("{name} not found in eBPF object");
            }
        }

        let (tx, _) = broadcast::channel(4096);
        let (tls_tx, _) = broadcast::channel(4096);
        let (rootkit_tx, _) = broadcast::channel(4096);
        let (canary_tx, _) = broadcast::channel(1024);
        let (privesc_tx, _) = broadcast::channel(1024);

        let mut ring =
            RingBuf::try_from(bpf.map_mut("RING_BUF").context("RING_BUF map not found")?)
                .context("failed to open ring buf")?;
        let tx_clone = tx.clone();

        let rx_task = tokio::task::spawn_blocking(move || {
            while let Some(data) = ring.next() {
                if tx_clone.send(data.to_vec()).is_err() {
                    break;
                }
            }
        });

        let tls_rx_task = Self::try_attach_uprobes(&mut bpf, &tls_tx);

        let rootkit_rx_task = Self::try_attach_rootkit_ring(&mut bpf, &rootkit_tx);
        let canary_rx_task = Self::try_attach_canary_ring(&mut bpf, &canary_tx);
        let privesc_rx_task = Self::try_attach_privesc_ring(&mut bpf, &privesc_tx);

        Ok(Self {
            bpf: Some(bpf),
            ring_tx: tx,
            tls_ring_tx: tls_tx,
            rootkit_tx,
            canary_tx,
            privesc_tx,
            rx_task: Some(rx_task),
            tls_rx_task,
            rootkit_rx_task,
            canary_rx_task,
            privesc_rx_task,
        })
    }

    fn try_attach_uprobes(
        bpf: &mut Bpf,
        tls_tx: &broadcast::Sender<Vec<u8>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let libssl_path = match find_libssl() {
            Some(p) => p,
            None => {
                warn!("libssl.so not found on any expected path, TLS uprobes disabled");
                return None;
            }
        };

        let attach_write = (|| -> Result<()> {
            let prog: &mut UProbe = bpf
                .program_mut("ring0_ssl_write")
                .context("ring0_ssl_write not found")?
                .try_into()
                .map_err(|e| anyhow::anyhow!("uprobe type mismatch: {e:?}"))?;
            prog.load().context("SSL_write uprobe load failed")?;
            prog.attach(Some("SSL_write"), 0, &libssl_path, None)
                .context("SSL_write attach failed")?;
            Ok(())
        })();

        if let Err(e) = attach_write {
            warn!("SSL_write uprobe attach failed (TLS disabled): {e:?}");
            return None;
        }

        let attach_read = (|| -> Result<()> {
            let prog: &mut UProbe = bpf
                .program_mut("ring0_ssl_read")
                .context("ring0_ssl_read not found")?
                .try_into()
                .map_err(|e| anyhow::anyhow!("uprobe type mismatch: {e:?}"))?;
            prog.load().context("SSL_read uprobe load failed")?;
            prog.attach(Some("SSL_read"), 0, &libssl_path, None)
                .context("SSL_read attach failed")?;
            Ok(())
        })();

        if let Err(e) = attach_read {
            warn!("SSL_read uprobe attach failed (TLS disabled): {e:?}");
            return None;
        }

        info!("uprobes attached to {libssl_path}");
        let tls_tx = tls_tx.clone();
        let mut tls_ring = RingBuf::try_from(
            bpf.map_mut("RING_BUF")
                .expect("RING_BUF map must exist after load"),
        )
        .expect("RingBuf from RING_BUF must succeed");

        Some(tokio::task::spawn_blocking(move || {
            while let Some(data) = tls_ring.next() {
                if tls_tx.send(data.to_vec()).is_err() {
                    break;
                }
            }
        }))
    }

    fn try_attach_rootkit_ring(
        bpf: &mut Bpf,
        rootkit_tx: &broadcast::Sender<Vec<u8>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let mut ring = match RingBuf::try_from(
            bpf.map_mut("ROOTKIT_EVENTS")
                .expect("ROOTKIT_EVENTS map must exist after load"),
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to open ROOTKIT_EVENTS ring buffer: {e:?}");
                return None;
            }
        };

        let tx = rootkit_tx.clone();
        Some(tokio::task::spawn_blocking(move || {
            while let Some(data) = ring.next() {
                if tx.send(data.to_vec()).is_err() {
                    break;
                }
            }
        }))
    }

    fn try_attach_canary_ring(
        bpf: &mut Bpf,
        canary_tx: &broadcast::Sender<Vec<u8>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let mut ring = match RingBuf::try_from(
            bpf.map_mut("CANARY_EVENTS")
                .expect("CANARY_EVENTS map must exist after load"),
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to open CANARY_EVENTS ring buffer: {e:?}");
                return None;
            }
        };
        let tx = canary_tx.clone();
        Some(tokio::task::spawn_blocking(move || {
            while let Some(data) = ring.next() {
                if tx.send(data.to_vec()).is_err() {
                    break;
                }
            }
        }))
    }

    fn try_attach_privesc_ring(
        bpf: &mut Bpf,
        privesc_tx: &broadcast::Sender<Vec<u8>>,
    ) -> Option<tokio::task::JoinHandle<()>> {
        let mut ring = match RingBuf::try_from(
            bpf.map_mut("PRIVESC_EVENTS")
                .expect("PRIVESC_EVENTS map must exist after load"),
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to open PRIVESC_EVENTS ring buffer: {e:?}");
                return None;
            }
        };
        let tx = privesc_tx.clone();
        Some(tokio::task::spawn_blocking(move || {
            while let Some(data) = ring.next() {
                if tx.send(data.to_vec()).is_err() {
                    break;
                }
            }
        }))
    }

    pub fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.ring_tx.subscribe()
    }

    pub fn subscribe_tls(&self) -> broadcast::Receiver<Vec<u8>> {
        self.tls_ring_tx.subscribe()
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

    pub fn add_established_flow(
        &self,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Result<()> {
        let bpf = self.bpf.as_ref().context("eBPF not loaded")?;
        let mut flows: AyaLruHashMap<_, [u8; 20], u32> =
            AyaLruHashMap::try_from(bpf.map("ESTABLISHED_FLOWS")?)
                .context("ESTABLISHED_FLOWS map access")?;
        let mut key = [0u8; 20];
        key[0..4].copy_from_slice(&src_ip.to_le_bytes());
        key[4..8].copy_from_slice(&dst_ip.to_le_bytes());
        key[8..10].copy_from_slice(&src_port.to_le_bytes());
        key[10..12].copy_from_slice(&dst_port.to_le_bytes());
        key[12] = protocol;
        flows.insert(key, 1, 0).with_context(|| {
            format!(
                "failed to insert flow {}:{} -> {}:{} proto {}",
                src_ip, src_port, dst_ip, dst_port, protocol
            )
        })?;
        Ok(())
    }

    pub fn remove_established_flow(
        &self,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Result<()> {
        let bpf = self.bpf.as_ref().context("eBPF not loaded")?;
        let mut flows: AyaLruHashMap<_, [u8; 20], u32> =
            AyaLruHashMap::try_from(bpf.map("ESTABLISHED_FLOWS")?)
                .context("ESTABLISHED_FLOWS map access")?;
        let mut key = [0u8; 20];
        key[0..4].copy_from_slice(&src_ip.to_le_bytes());
        key[4..8].copy_from_slice(&dst_ip.to_le_bytes());
        key[8..10].copy_from_slice(&src_port.to_le_bytes());
        key[10..12].copy_from_slice(&dst_port.to_le_bytes());
        key[12] = protocol;
        flows.remove(&key).with_context(|| {
            format!(
                "failed to remove flow {}:{} -> {}:{}",
                src_ip, src_port, dst_ip, dst_port
            )
        })?;
        Ok(())
    }

    pub fn block_ip(&mut self, ip: IpAddr) -> Result<()> {
        let bpf = self.bpf.as_mut().context("eBPF not loaded")?;
        let mut blocked: AyaLpmTrie<_, u32, u8> =
            AyaLpmTrie::try_from(bpf.map_mut("BLOCKED_IPS")?).context("BLOCKED_IPS map access")?;
        let (prefix_len, ip_bits) = match ip {
            IpAddr::V4(v4) => (32, u32::from(v4)),
            IpAddr::V6(v6) => {
                let bytes = v6.octets();
                let high = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                (32, high)
            }
        };
        blocked
            .insert(prefix_len, &ip_bits, 1, 0)
            .with_context(|| format!("failed to insert IP {ip} into BLOCKED_IPS"))?;
        info!("blocked IP: {ip}");
        Ok(())
    }

    pub fn unblock_ip(&mut self, ip: IpAddr) -> Result<()> {
        let bpf = self.bpf.as_mut().context("eBPF not loaded")?;
        let mut blocked: AyaLpmTrie<_, u32, u8> =
            AyaLpmTrie::try_from(bpf.map_mut("BLOCKED_IPS")?).context("BLOCKED_IPS map access")?;
        let (prefix_len, ip_bits) = match ip {
            IpAddr::V4(v4) => (32, u32::from(v4)),
            IpAddr::V6(_) => anyhow::bail!("IPv6 unblock not yet implemented"),
        };
        blocked
            .remove(prefix_len, &ip_bits)
            .with_context(|| format!("failed to remove IP {ip} from BLOCKED_IPS"))?;
        info!("unblocked IP: {ip}");
        Ok(())
    }

    pub fn block_port(&mut self, port: u16) -> Result<()> {
        let bpf = self.bpf.as_mut().context("eBPF not loaded")?;
        let mut ports: AyaHashMap<_, u16, u32> =
            AyaHashMap::try_from(bpf.map_mut("BLOCKED_PORTS")?)
                .context("BLOCKED_PORTS map access")?;
        ports
            .insert(port, 1, 0)
            .with_context(|| format!("failed to block port {port}"))?;
        info!("blocked port: {port}");
        Ok(())
    }

    pub fn unblock_port(&mut self, port: u16) -> Result<()> {
        let bpf = self.bpf.as_mut().context("eBPF not loaded")?;
        let mut ports: AyaHashMap<_, u16, u32> =
            AyaHashMap::try_from(bpf.map_mut("BLOCKED_PORTS")?)
                .context("BLOCKED_PORTS map access")?;
        ports
            .remove(&port)
            .with_context(|| format!("failed to unblock port {port}"))?;
        info!("unblocked port: {port}");
        Ok(())
    }

    pub fn detach(&mut self) {
        if let Some(bpf) = self.bpf.take() {
            drop(bpf);
            info!("eBPF programs detached");
        }
        if let Some(handle) = self.rx_task.take() {
            handle.abort();
        }
        if let Some(handle) = self.tls_rx_task.take() {
            handle.abort();
        }
        if let Some(handle) = self.rootkit_rx_task.take() {
            handle.abort();
        }
        if let Some(handle) = self.canary_rx_task.take() {
            handle.abort();
        }
        if let Some(handle) = self.privesc_rx_task.take() {
            handle.abort();
        }
    }
}

impl Drop for EbpfManager {
    fn drop(&mut self) {
        self.detach();
    }
}
