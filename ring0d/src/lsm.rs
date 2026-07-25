use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use aya::programs::Lsm;
use aya::{
    include_bytes_aligned,
    maps::{HashMap as AyaHashMap, RingBuf},
    programs::BtfTracePoint,
    Bpf,
};
use tracing::{error, info, warn};

const LSM_COMPAT_PATH: &str = "/sys/kernel/security/lsm";

pub struct LsmManager {
    bpf: Option<Bpf>,
    enforce: bool,
    lsm_available: bool,
    ring_tx: tokio::sync::broadcast::Sender<Vec<u8>>,
    rx_task: Option<tokio::task::JoinHandle<()>>,
}

impl LsmManager {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(1024);
        Self {
            bpf: None,
            enforce: false,
            lsm_available: false,
            ring_tx: tx,
            rx_task: None,
        }
    }

    pub fn check_kernel_compat() -> bool {
        let content = match fs::read_to_string(LSM_COMPAT_PATH) {
            Ok(c) => c,
            Err(e) => {
                warn!("LSM compat check failed (cannot read {LSM_COMPAT_PATH}): {e}");
                return false;
            }
        };
        let has_bpf = content.split(',').any(|s| s.trim() == "bpf");
        if has_bpf {
            info!("Kernel LSM subsystem supports bpf (LSM_BPF enabled)");
        } else {
            warn!("Kernel LSM list ({content:?}) does not include 'bpf' — LSM hooks unavailable");
        }
        has_bpf
    }

    pub fn load_and_attach(&mut self) -> Result<bool> {
        if !Self::check_kernel_compat() {
            warn!("eBPF LSM not supported by kernel — falling back to tracepoint enforcement");
            self.lsm_available = false;
            return Ok(false);
        }

        let mut bpf = match Bpf::load(include_bytes_aligned!(
            "../../target/bpfel-unknown-none/release/ring0-ebpf"
        )) {
            Ok(b) => b,
            Err(e) => {
                warn!("Failed to load eBPF object for LSM: {e:?} — falling back");
                self.lsm_available = false;
                return Ok(false);
            }
        };

        let lsm_progs = [
            "ring0_lsm_file_open",
            "ring0_lsm_bprm_check",
            "ring0_lsm_socket_connect",
        ];
        for name in &lsm_progs {
            match bpf.program_mut(name) {
                Ok(prog) => {
                    let lsm: &mut Lsm = match prog.try_into() {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("{name} type mismatch: {e:?}");
                            continue;
                        }
                    };
                    if let Err(e) = lsm.load() {
                        warn!("{name} load failed: {e:?}");
                        continue;
                    }
                    if let Err(e) = lsm.attach() {
                        warn!("{name} attach failed: {e:?}");
                        continue;
                    }
                    info!("{name} LSM program attached");
                }
                Err(e) => {
                    warn!("{name} not found in eBPF object: {e:?}");
                }
            }
        }

        let mut ring = match RingBuf::try_from(
            bpf.map_mut("LSM_EVENTS")
                .context("LSM_EVENTS map not found")?,
        ) {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to open LSM_EVENTS ring buffer: {e:?}");
                self.lsm_available = false;
                return Ok(false);
            }
        };

        let tx = self.ring_tx.clone();
        let rx_task = tokio::task::spawn_blocking(move || {
            while let Some(data) = ring.next() {
                if tx.send(data.to_vec()).is_err() {
                    break;
                }
            }
        });

        self.bpf = Some(bpf);
        self.lsm_available = true;
        self.rx_task = Some(rx_task);
        Ok(true)
    }

    pub fn enable_enforcement(&mut self) {
        if !self.lsm_available {
            warn!("Cannot enable LSM enforcement: LSM not available");
            return;
        }
        let bpf = match self.bpf.as_mut() {
            Some(b) => b,
            None => {
                warn!("Cannot enable LSM enforcement: eBPF not loaded");
                return;
            }
        };
        let mut enforce: AyaHashMap<_, u32, u8> =
            match AyaHashMap::try_from(bpf.map_mut("LSM_ENFORCE")) {
                Ok(m) => m,
                Err(e) => {
                    error!("Failed to access LSM_ENFORCE map: {e:?}");
                    return;
                }
            };
        if let Err(e) = enforce.insert(1, 1, 0) {
            error!("Failed to set LSM_ENFORCE flag: {e:?}");
            return;
        }
        self.enforce = true;
        info!("LSM inline enforcement enabled — EPERM will be returned for blocked operations");
    }

    pub fn disable_enforcement(&mut self) {
        let bpf = match self.bpf.as_mut() {
            Some(b) => b,
            None => return,
        };
        let mut enforce: AyaHashMap<_, u32, u8> =
            match AyaHashMap::try_from(bpf.map_mut("LSM_ENFORCE")) {
                Ok(m) => m,
                Err(e) => {
                    error!("Failed to access LSM_ENFORCE map: {e:?}");
                    return;
                }
            };
        let _ = enforce.remove(&1);
        self.enforce = false;
        info!("LSM inline enforcement disabled");
    }

    pub fn block_binary(&mut self, name: &str) -> Result<()> {
        let bpf = self.bpf.as_mut().context("eBPF not loaded")?;
        let mut blocked: AyaHashMap<_, [u8; 64], u8> =
            AyaHashMap::try_from(bpf.map_mut("BLOCKED_BINARIES"))
                .context("BLOCKED_BINARIES map access")?;
        let mut key = [0u8; 64];
        let bytes = name.as_bytes();
        let len = bytes.len().min(63);
        key[..len].copy_from_slice(&bytes[..len]);
        blocked
            .insert(key, 1, 0)
            .with_context(|| format!("failed to insert binary {name} into BLOCKED_BINARIES"))?;
        info!("LSM blocked binary: {name}");
        Ok(())
    }

    pub fn unblock_binary(&mut self, name: &str) -> Result<()> {
        let bpf = self.bpf.as_mut().context("eBPF not loaded")?;
        let mut blocked: AyaHashMap<_, [u8; 64], u8> =
            AyaHashMap::try_from(bpf.map_mut("BLOCKED_BINARIES"))
                .context("BLOCKED_BINARIES map access")?;
        let mut key = [0u8; 64];
        let bytes = name.as_bytes();
        let len = bytes.len().min(63);
        key[..len].copy_from_slice(&bytes[..len]);
        blocked
            .remove(&key)
            .with_context(|| format!("failed to remove binary {name} from BLOCKED_BINARIES"))?;
        info!("LSM unblocked binary: {name}");
        Ok(())
    }

    pub fn subscribe(&self) -> tokio::sync::broadcast::Receiver<Vec<u8>> {
        self.ring_tx.subscribe()
    }

    pub fn is_enforcing(&self) -> bool {
        self.enforce
    }

    pub fn is_available(&self) -> bool {
        self.lsm_available
    }

    pub fn detach(&mut self) {
        if let Some(bpf) = self.bpf.take() {
            drop(bpf);
            info!("LSM eBPF programs detached");
        }
        if let Some(handle) = self.rx_task.take() {
            handle.abort();
        }
    }
}

impl Drop for LsmManager {
    fn drop(&mut self) {
        self.detach();
    }
}
