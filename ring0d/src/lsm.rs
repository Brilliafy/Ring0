use anyhow::Result;
use tokio::sync::broadcast;
use tracing::{info, warn};

pub struct LsmManager {
    ring_tx: broadcast::Sender<Vec<u8>>,
    enforce: bool,
    lsm_available: bool,
}

impl LsmManager {
    pub fn new() -> Self {
        let (tx, _) = tokio::sync::broadcast::channel(1024);
        Self {
            ring_tx: tx,
            enforce: false,
            lsm_available: false,
        }
    }

    pub fn check_kernel_compat() -> bool {
        let content = match std::fs::read_to_string("/sys/kernel/security/lsm") {
            Ok(c) => c,
            Err(_) => return false,
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
        info!("LSM manager initialized (stub mode — no eBPF programs loaded)");
        self.lsm_available = false;
        Ok(false)
    }

    pub fn enable_enforcement(&mut self) {
        warn!("Cannot enable LSM enforcement: LSM not available");
    }
    pub fn disable_enforcement(&mut self) {}
    pub fn block_binary(&mut self, _name: &str) -> Result<()> {
        Ok(())
    }
    pub fn unblock_binary(&mut self, _name: &str) -> Result<()> {
        Ok(())
    }
    pub fn subscribe(&self) -> broadcast::Receiver<Vec<u8>> {
        self.ring_tx.subscribe()
    }
    pub fn is_enforcing(&self) -> bool {
        self.enforce
    }
    pub fn is_available(&self) -> bool {
        self.lsm_available
    }
    pub fn detach(&mut self) {
        info!("LSM detached (stub)");
    }
}

impl Drop for LsmManager {
    fn drop(&mut self) {
        self.detach();
    }
}
