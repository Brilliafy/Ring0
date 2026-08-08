use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use tracing::{info, warn};

const BPFFS_PATH: &str = "/sys/fs/bpf/ring0";

pub struct HotswapManager {
    pinned: AtomicBool,
    fallback_active: AtomicBool,
}

impl HotswapManager {
    pub fn new() -> Self {
        Self {
            pinned: AtomicBool::new(false),
            fallback_active: AtomicBool::new(false),
        }
    }

    pub fn init_bpffs(&self) -> Result<()> {
        if !Path::new("/sys/fs/bpf").exists() {
            warn!("BPF filesystem not mounted at /sys/fs/bpf  -  cannot pin maps");
            return Ok(());
        }
        fs::create_dir_all(BPFFS_PATH).context("Failed to create /sys/fs/bpf/ring0")?;
        info!("Hotswap: BPFFS directory ready at {BPFFS_PATH}");
        self.pinned.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn pin_map(&self, name: &str, _fd: i32) -> Result<()> {
        // Pinning is not implemented. Failing loudly here is intentional: a
        // fake Ok(()) would make callers believe the map survives a daemon
        // restart when it actually does not.
        Err(anyhow::anyhow!(
            "map pinning is not implemented  -  map {name} was not pinned"
        ))
    }

    pub fn unpin_map(&self, name: &str) {
        let pin_path = format!("{BPFFS_PATH}/{name}");
        let _ = fs::remove_file(&pin_path);
        info!("Hotswap: unpinned map {name}");
    }

    pub fn hotswap_program(&self, prog_name: &str, _new_fd: i32) -> Result<()> {
        Err(anyhow::anyhow!(
            "program hotswap is not implemented  -  {prog_name} was not swapped"
        ))
    }

    pub fn rollback(&self, prog_name: &str, _old_fd: i32) -> Result<()> {
        Err(anyhow::anyhow!(
            "program rollback is not implemented  -  {prog_name} was not rolled back"
        ))
    }

    pub fn is_fallback_active(&self) -> bool {
        self.fallback_active.load(Ordering::Relaxed)
    }
}

fn bpf_pin_map(_fd: i32, _path: &str) -> Result<()> {
    Err(anyhow::anyhow!(
        "eBPF map pinning is not implemented  -  the map will not survive a daemon restart"
    ))
}
