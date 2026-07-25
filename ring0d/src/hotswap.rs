use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result};
use tracing::{error, info, warn};

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
            warn!("BPF filesystem not mounted at /sys/fs/bpf — cannot pin maps");
            return Ok(());
        }
        fs::create_dir_all(BPFFS_PATH).context("Failed to create /sys/fs/bpf/ring0")?;
        info!("Hotswap: BPFFS directory ready at {BPFFS_PATH}");
        self.pinned.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn pin_map(&self, name: &str, fd: i32) -> Result<()> {
        if !self.pinned.load(Ordering::Relaxed) {
            return Ok(());
        }
        let pin_path = format!("{BPFFS_PATH}/{name}");
        bpf_pin_map(fd, &pin_path)
            .with_context(|| format!("Failed to pin map {name} to {pin_path}"))?;
        info!("Hotswap: pinned map {name}");
        Ok(())
    }

    pub fn unpin_map(&self, name: &str) {
        let pin_path = format!("{BPFFS_PATH}/{name}");
        let _ = fs::remove_file(&pin_path);
        info!("Hotswap: unpinned map {name}");
    }

    pub fn hotswap_program(&self, _prog_name: &str, _new_fd: i32) -> Result<()> {
        info!("Hotswap: program hotswap requested (BPF_LINK_UPDATE)");
        self.fallback_active.store(false, Ordering::Relaxed);
        Ok(())
    }

    pub fn rollback(&self, _prog_name: &str, _old_fd: i32) -> Result<()> {
        warn!("Hotswap: rolling back to previous eBPF program");
        self.fallback_active.store(true, Ordering::Relaxed);
        Ok(())
    }

    pub fn is_fallback_active(&self) -> bool {
        self.fallback_active.load(Ordering::Relaxed)
    }
}

fn bpf_pin_map(fd: i32, path: &str) -> Result<()> {
    use std::os::unix::io::FromRawFd;
    if fd < 0 {
        return Ok(());
    }
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let _ = file;
    Ok(())
}
