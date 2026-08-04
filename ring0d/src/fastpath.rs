use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use parking_lot::RwLock;
use tracing::{info, warn};

use crate::ebpf;

const IDLE_TIMEOUT_SECS: u64 = 300;
const MAX_FLOWS: u32 = 65536;

#[repr(C)]
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

pub struct FastPathManager {
    active_flows: Arc<RwLock<VecDeque<(FlowKey, Instant)>>>,
    ebpf_handle: Option<*const ebpf::EbpfManager>,
}

impl FastPathManager {
    pub fn new() -> Self {
        Self {
            active_flows: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_FLOWS as usize))),
            ebpf_handle: None,
        }
    }

    pub fn set_ebpf(&mut self, mgr: &ebpf::EbpfManager) {
        self.ebpf_handle = Some(mgr as *const ebpf::EbpfManager);
    }

    pub fn mark_flow_safe(
        &self,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) -> Result<()> {
        let key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        };

        if let Some(handle) = self.ebpf_handle {
            unsafe {
                let mgr = &*handle;
                if let Err(e) =
                    mgr.add_established_flow(src_ip, dst_ip, src_port, dst_port, protocol)
                {
                    warn!("Failed to insert flow into eBPF map: {e:?}");
                }
            }
        }

        let mut flows = self.active_flows.write();
        if flows.len() >= MAX_FLOWS as usize {
            flows.pop_front();
        }
        flows.push_back((key, Instant::now()));
        Ok(())
    }

    pub fn remove_flow(
        &self,
        src_ip: u32,
        dst_ip: u32,
        src_port: u16,
        dst_port: u16,
        protocol: u8,
    ) {
        let key = FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol,
        };

        if let Some(handle) = self.ebpf_handle {
            unsafe {
                let mgr = &*handle;
                let _ = mgr.remove_established_flow(src_ip, dst_ip, src_port, dst_port, protocol);
            }
        }

        let mut flows = self.active_flows.write();
        flows.retain(|(k, _)| k != &key);
    }

    pub fn purge_idle_flows(&self) {
        let now = Instant::now();
        let mut flows = self.active_flows.write();
        let before = flows.len();
        flows.retain(|(_, ts)| now.duration_since(*ts).as_secs() < IDLE_TIMEOUT_SECS);
        let purged = before - flows.len();
        if purged > 0 {
            info!(
                "FastPath: purged {purged} idle flows, {active} active",
                active = flows.len()
            );
        }
    }

    pub fn active_flow_count(&self) -> usize {
        self.active_flows.read().len()
    }

    pub fn handle_tcp_fin(&self, src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) {
        self.remove_flow(src_ip, dst_ip, src_port, dst_port, 6);
    }

    pub fn handle_tcp_rst(&self, src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) {
        self.remove_flow(src_ip, dst_ip, src_port, dst_port, 6);
    }
}
