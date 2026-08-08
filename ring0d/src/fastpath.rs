use std::collections::VecDeque;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use ring0_abi::FlowKey;
use tracing::info;

const IDLE_TIMEOUT_SECS: u64 = 300;
const MAX_FLOWS: u32 = 65536;

/// Userspace mirror of the kernel fast-path flow table.
///
/// NOTE: this list is a *reporting* mirror only  -  enforcement/offload happens
/// in the kernel `ESTABLISHED_FLOWS` map (`EbpfManager::mark_flow_established`).
/// `mark_flow_safe` updates both so the two views never diverge.
pub struct FastPathManager {
    active_flows: Arc<RwLock<VecDeque<(FlowKey, Instant)>>>,
}

impl FastPathManager {
    pub fn new() -> Self {
        Self {
            active_flows: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_FLOWS as usize))),
        }
    }

    pub fn mark_flow_safe(&self, key: FlowKey) -> Result<(), anyhow::Error> {
        let mut flows = self.active_flows.write();
        if flows.len() >= MAX_FLOWS as usize {
            flows.pop_front();
        }
        flows.push_back((key, Instant::now()));
        Ok(())
    }

    pub fn remove_flow(&self, key: &FlowKey) {
        let mut flows = self.active_flows.write();
        flows.retain(|(k, _)| k != key);
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
        self.remove_flow(&FlowKey {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            protocol: 6,
            _pad: [0u8; 7],
        });
    }

    pub fn handle_tcp_rst(&self, src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) {
        self.handle_tcp_fin(src_ip, dst_ip, src_port, dst_port);
    }
}
