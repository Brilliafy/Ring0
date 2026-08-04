use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tracing::info;

#[derive(Debug, Clone)]
pub struct QosPolicy {
    pub pid: u32,
    pub rate_limit_bps: u64,
    pub burst_bytes: u64,
    pub tokens: u64,
    pub last_update: Instant,
    pub enabled: bool,
}

pub struct QosManager {
    policies: Arc<RwLock<HashMap<u32, QosPolicy>>>,
}

impl QosManager {
    pub fn new() -> Self {
        Self {
            policies: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn set_policy(&self, pid: u32, rate_kbps: u64) {
        let rate_bps = rate_kbps * 1000;
        let burst = rate_bps / 10;
        let mut policies = self.policies.write();
        policies.insert(
            pid,
            QosPolicy {
                pid,
                rate_limit_bps: rate_bps,
                burst_bytes: burst,
                tokens: burst,
                last_update: Instant::now(),
                enabled: true,
            },
        );
        info!("QoS: set rate limit for PID {pid} to {rate_kbps} KB/s");
    }

    pub fn remove_policy(&self, pid: u32) {
        self.policies.write().remove(&pid);
        info!("QoS: removed rate limit for PID {pid}");
    }

    pub fn get_policy(&self, pid: u32) -> Option<QosPolicy> {
        self.policies.read().get(&pid).cloned()
    }

    pub fn all_policies(&self) -> Vec<QosPolicy> {
        self.policies.read().values().cloned().collect()
    }

    pub fn check_packet(&self, pid: u32, pkt_len: u64) -> bool {
        let mut policies = self.policies.write();
        if let Some(policy) = policies.get_mut(&pid) {
            if !policy.enabled {
                return true;
            }
            let now = Instant::now();
            let elapsed = now.duration_since(policy.last_update).as_secs_f64();
            if elapsed > 0.0 {
                let replenish = (elapsed * policy.rate_limit_bps as f64) as u64;
                policy.tokens = (policy.tokens + replenish).min(policy.burst_bytes);
                policy.last_update = now;
            }
            if policy.tokens >= pkt_len {
                policy.tokens -= pkt_len;
                true
            } else {
                false
            }
        } else {
            true
        }
    }

    pub fn policy_count(&self) -> usize {
        self.policies.read().len()
    }
}
