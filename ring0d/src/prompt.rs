use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::info;

use crate::ipc::DaemonCmd;

const PROMPT_TIMEOUT_SECS: u64 = 15;
const MAX_PENDING_PROMPTS: usize = 256;

static NEXT_PROMPT_ID: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

#[derive(Debug, Clone)]
pub struct ConnectionPrompt {
    pub prompt_id: u64,
    pub pid: u32,
    pub ppid: u32,
    pub binary_path: String,
    pub parent_binary: String,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
    pub country_code: String,
    pub country_name: String,
    pub rdns_name: String,
    pub created_at: Instant,
    pub timeout_secs: u64,
}

#[derive(Debug, Clone)]
pub struct PromptDecision {
    pub prompt_id: u64,
    pub action: PromptAction,
    pub scope: PromptScope,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PromptAction {
    AllowOnce,
    AllowAlways,
    Block,
    BlockAlways,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PromptScope {
    ExactIp,
    Domain,
    Port,
    Process,
}

pub struct PromptEngine {
    pending: Arc<RwLock<HashMap<u64, ConnectionPrompt>>>,
    decision_tx: mpsc::UnboundedSender<PromptDecision>,
    decision_rx: Arc<RwLock<Option<mpsc::UnboundedReceiver<PromptDecision>>>>,
    cmd_tx: mpsc::UnboundedSender<DaemonCmd>,
    rules_path: String,
}

impl PromptEngine {
    pub fn new(cmd_tx: mpsc::UnboundedSender<DaemonCmd>, rules_path: &str) -> Self {
        let (decision_tx, decision_rx) = mpsc::unbounded_channel();
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
            decision_tx,
            decision_rx: Arc::new(RwLock::new(Some(decision_rx))),
            cmd_tx,
            rules_path: rules_path.to_string(),
        }
    }

    pub fn create_prompt(
        &self,
        pid: u32,
        ppid: u32,
        binary_path: &str,
        parent_binary: &str,
        dst_ip: u32,
        dst_port: u16,
        protocol: u8,
        country_code: &str,
        country_name: &str,
        rdns_name: &str,
    ) -> u64 {
        let prompt_id = NEXT_PROMPT_ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let prompt = ConnectionPrompt {
            prompt_id,
            pid,
            ppid,
            binary_path: binary_path.to_string(),
            parent_binary: parent_binary.to_string(),
            dst_ip,
            dst_port,
            protocol,
            country_code: country_code.to_string(),
            country_name: country_name.to_string(),
            rdns_name: rdns_name.to_string(),
            created_at: Instant::now(),
            timeout_secs: PROMPT_TIMEOUT_SECS,
        };

        let mut pending = self.pending.write();
        if pending.len() >= MAX_PENDING_PROMPTS {
            if let Some(oldest_id) = pending.keys().next().copied() {
                pending.remove(&oldest_id);
                info!("PromptEngine: evicted oldest prompt {oldest_id} due to queue full");
            }
        }
        pending.insert(prompt_id, prompt.clone());
        info!(
            "PromptEngine: created prompt {} for PID {} ({}) to {}.{}.{}.{}:{}",
            prompt_id,
            pid,
            binary_path,
            (dst_ip >> 24) & 0xFF,
            (dst_ip >> 16) & 0xFF,
            (dst_ip >> 8) & 0xFF,
            dst_ip & 0xFF,
            dst_port,
        );
        prompt_id
    }

    pub fn resolve_prompt(&self, prompt_id: u64, decision: PromptDecision) -> Result<()> {
        let prompt =
            self.pending.write().remove(&prompt_id).ok_or_else(|| {
                anyhow::anyhow!("Prompt {prompt_id} not found or already resolved")
            })?;

        info!(
            "PromptEngine: prompt {} resolved: {:?} scope={:?} for {}:{}",
            prompt_id, decision.action, decision.scope, prompt.dst_ip, prompt.dst_port,
        );

        match decision.action {
            PromptAction::AllowOnce => {
                info!(
                    "PromptEngine: allowing {}:{} once",
                    prompt.dst_ip, prompt.dst_port
                );
            }
            PromptAction::AllowAlways => {
                self.synthesize_rule(&prompt, &decision, true)?;
            }
            PromptAction::Block => {
                let cmd = DaemonCmd::BlockIp(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    prompt.dst_ip,
                )));
                let _ = self.cmd_tx.send(cmd);
            }
            PromptAction::BlockAlways => {
                self.synthesize_rule(&prompt, &decision, false)?;
            }
        }

        Ok(())
    }

    fn synthesize_rule(
        &self,
        prompt: &ConnectionPrompt,
        _decision: &PromptDecision,
        allow: bool,
    ) -> Result<()> {
        let dip_str = format!(
            "{}.{}.{}.{}",
            (prompt.dst_ip >> 24) & 0xFF,
            (prompt.dst_ip >> 16) & 0xFF,
            (prompt.dst_ip >> 8) & 0xFF,
            prompt.dst_ip & 0xFF,
        );

        let rule_name = if allow {
            format!(
                "user-allow-{}-{}",
                prompt.binary_path.replace('/', "_"),
                dip_str
            )
        } else {
            format!(
                "user-block-{}-{}",
                prompt.binary_path.replace('/', "_"),
                dip_str
            )
        };
        let rule_action = if allow { "pass" } else { "drop" };

        let rule_yaml = format!(
            r#"
  - name: "{}"
    cidr: "{}/32"
    ports: [{}]
    protocol: {}
    action: {}
    user_rule: true
    source_binary: "{}"
"#,
            rule_name,
            dip_str,
            prompt.dst_port,
            if prompt.protocol == 17 { "udp" } else { "tcp" },
            rule_action,
            prompt.binary_path,
        );

        let existing = fs::read_to_string(&self.rules_path).unwrap_or_default();
        let updated = if existing.trim().ends_with("rules:") || existing.trim().is_empty() {
            format!("rules:\n  network:\n{}\n", rule_yaml)
        } else if let Some(pos) = existing.rfind("  network:") {
            let _before = &existing[..=pos];
            let after = &existing[pos + 10..];
            let end_marker = after.rfind("\n  ");
            let insertion_point = match end_marker {
                Some(ep) => pos + 10 + ep,
                None => existing.len(),
            };
            format!(
                "{}{}{}",
                &existing[..insertion_point],
                rule_yaml,
                &existing[insertion_point..]
            )
        } else {
            format!("{}\n  network:\n{}\n", existing, rule_yaml)
        };

        fs::write(&self.rules_path, &updated)
            .with_context(|| format!("Failed to write rule to {}", self.rules_path))?;

        info!(
            "PromptEngine: synthesized rule '{rule_name}' written to {}",
            self.rules_path
        );
        Ok(())
    }

    pub fn check_timeouts(&self) {
        let now = Instant::now();
        let mut pending = self.pending.write();
        let timed_out: Vec<u64> = pending
            .iter()
            .filter(|(_, p)| now.duration_since(p.created_at) > Duration::from_secs(p.timeout_secs))
            .map(|(id, _)| *id)
            .collect();

        for id in timed_out {
            if let Some(prompt) = pending.remove(&id) {
                info!(
                    "PromptEngine: prompt {id} timed out after {}s — default deny for {}:{} ({})",
                    prompt.timeout_secs, prompt.dst_ip, prompt.dst_port, prompt.binary_path,
                );
                // Enforce the documented "default deny": block the destination IP
                // so the untrusted binary can no longer reach it.
                let cmd = DaemonCmd::BlockIp(std::net::IpAddr::V4(std::net::Ipv4Addr::from(
                    prompt.dst_ip,
                )));
                let _ = self.cmd_tx.send(cmd);
            }
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.read().len()
    }

    pub fn take_decision_rx(&self) -> Option<mpsc::UnboundedReceiver<PromptDecision>> {
        self.decision_rx.write().take()
    }

    pub fn get_decision_sender(&self) -> mpsc::UnboundedSender<PromptDecision> {
        self.decision_tx.clone()
    }
}
