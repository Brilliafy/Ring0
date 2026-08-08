use std::collections::HashMap;
use std::fs;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use parking_lot::RwLock;
use tokio::sync::mpsc;
use tracing::{info, warn};

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
    cmd_tx: mpsc::UnboundedSender<DaemonCmd>,
    rules_path: String,
}

impl PromptEngine {
    pub fn new(cmd_tx: mpsc::UnboundedSender<DaemonCmd>, rules_path: &str) -> Self {
        Self {
            pending: Arc::new(RwLock::new(HashMap::new())),
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
        // Coalesce: an untrusted process making many connections (a browser, a
        // C2 client) used to spawn one prompt PER connection  -  flooding the
        // GUI and, once they timed out, auto-blocking every destination IP.
        // Reuse the existing prompt for this process instead; the user answers
        // once and the decision's scope applies to the rest.
        if let Some((existing_id, existing)) = pending.iter_mut().find(|(_, p)| p.pid == pid) {
            // Refresh the timeout so an actively-connecting process keeps its
            // single prompt alive instead of silently expiring.
            existing.created_at = Instant::now();
            return *existing_id;
        }
        if pending.len() >= MAX_PENDING_PROMPTS {
            if let Some(oldest_id) = pending.keys().next().copied() {
                if let Some(oldest) = pending.remove(&oldest_id) {
                    info!("PromptEngine: evicted oldest prompt {oldest_id} due to queue full");
                    // An evicted prompt is never decided; the destination is
                    // already open (the connection was observed, not prevented).
                    // Log it for the operator instead of auto-blocking the IP.
                    warn!(
                        "PromptEngine: evicted prompt {oldest_id} for {}:{} ({}) left undecided",
                        oldest.dst_ip, oldest.dst_port, oldest.binary_path
                    );
                }
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
                // "Allow once" must actually do something: mark the flow so the
                // kernel fast path stops re-evaluating it. (A fully synchronous
                // allow-before-connect gate would require the LSM to block the
                // pending connect  -  see the audit's structural recommendations;
                // this at least prevents repeat prompting and offloads the flow.)
                let cmd = DaemonCmd::MarkFlowAllowed(
                    prompt.dst_ip,
                    prompt.dst_port,
                    prompt.protocol,
                    prompt.pid,
                );
                let _ = self.cmd_tx.send(cmd);
                info!(
                    "PromptEngine: allowing {}:{} once  -  flow marked allowed",
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
            format!("user-allow-{}", dip_str)
        } else {
            format!("user-block-{}", dip_str)
        };

        // F6: serialize the rule as structured data  -  never string-interpolate
        // the attacker-controlled binary_path into YAML (a binary named
        // `"x" \n ...` could previously break out of the quoted scalar and
        // inject arbitrary rules). serde_yaml escapes quotes/backslashes and
        // control characters, so injection is impossible. The schema requires
        // a u32 `id`; the previous hand-rolled format omitted it, which made
        // the written file unparseable and broke every subsequent ReloadRules.
        let rule = serde_yaml::to_string(&serde_json::json!({
            "id": 70000u32 + (prompt.prompt_id % 30000) as u32,
            "name": rule_name,
            "cidrs": [format!("{dip_str}/32")],
            "ports": [prompt.dst_port],
            "protocols": [if prompt.protocol == 17 { "udp" } else { "tcp" }],
            "severity": if allow { 1 } else { 3 },
            "source_binary": prompt.binary_path,
        }))
        .with_context(|| "failed to serialize synthesized rule")?;

        // Indent into a list item under `network:`.
        let mut rule_yaml = String::new();
        for (i, line) in rule.lines().enumerate() {
            if i == 0 {
                rule_yaml.push_str("  - ");
            } else {
                rule_yaml.push_str("    ");
            }
            rule_yaml.push_str(line);
            rule_yaml.push('\n');
        }

        let existing = fs::read_to_string(&self.rules_path).unwrap_or_default();
        let updated = if existing.trim().ends_with("rules:") || existing.trim().is_empty() {
            format!("rules:\n  network:\n{}\n", rule_yaml)
        } else if let Some(pos) = existing.rfind("  network:") {
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

        // F6: validate the merged document parses BEFORE touching the live
        // file  -  a malformed merge must never corrupt /etc/ring0/rules.yaml.
        serde_yaml::from_str::<serde_yaml::Value>(&updated)
            .with_context(|| "synthesized rule produced invalid YAML  -  refusing to write")?;

        // Atomic write: temp file + fsync + rename, so a crash mid-write (or a
        // concurrent rules reload) never observes a torn rules file.
        let tmp_path = format!("{}.tmp", self.rules_path);
        {
            use std::io::Write;
            let mut f = fs::File::create(&tmp_path)
                .with_context(|| format!("Failed to create temp rules file {}", self.rules_path))?;
            f.write_all(updated.as_bytes())?;
            f.sync_all()?;
        }
        fs::rename(&tmp_path, &self.rules_path)
            .with_context(|| format!("Failed to replace {}", self.rules_path))?;

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
                // The connection was observed, not prevented: the daemon cannot
                // retroactively stop it. Auto-blocking the destination IP on an
                // unanswered prompt used to silently cut off entire sites (a
                // browser's 20 parallel connections -> 20 unanswered prompts ->
                // 20 destination blocks), which looked like a network outage.
                // Timeout now just closes the prompt; explicit user decisions
                // (allow/deny) still apply through SubmitPromptDecision.
                warn!(
                    "PromptEngine: prompt {id} timed out after {}s  -  dropped (no auto-block) for {}:{} ({})",
                    prompt.timeout_secs, prompt.dst_ip, prompt.dst_port, prompt.binary_path,
                );
            }
        }
    }

    pub fn pending_count(&self) -> usize {
        self.pending.read().len()
    }

    /// Look up a pending prompt (used by the command handler to reject
    /// self-approval: the process under scrutiny may never decide its own
    /// prompt).
    pub fn pending_get(&self, prompt_id: u64) -> Option<ConnectionPrompt> {
        self.pending.read().get(&prompt_id).cloned()
    }
}
