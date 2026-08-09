use std::fs;
use std::sync::Arc;

use anyhow::{Context, Result};
use parking_lot::RwLock;
use serde::Deserialize;
use tracing::{error, info};

#[derive(Debug, Clone, Deserialize)]
pub struct RuleConfig {
    pub rules: Rules,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Rules {
    #[serde(default)]
    pub network: Vec<NetworkRule>,
    #[serde(default)]
    pub process: Vec<ProcessRule>,
    #[serde(default)]
    pub file: Vec<FileRule>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct NetworkRule {
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub cidrs: Vec<String>,
    #[serde(default)]
    pub ports: Vec<u16>,
    #[serde(default)]
    pub protocols: Vec<String>,
    #[serde(default)]
    pub signatures: Vec<String>,
    #[serde(default = "default_severity")]
    pub severity: u8,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProcessRule {
    pub id: u32,
    pub name: String,
    #[serde(default)]
    pub binary_paths: Vec<String>,
    #[serde(default)]
    pub child_blacklist: Vec<String>,
    #[serde(default)]
    pub sha256_hashes: Vec<String>,
    #[serde(default = "default_severity")]
    pub severity: u8,
    pub enabled: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct FileRule {
    pub id: u32,
    pub name: String,
    pub path_glob: String,
    #[serde(default = "default_severity")]
    pub severity: u8,
    #[serde(default)]
    pub read_only: bool,
    pub enabled: Option<bool>,
}

fn default_severity() -> u8 {
    2
}

pub struct RuleEngine {
    config: Arc<RwLock<RuleConfig>>,
    path: String,
    signatures: Arc<RwLock<Vec<String>>>,
}

impl RuleEngine {
    /// Look up a process-rule's display name by id (for alert messages).
    pub fn process_rule_name(&self, id: u32) -> String {
        let config = self.config.read();
        config
            .rules
            .process
            .iter()
            .find(|r| r.id == id)
            .map(|r| r.name.clone())
            .unwrap_or_else(|| format!("rule {id}"))
    }

    pub fn empty() -> Self {
        Self {
            config: Arc::new(RwLock::new(RuleConfig {
                rules: Rules {
                    network: Vec::new(),
                    process: Vec::new(),
                    file: Vec::new(),
                },
            })),
            path: String::new(),
            signatures: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn load(path: &str) -> Result<Self> {
        let config = Self::parse_file(path)?;
        let sigs = config
            .rules
            .network
            .iter()
            .flat_map(|r| r.signatures.clone())
            .collect();
        info!("loaded {} rules from {path}", Self::count_rules(&config));
        Ok(Self {
            config: Arc::new(RwLock::new(config)),
            path: path.to_string(),
            signatures: Arc::new(RwLock::new(sigs)),
        })
    }

    fn parse_file(path: &str) -> Result<RuleConfig> {
        let expanded = shellexpand::tilde(path).to_string();
        let content = fs::read_to_string(&expanded)
            .with_context(|| format!("failed to read rules file: {expanded}"))?;
        serde_yaml::from_str::<RuleConfig>(&content)
            .with_context(|| format!("failed to parse YAML rules from {expanded}"))
    }

    pub fn reload(&self) -> Result<()> {
        match Self::parse_file(&self.path) {
            Ok(config) => {
                let sigs: Vec<String> = config
                    .rules
                    .network
                    .iter()
                    .flat_map(|r| r.signatures.clone())
                    .collect();
                *self.config.write() = config.clone();
                *self.signatures.write() = sigs;
                info!("rules reloaded from {}", self.path);
                Ok(())
            }
            Err(e) => {
                error!("failed to reload rules: {e:?}");
                Err(e)
            }
        }
    }

    pub fn get_signatures(&self) -> Vec<String> {
        self.signatures.read().clone()
    }

    pub fn check_file_access(&self, file_path: &str, _pid: u32, write_flag: bool) -> Vec<u32> {
        let config = self.config.read();
        let mut alerts = Vec::new();
        for rule in &config.rules.file {
            if !rule.enabled.unwrap_or(true) {
                continue;
            }
            let glob_pattern = shellexpand::tilde(&rule.path_glob).to_string();
            if glob::Pattern::new(&glob_pattern)
                .map(|p| p.matches(file_path))
                .unwrap_or(false)
                && (!rule.read_only || write_flag)
            {
                alerts.push(rule.id);
            }
        }
        alerts
    }

    pub fn check_process_anomaly(
        &self,
        binary_path: &str,
        parent_binary: Option<&str>,
    ) -> Vec<u32> {
        let config = self.config.read();
        let mut alerts = Vec::new();
        for rule in &config.rules.process {
            if !rule.enabled.unwrap_or(true) {
                continue;
            }
            for bl in &rule.binary_paths {
                if binary_path.contains(bl) {
                    alerts.push(rule.id);
                    break;
                }
            }
            if let Some(parent) = parent_binary {
                for bl in &rule.child_blacklist {
                    if binary_path.contains(bl) {
                        for bp in &rule.binary_paths {
                            if parent.contains(bp) {
                                alerts.push(rule.id);
                                break;
                            }
                        }
                    }
                }
            }
        }
        alerts
    }

    pub fn config(&self) -> parking_lot::RwLockReadGuard<'_, RuleConfig> {
        self.config.read()
    }

    fn count_rules(config: &RuleConfig) -> usize {
        config.rules.network.len() + config.rules.process.len() + config.rules.file.len()
    }
}
