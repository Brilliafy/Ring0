use anyhow::Result;
use tracing::warn;

#[derive(Debug, Clone)]
pub struct DpiMatch {
    pub rule_id: u32,
    pub signature_name: String,
    pub severity: u8,
}

pub struct DpiEngine;

impl DpiEngine {
    pub fn new() -> Result<Self> {
        warn!("DPI engine initialized (stub mode)");
        Ok(Self)
    }

    pub fn scan_payload(&self, _payload: &[u8]) -> Vec<DpiMatch> {
        Vec::new()
    }
}
