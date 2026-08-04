use std::collections::HashMap;
use std::sync::Arc;

use parking_lot::RwLock;
use tracing::info;

const NEXDNS_API: &str = "https://api.nextdns.io/v1/domain";
const VT_API: &str = "https://www.virustotal.com/api/v3/domains";

pub struct IntelApiClient {
    nextdns_api_key: Arc<RwLock<Option<String>>>,
    vt_api_key: Arc<RwLock<Option<String>>>,
    cache: Arc<RwLock<HashMap<String, DomainReputation>>>,
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct DomainReputation {
    pub domain: String,
    pub threat_score: u8,
    pub category: String,
    pub source: String,
    pub is_malicious: bool,
}

impl IntelApiClient {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .user_agent("Ring0-IntelAPI/1.0")
            .build()
            .unwrap_or_default();

        Self {
            nextdns_api_key: Arc::new(RwLock::new(None)),
            vt_api_key: Arc::new(RwLock::new(None)),
            cache: Arc::new(RwLock::new(HashMap::with_capacity(5000))),
            client,
        }
    }

    pub fn configure(&self, nextdns_key: Option<String>, vt_key: Option<String>) {
        if let Some(k) = nextdns_key {
            *self.nextdns_api_key.write() = Some(k);
        }
        if let Some(k) = vt_key {
            *self.vt_api_key.write() = Some(k);
        }
        info!(
            "IntelAPI: configured NextDNS={} VirusTotal={}",
            self.nextdns_api_key.read().is_some(),
            self.vt_api_key.read().is_some()
        );
    }

    pub async fn lookup_domain(&self, domain: &str) -> Option<DomainReputation> {
        if domain.is_empty() || !domain.contains('.') {
            return None;
        }

        {
            let cache = self.cache.read();
            if let Some(rep) = cache.get(domain) {
                return Some(rep.clone());
            }
        }

        let mut rep = DomainReputation {
            domain: domain.to_string(),
            threat_score: 0,
            category: "Unknown".into(),
            source: "Unknown".into(),
            is_malicious: false,
        };

        let nextdns_key = self.nextdns_api_key.read().clone();
        if let Some(key) = nextdns_key {
            if let Ok(r) = self.query_nextdns(domain, &key).await {
                rep = r;
            }
        }

        let vt_key = self.vt_api_key.read().clone();
        if let Some(key) = vt_key {
            if let Ok(vt_rep) = self.query_virustotal(domain, &key).await {
                if vt_rep.threat_score > rep.threat_score {
                    rep = vt_rep;
                }
            }
        }

        let mut cache = self.cache.write();
        if cache.len() >= 5000 {
            // Keep the cache bounded: drop a small portion of the oldest entries.
            let drop = cache.len() / 4;
            let keys: Vec<String> = cache.keys().take(drop).cloned().collect();
            for k in keys {
                cache.remove(&k);
            }
        }
        cache.insert(domain.to_string(), rep.clone());
        Some(rep)
    }

    async fn query_nextdns(&self, domain: &str, api_key: &str) -> Result<DomainReputation, String> {
        let url = format!("{NEXDNS_API}/{domain}");
        let resp = self
            .client
            .get(&url)
            .header("X-API-Key", api_key)
            .send()
            .await
            .map_err(|e| format!("NextDNS HTTP: {e}"))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("NextDNS parse: {e}"))?;

        let threat_score = body
            .get("threatScore")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;
        let category = body
            .get("category")
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();
        let is_malicious = threat_score >= 70;

        Ok(DomainReputation {
            domain: domain.to_string(),
            threat_score,
            category,
            source: "NextDNS".into(),
            is_malicious,
        })
    }

    async fn query_virustotal(
        &self,
        domain: &str,
        api_key: &str,
    ) -> Result<DomainReputation, String> {
        let url = format!("{VT_API}/{domain}");
        let resp = self
            .client
            .get(&url)
            .header("x-apikey", api_key)
            .send()
            .await
            .map_err(|e| format!("VT HTTP: {e}"))?;

        let body: serde_json::Value = resp.json().await.map_err(|e| format!("VT parse: {e}"))?;

        let stats = &body["data"]["attributes"]["last_analysis_stats"];
        let malicious = stats.get("malicious").and_then(|v| v.as_u64()).unwrap_or(0) as u8;
        let suspicious = stats
            .get("suspicious")
            .and_then(|v| v.as_u64())
            .unwrap_or(0) as u8;
        let total = malicious + suspicious;
        let threat_score = if total > 0 {
            (total as f32 / 60.0 * 100.0) as u8
        } else {
            0
        };

        let categories = &body["data"]["attributes"]["categories"];
        let category = categories
            .as_object()
            .and_then(|m| m.values().next())
            .and_then(|v| v.as_str())
            .unwrap_or("Unknown")
            .to_string();

        Ok(DomainReputation {
            domain: domain.to_string(),
            threat_score,
            category,
            source: "VirusTotal".into(),
            is_malicious: threat_score >= 50,
        })
    }

    pub fn cache_size(&self) -> usize {
        self.cache.read().len()
    }
}
