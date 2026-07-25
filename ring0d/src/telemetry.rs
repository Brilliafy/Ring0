use std::collections::HashMap;

use tracing::info;

pub struct TelemetryEngine {
    ja4_cache: HashMap<String, String>,
}

impl TelemetryEngine {
    pub fn new() -> Self {
        Self {
            ja4_cache: HashMap::new(),
        }
    }

    pub fn compute_ja4(tls_version: u8, ciphers: &[u16], extensions: &[u16]) -> String {
        let t = match tls_version {
            0x0304 => "t13",
            0x0303 => "t12",
            0x0302 => "t11",
            _ => "t0x",
        };
        let cipher_group = if ciphers.is_empty() {
            "0000".to_string()
        } else {
            format!("{:04x}", ciphers[0] & 0xff00)
        };
        let ext_count = extensions.len().min(99);
        let ext_str = format!("{:02}", ext_count);
        let first_alpn = extensions
            .iter()
            .find(|e| **e == 0x0010)
            .map(|_| "h2")
            .unwrap_or("00");
        let sig_algs = extensions
            .iter()
            .find(|e| **e == 0x000d)
            .map(|_| "s1")
            .unwrap_or("00");
        format!("{}{}{}{}{}", t, cipher_group, ext_str, first_alpn, sig_algs)
    }

    pub fn parse_dns_query(payload: &[u8]) -> Option<DnsRecord> {
        if payload.len() < 12 {
            return None;
        }
        let tid = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let qdcount = u16::from_be_bytes([payload[4], payload[5]]);
        if qdcount == 0 || (flags & 0x8000) != 0 {
            return None;
        }

        let mut pos = 12;
        let mut domain = String::new();
        loop {
            if pos >= payload.len() {
                return None;
            }
            let len = payload[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if pos + 1 + len > payload.len() {
                return None;
            }
            if !domain.is_empty() {
                domain.push('.');
            }
            if let Ok(s) = std::str::from_utf8(&payload[pos + 1..pos + 1 + len]) {
                domain.push_str(s);
            }
            pos += 1 + len;
        }
        if pos + 4 > payload.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([payload[pos], payload[pos + 1]]);

        Some(DnsRecord {
            timestamp: chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64,
            transaction_id: tid,
            domain,
            query_type: qtype,
            dga_score: 0.0,
        })
    }

    pub fn compute_dga_score(domain: &str) -> f32 {
        let name = domain.trim_end_matches('.');
        if let Some(dot) = name.rfind('.') {
            let tld = &name[dot + 1..];
            let sld = &name[..dot];
            if let Some(dot2) = sld.rfind('.') {
                let reg = &sld[dot2 + 1..];
                let entropy = Self::shannon_entropy(reg);
                let vowel_ratio = reg.chars().filter(|c| "aeiou".contains(*c)).count() as f32
                    / reg.len().max(1) as f32;
                if entropy > 3.5 && vowel_ratio < 0.2 {
                    return 0.8;
                } else if entropy > 2.8 {
                    return 0.4;
                }
            }
        }
        0.0
    }

    fn shannon_entropy(s: &str) -> f32 {
        if s.is_empty() {
            return 0.0;
        }
        let mut freq = [0u32; 256];
        for b in s.bytes() {
            freq[b as usize] += 1;
        }
        let len = s.len() as f32;
        freq.iter()
            .filter(|c| **c > 0)
            .map(|c| {
                let p = *c as f32 / len;
                -p * p.log2()
            })
            .sum()
    }

    pub fn known_malicious_ja4() -> Vec<&'static str> {
        vec!["t13d151600_h2_s1", "t12d150900_00_00", "t13d1e0000_h2_s1"]
    }
}

#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub timestamp: u64,
    pub transaction_id: u16,
    pub domain: String,
    pub query_type: u16,
    pub dga_score: f32,
}
