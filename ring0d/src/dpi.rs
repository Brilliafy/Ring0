use anyhow::Result;
use tracing::warn;

const RULES: &[(&str, u32, &str)] = &[
    (r"(?i)(\%27|')\s*OR\s*", 1001, "SQLi - OR injection"),
    (r"(?i)UNION\s+.*SELECT\s+", 1002, "SQLi - UNION SELECT"),
    (r"(?i)DROP\s+TABLE", 1003, "SQLi - DROP TABLE"),
    (r"(?i)cmd=whoami", 2001, "C2 - whoami probe"),
    (r"(?i)cmd=id\b", 2002, "C2 - id probe"),
    (r"(?i)cmd=cat\s+/etc/passwd", 2003, "C2 - passwd exfil"),
    (r"(/etc/shadow)", 2004, "File access - shadow"),
    (
        r"(?i)curl\s+.*(?:10\.|172\.|192\.168)",
        3001,
        "Lateral movement",
    ),
    (
        r"(?i)wget\s+.*(?:10\.|172\.|192\.168)",
        3002,
        "Lateral movement",
    ),
];

#[derive(Debug, Clone)]
pub struct DpiMatch {
    pub rule_id: u32,
    pub signature_name: String,
    pub severity: u8,
}

pub struct DpiEngine {
    db: hyperscan::BlockDatabase,
}

impl DpiEngine {
    pub fn new() -> Result<Self> {
        let patterns: Vec<hyperscan::Pattern> = RULES
            .iter()
            .map(|(pat, id, _)| {
                hyperscan::Pattern::new(pat)
                    .id(*id)
                    .flags(hyperscan::PatternFlags::all())
                    .build()
            })
            .collect::<Result<Vec<_>, _>>()
            .map_err(|e| anyhow::anyhow!("Hyperscan pattern compilation failed: {e:?}"))?;

        let db = hyperscan::BlockDatabase::new(&patterns)
            .map_err(|e| anyhow::anyhow!("Hyperscan database creation failed: {e:?}"))?;
        Ok(Self { db })
    }

    pub fn scan_payload(&self, payload: &[u8]) -> Vec<DpiMatch> {
        if payload.is_empty() {
            return Vec::new();
        }
        let mut results = Vec::new();
        let mut scratch = match hyperscan::scratch::Scratch::new(&self.db) {
            Ok(s) => s,
            Err(e) => {
                warn!("Hyperscan scratch allocation failed: {e:?}");
                return Vec::new();
            }
        };

        let scan_result = self
            .db
            .scan(payload, &mut scratch, |id, _from, _to, _flags| {
                for (_, rule_id, sig_name) in RULES {
                    if *rule_id == id {
                        let severity = match rule_id {
                            1001..=1999 => 2,
                            2001..=2999 => 3,
                            3001..=3999 => 1,
                            _ => 0,
                        };
                        results.push(DpiMatch {
                            rule_id: *rule_id,
                            signature_name: sig_name.to_string(),
                            severity,
                        });
                        break;
                    }
                }
                hyperscan::scan::ScanResult::Continue
            });

        if let Err(e) = scan_result {
            warn!("Hyperscan scan failed: {e:?}");
        }

        results
    }
}
