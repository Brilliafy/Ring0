use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct DpiMatch {
    pub rule_id: u32,
    pub signature_name: String,
    pub severity: u8,
}

pub struct Signature {
    pub rule_id: u32,
    pub name: &'static str,
    pub pattern: &'static str,
    pub severity: u8,
}

/// Built-in NIDS/DPI signature set (hyperscan regexes).
const SIGNATURES: &[Signature] = &[
    Signature {
        rule_id: 5001,
        name: "ET WEB_SPECIFIC_APPS /bin/sh command execution attempt",
        pattern: "/bin/sh",
        severity: 3,
    },
    Signature {
        rule_id: 5002,
        name: "ET POLICY suspicious cmd.exe execution",
        pattern: "cmd\\.exe",
        severity: 2,
    },
    Signature {
        rule_id: 5003,
        name: "ET WEB_SERVER SQL injection SELECT..FROM",
        pattern: "(?i)select\\s+.{0,16}from",
        severity: 3,
    },
    Signature {
        rule_id: 5004,
        name: "ET WEB_SPECIFIC_APPS PHP webshell eval(base64_decode",
        pattern: "eval\\s*\\(\\s*base64_decode",
        severity: 4,
    },
    Signature {
        rule_id: 5005,
        name: "ET SCAN sqlmap user-agent",
        pattern: "(?i)user-agent:.*sqlmap",
        severity: 2,
    },
    Signature {
        rule_id: 5006,
        name: "ET SCAN Nikto user-agent",
        pattern: "(?i)user-agent:.*nikto",
        severity: 2,
    },
    Signature {
        rule_id: 5007,
        name: "ET SCAN Nmap scripted scan",
        pattern: "(?i)user-agent:.*nmap",
        severity: 2,
    },
    Signature {
        rule_id: 5008,
        name: "ET INFO /etc/passwd access attempt",
        pattern: "/etc/passwd",
        severity: 2,
    },
    Signature {
        rule_id: 5009,
        name: "ET INFO /etc/shadow access attempt",
        pattern: "/etc/shadow",
        severity: 2,
    },
    Signature {
        rule_id: 5010,
        name: "ET INFO /etc/hosts access attempt",
        pattern: "/etc/hosts",
        severity: 2,
    },
    Signature {
        rule_id: 5011,
        name: "ET INFO /root/.ssh/id_rsa access attempt",
        pattern: "\\.ssh/id_rsa",
        severity: 4,
    },
    Signature {
        rule_id: 5012,
        name: "ET INFO AWS credentials leak",
        pattern: "AKIA[0-9A-Z]{16}",
        severity: 4,
    },
    Signature {
        rule_id: 5013,
        name: "ET INFO GitHub token leak",
        pattern: "ghp_[0-9A-Za-z]{36}",
        severity: 4,
    },
    Signature {
        rule_id: 5014,
        name: "ET MALWARE webshell one-liner",
        pattern: "(?i)(assert|system|exec)\\(\\$_",
        severity: 4,
    },
    Signature {
        rule_id: 5015,
        name: "ET WEB_SERVER PHP code injection",
        pattern: "\\$_GET.{0,32}exec",
        severity: 4,
    },
    Signature {
        rule_id: 5016,
        name: "ET SHELLCODE x86 NOP sled",
        pattern: "\\x90{8,}",
        severity: 3,
    },
    Signature {
        rule_id: 5017,
        name: "ET MALWARE UPX packed binary",
        pattern: "UPX!",
        severity: 2,
    },
    Signature {
        rule_id: 5018,
        name: "ET MALWARE Mimikatz strings",
        pattern: "(?i)mimikatz",
        severity: 4,
    },
    Signature {
        rule_id: 5019,
        name: "ET TROJAN C2 check-in",
        pattern: "(?i)(POST|GET).{0,32}(/api/|/c2/)",
        severity: 2,
    },
    Signature {
        rule_id: 5020,
        name: "ET TROJAN TOR bridge connection",
        pattern: "(?i)bridgedb|torproject",
        severity: 2,
    },
];

/// Maximum payloads scanned per second. Each TLS uprobe event carries a
/// payload snippet; under TLS-heavy traffic (video streaming, bulk transfers)
/// the raw event rate can reach thousands/sec. Hyperscan is O(n) per scan, but
/// per-scan call overhead plus the daemon's alert/storage pipeline still
/// needs a hard ceiling so ordinary traffic cannot peg a core. Scans beyond
/// the budget are skipped (the most recent traffic still gets scanned).
const MAX_SCANS_PER_SEC: u64 = 300;

/// Single-pass DPI engine.
///
/// All signatures live in ONE hyperscan database (compiled multi-pattern), so
/// each payload is scanned in a single O(n) pass with one shared scratch
/// buffer. The previous implementation ran one `hs_scan` per signature
/// (O(signatures × n)) and copied every payload through `String::from_utf8_lossy`;
/// both are gone — scanning is zero-copy over the raw bytes.
pub struct DpiEngine {
    db: hyperscan::BlockDatabase,
    scratch: hyperscan::Scratch,
    /// Parallel to the compiled pattern ids: (rule_id, name, severity).
    ids: Vec<(u32, &'static str, u8)>,
    /// Dynamic Suricata-derived signature set (fed by sucadara). Compiled into
    /// its own database so a bad batch never corrupts the built-in one; a
    /// failed recompile keeps the previous set.
    dyn_db: Option<hyperscan::BlockDatabase>,
    dyn_scratch: Option<hyperscan::Scratch>,
    dyn_ids: Vec<(u32, String, u8)>,
    /// 1-second sliding bucket for the scan rate limit.
    scan_bucket: AtomicU64,
    scan_count: AtomicU64,
}

impl DpiEngine {
    pub fn new() -> Result<Self> {
        use hyperscan::prelude::*;

        let mut patterns = Vec::with_capacity(SIGNATURES.len());
        let mut ids = Vec::with_capacity(SIGNATURES.len());
        let mut failed = 0usize;
        for (i, sig) in SIGNATURES.iter().enumerate() {
            match Pattern::new(sig.pattern) {
                Ok(mut p) => {
                    p.id = Some(i);
                    patterns.push(p);
                    ids.push((sig.rule_id, sig.name, sig.severity));
                }
                Err(e) => {
                    warn!("DPI signature {:?} failed to compile: {e}", sig.name);
                    failed += 1;
                }
            }
        }
        if patterns.is_empty() {
            anyhow::bail!("DPI engine has zero compiled signatures");
        }
        let db: BlockDatabase = Patterns(patterns).build()?;
        let scratch = db.alloc_scratch()?;
        info!(
            "DPI engine: {} signatures in one O(n) hyperscan database ({} skipped)",
            ids.len(),
            failed
        );
        Ok(Self {
            db,
            scratch,
            ids,
            dyn_db: None,
            dyn_scratch: None,
            dyn_ids: Vec::new(),
            scan_bucket: AtomicU64::new(0),
            scan_count: AtomicU64::new(0),
        })
    }

    pub fn signature_count(&self) -> usize {
        self.ids.len()
    }

    /// Look up a signature name by rule id (for the kernel fast-path DPI
    /// events, whose rule ids mirror this table).
    pub fn signature_name(&self, rule_id: u32) -> Option<&'static str> {
        SIGNATURES
            .iter()
            .find(|s| s.rule_id == rule_id)
            .map(|s| s.name)
    }

    /// Replace the dynamic (Suricata-derived) signature set. Patterns arrive
    /// as hyperscan-ready strings (already escaped; `(?i)` inline for nocase)
    /// with (sid, severity). A failed compile keeps the previous set and the
    /// batch is logged — a poisoned feed must not disable detection.
    pub fn set_dynamic_patterns(&mut self, patterns: Vec<(u32, String, u8)>) {
        use hyperscan::prelude::*;
        if patterns.is_empty() {
            self.dyn_db = None;
            self.dyn_scratch = None;
            self.dyn_ids.clear();
            info!(
                "DPI: dynamic signature set cleared ({} patterns)",
                patterns.len()
            );
            return;
        }
        let mut compiled = Vec::with_capacity(patterns.len());
        let mut skipped = 0usize;
        for (i, (sid, pat, sev)) in patterns.iter().enumerate() {
            match Pattern::new(pat) {
                Ok(mut p) => {
                    p.id = Some(i);
                    compiled.push(p);
                    self.dyn_ids.push((*sid, pat.clone(), *sev));
                }
                Err(e) => {
                    warn!("DPI: suricata pattern {pat:?} (sid {sid}) failed to compile: {e}");
                    skipped += 1;
                }
            }
        }
        let build_result: Result<hyperscan::BlockDatabase, _> = Patterns(compiled).build();
        match build_result {
            Ok(db) => match db.alloc_scratch() {
                Ok(scratch) => {
                    self.dyn_db = Some(db);
                    self.dyn_scratch = Some(scratch);
                    info!(
                        "DPI: {} dynamic (suricata) signatures compiled ({} skipped)",
                        self.dyn_ids.len(),
                        skipped
                    );
                }
                Err(e) => warn!("DPI: dynamic scratch alloc failed: {e}"),
            },
            Err(e) => {
                warn!(
                    "DPI: dynamic signature compile failed ({e}) — keeping previous set of {}",
                    self.dyn_ids.len()
                );
            }
        }
    }

    fn scan_allowed(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let bucket = self.scan_bucket.load(Ordering::Relaxed);
        if bucket != now {
            // New 1-second window: reset the counter (benign race — worst case
            // we under- or over-count by one window).
            self.scan_bucket.store(now, Ordering::Relaxed);
            self.scan_count.store(1, Ordering::Relaxed);
            return true;
        }
        let count = self.scan_count.fetch_add(1, Ordering::Relaxed);
        count < MAX_SCANS_PER_SEC
    }

    /// Scan a payload (e.g. TLS plaintext, reassembled stream) for threat
    /// signatures. Single O(n) hyperscan pass over ALL signatures; the payload
    /// is scanned in place (zero-copy, no UTF-8 validation — patterns are
    /// byte-oriented). Rate-limited to `MAX_SCANS_PER_SEC` payloads/sec.
    pub fn scan_payload(&self, payload: &[u8]) -> Vec<DpiMatch> {
        if payload.is_empty() || !self.scan_allowed() {
            return Vec::new();
        }
        let ids = &self.ids;
        let dyn_ids = &self.dyn_ids;
        let mut matches: Vec<DpiMatch> = Vec::new();
        let mut push_match = |rule_id: u32, name: String, sev: u8| {
            if !matches.iter().any(|m: &DpiMatch| m.rule_id == rule_id) {
                matches.push(DpiMatch {
                    rule_id,
                    signature_name: name,
                    severity: sev,
                });
            }
        };
        // Ignore scan errors: hyperscan only fails on invalid scratch/limits,
        // which cannot happen here; a failed scan should not disrupt the loop.
        let _ = self.db.scan(payload, &self.scratch, |id, _from, _to, _| {
            if let Some((rule_id, name, sev)) = ids.get(id as usize) {
                push_match(*rule_id, name.to_string(), *sev);
            }
            hyperscan::Matching::Continue
        });
        // Dynamic (Suricata) set, when compiled.
        if let (Some(db), Some(scratch)) = (&self.dyn_db, &self.dyn_scratch) {
            let _ = db.scan(payload, scratch, |id, _from, _to, _| {
                if let Some((sid, name, sev)) = dyn_ids.get(id as usize) {
                    push_match(*sid, name.clone(), *sev);
                }
                hyperscan::Matching::Continue
            });
        }
        matches
    }
}

impl Default for DpiEngine {
    fn default() -> Self {
        // The engine is built once at daemon startup; a compile failure is a
        // configuration error (a signature failed to compile) and should be
        // loud, not silently disabled.
        Self::new().expect("DPI engine initialization failed")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpi_matches_literals_and_regexes() {
        let engine = DpiEngine::new().unwrap();
        assert!(engine.signature_count() >= 20);
        let hits = engine.scan_payload(b"GET /api/ HTTP/1.1\nUser-Agent: sqlmap");
        assert!(
            hits.iter().any(|m| m.rule_id == 5005),
            "sqlmap UA should match: {:?}",
            hits
        );
        let hits = engine.scan_payload(b"eval(base64_decode(\"abc\"))");
        assert!(hits.iter().any(|m| m.rule_id == 5004), "{:?}", hits);
        let hits = engine.scan_payload(b"AKIA0123456789ABCDEF");
        assert!(hits.iter().any(|m| m.rule_id == 5012), "{:?}", hits);
    }

    #[test]
    fn dpi_dynamic_suricata_patterns_match() {
        let mut engine = DpiEngine::new().unwrap();
        // Simulates what sucadara pushes: (sid, escaped-regex pattern, sev).
        engine.set_dynamic_patterns(vec![
            (2024242, r"(?i)malware-c2\.example".to_string(), 2),
            (2025555, "GET /cgi-bin/".to_string(), 3),
        ]);
        let hits = engine.scan_payload(b"POST https://malware-c2.example/beacon HTTP/1.1");
        assert!(
            hits.iter().any(|m| m.rule_id == 2024242),
            "dynamic suricata pattern should match: {:?}",
            hits
        );
        let hits = engine.scan_payload(b"GET /cgi-bin/cmd.php");
        assert!(hits.iter().any(|m| m.rule_id == 2025555), "{:?}", hits);
        // Clearing the set must remove dynamic matches.
        engine.set_dynamic_patterns(Vec::new());
        let hits = engine.scan_payload(b"POST https://malware-c2.example/beacon HTTP/1.1");
        assert!(!hits.iter().any(|m| m.rule_id == 2024242));
    }

    #[test]
    fn dpi_zero_copy_empty_and_non_utf8() {
        let engine = DpiEngine::new().unwrap();
        assert!(engine.scan_payload(b"").is_empty());
        // Non-UTF8 payload must not panic (no from_utf8_lossy anymore).
        let garbage = [
            0xffu8, 0xfe, 0x00, 0x80, b'/', b'b', b'i', b'n', b'/', b's', b'h',
        ];
        let hits = engine.scan_payload(&garbage);
        assert!(hits.iter().any(|m| m.rule_id == 5001), "{:?}", hits);
    }
}
