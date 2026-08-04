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
        severity: 3,
    },
    Signature {
        rule_id: 5010,
        name: "ET POLICY powershell encoded command",
        pattern: "(?i)powershell.{0,32}-e",
        severity: 3,
    },
    Signature {
        rule_id: 5011,
        name: "ET TROJAN suspicious wget -O",
        pattern: "(?i)wget.{0,24}-O",
        severity: 2,
    },
    Signature {
        rule_id: 5012,
        name: "ET TROJAN suspicious curl -o",
        pattern: "(?i)curl.{0,24}-o",
        severity: 2,
    },
    Signature {
        rule_id: 5013,
        name: "ET TROJAN Cobalt Strike beacon",
        pattern: "(?i)(MZ|beacon)",
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

pub struct DpiEngine {
    regexes: Vec<(u32, &'static str, u8, hyperscan::regex::Regex)>,
}

impl DpiEngine {
    pub fn new() -> Result<Self> {
        let mut regexes = Vec::new();
        let mut failed = 0usize;
        for sig in SIGNATURES {
            match hyperscan::regex::Regex::new(sig.pattern) {
                Ok(re) => regexes.push((sig.rule_id, sig.name, sig.severity, re)),
                Err(e) => {
                    warn!("DPI signature {:?} failed to compile: {e}", sig.name);
                    failed += 1;
                }
            }
        }
        info!(
            "DPI engine initialized with {} signatures ({} skipped)",
            regexes.len(),
            failed
        );
        Ok(Self { regexes })
    }

    pub fn signature_count(&self) -> usize {
        self.regexes.len()
    }

    /// Scan a payload (e.g. TLS plaintext, reassembled stream) for threat signatures.
    pub fn scan_payload(&self, payload: &[u8]) -> Vec<DpiMatch> {
        if payload.is_empty() {
            return Vec::new();
        }
        let text = String::from_utf8_lossy(payload);
        let mut matches = Vec::new();
        for (rule_id, name, sev, re) in &self.regexes {
            if re.is_match(&text) {
                matches.push(DpiMatch {
                    rule_id: *rule_id,
                    signature_name: name.to_string(),
                    severity: *sev,
                });
            }
        }
        matches
    }
}

impl Default for DpiEngine {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            regexes: Vec::new(),
        })
    }
}
