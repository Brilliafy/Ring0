//! Heuristic risk scoring: `score = w_process + w_network + w_payload`.
//!
//! A payload alone rarely tells you something is malicious — context does.
//! `python3` exec'ing from /tmp and uploading to a raw IP is interesting;
//! `firefox` downloading to ~/Downloads is not. The risk engine combines
//! process lineage, destination reputation signals, and payload matches into
//! a single score, and the daemon decides what (if anything) to do about it
//! based on the configured [`ResponseMode`] (default: notify only).

use crate::dpi::DpiMatch;
use crate::lineage::{LineageTree, SCRIPT_HOSTS};

/// Verdict thresholds from the decision matrix.
pub const FLAG_THRESHOLD: i32 = 40;
pub const ACTIVE_THRESHOLD: i32 = 70;

/// Default response to a high-risk (> 70) event. The default is NOTIFY:
/// killing/freezing processes can destroy work (an editor losing hours of
/// unsaved changes), so enforcement is strictly opt-in via
/// `RING0_RESPONSE=block|freeze|kill`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseMode {
    Notify,
    BlockNetwork,
    Freeze,
    Kill,
}

impl ResponseMode {
    pub fn from_env() -> Self {
        match std::env::var("RING0_RESPONSE").as_deref() {
            Ok("block") => ResponseMode::BlockNetwork,
            Ok("freeze") => ResponseMode::Freeze,
            Ok("kill") => ResponseMode::Kill,
            _ => ResponseMode::Notify,
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Verdict {
    Pass,
    Flagged,
    HighRisk,
}

#[derive(Debug, Clone, Default)]
pub struct RiskFactors {
    pub process_path: i32,
    pub script_parent: i32,
    pub new_destination: i32,
    pub nonstandard_port: i32,
    pub signature_match: i32,
    pub file_magic: i32,
}

#[derive(Debug, Clone)]
pub struct RiskResult {
    pub score: i32,
    pub verdict: Verdict,
    pub factors: RiskFactors,
}

/// Magic byte signatures that indicate a file payload in the TLS plaintext.
/// Presence in an UPLOAD (SSL_write) is exfiltration-ish; in a download it is
/// informational (a downloaded binary is normal — but worth noting).
fn detect_file_magic(buf: &[u8]) -> Option<&'static str> {
    if buf.starts_with(b"\x7fELF") {
        Some("ELF binary")
    } else if buf.starts_with(b"MZ") {
        Some("PE/DOS binary")
    } else if buf.starts_with(b"PK\x03\x04") {
        Some("ZIP archive")
    } else if buf.starts_with(b"#!") {
        Some("script shebang")
    } else if buf.starts_with(b"\x89PNG") {
        Some("PNG image")
    } else if buf.starts_with(b"\xff\xd8\xff") {
        Some("JPEG image")
    } else {
        None
    }
}

/// Suspicious execution roots for the process-path factor.
const SUSPICIOUS_PATH_MARKERS: &[&str] = &[
    "/tmp/",
    "/dev/shm/",
    "/var/tmp/",
    "/var/run/",
    "/proc/",
    "/dev/",
    "/home/",
    ".cache",
    ".local/tmp",
];

pub struct RiskEngine;

impl RiskEngine {
    pub fn score(
        lineage: &LineageTree,
        pid: u32,
        dst_ip: Option<u32>,
        dst_port: u16,
        is_write: bool,
        payload: &[u8],
        payload_hits: &[DpiMatch],
        trust_untrusted: bool,
    ) -> RiskResult {
        let mut f = RiskFactors::default();

        // ── Process factors ──
        let info = lineage.lookup(pid);
        let ancestry = lineage.ancestry(pid, 4);
        let binary = info.as_ref().map(|i| i.binary.as_str()).unwrap_or("");
        let cwd = info.as_ref().map(|i| i.cwd.as_str()).unwrap_or("");

        if SUSPICIOUS_PATH_MARKERS
            .iter()
            .any(|m| binary.contains(m) || (cwd.starts_with('/') && cwd.contains(m)))
            || (cwd.starts_with("/tmp") || cwd.starts_with("/dev/shm"))
        {
            f.process_path += 30;
        }
        if trust_untrusted {
            // Untrusted/unverifiable binary already adds weight on its own.
            f.process_path += 25;
        }
        // Script-host parent: any ancestor in the chain (excluding self) that
        // is a script host makes the leaf process's network activity risky.
        if ancestry
            .iter()
            .skip(1)
            .any(|a| SCRIPT_HOSTS.contains(&a.binary.rsplit('/').next().unwrap_or("").trim()))
        {
            f.script_parent += 20;
        }

        // ── Network factors ──
        // A destination we have never seen before is more likely to be
        // command-and-control or exfil than a habitual one. The baseline
        // module learns normal destinations; here we approximate "new" with
        // "no connection record in the lineage window".
        if let Some(ip) = dst_ip {
            if lineage.latest_connection(pid).map(|c| c.dst_ip) != Some(ip) {
                f.new_destination += 15;
            }
        } else {
            f.new_destination += 15;
        }
        if dst_port != 0 && !matches!(dst_port, 443 | 8443 | 80 | 8080) {
            f.nonstandard_port += 15;
        }

        // ── Payload factors ──
        let worst_sev = payload_hits.iter().map(|m| m.severity).max().unwrap_or(0);
        f.signature_match = match worst_sev {
            4 => 50,
            3 => 25,
            2 => 10,
            _ => 0,
        };
        // File magic in an UPLOAD is exfil/weapon-drop territory; in a
        // download it is informational.
        if let Some(_magic) = detect_file_magic(payload) {
            f.file_magic = if is_write { 30 } else { 10 };
        }

        let score = f.process_path
            + f.script_parent
            + f.new_destination
            + f.nonstandard_port
            + f.signature_match
            + f.file_magic;
        let verdict = if score >= ACTIVE_THRESHOLD {
            Verdict::HighRisk
        } else if score >= FLAG_THRESHOLD {
            Verdict::Flagged
        } else {
            Verdict::Pass
        };
        RiskResult {
            score,
            verdict,
            factors: f,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lineage::LineageTree;

    fn hit(sev: u8) -> DpiMatch {
        DpiMatch {
            rule_id: 9999,
            signature_name: "test".into(),
            severity: sev,
        }
    }

    #[test]
    fn trusted_browser_download_is_pass() {
        let tree = LineageTree::new();
        tree.record_exec(100, 1, "/usr/lib64/firefox/firefox", "firefox");
        tree.record_connect(100, 0x08080808, 443);
        let r = RiskEngine::score(
            &tree,
            100,
            Some(0x08080808),
            443,
            false,
            b"\x7fELF\x02\x01",
            &[],
            false,
        );
        // ELF download from a trusted browser: file_magic +10, nothing else.
        assert_eq!(r.score, 10);
        assert_eq!(r.verdict, Verdict::Pass);
    }

    #[test]
    fn tmp_python_upload_is_high_risk() {
        let tree = LineageTree::new();
        tree.record_exec(200, 150, "/tmp/x", "python3 exfil.py");
        tree.record_exec(150, 1, "/usr/bin/bash", "bash");
        // No prior connection -> "new destination".
        let r = RiskEngine::score(
            &tree,
            200,
            Some(0x0A000064),
            4444,
            true,
            b"MZ\x90\x00",
            &[hit(4)],
            true,
        );
        // process_path 30 + untrusted 25 + script_parent 20 + new_dst 15
        // + nonstandard 15 + signature 50 + magic(upload) 30 = 185
        assert!(r.score >= 100, "score={}", r.score);
        assert_eq!(r.verdict, Verdict::HighRisk);
    }

    #[test]
    fn moderate_case_is_flagged_not_active() {
        let tree = LineageTree::new();
        // A trusted binary (curl) to a NEW destination with a sev-3 match:
        // new_destination 15 + signature 25 = 40 -> exactly flagged, not active.
        tree.record_exec(300, 1, "/usr/bin/curl", "curl http://10.1.1.1/");
        // Note: no record_connect, so the destination counts as unseen.
        let r = RiskEngine::score(
            &tree,
            300,
            Some(0x0A010101),
            8080,
            false,
            b"<html>",
            &[hit(3)],
            false,
        );
        assert!(
            r.score >= FLAG_THRESHOLD && r.score < ACTIVE_THRESHOLD,
            "score={}",
            r.score
        );
        assert_eq!(r.verdict, Verdict::Flagged);
    }
}
