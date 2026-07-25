use std::collections::VecDeque;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use flate2::write::GzEncoder;
use flate2::Compression;
use parking_lot::RwLock;
use tracing::{error, info, warn};

const PCAP_BUFFER_SIZE: usize = 100 * 1024 * 1024;
const PCAP_WINDOW_SECS: u64 = 30;
const FORENSICS_DIR: &str = "/var/log/ring0/forensics";

static NEXT_CASE_ID: AtomicU64 = AtomicU64::new(1);

struct PacketFrame {
    timestamp_ns: u64,
    data: Vec<u8>,
}

struct PcapHeader {
    magic: u32,
    version_major: u16,
    version_minor: u16,
    thiszone: i32,
    sigfigs: u32,
    snaplen: u32,
    network: u32,
}

impl PcapHeader {
    fn as_bytes(&self) -> [u8; 24] {
        let mut buf = [0u8; 24];
        buf[0..4].copy_from_slice(&self.magic.to_le_bytes());
        buf[4..6].copy_from_slice(&self.version_major.to_le_bytes());
        buf[6..8].copy_from_slice(&self.version_minor.to_le_bytes());
        buf[8..12].copy_from_slice(&self.thiszone.to_le_bytes());
        buf[12..16].copy_from_slice(&self.sigfigs.to_le_bytes());
        buf[16..20].copy_from_slice(&self.snaplen.to_le_bytes());
        buf[20..24].copy_from_slice(&self.network.to_le_bytes());
        buf
    }
}

fn pcap_packet_header(ts_ns: u64, orig_len: u32) -> [u8; 16] {
    let secs = (ts_ns / 1_000_000_000) as u32;
    let frac = (ts_ns % 1_000_000_000) as u32;
    let incl_len = orig_len.min(65535);
    let mut buf = [0u8; 16];
    buf[0..4].copy_from_slice(&secs.to_le_bytes());
    buf[4..8].copy_from_slice(&frac.to_le_bytes());
    buf[8..12].copy_from_slice(&incl_len.to_le_bytes());
    buf[12..16].copy_from_slice(&orig_len.to_le_bytes());
    buf
}

pub struct RollingPacketBuffer {
    buffer: Arc<RwLock<VecDeque<PacketFrame>>>,
    total_size: AtomicU64,
    max_size: usize,
    window_secs: u64,
    enabled: AtomicBool,
}

impl RollingPacketBuffer {
    pub fn new() -> Self {
        Self {
            buffer: Arc::new(RwLock::new(VecDeque::with_capacity(4096))),
            total_size: AtomicU64::new(0),
            max_size: PCAP_BUFFER_SIZE,
            window_secs: PCAP_WINDOW_SECS,
            enabled: AtomicBool::new(true),
        }
    }

    pub fn push(&self, data: &[u8], timestamp_ns: u64) {
        if !self.enabled.load(Ordering::Relaxed) {
            return;
        }
        let frame_len = data.len() + 16;
        let mut buf = self.buffer.write();
        self.total_size
            .fetch_add(frame_len as u64, Ordering::Relaxed);
        buf.push_back(PacketFrame {
            timestamp_ns,
            data: data.to_vec(),
        });
        while self.total_size.load(Ordering::Relaxed) > self.max_size as u64 {
            if let Some(front) = buf.pop_front() {
                let freed = front.data.len() + 16;
                self.total_size.fetch_sub(freed as u64, Ordering::Relaxed);
            } else {
                break;
            }
        }
        let cutoff = timestamp_ns.saturating_sub(self.window_secs * 1_000_000_000);
        while let Some(front) = buf.front() {
            if front.timestamp_ns < cutoff {
                if let Some(removed) = buf.pop_front() {
                    let freed = removed.data.len() + 16;
                    self.total_size.fetch_sub(freed as u64, Ordering::Relaxed);
                }
            } else {
                break;
            }
        }
    }

    pub fn snapshot(&self) -> Vec<PacketFrame> {
        self.buffer
            .read()
            .iter()
            .map(|f| PacketFrame {
                timestamp_ns: f.timestamp_ns,
                data: f.data.clone(),
            })
            .collect()
    }

    pub fn enable(&self) {
        self.enabled.store(true, Ordering::Relaxed);
    }

    pub fn disable(&self) {
        self.enabled.store(false, Ordering::Relaxed);
    }

    pub fn buffer_size(&self) -> usize {
        self.buffer.read().len()
    }
}

pub struct ForensicExporter {
    packet_buffer: Arc<RollingPacketBuffer>,
    db: Arc<rocksdb::DB>,
    storage: Arc<crate::storage::RocksManager>,
}

impl ForensicExporter {
    pub fn new(
        packet_buffer: Arc<RollingPacketBuffer>,
        db: Arc<rocksdb::DB>,
        storage: Arc<crate::storage::RocksManager>,
    ) -> Self {
        fs::create_dir_all(FORENSICS_DIR).ok();
        Self {
            packet_buffer,
            db,
            storage,
        }
    }

    pub fn trigger_export(&self, alert_id: u64, severity: u8, description: &str) {
        let frames = self.packet_buffer.snapshot();
        let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S").to_string();
        let case_id = NEXT_CASE_ID.fetch_add(1, Ordering::Relaxed);
        let filename = format!("incident_{}_{}.tar.gz", timestamp, case_id);
        let path = PathBuf::from(FORENSICS_DIR).join(&filename);

        let desc_owned = description.to_string();
        tokio::task::spawn_blocking(move || {
            if let Err(e) = Self::write_bundle(
                &path,
                &frames,
                alert_id,
                severity,
                &desc_owned,
                timestamp,
                case_id,
            ) {
                error!("Forensic export failed for case_{case_id}: {e:?}");
            } else {
                info!(
                    "Forensic bundle written: {} ({:.2} MB, {} packets, severity={})",
                    path.display(),
                    frames.len() as f64 * 1500.0 / 1024.0 / 1024.0,
                    frames.len(),
                    severity,
                );
            }
        });
    }

    fn write_bundle(
        path: &Path,
        frames: &[PacketFrame],
        alert_id: u64,
        severity: u8,
        description: &str,
        timestamp: String,
        case_id: u64,
    ) -> Result<()> {
        let file = File::create(path).context("Failed to create forensic archive")?;
        let buf_writer = BufWriter::new(file);
        let mut encoder = GzEncoder::new(buf_writer, Compression::best());

        {
            let mut header = tar::Header::new_gnu();
            header.set_path("incident.json")?;
            let manifest = serde_json::json!({
                "case_id": case_id,
                "alert_id": alert_id,
                "severity": severity,
                "timestamp": timestamp,
                "description": description,
                "packet_count": frames.len(),
            });
            let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
            header.set_size(manifest_bytes.len() as u64);
            header.set_cksum();
            encoder.write_all(&header.as_bytes())?;
            encoder.write_all(&manifest_bytes)?;
        }

        {
            let mut header = tar::Header::new_gnu();
            header.set_path("capture.pcap")?;
            let pcap_bytes = Self::build_pcap(frames);
            header.set_size(pcap_bytes.len() as u64);
            header.set_cksum();
            encoder.write_all(&header.as_bytes())?;
            encoder.write_all(&pcap_bytes)?;
        }

        {
            let mut header = tar::Header::new_gnu();
            header.set_path("process_snapshot.txt")?;
            let snapshot = Self::capture_process_snapshot();
            let snapshot_bytes = snapshot.as_bytes();
            header.set_size(snapshot_bytes.len() as u64);
            header.set_cksum();
            encoder.write_all(&header.as_bytes())?;
            encoder.write_all(snapshot_bytes)?;
        }

        encoder.finish()?;
        Ok(())
    }

    fn build_pcap(frames: &[PacketFrame]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(24 + frames.len() * (16 + 1500));
        let header = PcapHeader {
            magic: 0xa1b2c3d4,
            version_major: 2,
            version_minor: 4,
            thiszone: 0,
            sigfigs: 0,
            snaplen: 65535,
            network: 1,
        };
        buf.extend_from_slice(&header.as_bytes());
        for frame in frames {
            let orig_len = frame.data.len() as u32;
            buf.extend_from_slice(&pcap_packet_header(frame.timestamp_ns, orig_len));
            buf.extend_from_slice(&frame.data);
        }
        buf
    }

    fn capture_process_snapshot() -> String {
        let mut output = String::new();
        output.push_str("=== Ring0 Forensic Process Snapshot ===\n");
        output.push_str(&format!(
            "Timestamp: {}\n\n",
            chrono::Utc::now().to_rfc3339()
        ));

        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                let pid_str = match entry.file_name().to_str() {
                    Some(s) => s.to_string(),
                    None => continue,
                };
                if let Ok(pid) = pid_str.parse::<u32>() {
                    let status_path = format!("/proc/{pid}/status");
                    if let Ok(content) = fs::read_to_string(&status_path) {
                        let name = content
                            .lines()
                            .find(|l| l.starts_with("Name:"))
                            .unwrap_or("")
                            .to_string();
                        let state = content
                            .lines()
                            .find(|l| l.starts_with("State:"))
                            .unwrap_or("")
                            .to_string();
                        let ppid = content
                            .lines()
                            .find(|l| l.starts_with("PPid:"))
                            .unwrap_or("")
                            .to_string();
                        let uid = content
                            .lines()
                            .find(|l| l.starts_with("Uid:"))
                            .unwrap_or("")
                            .to_string();
                        output.push_str(&format!(
                            "PID {}: {} | {} | {} | {}\n",
                            pid, name, state, ppid, uid
                        ));
                    }
                    let cmdline_path = format!("/proc/{pid}/cmdline");
                    if let Ok(cmd) = fs::read_to_string(&cmdline_path) {
                        let clean = cmd.replace('\0', " ");
                        if !clean.trim().is_empty() {
                            output.push_str(&format!("  cmdline: {}\n", clean.trim()));
                        }
                    }
                }
            }
        }

        output.push_str("\n=== Memory & Environment Metrics ===\n");
        if let Ok(meminfo) = fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines().take(10) {
                output.push_str(line);
                output.push('\n');
            }
        }
        if let Ok(loadavg) = fs::read_to_string("/proc/loadavg") {
            output.push_str(&format!("loadavg: {}\n", loadavg.trim()));
        }

        output
    }
}
