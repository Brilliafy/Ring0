use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::RwLock;
use tracing::info;

use crate::dpi::DpiEngine;

const MAX_STREAM_SIZE: usize = 64 * 1024;
const IDLE_TIMEOUT_SECS: u64 = 120;

#[repr(C)]
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct FlowKey5 {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
}

struct StreamBuffer {
    buffer: Vec<u8>,
    expected_seq: u32,
    segments: Vec<TcpSegment>,
    last_activity: Instant,
    complete: bool,
}

struct TcpSegment {
    seq: u32,
    data: Vec<u8>,
    length: u32,
}

pub struct ReassemblyEngine {
    streams: Arc<RwLock<HashMap<FlowKey5, StreamBuffer>>>,
}

impl ReassemblyEngine {
    pub fn new() -> Self {
        Self {
            streams: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn ingest_tcp_segment(
        &self,
        key: &FlowKey5,
        seq: u32,
        payload: &[u8],
        _ack: u32,
        fin: bool,
        dpi: &DpiEngine,
    ) -> Vec<String> {
        if payload.is_empty() && !fin {
            return Vec::new();
        }

        let mut streams = self.streams.write();
        let stream = streams.entry(key.clone()).or_insert_with(|| StreamBuffer {
            buffer: Vec::with_capacity(MAX_STREAM_SIZE),
            expected_seq: seq,
            segments: Vec::new(),
            last_activity: Instant::now(),
            complete: false,
        });

        stream.last_activity = Instant::now();

        if fin {
            stream.complete = true;
            let payload = std::mem::take(&mut stream.buffer);
            if !payload.is_empty() {
                let matches = dpi.scan_payload(&payload);
                let alerts: Vec<String> = matches
                    .iter()
                    .map(|m| format!("sid={} msg={}", m.rule_id, m.signature_name))
                    .collect();
                if !alerts.is_empty() {
                    info!(
                        "Reassembly: flow {:?} complete — {} alerts",
                        key,
                        alerts.len()
                    );
                }
                return alerts;
            }
            return Vec::new();
        }

        if seq == stream.expected_seq {
            let avail = MAX_STREAM_SIZE.saturating_sub(stream.buffer.len());
            let end = payload.len().min(avail);
            stream.buffer.extend_from_slice(&payload[..end]);
            stream.expected_seq = seq.wrapping_add(payload.len() as u32);

            let mut merged = true;
            while merged {
                merged = false;
                let mut to_remove = Vec::new();
                for (i, seg) in stream.segments.iter().enumerate() {
                    if seg.seq == stream.expected_seq {
                        let avail = MAX_STREAM_SIZE.saturating_sub(stream.buffer.len());
                        let end = seg.data.len().min(avail);
                        stream.buffer.extend_from_slice(&seg.data[..end]);
                        stream.expected_seq = stream.expected_seq.wrapping_add(seg.length);
                        to_remove.push(i);
                        merged = true;
                        break;
                    }
                }
                for i in to_remove.into_iter().rev() {
                    stream.segments.remove(i);
                }
            }

            if stream.buffer.len() > MAX_STREAM_SIZE / 2 {
                let payload = std::mem::take(&mut stream.buffer);
                let matches = dpi.scan_payload(&payload);
                let alerts: Vec<String> = matches
                    .iter()
                    .map(|m| format!("sid={} msg={}", m.rule_id, m.signature_name))
                    .collect();
                if !alerts.is_empty() {
                    info!("Reassembly: mid-stream scan — {} alerts", alerts.len());
                }
                return alerts;
            }
        } else if seq.wrapping_sub(stream.expected_seq) < 10000 {
            stream.segments.push(TcpSegment {
                seq,
                data: payload.to_vec(),
                length: payload.len() as u32,
            });
        }

        Vec::new()
    }

    pub fn remove_flow(&self, key: &FlowKey5) {
        self.streams.write().remove(key);
        info!("Reassembly: removed flow {:?}", key);
    }

    pub fn purge_idle(&self) {
        let now = Instant::now();
        let mut streams = self.streams.write();
        let before = streams.len();
        streams.retain(|_, s| now.duration_since(s.last_activity).as_secs() < IDLE_TIMEOUT_SECS);
        let purged = before - streams.len();
        if purged > 0 {
            info!(
                "Reassembly: purged {purged} idle streams, {active} active",
                active = streams.len()
            );
        }
    }

    pub fn active_streams(&self) -> usize {
        self.streams.read().len()
    }
}
