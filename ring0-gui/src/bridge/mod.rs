use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ring0_common::{DaemonCommand, LogQuery, QueryResponse, Ring0Event};
use ring0_common::proto as capnp_schema;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::notify::{DbusNotifier, Notification};

const MAX_QUEUED_EVENTS: usize = 1024;

pub struct Ring0BridgeRust {
    stream: Option<Arc<Mutex<UnixStream>>>,
    event_queue: Arc<Mutex<VecDeque<String>>>,
    reader_handle: Option<thread::JoinHandle<()>>,
    running: Arc<AtomicBool>,
    dbus_notifier: Arc<tokio::sync::Mutex<Option<DbusNotifier>>>,
}

impl Default for Ring0BridgeRust {
    fn default() -> Self {
        Self {
            stream: None,
            event_queue: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_QUEUED_EVENTS))),
            reader_handle: None,
            running: Arc::new(AtomicBool::new(false)),
            dbus_notifier: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
}

impl Drop for Ring0BridgeRust {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.reader_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Ring0BridgeRust {
    pub fn connect_daemon(self: Pin<&mut Self>, socket_path: String) -> bool {
        let this = self.get_mut();
        let rt = match tokio::runtime::Runtime::new() {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Ring0Bridge: tokio runtime failed: {e}");
                return false;
            }
        };
        let stream = match rt.block_on(UnixStream::connect(&socket_path)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Ring0Bridge: connect to {socket_path} failed: {e}");
                return false;
            }
        };
        drop(rt);

        let stream = Arc::new(Mutex::new(stream));
        this.stream = Some(stream.clone());
        this.running.store(true, Ordering::Relaxed);

        let event_queue = this.event_queue.clone();
        let running = this.running.clone();

        let handle = thread::Builder::new()
            .name("ring0-bridge-reader".into())
            .spawn(move || {
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Ring0Bridge reader: runtime failed: {e}");
                        return;
                    }
                };
                rt.block_on(async move {
                    let mut len_buf = [0u8; 4];
                    loop {
                        if !running.load(Ordering::Relaxed) {
                            break;
                        }
                        let mut guard = match stream.lock() {
                            Ok(g) => g,
                            Err(_) => break,
                        };
                        match guard.read_exact(&mut len_buf).await {
                            Ok(()) => {}
                            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                drop(guard);
                                tokio::time::sleep(Duration::from_millis(1)).await;
                                continue;
                            }
                            Err(_) => break,
                        }
                        let msg_len = u32::from_le_bytes(len_buf) as usize;
                        if msg_len == 0 || msg_len > 65536 {
                            break;
                        }
                        let mut msg_buf = vec![0u8; msg_len];
                        if guard.read_exact(&mut msg_buf).await.is_err() {
                            break;
                        }
                        drop(guard);

                        let event_json = match deserialize_to_json(&msg_buf) {
                            Some(j) => j,
                            None => continue,
                        };
                        if let Ok(mut q) = event_queue.lock() {
                            if q.len() >= MAX_QUEUED_EVENTS {
                                q.pop_front();
                            }
                            q.push_back(event_json);
                        }
                    }
                });
            });

        match handle {
            Ok(h) => this.reader_handle = Some(h),
            Err(e) => {
                eprintln!("Ring0Bridge: failed to spawn reader thread: {e}");
                this.running.store(false, Ordering::Relaxed);
                return false;
            }
        }
        true
    }

    pub fn block_ip(self: Pin<&mut Self>, ip: String) {
        let this = self.get_mut();
        if let Some(stream) = &this.stream {
            let frame = build_command_frame(|cmd| {
                cmd.setBlockIp(&ip);
            });
            if let Ok(guard) = stream.lock() {
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Ring0Bridge: runtime failed: {e}");
                        return;
                    }
                };
                rt.block_on(async {
                    let len = (frame.len() as u32).to_le_bytes();
                    let _ = guard.write_all(&len).await;
                    let _ = guard.write_all(&frame).await;
                });
            }
        }
    }

    pub fn kill_process(self: Pin<&mut Self>, pid: u32) {
        let this = self.get_mut();
        if let Some(stream) = &this.stream {
            let frame = build_command_frame(|cmd| {
                cmd.setKillProcess(pid);
            });
            if let Ok(guard) = stream.lock() {
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(r) => r,
                    Err(e) => {
                        eprintln!("Ring0Bridge: runtime failed: {e}");
                        return;
                    }
                };
                rt.block_on(async {
                    let len = (frame.len() as u32).to_le_bytes();
                    let _ = guard.write_all(&len).await;
                    let _ = guard.write_all(&frame).await;
                });
            }
        }
    }

    pub fn poll_events(self: Pin<&mut Self>) -> String {
        let this = self.get_mut();
        let mut buf = String::new();
        if let Ok(mut q) = this.event_queue.lock() {
            while let Some(evt) = q.pop_front() {
                if !buf.is_empty() {
                    buf.push('\n');
                }
                buf.push_str(&evt);
            }
        }
        buf
    }

    pub fn send_desktop_notification(
        self: Pin<&mut Self>,
        severity: u32,
        title: String,
        message: String,
    ) {
        let this = self.get_mut();
        let notifier = this.dbus_notifier.clone();
        tokio::spawn(async move {
            let urgency = match severity {
                0..=1 => 0,
                2 => 1,
                _ => 2,
            };
            let notif = Notification {
                summary: title,
                body: message,
                urgency,
                actions: vec![
                    ("block_ip".into(), "Block IP".into()),
                    ("quarantine".into(), "Quarantine PID".into()),
                ],
            };
            let mut guard = notifier.lock().await;
            if let Some(ref mut n) = *guard {
                let _ = n.send_notification(notif).await;
            }
        });
    }

    pub fn init_dbus_notifications(self: Pin<&mut Self>) {
        let this = self.get_mut();
        let notifier = this.dbus_notifier.clone();
        tokio::spawn(async move {
            let mut n = DbusNotifier::new();
            match n.0.connect().await {
                Ok(true) => {
                    let mut guard = notifier.lock().await;
                    *guard = Some(n.0);
                    println!("[Ring0Bridge] D-Bus notifications initialized");
                }
                _ => {
                    println!("[Ring0Bridge] D-Bus unavailable — desktop notifications disabled");
                }
            }
        });
    }
}

fn deserialize_to_json(data: &[u8]) -> Option<String> {
    let reader =
        capnp::serialize::read_message_from_flat_slice(data, capnp::message::ReaderOptions::new())
            .ok()?;
    let event = reader.get_root::<Ring0Event::Reader>().ok()?;
    use capnp_schema::ring0_event::Which;
    match event.which().ok()? {
        Which::Packet(pkt) => {
            let pkt = pkt.ok()?;
            let json = serde_json::json!({
                "type": "packet",
                "timestamp": pkt.getTimestamp(),
                "src_ip": format_ip(pkt.getSrcIp().ok()?.which().ok()?),
                "dst_ip": format_ip(pkt.getDstIp().ok()?.which().ok()?),
                "src_port": pkt.getSrcPort(),
                "dst_port": pkt.getDstPort(),
                "protocol": format_proto(pkt.getProtocol()),
                "pid": pkt.getPid(),
                "binary": pkt.getBinaryPath().ok().map(|s| s.to_string()).unwrap_or_default(),
                "action": format_action(pkt.getAction()),
            });
            Some(json.to_string())
        }
        Which::Alert(alert) => {
            let alert = alert.ok()?;
            let json = serde_json::json!({
                "type": "alert",
                "timestamp": alert.getTimestamp(),
                "severity": format_severity(alert.getSeverity()),
                "rule_id": alert.getRuleId(),
                "signature": alert.getSignatureName().ok().map(|s| s.to_string()).unwrap_or_default(),
            });
            Some(json.to_string())
        }
        Which::ProcessExec(exec) => {
            let e = exec.ok()?;
            let json = serde_json::json!({
                "type": "processExec",
                "pid": e.getPid(),
                "ppid": e.getPpid(),
                "uid": e.getUid(),
                "binary": e.getBinaryPath().ok().map(|s| s.to_string()).unwrap_or_default(),
                "cmdline": e.getCommandLine().ok().map(|s| s.to_string()).unwrap_or_default(),
            });
            Some(json.to_string())
        }
        Which::FileAccess(fa) => {
            let f = fa.ok()?;
            let json = serde_json::json!({
                "type": "fileAccess",
                "pid": f.getPid(),
                "uid": f.getUid(),
                "binary": f.getBinaryPath().ok().map(|s| s.to_string()).unwrap_or_default(),
                "file": f.getFilePath().ok().map(|s| s.to_string()).unwrap_or_default(),
            });
            Some(json.to_string())
        }
        Which::Connect(conn) => {
            let c = conn.ok()?;
            let json = serde_json::json!({
                "type": "connect",
                "pid": c.getPid(),
                "binary": c.getBinaryPath().ok().map(|s| s.to_string()).unwrap_or_default(),
                "dst_ip": format_ip(c.getDstIp().ok()?.which().ok()?),
                "dst_port": c.getDstPort(),
                "protocol": format_proto(c.getProtocol()),
            });
            Some(json.to_string())
        }
        Which::ConnectionPrompt(prompt) => {
            let p = prompt.ok()?;
            let json = serde_json::json!({
                "type": "connectionPrompt",
                "promptId": p.getPromptId(),
                "pid": p.getPid(),
                "ppid": p.getPpid(),
                "binaryPath": p.getBinaryPath().ok().map(|s| s.to_string()).unwrap_or_default(),
                "parentBinary": p.getParentBinary().ok().map(|s| s.to_string()).unwrap_or_default(),
                "dstIp": p.getDstIp(),
                "dstPort": p.getDstPort(),
                "protocol": p.getProtocol(),
                "countryCode": p.getCountryCode().ok().map(|s| s.to_string()).unwrap_or_default(),
                "countryName": p.getCountryName().ok().map(|s| s.to_string()).unwrap_or_default(),
                "rdnsName": p.getRdnsName().ok().map(|s| s.to_string()).unwrap_or_default(),
                "timeoutSecs": p.getTimeoutSecs(),
            });
            Some(json.to_string())
        }
        _ => None,
    }
}

fn format_ip(which: capnp_schema::ip_addr::Which<'_>) -> String {
    match which {
        capnp_schema::ip_addr::Which::V4(v) => std::net::Ipv4Addr::from(v).to_string(),
        _ => "::".into(),
    }
}

fn format_proto(p: capnp_schema::Protocol) -> &'static str {
    match p {
        capnp_schema::Protocol::Tcp => "TCP",
        capnp_schema::Protocol::Udp => "UDP",
        capnp_schema::Protocol::Icmp => "ICMP",
    }
}

fn format_action(a: capnp_schema::Action) -> &'static str {
    match a {
        capnp_schema::Action::Pass => "PASS",
        capnp_schema::Action::Drop => "DROP",
        capnp_schema::Action::Alert => "ALERT",
    }
}

fn format_severity(s: capnp_schema::Severity) -> &'static str {
    match s {
        capnp_schema::Severity::Low => "LOW",
        capnp_schema::Severity::Med => "MED",
        capnp_schema::Severity::High => "HIGH",
        capnp_schema::Severity::Critical => "CRITICAL",
    }
}

fn build_command_frame(f: impl FnOnce(&mut DaemonCommand::Builder)) -> Vec<u8> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut cmd = message.init_root::<DaemonCommand::Builder>();
        f(&mut cmd);
    }
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &message);
    buf
}
