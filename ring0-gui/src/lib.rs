#![allow(overflowing_literals)]
// The bridge methods intentionally use camelCase because they are exported to
// QML through cxx-qt and QML/JS convention requires it.
#![allow(non_snake_case)]

pub mod notify;

// ==================== CXX-Qt Bridge ====================
#[cxx_qt::bridge(namespace = "ring0")]
pub mod qobject {
    unsafe extern "C++" {
        include!("cxx-qt-lib/qstring.h");
        #[namespace = ""]
        type QString = cxx_qt_lib::QString;
    }

    unsafe extern "RustQt" {
        #[qobject]
        type Ring0Bridge = super::Ring0BridgeRust;

        #[auto_wrap]
        #[qinvokable]
        fn connectDaemon(self: Pin<&mut Ring0Bridge>, socket_path: QString) -> bool;
        #[auto_wrap]
        #[qinvokable]
        fn isConnected(self: Pin<&mut Ring0Bridge>) -> bool;
        #[auto_wrap]
        #[qinvokable]
        fn disconnectDaemon(self: Pin<&mut Ring0Bridge>);
        #[auto_wrap]
        #[qinvokable]
        fn pollEvents(self: Pin<&mut Ring0Bridge>) -> QString;
        #[auto_wrap]
        #[qinvokable]
        fn blockIp(self: Pin<&mut Ring0Bridge>, ip: QString);
        #[auto_wrap]
        #[qinvokable]
        fn unblockIp(self: Pin<&mut Ring0Bridge>, ip: QString);
        #[auto_wrap]
        #[qinvokable]
        fn killProcess(self: Pin<&mut Ring0Bridge>, pid: u32);
        #[auto_wrap]
        #[qinvokable]
        fn blockPort(self: Pin<&mut Ring0Bridge>, port: u32);
        #[auto_wrap]
        #[qinvokable]
        fn unblockPort(self: Pin<&mut Ring0Bridge>, port: u32);
        #[auto_wrap]
        #[qinvokable]
        fn quarantine(self: Pin<&mut Ring0Bridge>, pid: u32);
        #[auto_wrap]
        #[qinvokable]
        fn runRootkitScan(self: Pin<&mut Ring0Bridge>);
        #[auto_wrap]
        #[qinvokable]
        fn syncIntelFeeds(self: Pin<&mut Ring0Bridge>);
        #[auto_wrap]
        #[qinvokable]
        fn powerStatus(self: Pin<&mut Ring0Bridge>);
        #[auto_wrap]
        #[qinvokable]
        fn runDoctor(self: Pin<&mut Ring0Bridge>);
        #[auto_wrap]
        #[qinvokable]
        fn flatpakList(self: Pin<&mut Ring0Bridge>);
        #[auto_wrap]
        #[qinvokable]
        fn queryLogs(
            self: Pin<&mut Ring0Bridge>,
            lastMinutes: u64,
            severity: u8,
            limit: u32,
        ) -> QString;
        #[auto_wrap]
        #[qinvokable]
        fn reloadRules(self: Pin<&mut Ring0Bridge>);
        #[auto_wrap]
        #[qinvokable]
        fn submitPromptDecision(
            self: Pin<&mut Ring0Bridge>,
            promptId: u64,
            action: QString,
            scope: QString,
        );
        #[auto_wrap]
        #[qinvokable]
        fn shutdownDaemon(self: Pin<&mut Ring0Bridge>);
        #[auto_wrap]
        #[qinvokable]
        fn daemonStatus(self: Pin<&mut Ring0Bridge>) -> QString;
        #[auto_wrap]
        #[qinvokable]
        fn updateSettings(self: Pin<&mut Ring0Bridge>, json: QString);
        #[auto_wrap]
        #[qinvokable]
        fn sendDesktopNotification(
            self: Pin<&mut Ring0Bridge>,
            severity: u32,
            title: QString,
            message: QString,
        );
        #[auto_wrap]
        #[qinvokable]
        fn initDbusNotifications(self: Pin<&mut Ring0Bridge>);

        #[qsignal]
        fn onEvent(self: Pin<&mut Ring0Bridge>, event_json: QString);
        #[qsignal]
        fn onAlert(self: Pin<&mut Ring0Bridge>, alert_json: QString);
    }
}

// ==================== Implementation types ====================
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use ring0_common::proto as capnp_schema;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use crate::notify::{DbusNotifier, Notification};

const MAX_QUEUED_EVENTS: usize = 4096;
// Reader polling interval used to make the reader thread responsive to
// disconnects while it is blocked waiting for the next daemon frame.
const READER_POLL_MS: u64 = 250;

// One Tokio runtime shared by all bridge calls. Creating a fresh runtime per
// `send_frame` call (the previous behavior) spawned thread pools and allocated
// heap on every IPC command.
static SHARED_RT: std::sync::LazyLock<tokio::runtime::Runtime> = std::sync::LazyLock::new(|| {
    tokio::runtime::Runtime::new().expect("failed to build shared tokio runtime")
});

pub struct Ring0BridgeRust {
    /// Non-blocking writer channel to a dedicated writer thread that owns the
    /// socket write half. Previously send_frame did `SHARED_RT.block_on(write_all)`
    /// on the Qt GUI thread, so a stalled daemon froze the whole UI.
    stream: Option<Sender<Vec<u8>>>,
    event_queue: Arc<Mutex<VecDeque<String>>>,
    /// Holds the JSON of the most recent QueryLogs response frame read by the
    /// reader thread (the daemon answers queries on the event channel).
    pending_query_response: Arc<Mutex<Option<String>>>,
    reader_handle: Option<thread::JoinHandle<()>>,
    writer_handle: Option<thread::JoinHandle<()>>,
    running: Arc<AtomicBool>,
    connected: Arc<AtomicBool>,
    dbus_notifier: Arc<tokio::sync::Mutex<Option<DbusNotifier>>>,
}

impl Default for Ring0BridgeRust {
    fn default() -> Self {
        Self {
            stream: None,
            event_queue: Arc::new(Mutex::new(VecDeque::with_capacity(MAX_QUEUED_EVENTS))),
            pending_query_response: Arc::new(Mutex::new(None)),
            reader_handle: None,
            writer_handle: None,
            running: Arc::new(AtomicBool::new(false)),
            connected: Arc::new(AtomicBool::new(false)),
            dbus_notifier: Arc::new(tokio::sync::Mutex::new(None)),
        }
    }
}

impl Drop for Ring0BridgeRust {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.connected.store(false, Ordering::Relaxed);
        // Closing the writer channel makes the writer thread exit promptly;
        // the reader polls with a timeout and exits within ~READER_POLL_MS.
        self.stream.take();
        if let Some(handle) = self.writer_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.reader_handle.take() {
            let _ = handle.join();
        }
    }
}

impl Ring0BridgeRust {
    /// Send a capnp DaemonCommand frame over the socket (fire-and-forget).
    /// Never blocks: the frame is queued to the writer thread, which owns the
    /// socket write half. A stalled daemon now backpressures only that thread.
    fn send_frame(&self, frame: &[u8]) {
        if let Some(tx) = &self.stream {
            let _ = tx.send(frame.to_vec());
        }
    }

    pub fn connectDaemon(self: Pin<&mut Self>, socket_path: cxx_qt_lib::QString) -> bool {
        let socket_path: String = socket_path.into();
        let this = self.get_mut();
        this.disconnect_internal();
        let rt = match tokio::runtime::Runtime::new() {
            Ok(rt) => rt,
            Err(_) => return false,
        };
        let stream = match rt.block_on(UnixStream::connect(&socket_path)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Ring0Bridge: connect failed: {e}");
                return false;
            }
        };
        // Split the stream: the reader thread owns the read half; a dedicated
        // writer thread owns the write half and drains a channel, so GUI-thread
        // calls never block on socket I/O.
        let (read_half, write_half) = stream.into_split();
        drop(rt);

        let (tx, rx): (Sender<Vec<u8>>, Receiver<Vec<u8>>) = std::sync::mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));
        let connected = Arc::new(AtomicBool::new(true));

        // Writer thread: serializes frames from the channel onto the socket.
        let writer = thread::Builder::new()
            .name("ring0-bridge-writer".into())
            .spawn(move || {
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(async move {
                    let mut writer = write_half;
                    for frame in rx.iter() {
                        let len = (frame.len() as u32).to_le_bytes();
                        if writer.write_all(&len).await.is_err() {
                            break;
                        }
                        if writer.write_all(&frame).await.is_err() {
                            break;
                        }
                    }
                });
            });
        let writer = match writer {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Ring0Bridge: failed to spawn writer thread: {e}");
                return false;
            }
        };

        let event_queue = this.event_queue.clone();
        let pending_query_response = this.pending_query_response.clone();
        let running_reader = running.clone();
        let connected_reader = connected.clone();
        let reader = thread::Builder::new()
            .name("ring0-bridge-reader".into())
            .spawn(move || {
                let rt = match tokio::runtime::Runtime::new() {
                    Ok(rt) => rt,
                    Err(_) => return,
                };
                rt.block_on(async move {
                    let mut reader = read_half;
                    let mut len_buf = [0u8; 4];
                    loop {
                        if !running_reader.load(Ordering::Relaxed) {
                            break;
                        }
                        // Poll with a timeout so a disconnect (running=false) is
                        // observed promptly even while blocked on the socket.
                        let read = tokio::time::timeout(
                            Duration::from_millis(READER_POLL_MS),
                            reader.read_exact(&mut len_buf),
                        )
                        .await;
                        match read {
                            Ok(Ok(_)) => {}
                            Ok(Err(_)) => break,
                            Err(_) => continue,
                        }
                        let msg_len = u32::from_le_bytes(len_buf) as usize;
                        if msg_len == 0 || msg_len > 1 << 20 {
                            break;
                        }
                        let mut msg_buf = vec![0u8; msg_len];
                        if reader.read_exact(&mut msg_buf).await.is_err() {
                            break;
                        }
                        if let Some(event_json) = deserialize_to_json(&msg_buf) {
                            if let Ok(mut q) = event_queue.lock() {
                                if q.len() >= MAX_QUEUED_EVENTS {
                                    q.pop_front();
                                }
                                q.push_back(event_json);
                            }
                        } else if let Some(resp_json) = deserialize_query_response(&msg_buf) {
                            // A QueryLogs reply — stash it for queryLogs().
                            if let Ok(mut slot) = pending_query_response.lock() {
                                *slot = Some(resp_json);
                            }
                        }
                    }
                    connected_reader.store(false, Ordering::Relaxed);
                });
            });
        let reader = match reader {
            Ok(h) => h,
            Err(e) => {
                eprintln!("Ring0Bridge: failed to spawn reader thread: {e}");
                return false;
            }
        };

        this.stream = Some(tx);
        this.writer_handle = Some(writer);
        this.reader_handle = Some(reader);
        this.running = running;
        this.connected = connected;
        true
    }

    fn disconnect_internal(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        self.connected.store(false, Ordering::Relaxed);
        *self
            .pending_query_response
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        // Close the writer channel → writer thread drains and exits.
        self.stream.take();
        if let Some(handle) = self.writer_handle.take() {
            let _ = handle.join();
        }
        if let Some(handle) = self.reader_handle.take() {
            // The reader polls with a timeout, so it observes running=false
            // within ~READER_POLL_MS and exits instead of hanging here.
            let _ = handle.join();
        }
        if let Ok(mut q) = self.event_queue.lock() {
            q.clear();
        }
    }

    pub fn isConnected(self: Pin<&mut Self>) -> bool {
        self.connected.load(Ordering::Relaxed)
    }

    pub fn disconnectDaemon(self: Pin<&mut Self>) {
        self.get_mut().disconnect_internal();
    }

    pub fn pollEvents(self: Pin<&mut Self>) -> cxx_qt_lib::QString {
        let mut buf = String::new();
        if let Ok(mut q) = self.get_mut().event_queue.lock() {
            while let Some(evt) = q.pop_front() {
                if !buf.is_empty() {
                    buf.push('\n');
                }
                buf.push_str(&evt);
            }
        }
        cxx_qt_lib::QString::from(buf)
    }

    pub fn blockIp(self: Pin<&mut Self>, ip: cxx_qt_lib::QString) {
        let ip: String = ip.into();
        let frame = build_command_frame(|cmd| cmd.setBlockIp(&ip));
        self.send_frame(&frame);
    }

    pub fn unblockIp(self: Pin<&mut Self>, ip: cxx_qt_lib::QString) {
        let ip: String = ip.into();
        let frame = build_command_frame(|cmd| cmd.setUnblockIp(&ip));
        self.send_frame(&frame);
    }

    pub fn killProcess(self: Pin<&mut Self>, pid: u32) {
        let frame = build_command_frame(|cmd| cmd.setKillProcess(pid));
        self.send_frame(&frame);
    }

    pub fn blockPort(self: Pin<&mut Self>, port: u32) {
        let frame = build_command_frame(|cmd| cmd.setBlockPort(port));
        self.send_frame(&frame);
    }

    pub fn unblockPort(self: Pin<&mut Self>, port: u32) {
        let frame = build_command_frame(|cmd| cmd.setUnblockPort(port));
        self.send_frame(&frame);
    }

    pub fn quarantine(self: Pin<&mut Self>, pid: u32) {
        let frame = build_command_frame(|cmd| cmd.setQuarantine(pid));
        self.send_frame(&frame);
    }

    pub fn runRootkitScan(self: Pin<&mut Self>) {
        let frame = build_command_frame(|cmd| cmd.setRunRootkitScan(()));
        self.send_frame(&frame);
    }

    pub fn syncIntelFeeds(self: Pin<&mut Self>) {
        let frame = build_command_frame(|cmd| cmd.setSyncIntelFeeds(()));
        self.send_frame(&frame);
    }

    pub fn powerStatus(self: Pin<&mut Self>) {
        let frame = build_command_frame(|cmd| cmd.setPowerStatus(()));
        self.send_frame(&frame);
    }

    pub fn runDoctor(self: Pin<&mut Self>) {
        let frame = build_command_frame(|cmd| cmd.setRunDoctor(()));
        self.send_frame(&frame);
    }

    pub fn flatpakList(self: Pin<&mut Self>) {
        let frame = build_command_frame(|cmd| cmd.setFlatpakList(()));
        self.send_frame(&frame);
    }

    /// Query the daemon's stored alerts and return them as a JSON array of
    /// {timestamp, severity, rule_id, signature}. The daemon answers on the
    /// event channel; this blocks the calling (Qt) thread for up to ~5s while
    /// the reader thread captures the reply.
    pub fn queryLogs(
        self: Pin<&mut Self>,
        lastMinutes: u64,
        severity: u8,
        limit: u32,
    ) -> cxx_qt_lib::QString {
        let this = self.get_mut();
        let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
        let start = now.saturating_sub(lastMinutes * 60 * 1_000_000_000);
        let mut message = capnp::message::Builder::new_default();
        {
            let cmd = message.init_root::<capnp_schema::daemon_command::Builder>();
            let mut q = cmd.initQueryLogs();
            q.setStartTimestamp(start);
            q.setEndTimestamp(now);
            q.setSeverityThreshold(severity);
            q.setLimit(limit);
        }
        let mut buf = Vec::new();
        let _ = capnp::serialize::write_message(&mut buf, &message);
        *this
            .pending_query_response
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = None;
        this.send_frame(&buf);
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while std::time::Instant::now() < deadline {
            if let Some(resp) = this
                .pending_query_response
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .take()
            {
                return cxx_qt_lib::QString::from(resp);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        cxx_qt_lib::QString::from("")
    }

    pub fn reloadRules(self: Pin<&mut Self>) {
        let frame = build_command_frame(|cmd| cmd.setReloadRules(()));
        self.send_frame(&frame);
    }

    pub fn submitPromptDecision(
        self: Pin<&mut Self>,
        promptId: u64,
        action: cxx_qt_lib::QString,
        scope: cxx_qt_lib::QString,
    ) {
        let action: String = action.into();
        let scope: String = scope.into();
        let frame = build_prompt_decision_frame(promptId, &action, &scope);
        self.send_frame(&frame);
    }

    pub fn shutdownDaemon(self: Pin<&mut Self>) {
        let frame = build_command_frame(|cmd| cmd.setShutdown(()));
        self.send_frame(&frame);
    }

    pub fn daemonStatus(self: Pin<&mut Self>) -> cxx_qt_lib::QString {
        let frame = build_command_frame(|cmd| cmd.setStatus(()));
        self.send_frame(&frame);
        cxx_qt_lib::QString::from("")
    }

    pub fn updateSettings(self: Pin<&mut Self>, json: cxx_qt_lib::QString) {
        let json: String = json.into();
        let frame = build_command_frame(|cmd| cmd.setUpdateSettings(&json));
        self.send_frame(&frame);
    }

    pub fn sendDesktopNotification(
        self: Pin<&mut Self>,
        severity: u32,
        title: cxx_qt_lib::QString,
        message: cxx_qt_lib::QString,
    ) {
        let title: String = title.into();
        let message: String = message.into();
        let notifier = self.get_mut().dbus_notifier.clone();
        std::thread::spawn(move || {
            SHARED_RT.block_on(async move {
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
                if let Some(n) = guard.as_mut() {
                    let _ = n.send_notification(notif).await;
                }
            });
        });
    }

    pub fn initDbusNotifications(self: Pin<&mut Self>) {
        let notifier = self.get_mut().dbus_notifier.clone();
        std::thread::spawn(move || {
            SHARED_RT.block_on(async move {
                let mut n = DbusNotifier::new();
                match n.connect().await {
                    Ok(true) => {
                        let mut guard = notifier.lock().await;
                        *guard = Some(n);
                    }
                    _ => {}
                }
            });
        });
    }
}

fn deserialize_to_json(data: &[u8]) -> Option<String> {
    let mut d = data;
    let reader = capnp::serialize::read_message_from_flat_slice(
        &mut d,
        capnp::message::ReaderOptions::new(),
    )
    .ok()?;
    let event = reader
        .get_root::<capnp_schema::ring0_event::Reader>()
        .ok()?;
    use capnp_schema::ring0_event::Which;
    let json = match event.which().ok()? {
        Which::Packet(pkt) => {
            let p = pkt.ok()?;
            serde_json::json!({"type":"packet","timestamp":p.getTimestamp(),"src_ip":format_ip(p.getSrcIp().ok()?.which().ok()?),"dst_ip":format_ip(p.getDstIp().ok()?.which().ok()?),"src_port":p.getSrcPort(),"dst_port":p.getDstPort(),"protocol":format_proto(p.getProtocol().unwrap_or(capnp_schema::Protocol::Tcp)),"pid":p.getPid(),"binary":text_or(p.getBinaryPath().ok()),"action":format_action(p.getAction().unwrap_or(capnp_schema::Action::Pass))})
        }
        Which::Alert(alert) => {
            let alert = alert.ok()?;
            serde_json::json!({"type":"alert","timestamp":alert.getTimestamp(),"severity":format_severity(alert.getSeverity().unwrap_or(capnp_schema::Severity::Low)),"rule_id":alert.getRuleId(),"signature":text_or(alert.getSignatureName().ok())})
        }
        Which::ProcessExec(e) => {
            let e = e.ok()?;
            serde_json::json!({"type":"processExec","pid":e.getPid(),"ppid":e.getPpid(),"uid":e.getUid(),"binary":text_or(e.getBinaryPath().ok()),"cmdline":text_or(e.getCommandLine().ok())})
        }
        Which::FileAccess(fa) => {
            let f = fa.ok()?;
            serde_json::json!({"type":"fileAccess","pid":f.getPid(),"uid":f.getUid(),"binary":text_or(f.getBinaryPath().ok()),"file":text_or(f.getFilePath().ok())})
        }
        Which::Connect(conn) => {
            let c = conn.ok()?;
            serde_json::json!({"type":"connect","pid":c.getPid(),"binary":text_or(c.getBinaryPath().ok()),"dst_ip":format_ip(c.getDstIp().ok()?.which().ok()?),"dst_port":c.getDstPort(),"protocol":format_proto(c.getProtocol().unwrap_or(capnp_schema::Protocol::Tcp))})
        }
        Which::Correlation(corr) => {
            let c = corr.ok()?;
            serde_json::json!({"type":"correlation","timestamp":c.getTimestamp(),"severity":format_severity(c.getSeverity().unwrap_or(capnp_schema::Severity::Low)),"pattern_id":c.getPatternId(),"pattern_name":text_or(c.getPatternName().ok()),"mitre_technique":text_or(c.getMitreTechnique().ok()),"description":text_or(c.getChainDescription().ok())})
        }
        Which::SelfDefense(sd) => {
            let s = sd.ok()?;
            serde_json::json!({"type":"selfDefense","timestamp":s.getTimestamp(),"attacker_pid":s.getAttackerPid(),"attacker_binary":text_or(s.getAttackerBinary().ok()),"syscall":text_or(s.getSyscall().ok()),"blocked":s.getBlocked()})
        }
        Which::Dns(dns) => {
            let d = dns.ok()?;
            serde_json::json!({"type":"dns","timestamp":d.getTimestamp(),"pid":d.getPid(),"domain":text_or(d.getDomain().ok()),"query_type":d.getQueryType(),"dga_score":d.getDgaScore()})
        }
        Which::ConnectionPrompt(p) => {
            let p = p.ok()?;
            serde_json::json!({"type":"connectionPrompt","promptId":p.getPromptId(),"pid":p.getPid(),"ppid":p.getPpid(),"binaryPath":text_or(p.getBinaryPath().ok()),"parentBinary":text_or(p.getParentBinary().ok()),"dstIp":p.getDstIp(),"dstPort":p.getDstPort(),"protocol":p.getProtocol(),"countryCode":text_or(p.getCountryCode().ok()),"countryName":text_or(p.getCountryName().ok()),"rdnsName":text_or(p.getRdnsName().ok()),"timeoutSecs":p.getTimeoutSecs()})
        }
        Which::Status(st) => {
            let st = st.ok()?;
            let mut filters: Vec<String> = Vec::new();
            if let Ok(list) = st.getActiveFilters() {
                for f in list.iter() {
                    filters.push(
                        f.ok()
                            .and_then(|r| r.to_str().ok())
                            .unwrap_or("")
                            .to_string(),
                    );
                }
            }
            serde_json::json!({"type":"status","activeFilters":filters,"cpuUsagePercent":st.getCpuUsagePercent(),"ramUsageBytes":st.getRamUsageBytes(),"eventsPerSec":st.getEventsPerSec(),"blockedDomains":st.getBlockedDomains(),"blockedCidrs":st.getBlockedCidrs(),"blockedPorts":st.getBlockedPorts(),"droppedEvents":st.getDroppedEvents(),"onBattery":st.getOnBattery(),"fimThrottled":st.getFimThrottled()})
        }
    };
    Some(json.to_string())
}

/// Parse a `QueryLogs` reply frame (a `QueryResponse`, not a `Ring0Event`)
/// into JSON `{"count":N,"alerts":[{timestamp,severity,rule_id,signature}]}`.
fn deserialize_query_response(data: &[u8]) -> Option<String> {
    let mut d = data;
    let reader = capnp::serialize::read_message_from_flat_slice(
        &mut d,
        capnp::message::ReaderOptions::new(),
    )
    .ok()?;
    let qr = reader
        .get_root::<capnp_schema::query_response::Reader>()
        .ok()?;
    let mut alerts = Vec::new();
    if let Ok(list) = qr.getAlerts() {
        for a in list.iter() {
            alerts.push(serde_json::json!({
                "timestamp": a.getTimestamp(),
                "severity": format_severity(a.getSeverity().unwrap_or(capnp_schema::Severity::Low)),
                "rule_id": a.getRuleId(),
                "signature": text_or(a.getSignatureName().ok()),
            }));
        }
    }
    Some(serde_json::json!({"count": qr.getCount(), "alerts": alerts}).to_string())
}

fn text_or(t: Option<capnp::text::Reader<'_>>) -> String {
    t.and_then(|r| r.to_str().ok()).unwrap_or("").to_string()
}

fn format_ip(which: capnp_schema::ip_addr::WhichReader<'_>) -> String {
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

fn build_command_frame(f: impl FnOnce(&mut capnp_schema::daemon_command::Builder)) -> Vec<u8> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut cmd = message.init_root::<capnp_schema::daemon_command::Builder>();
        f(&mut cmd);
    }
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &message);
    buf
}

/// Build a `submitPromptDecision` command frame. This needs an owned builder
/// because the Cap'n Proto union accessor (`initSubmitPromptDecision`) consumes
/// the enclosing builder.
fn build_prompt_decision_frame(prompt_id: u64, action: &str, scope: &str) -> Vec<u8> {
    let mut message = capnp::message::Builder::new_default();
    {
        let cmd = message.init_root::<capnp_schema::daemon_command::Builder>();
        let mut pd = cmd.initSubmitPromptDecision();
        pd.setPromptId(prompt_id);
        pd.setAction(action);
        pd.setScope(scope);
    }
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &message);
    buf
}
