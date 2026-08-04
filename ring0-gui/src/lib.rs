#![allow(overflowing_literals)]

pub mod notify;

// ==================== CXX-Qt Bridge ====================
#[cxx_qt::bridge(namespace = "ring0")]
pub mod qobject {
    unsafe extern "RustQt" {
        #[qobject]
        type Ring0Bridge = super::Ring0BridgeRust;

        #[qinvokable]
        fn connectDaemon(self: Pin<&mut Ring0Bridge>, socket_path: String) -> bool;
        #[qinvokable]
        fn blockIp(self: Pin<&mut Ring0Bridge>, ip: String);
        #[qinvokable]
        fn killProcess(self: Pin<&mut Ring0Bridge>, pid: u32);
        #[qinvokable]
        fn pollEvents(self: Pin<&mut Ring0Bridge>) -> String;
        #[qinvokable]
        fn sendDesktopNotification(
            self: Pin<&mut Ring0Bridge>,
            severity: u32,
            title: String,
            message: String,
        );
        #[qinvokable]
        fn initDbusNotifications(self: Pin<&mut Ring0Bridge>);

        #[qsignal]
        fn onEvent(self: Pin<&mut Ring0Bridge>, event_json: String);
        #[qsignal]
        fn onAlert(self: Pin<&mut Ring0Bridge>, alert_json: String);
    }

    unsafe extern "RustQt" {
        #[qobject]
        type PacketLogModel = super::PacketLogModelRust;

        #[qinvokable]
        fn appendPackets(self: Pin<&mut PacketLogModel>, packets: Vec<PacketRecord>);
        #[qinvokable]
        fn clearPackets(self: Pin<&mut PacketLogModel>);
        #[qinvokable]
        fn packetCount(self: Pin<&mut PacketLogModel>) -> i32;
        #[qinvokable]
        fn packetAt(self: Pin<&mut PacketLogModel>, index: i32) -> PacketRecord;
        #[qinvokable]
        fn removeOlderThan(self: Pin<&mut PacketLogModel>, max_count: i32);
    }

    unsafe extern "RustQt" {
        #[qobject]
        type ProcessListModel = super::ProcessListModelRust;

        #[qinvokable]
        fn appendProcess(self: Pin<&mut ProcessListModel>, proc: ProcessRecord);
        #[qinvokable]
        fn clearProcesses(self: Pin<&mut ProcessListModel>);
        #[qinvokable]
        fn processCount(self: Pin<&mut ProcessListModel>) -> i32;
        #[qinvokable]
        fn processAt(self: Pin<&mut ProcessListModel>, index: i32) -> ProcessRecord;
        #[qinvokable]
        fn removeOlderThan(self: Pin<&mut ProcessListModel>, max_count: i32);
    }

    unsafe extern "RustQt" {
        #[qobject]
        type TopologyModel = super::TopologyModelRust;

        #[qinvokable]
        fn setNodes(self: Pin<&mut TopologyModel>, nodes: Vec<TopologyNode>);
        #[qinvokable]
        fn addEdge(self: Pin<&mut TopologyModel>, edge: TopologyEdge);
        #[qinvokable]
        fn nodeCount(self: Pin<&mut TopologyModel>) -> i32;
        #[qinvokable]
        fn edgeCount(self: Pin<&mut TopologyModel>) -> i32;
        #[qinvokable]
        fn clearGraph(self: Pin<&mut TopologyModel>);
    }

    #[derive(Debug, Clone)]
    pub struct PacketRecord {
        pub timestamp: String,
        pub src_ip: String,
        pub dst_ip: String,
        pub src_port: u16,
        pub dst_port: u16,
        pub protocol: String,
        pub pid: u32,
        pub action: String,
    }

    #[derive(Debug, Clone)]
    pub struct ProcessRecord {
        pub pid: u32,
        pub ppid: u32,
        pub binary: String,
        pub cmdline: String,
    }

    #[derive(Debug, Clone)]
    pub struct TopologyNode {
        pub node_id: u32,
        pub node_type: String,
        pub label: String,
        pub ip: String,
        pub port: u16,
        pub pid: u32,
        pub threat_level: u8,
        pub bytes_per_sec: u64,
        pub country_code: String,
    }

    #[derive(Debug, Clone)]
    pub struct TopologyEdge {
        pub source_id: u32,
        pub target_id: u32,
        pub bytes_per_sec: u64,
        pub protocol: String,
        pub is_active: bool,
    }
}

// ==================== Implementation types ====================
use std::collections::VecDeque;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

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
        let rt = tokio::runtime::Runtime::new().unwrap();
        let stream = match rt.block_on(UnixStream::connect(&socket_path)) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("Ring0Bridge: connect failed: {e}");
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
                let rt = tokio::runtime::Runtime::new().unwrap();
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
                        if let Some(event_json) = deserialize_to_json(&msg_buf) {
                            if let Ok(mut q) = event_queue.lock() {
                                if q.len() >= MAX_QUEUED_EVENTS {
                                    q.pop_front();
                                }
                                q.push_back(event_json);
                            }
                        }
                    }
                });
            })
            .unwrap();
        this.reader_handle = Some(handle);
        true
    }

    pub fn block_ip(self: Pin<&mut Self>, ip: String) {
        if let Some(stream) = &self.get_mut().stream {
            let frame = build_command_frame(|cmd| cmd.setBlockIp(&ip));
            if let Ok(guard) = stream.lock() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let len = (frame.len() as u32).to_le_bytes();
                    let _ = guard.write_all(&len).await;
                    let _ = guard.write_all(&frame).await;
                });
            }
        }
    }

    pub fn kill_process(self: Pin<&mut Self>, pid: u32) {
        if let Some(stream) = &self.get_mut().stream {
            let frame = build_command_frame(|cmd| cmd.setKillProcess(pid));
            if let Ok(guard) = stream.lock() {
                let rt = tokio::runtime::Runtime::new().unwrap();
                rt.block_on(async {
                    let len = (frame.len() as u32).to_le_bytes();
                    let _ = guard.write_all(&len).await;
                    let _ = guard.write_all(&frame).await;
                });
            }
        }
    }

    pub fn poll_events(self: Pin<&mut Self>) -> String {
        let mut buf = String::new();
        if let Ok(mut q) = self.get_mut().event_queue.lock() {
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
        let notifier = self.get_mut().dbus_notifier.clone();
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
        let notifier = self.get_mut().dbus_notifier.clone();
        tokio::spawn(async move {
            let mut n = DbusNotifier::new();
            match n.0.connect().await {
                Ok(true) => {
                    let mut guard = notifier.lock().await;
                    *guard = Some(n.0);
                }
                _ => {}
            }
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
        Which::ConnectionPrompt(p) => {
            let p = p.ok()?;
            serde_json::json!({"type":"connectionPrompt","promptId":p.getPromptId(),"pid":p.getPid(),"ppid":p.getPpid(),"binaryPath":text_or(p.getBinaryPath().ok()),"parentBinary":text_or(p.getParentBinary().ok()),"dstIp":p.getDstIp(),"dstPort":p.getDstPort(),"protocol":p.getProtocol(),"countryCode":text_or(p.getCountryCode().ok()),"countryName":text_or(p.getCountryName().ok()),"rdnsName":text_or(p.getRdnsName().ok()),"timeoutSecs":p.getTimeoutSecs()})
        }
        _ => return None,
    };
    Some(json.to_string())
}

fn text_or(t: Option<Result<capnp::text::Reader<'_>, capnp::NotInSchema>>) -> String {
    t.and_then(|r| r.ok())
        .and_then(|r| r.to_str().ok())
        .unwrap_or("")
        .to_string()
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

pub struct PacketLogModelRust {
    packets: VecDeque<crate::qobject::PacketRecord>,
    max_size: usize,
}
impl Default for PacketLogModelRust {
    fn default() -> Self {
        Self {
            packets: VecDeque::with_capacity(2048),
            max_size: 5000,
        }
    }
}
impl PacketLogModelRust {
    pub fn append_packets(self: Pin<&mut Self>, new_packets: Vec<crate::qobject::PacketRecord>) {
        let this = self.get_mut();
        for p in new_packets {
            if this.packets.len() >= this.max_size {
                this.packets.pop_front();
            }
            this.packets.push_back(p);
        }
    }
    pub fn clear_packets(self: Pin<&mut Self>) {
        self.get_mut().packets.clear();
    }
    pub fn packet_count(self: Pin<&mut Self>) -> i32 {
        self.get_mut().packets.len() as i32
    }
    pub fn packet_at(self: Pin<&mut Self>, index: i32) -> crate::qobject::PacketRecord {
        let this = self.get_mut();
        if index >= 0 && (index as usize) < this.packets.len() {
            this.packets[index as usize].clone()
        } else {
            crate::qobject::PacketRecord {
                timestamp: String::new(),
                src_ip: String::new(),
                dst_ip: String::new(),
                src_port: 0,
                dst_port: 0,
                protocol: String::new(),
                pid: 0,
                action: String::new(),
            }
        }
    }
    pub fn remove_older_than(self: Pin<&mut Self>, max_count: i32) {
        while self.get_mut().packets.len() > max_count as usize {
            self.get_mut().packets.pop_front();
        }
    }
}

pub struct ProcessListModelRust {
    processes: VecDeque<crate::qobject::ProcessRecord>,
    max_size: usize,
}
impl Default for ProcessListModelRust {
    fn default() -> Self {
        Self {
            processes: VecDeque::with_capacity(1024),
            max_size: 2000,
        }
    }
}
impl ProcessListModelRust {
    pub fn append_process(self: Pin<&mut Self>, proc: crate::qobject::ProcessRecord) {
        let this = self.get_mut();
        if this.processes.len() >= this.max_size {
            this.processes.pop_front();
        }
        this.processes.push_back(proc);
    }
    pub fn clear_processes(self: Pin<&mut Self>) {
        self.get_mut().processes.clear();
    }
    pub fn process_count(self: Pin<&mut Self>) -> i32 {
        self.get_mut().processes.len() as i32
    }
    pub fn process_at(self: Pin<&mut Self>, index: i32) -> crate::qobject::ProcessRecord {
        let this = self.get_mut();
        if index >= 0 && (index as usize) < this.processes.len() {
            this.processes[index as usize].clone()
        } else {
            crate::qobject::ProcessRecord {
                pid: 0,
                ppid: 0,
                binary: String::new(),
                cmdline: String::new(),
            }
        }
    }
    pub fn remove_older_than(self: Pin<&mut Self>, max_count: i32) {
        while self.get_mut().processes.len() > max_count as usize {
            self.get_mut().processes.pop_front();
        }
    }
}

pub struct TopologyModelRust {
    nodes: VecDeque<crate::qobject::TopologyNode>,
    edges: VecDeque<crate::qobject::TopologyEdge>,
    max_nodes: usize,
    max_edges: usize,
}
impl Default for TopologyModelRust {
    fn default() -> Self {
        Self {
            nodes: VecDeque::with_capacity(200),
            edges: VecDeque::with_capacity(1000),
            max_nodes: 200,
            max_edges: 1000,
        }
    }
}
impl TopologyModelRust {
    pub fn set_nodes(self: Pin<&mut Self>, new_nodes: Vec<crate::qobject::TopologyNode>) {
        let this = self.get_mut();
        this.nodes.clear();
        for n in new_nodes {
            if this.nodes.len() >= this.max_nodes {
                break;
            }
            this.nodes.push_back(n);
        }
    }
    pub fn add_edge(self: Pin<&mut Self>, edge: crate::qobject::TopologyEdge) {
        let this = self.get_mut();
        if this.edges.len() >= this.max_edges {
            this.edges.pop_front();
        }
        this.edges.push_back(edge);
    }
    pub fn node_count(self: Pin<&mut Self>) -> i32 {
        self.get_mut().nodes.len() as i32
    }
    pub fn edge_count(self: Pin<&mut Self>) -> i32 {
        self.get_mut().edges.len() as i32
    }
    pub fn clear_graph(self: Pin<&mut Self>) {
        let this = self.get_mut();
        this.nodes.clear();
        this.edges.clear();
    }
}
