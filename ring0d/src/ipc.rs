use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use ring0_common::proto as capnp_schema;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::sync::broadcast;
use tracing::{error, warn};

use crate::storage::RocksManager;

#[derive(Debug, Clone)]
pub enum DaemonCmd {
    BlockIp(IpAddr),
    UnblockIp(IpAddr),
    KillProcess(u32),
    ReloadFilters,
    Shutdown,
    QueryLogs(u64, u64, u8, u32),
    ReloadRules,
    Quarantine(u32),
    RunRootkitScan,
    SyncIntelFeeds,
    SubmitPromptDecision(u64, String, String),
    FlatpakList,
    PowerStatus,
    UpdateSettings(String),
    RunDoctor,
}

pub struct IpcServer {
    evt_tx: broadcast::Sender<Vec<u8>>,
    _accept_handle: tokio::task::JoinHandle<()>,
}

impl IpcServer {
    pub async fn bind(
        path: &str,
        storage: Arc<RocksManager>,
        cmd_tx: tokio::sync::mpsc::UnboundedSender<DaemonCmd>,
    ) -> Result<Self> {
        let _ = std::fs::remove_file(path);
        let listener =
            UnixListener::bind(path).map_err(|e| anyhow::anyhow!("failed to bind {path}: {e}"))?;
        // Allow any local user to talk to the daemon (CLI, GUI, scripts).
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
        let (evt_tx, _) = broadcast::channel(4096);
        let evt_tx_for_struct = evt_tx.clone();

        let accept_handle = tokio::spawn(async move {
            let listener = listener;
            let client_count = Arc::new(AtomicUsize::new(0));

            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        let evt_tx: tokio::sync::broadcast::Sender<Vec<u8>> = evt_tx.clone();
                        let cmd_tx = cmd_tx.clone();
                        let storage = storage.clone();
                        let client_count = client_count.clone();

                        tokio::spawn(async move {
                            client_count.fetch_add(1, Ordering::Relaxed);
                            let (reader, writer) = stream.into_split();
                            let evt_tx_for_read = evt_tx.clone();

                            let write_handle = tokio::spawn(async move {
                                let mut writer = writer;
                                let mut rx = evt_tx.subscribe();
                                loop {
                                    match rx.recv().await {
                                        Ok(data) => {
                                            let len = (data.len() as u32).to_le_bytes();
                                            if writer.write_all(&len).await.is_err() {
                                                break;
                                            }
                                            if writer.write_all(&data).await.is_err() {
                                                break;
                                            }
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });

                            let read_handle = tokio::spawn(async move {
                                let mut reader = reader;
                                let mut len_buf = [0u8; 4];
                                loop {
                                    match reader.read_exact(&mut len_buf).await {
                                        Ok(_) => {}
                                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                            continue;
                                        }
                                        Err(_) => break,
                                    }
                                    let msg_len = u32::from_le_bytes(len_buf) as usize;
                                    if msg_len == 0 || msg_len > 65536 {
                                        warn!("invalid IPC frame length: {msg_len}");
                                        break;
                                    }
                                    let mut msg_buf = vec![0u8; msg_len];
                                    if reader.read_exact(&mut msg_buf).await.is_err() {
                                        break;
                                    }
                                    match parse_command_frame(&msg_buf) {
                                        Ok(DaemonCmd::QueryLogs(_start, _end, sev, limit)) => {
                                            let results = storage.query_alerts(sev, limit as usize);
                                            let response = build_query_response(&results);
                                            let _ = evt_tx_for_read.send(response);
                                        }
                                        Ok(cmd) => {
                                            if cmd_tx.send(cmd).is_err() {
                                                break;
                                            }
                                        }
                                        Err(e) => {
                                            warn!("invalid IPC command: {e}");
                                        }
                                    }
                                }
                            });

                            tokio::select! {
                                _ = write_handle => {},
                                _ = read_handle => {},
                            }
                            client_count.fetch_sub(1, Ordering::Relaxed);
                        });
                    }
                    Err(e) => {
                        error!("IPC accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        });

        Ok(Self {
            evt_tx: evt_tx_for_struct,
            _accept_handle: accept_handle,
        })
    }

    pub async fn broadcast_raw(&self, data: &[u8]) {
        if self.evt_tx.receiver_count() == 0 {
            return;
        }
        let _ = self.evt_tx.send(data.to_vec());
    }
}

fn parse_command_frame(data: &[u8]) -> Result<DaemonCmd> {
    let mut data_mut = data;
    let reader = capnp::serialize::read_message_from_flat_slice(
        &mut data_mut,
        capnp::message::ReaderOptions::new(),
    )
    .map_err(|e| anyhow::anyhow!("capnp parse error: {e}"))?;
    let cmd = reader
        .get_root::<capnp_schema::daemon_command::Reader>()
        .map_err(|e| anyhow::anyhow!("capnp root error: {e}"))?;
    use capnp_schema::daemon_command::Which;
    match cmd
        .which()
        .map_err(|e| anyhow::anyhow!("capnp which error: {e}"))?
    {
        Which::BlockIp(ip) => {
            let ip_str = ip.map_err(|e| anyhow::anyhow!("capnp text error: {e}"))?;
            let ip_str = ip_str
                .to_str()
                .map_err(|e| anyhow::anyhow!("invalid utf8: {e}"))?;
            let addr: IpAddr = ip_str
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid IP: {e}"))?;
            Ok(DaemonCmd::BlockIp(addr))
        }
        Which::UnblockIp(ip) => {
            let ip_str = ip.map_err(|e| anyhow::anyhow!("capnp text error: {e}"))?;
            let ip_str = ip_str
                .to_str()
                .map_err(|e| anyhow::anyhow!("invalid utf8: {e}"))?;
            let addr: IpAddr = ip_str
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid IP: {e}"))?;
            Ok(DaemonCmd::UnblockIp(addr))
        }
        Which::KillProcess(pid) => Ok(DaemonCmd::KillProcess(pid)),
        Which::ReloadFilters(()) => Ok(DaemonCmd::ReloadFilters),
        Which::ReloadRules(()) => Ok(DaemonCmd::ReloadRules),
        Which::Shutdown(()) => Ok(DaemonCmd::Shutdown),
        Which::QueryLogs(query) => {
            let q = query.map_err(|e| anyhow::anyhow!("capnp query error: {e}"))?;
            Ok(DaemonCmd::QueryLogs(
                q.getStartTimestamp(),
                q.getEndTimestamp(),
                q.getSeverityThreshold(),
                q.getLimit(),
            ))
        }
        Which::Quarantine(pid) => Ok(DaemonCmd::Quarantine(pid)),
        Which::RunRootkitScan(()) => Ok(DaemonCmd::RunRootkitScan),
        Which::SyncIntelFeeds(()) => Ok(DaemonCmd::SyncIntelFeeds),
        Which::SubmitPromptDecision(pd) => {
            let d = pd.map_err(|e| anyhow::anyhow!("capnp prompt error: {e}"))?;
            Ok(DaemonCmd::SubmitPromptDecision(
                d.getPromptId(),
                d.getAction()
                    .map_err(|e| anyhow::anyhow!("action: {e}"))?
                    .to_str()
                    .unwrap_or("")
                    .to_string(),
                d.getScope()
                    .map_err(|e| anyhow::anyhow!("scope: {e}"))?
                    .to_str()
                    .unwrap_or("")
                    .to_string(),
            ))
        }
        Which::FlatpakList(()) => Ok(DaemonCmd::FlatpakList),
        Which::PowerStatus(()) => Ok(DaemonCmd::PowerStatus),
        Which::UpdateSettings(json) => {
            let s = json.map_err(|e| anyhow::anyhow!("capnp settings error: {e}"))?;
            Ok(DaemonCmd::UpdateSettings(
                s.to_str().unwrap_or("").to_string(),
            ))
        }
        Which::RunDoctor(()) => Ok(DaemonCmd::RunDoctor),
    }
}

fn build_query_response(results: &[(Vec<u8>, Vec<u8>)]) -> Vec<u8> {
    let mut message = capnp::message::Builder::new_default();
    {
        let mut resp = message.init_root::<capnp_schema::query_response::Builder>();
        let count = results.len().min(500) as u32;
        resp.setCount(count);
        let mut alerts = resp.initAlerts(count);
        for (i, (_, v)) in results.iter().enumerate().take(count as usize) {
            let mut alert = alerts.reborrow().get(i as u32);
            if v.len() >= 8 {
                let ts = u64::from_be_bytes([v[0], v[1], v[2], v[3], v[4], v[5], v[6], v[7]]);
                alert.setTimestamp(ts);
            }
            if v.len() > 8 {
                alert.setSeverity(capnp_schema::Severity::High);
                alert.setRuleId(v[8] as u32);
            }
        }
    }
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &message);
    buf
}

pub fn build_connection_prompt_event(
    prompt_id: u64,
    pid: u32,
    ppid: u32,
    binary_path: &str,
    parent_binary: &str,
    dst_ip: u32,
    dst_port: u16,
    protocol: u8,
    country_code: &str,
    country_name: &str,
    rdns_name: &str,
    timeout_secs: u32,
) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    let evt = msg.init_root::<capnp_schema::ring0_event::Builder>();
    let mut p = evt.initConnectionPrompt();
    p.setPromptId(prompt_id);
    p.setPid(pid);
    p.setPpid(ppid);
    p.setBinaryPath(binary_path);
    p.setParentBinary(parent_binary);
    p.setDstIp(dst_ip);
    p.setDstPort(dst_port);
    p.setProtocol(protocol);
    p.setCountryCode(country_code);
    p.setCountryName(country_name);
    p.setRdnsName(rdns_name);
    p.setTimeoutSecs(timeout_secs);
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &msg);
    buf
}

pub fn build_process_exec_event(
    pid: u32,
    ppid: u32,
    uid: u32,
    binary: &str,
    cmdline: &str,
) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    let evt = msg.init_root::<capnp_schema::ring0_event::Builder>();
    let mut p = evt.initProcessExec();
    p.setTimestamp(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64);
    p.setPid(pid);
    p.setPpid(ppid);
    p.setUid(uid);
    p.setBinaryPath(binary);
    p.setCommandLine(cmdline);
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &msg);
    buf
}

pub fn build_file_access_event(pid: u32, uid: u32, binary: &str, path: &str) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    let evt = msg.init_root::<capnp_schema::ring0_event::Builder>();
    let mut f = evt.initFileAccess();
    f.setTimestamp(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64);
    f.setPid(pid);
    f.setUid(uid);
    f.setBinaryPath(binary);
    f.setFilePath(path);
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &msg);
    buf
}

pub fn build_connect_event(
    pid: u32,
    uid: u32,
    binary: &str,
    dst_ip: u32,
    dst_port: u16,
    proto: u8,
) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    let evt = msg.init_root::<capnp_schema::ring0_event::Builder>();
    let mut c = evt.initConnect();
    c.setTimestamp(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64);
    c.setPid(pid);
    c.setUid(uid);
    c.setBinaryPath(binary);
    {
        let mut ip = c.reborrow().getDstIp().unwrap();
        ip.setV4(dst_ip);
    }
    c.setDstPort(dst_port);
    c.setProtocol(if proto == 17 {
        capnp_schema::Protocol::Udp
    } else {
        capnp_schema::Protocol::Tcp
    });
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &msg);
    buf
}
