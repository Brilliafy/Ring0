use std::net::IpAddr;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::io::AsRawFd;
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
    /// Internal command (daemon-generated only, never parsed from the wire):
    /// mark the flow owned by `pid` as allowed in the kernel fast path after
    /// a user "allow once" decision.
    MarkFlowAllowed(u32, u16, u8, u32),
    /// `caller_pid` is the kernel-verified SO_PEERCRED pid of the process that
    /// submitted the decision  -  used to reject self-approval by the process
    /// under scrutiny (defense in depth on top of the privilege gate).
    SubmitPromptDecision(u64, String, String, u32),
    FlatpakList,
    PowerStatus,
    UpdateSettings(String),
    RunDoctor,
    Status,
    BlockPort(u16),
    UnblockPort(u16),
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
        // E11: a NUL byte in the socket path would make CString::new unwrap
        // panic in the daemon init path (env-controlled RING0_SOCKET).
        if path.as_bytes().contains(&0) {
            return Err(anyhow::anyhow!("socket path contains a NUL byte: {path:?}"));
        }
        let _ = std::fs::remove_file(path);
        let listener =
            UnixListener::bind(path).map_err(|e| anyhow::anyhow!("failed to bind {path}: {e}"))?;
        // Socket permissions:
        //  * production (daemon runs as root): restrict to root + the "ring0"
        //    admin group (0660, chowned root:ring0). The event stream carries
        //    process/network telemetry of every local user; a world-writable
        //    socket (0666) leaked it to any local process and enabled prompt
        //    self-approval (the subject process can read its own prompt id).
        //  * dev/test (daemon not root, or no ring0 group): fall back to the
        //    historical 0666 but log loudly so the exposure is visible.
        //
        // E11: chown/chmod by path would follow a symlink if an attacker could
        // swap the path between bind and chown. Verify the path still refers
        // to the exact socket inode we bound (lstat vs fstat of the fd) before
        // touching it by path.
        let bound_inode = {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            if unsafe { libc::fstat(listener.as_raw_fd(), &mut st) } == 0 {
                Some((st.st_dev, st.st_ino))
            } else {
                None
            }
        };
        let path_matches_fd = match std::fs::symlink_metadata(path) {
            Ok(m) => {
                use std::os::unix::fs::MetadataExt;
                bound_inode
                    .map(|(dev, ino)| (m.dev(), m.ino()) == (dev, ino))
                    .unwrap_or(false)
            }
            Err(_) => false,
        };
        let group_gid = ring0_group_gid();
        let is_root = unsafe { libc::geteuid() } == 0;
        if is_root && group_gid.is_some() {
            if path_matches_fd {
                let gid = group_gid.unwrap();
                unsafe {
                    libc::chown(
                        std::ffi::CString::new(path.as_bytes()).unwrap().as_ptr(),
                        0,
                        gid,
                    );
                }
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660));
            } else {
                warn!(
                    "IPC socket path {path} changed after bind  -  refusing chown/chmod (possible symlink swap)"
                );
            }
        } else {
            warn!(
                "IPC socket {path}: running {}root with no ring0 group  -  using permissive 0o666 mode (telemetry readable by any local process). Install creates the ring0 group and runs the daemon as root to harden this.",
                if is_root { "" } else { "non-" }
            );
            let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o666));
        }
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
                        let peer_cred = peer_credentials(&stream);

                        tokio::spawn(async move {
                            client_count.fetch_add(1, Ordering::Relaxed);
                            let (reader, writer) = stream.into_split();

                            // Per-connection response channel: QueryLogs
                            // answers go to the requesting client only, not to
                            // every subscriber (previously responses were sent
                            // over the shared broadcast and leaked to all peers).
                            let (resp_tx, mut resp_rx) =
                                tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

                            let write_handle = tokio::spawn(async move {
                                let mut writer = writer;
                                let mut rx = evt_tx.subscribe();
                                loop {
                                    tokio::select! {
                                        frame = rx.recv() => {
                                            match frame {
                                                Ok(data) => {
                                                    let len = (data.len() as u32).to_le_bytes();
                                                    if writer.write_all(&len).await.is_err() {
                                                        break;
                                                    }
                                                    if writer.write_all(&data).await.is_err() {
                                                        break;
                                                    }
                                                }
                                                // Lagged: the client fell behind the
                                                // broadcast backlog. Resync instead of
                                                // silently severing the connection.
                                                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                                                    warn!("IPC client lagged {n} events  -  resynchronizing");
                                                }
                                                Err(_) => break,
                                            }
                                        }
                                        resp = resp_rx.recv() => {
                                            match resp {
                                                Some(data) => {
                                                    let len = (data.len() as u32).to_le_bytes();
                                                    if writer.write_all(&len).await.is_err() {
                                                        break;
                                                    }
                                                    if writer.write_all(&data).await.is_err() {
                                                        break;
                                                    }
                                                }
                                                None => break,
                                            }
                                        }
                                    }
                                }
                            });

                            let read_handle = tokio::spawn(async move {
                                let resp_tx = resp_tx;
                                let mut reader = reader;
                                let mut len_buf = [0u8; 4];
                                loop {
                                    match reader.read_exact(&mut len_buf).await {
                                        Ok(_) => {}
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
                                    match parse_command_frame(&msg_buf, peer_cred.pid as u32) {
                                        Ok(DaemonCmd::QueryLogs(_start, _end, sev, limit)) => {
                                            let results = storage.query_alerts(sev, limit as usize);
                                            let response = build_query_response(&results);
                                            if resp_tx.send(response).is_err() {
                                                break;
                                            }
                                        }
                                        Ok(cmd) => {
                                            // Destructive/sensitive commands are
                                            // restricted to root or members of the
                                            // "ring0" admin group. Everyone else is
                                            // asked via polkitd, which pops the
                                            // desktop authentication dialog.
                                            //
                                            // The client keeps its connection open
                                            // waiting for our ack, which also keeps
                                            // its /proc/<pid> entry alive so the
                                            // polkit subject can be built (the peer
                                            // previously exited before
                                            // `Subject::new_for_owner` read /proc,
                                            // turning every first command into a
                                            // spurious denial).
                                            let privileged = is_privileged_command(&cmd);
                                            let allowed =
                                                if privileged && !peer_is_privileged(&peer_cred) {
                                                    crate::polkit::check_authorization(
                                                        peer_cred.pid as u32,
                                                        peer_cred.uid,
                                                    )
                                                    .await
                                                } else {
                                                    true
                                                };
                                            if allowed {
                                                if cmd_tx.send(cmd).is_err() {
                                                    break;
                                                }
                                                if privileged
                                                    && resp_tx.send(b"OK".to_vec()).is_err()
                                                {
                                                    break;
                                                }
                                            } else {
                                                warn!(
                                                    "denied privileged command {cmd:?} from uid {}",
                                                    peer_cred.uid
                                                );
                                                if resp_tx.send(b"DENIED".to_vec()).is_err() {
                                                    break;
                                                }
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

    pub fn broadcast_sync(&self, data: &[u8]) {
        if self.evt_tx.receiver_count() == 0 {
            return;
        }
        let _ = self.evt_tx.send(data.to_vec());
    }
}

/// Kernel-verified credentials of the peer on the other end of a Unix socket
/// (SO_PEERCRED): the caller's pid, uid and gid, as seen by the kernel.
fn peer_credentials(stream: &tokio::net::UnixStream) -> libc::ucred {
    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        cred.uid = u32::MAX;
        cred.pid = 0;
    }
    cred
}

/// GID of the "ring0" admin group (as created by dist/install.sh), if present.
fn ring0_group_gid() -> Option<u32> {
    static RING0_GID: std::sync::LazyLock<Option<u32>> = std::sync::LazyLock::new(|| unsafe {
        let gr = libc::getgrnam(c"ring0".as_ptr());
        if gr.is_null() {
            None
        } else {
            Some((*gr).gr_gid)
        }
    });
    *RING0_GID
}

/// Supplementary groups of the given process, read from /proc/<pid>/status
/// (the daemon runs as root, so this always succeeds for local processes).
fn process_groups(pid: u32) -> Option<Vec<u32>> {
    let status = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Groups:") {
            return Some(
                rest.split_whitespace()
                    .filter_map(|g| g.parse::<u32>().ok())
                    .collect(),
            );
        }
    }
    None
}

/// A peer may issue privileged commands if it runs as root or is a member of
/// the dedicated "ring0" admin group.
fn peer_is_privileged(cred: &libc::ucred) -> bool {
    if cred.uid == 0 {
        return true;
    }
    if let Some(ring0_gid) = ring0_group_gid() {
        // Include the peer's primary gid as well as its supplementary groups.
        if cred.gid == ring0_gid {
            return true;
        }
        if let Some(groups) = process_groups(cred.pid as u32) {
            return groups.contains(&ring0_gid);
        }
    }
    false
}

/// Commands that can damage the system and are therefore restricted to
/// privileged callers (see [`peer_is_privileged`]); the unprivileged GUI/CLI
/// can still connect for monitoring.
///
/// `SubmitPromptDecision` is privileged because the prompt stream is readable
/// by any local process: without this gate, the very process being prompted
/// could approve its own outbound connection by reading its prompt id from the
/// broadcast event stream and echoing a decision back (self-approval attack).
fn is_privileged_command(cmd: &DaemonCmd) -> bool {
    use DaemonCmd::*;
    matches!(
        cmd,
        BlockIp(_)
            | UnblockIp(_)
            | KillProcess(_)
            | BlockPort(_)
            | UnblockPort(_)
            | ReloadRules
            | Quarantine(_)
            | RunRootkitScan
            | SyncIntelFeeds
            | SubmitPromptDecision(_, _, _, _)
            | Shutdown
    )
}

pub(crate) fn parse_command_frame(data: &[u8], caller_pid: u32) -> Result<DaemonCmd> {
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
            // F3: the limit drives an unbounded RocksDB iteration + collection
            // on an unprivileged command; clamp it here so a malicious peer
            // cannot force a full-table scan / OOM of the root daemon.
            const MAX_LOG_LIMIT: u32 = 1000;
            Ok(DaemonCmd::QueryLogs(
                q.getStartTimestamp(),
                q.getEndTimestamp(),
                q.getSeverityThreshold(),
                q.getLimit().min(MAX_LOG_LIMIT),
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
                caller_pid,
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
        Which::Status(()) => Ok(DaemonCmd::Status),
        Which::BlockPort(port) => Ok(DaemonCmd::BlockPort(port as u16)),
        Which::UnblockPort(port) => Ok(DaemonCmd::UnblockPort(port as u16)),
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
            // Decode through the canonical alert format instead of hand-rolling
            // offsets (see crate::alert::AlertRecord).
            match crate::alert::AlertRecord::decode(v) {
                Some(rec) => {
                    alert.setTimestamp(rec.timestamp_ns);
                    let sev = match crate::alert::AlertRecord::severity_level(rec.severity) {
                        1 => capnp_schema::Severity::Low,
                        2 => capnp_schema::Severity::Med,
                        3 => capnp_schema::Severity::High,
                        _ => capnp_schema::Severity::Critical,
                    };
                    alert.setSeverity(sev);
                    alert.setRuleId(rec.rule_id);
                    alert.setSignatureName(&rec.message);
                }
                None => {
                    // Undecodable record (e.g. written by an older build):
                    // surface it as a placeholder rather than silently shifting.
                    alert.setTimestamp(0);
                    alert.setSeverity(capnp_schema::Severity::Low);
                    alert.setRuleId(0);
                    alert.setSignatureName("<undecodable alert record>");
                }
            }
        }
    }
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &message);
    buf
}

pub fn build_status_event(
    active_filters: &[String],
    cpu_percent: f32,
    ram_bytes: u64,
    events_per_sec: f64,
    blocked_domains: u32,
    blocked_cidrs: u32,
    blocked_ports: u32,
    dropped_events: u64,
    on_battery: bool,
    fim_throttled: bool,
) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    let evt = msg.init_root::<capnp_schema::ring0_event::Builder>();
    let mut s = evt.initStatus();
    let mut filters = s.reborrow().initActiveFilters(active_filters.len() as u32);
    for (i, f) in active_filters.iter().enumerate() {
        filters.reborrow().set(i as u32, f);
    }
    s.setCpuUsagePercent(cpu_percent);
    s.setRamUsageBytes(ram_bytes);
    s.setEventsPerSec(events_per_sec);
    s.setBlockedDomains(blocked_domains);
    s.setBlockedCidrs(blocked_cidrs);
    s.setBlockedPorts(blocked_ports);
    s.setDroppedEvents(dropped_events);
    s.setOnBattery(on_battery);
    s.setFimThrottled(fim_throttled);
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &msg);
    buf
}

pub fn build_packet_event(
    timestamp: u64,
    src_ip: u32,
    dst_ip: u32,
    src_port: u16,
    dst_port: u16,
    protocol: u8,
    pid: u32,
    action: u8,
) -> Vec<u8> {
    let mut msg = capnp::message::Builder::new_default();
    let evt = msg.init_root::<capnp_schema::ring0_event::Builder>();
    let mut p = evt.initPacket();
    p.setTimestamp(timestamp);
    {
        let mut ip = p.reborrow().getSrcIp().unwrap();
        ip.setV4(src_ip);
    }
    {
        let mut ip = p.reborrow().getDstIp().unwrap();
        ip.setV4(dst_ip);
    }
    p.setSrcPort(src_port);
    p.setDstPort(dst_port);
    p.setProtocol(if protocol == 17 {
        capnp_schema::Protocol::Udp
    } else if protocol == 1 {
        capnp_schema::Protocol::Icmp
    } else {
        capnp_schema::Protocol::Tcp
    });
    p.setPid(pid);
    p.setAction(if action == 1 {
        capnp_schema::Action::Drop
    } else if action == 2 {
        capnp_schema::Action::Alert
    } else {
        capnp_schema::Action::Pass
    });
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &msg);
    buf
}

/// Serialize a rule alert as a capnp `ring0_event::Alert` frame for the IPC
/// broadcast stream. Alerts are ALSO persisted as the compact `AlertRecord`
/// binary format (see `storage.write_alert`); the broadcast must use the capnp
/// schema so every subscriber (GUI, ring0ctl tail, …) can decode it with the
/// same `ring0_event` parser instead of special-casing a second format.
pub fn build_alert_event(rid: u32, sev: u8, msg: &str) -> Vec<u8> {
    let mut msg_b = capnp::message::Builder::new_default();
    let evt = msg_b.init_root::<capnp_schema::ring0_event::Builder>();
    let mut a = evt.initAlert();
    a.setTimestamp(chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64);
    a.setRuleId(rid);
    a.setSeverity(match sev {
        4 => capnp_schema::Severity::Critical,
        3 => capnp_schema::Severity::High,
        2 => capnp_schema::Severity::Med,
        _ => capnp_schema::Severity::Low,
    });
    a.setSignatureName(msg);
    let mut buf = Vec::new();
    let _ = capnp::serialize::write_message(&mut buf, &msg_b);
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
