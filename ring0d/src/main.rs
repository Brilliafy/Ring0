#![allow(dead_code)]
pub mod baseline;
pub mod containment;
pub mod contextual_security;
pub mod correlation;
pub mod desktop_sandbox;
pub mod dpi;
pub mod ebpf;
pub mod enrichment;
pub mod fastpath;
pub mod fim;
pub mod forensics;
pub mod governor;
pub mod hotswap;
pub mod intel;
// NextDNS/VirusTotal domain-reputation client. Parsed/compiled but not yet
// wired into the event pipeline (see IntelApiClient).
pub mod intel_api;
pub mod ipc;
pub mod power;
pub mod privesc;
pub mod process;
pub mod prompt;
pub mod rootkit;
pub mod rules;
pub mod self_defense;
pub mod storage;
pub mod sucadara;
pub mod threat_blocklist;
pub mod trust;

use std::sync::Arc;

use anyhow::Result;
use tokio::sync::Notify;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let shutdown = Arc::new(Notify::new());
    let sig_shutdown = shutdown.clone();

    tokio::spawn(async move { listen_signals(sig_shutdown).await });

    let mut daemon = match Daemon::new(shutdown.clone()).await {
        Ok(d) => d,
        Err(e) => {
            error!("daemon init failed: {e:?}");
            return Err(e);
        }
    };
    daemon.run().await?;
    Ok(())
}

async fn listen_signals(shutdown: Arc<Notify>) {
    use futures_util::StreamExt;
    use signal_hook::consts::*;
    use signal_hook_tokio::Signals;
    let mut signals = match Signals::new(&[SIGINT, SIGTERM, SIGUSR1]) {
        Ok(s) => s,
        Err(e) => {
            error!("signal register: {e}");
            return;
        }
    };
    loop {
        match signals.next().await {
            Some(SIGUSR1) => info!("SIGUSR1 — rules reload pending"),
            Some(_) => {
                shutdown.notify_waiters();
                break;
            }
            None => break,
        }
    }
}

struct Daemon {
    ebpf: ebpf::EbpfManager,
    storage: Arc<storage::RocksManager>,
    dpi: dpi::DpiEngine,
    rules: rules::RuleEngine,
    correlation: correlation::CorrelationEngine,
    self_defense: self_defense::SelfDefense,
    ipc: ipc::IpcServer,
    cmd_rx: tokio::sync::mpsc::UnboundedReceiver<ipc::DaemonCmd>,
    shutdown: Arc<Notify>,
    baseline: baseline::BaselineEngine,
    forensics: forensics::ForensicExporter,
    pcap_buffer: Arc<forensics::RollingPacketBuffer>,
    rootkit: rootkit::RootkitDetector,
    intel: Arc<intel::IntelManager>,
    governor: governor::CpuGovernor,
    trust: trust::TrustEngine,
    fastpath: fastpath::FastPathManager,
    prompt: prompt::PromptEngine,
    enrichment: enrichment::EnrichmentEngine,
    threat_blocklist: threat_blocklist::ThreatBlocklist,
    contextual: contextual_security::ContextualSecurity,
    fim: fim::FimEngine,
    privesc: privesc::PrivEscDetector,
    desktop_sandbox: desktop_sandbox::DesktopSandbox,
    hotswap: hotswap::HotswapManager,
    power: power::PowerGovernor,
    event_count: std::sync::atomic::AtomicU64,
    last_status: parking_lot::Mutex<Option<(u64, std::time::Instant)>>,
    blocklist_payload: Arc<parking_lot::Mutex<Option<sucadara::SyncPayload>>>,
}

impl Daemon {
    async fn new(shutdown: Arc<Notify>) -> Result<Self> {
        let mut ebpf = ebpf::EbpfManager::load()?;
        // Fast-path DPI: sync literal patterns into the kernel map. Observe-only
        // by default; RING0_DPI_ENFORCE=1 switches the fast path to drop.
        let dpi_synced = ebpf.sync_dpi_patterns(ebpf::BPF_DPI_SIGNATURES);
        let dpi_enforce = std::env::var("RING0_DPI_ENFORCE").as_deref() == Ok("1");
        ebpf.set_dpi_enforce(dpi_enforce);
        info!("DPI fast path: {dpi_synced} literal patterns synced");
        let storage = Arc::new(storage::RocksManager::open(&ring0_common::db_path())?);
        let dpi = dpi::DpiEngine::new()?;
        let rules_path = bundled_config_path("rules.yaml");
        let rules = rules::RuleEngine::load(&rules_path).unwrap_or_else(|e| {
            warn!("no rules file: {e:?}");
            rules::RuleEngine::empty()
        });
        let correlation = correlation::CorrelationEngine::new();
        let self_defense = self_defense::SelfDefense::new();
        self_defense.lock_ebpf_maps();
        let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
        let ipc = ipc::IpcServer::bind(
            &ring0_common::socket_path(),
            storage.clone(),
            cmd_tx.clone(),
        )
        .await?;

        let lsm_attached = ebpf.lsm_available();
        if lsm_attached {
            // Audit-by-default: the LSM hooks emit alerts but do not deny until
            // inline enforcement is explicitly enabled. The previous behavior
            // (always-on deny) broke gdb/strace and system daemons that rely on
            // ptrace/CAP_NET_ADMIN/CAP_SYS_ADMIN.
            if std::env::var("RING0_LSM_ENFORCE").as_deref() == Ok("1") {
                ebpf.enable_lsm_enforcement();
                info!("eBPF LSM inline prevention active (enforce mode)");
            } else {
                info!(
                    "eBPF LSM in AUDIT mode — set RING0_LSM_ENFORCE=1 to enable inline prevention"
                );
            }
        } else {
            warn!("eBPF LSM not available — using XDP/tracepoint fallback enforcement");
        }

        let rocksdb_inner = storage.inner_db();
        let baseline = baseline::BaselineEngine::new(rocksdb_inner.clone());
        info!(
            "Baseline engine initialized (learning_mode={})",
            baseline.is_learning()
        );

        let pcap_buffer = Arc::new(forensics::RollingPacketBuffer::new());
        let forensics = forensics::ForensicExporter::new(
            pcap_buffer.clone(),
            rocksdb_inner.clone(),
            storage.clone(),
        );

        let rootkit = rootkit::RootkitDetector::new();
        let intel = Arc::new(intel::IntelManager::new(rocksdb_inner.clone()));

        let yara_count = intel.load_yara_rules().unwrap_or(0);
        info!("Loaded {yara_count} YARA rules");

        let governor = governor::CpuGovernor::new();
        let trust = trust::TrustEngine::new();
        let fastpath = fastpath::FastPathManager::new();
        let prompt = prompt::PromptEngine::new(cmd_tx.clone(), &rules_path);
        let enrichment = enrichment::EnrichmentEngine::new();
        let threat_blocklist = threat_blocklist::ThreatBlocklist::new();
        threat_blocklist.load_local_file(&bundled_config_path("threat_domains.txt"));
        info!(
            "ThreatBlocklist: {} domains loaded",
            threat_blocklist.domain_count()
        );
        let mut contextual = contextual_security::ContextualSecurity::new();
        contextual.start_dbus_monitor();
        let fim = fim::FimEngine::new(rocksdb_inner.clone());
        // Hash the system directories in the background: /usr/lib64 alone can
        // be several GB, and a synchronous scan would leave the daemon
        // unresponsive (no IPC, no event processing) for minutes at startup.
        {
            let fim_bg = fim.clone();
            tokio::task::spawn_blocking(move || {
                let count = fim_bg.scan_and_baseline();
                info!("FIM: background baseline complete — {count} system files");
            });
        }
        let privesc = privesc::PrivEscDetector::new();
        let desktop_sandbox = desktop_sandbox::DesktopSandbox::new();
        let hotswap = hotswap::HotswapManager::new();
        let _ = hotswap.init_bpffs();
        let mut power = power::PowerGovernor::new();
        power.start_dbus_monitor();

        let event_count = std::sync::atomic::AtomicU64::new(0);
        let last_status = parking_lot::Mutex::new(None);

        // Kick off the Suricata rules + DNS/IP blocklist sync in the background.
        let blocklist_payload: Arc<parking_lot::Mutex<Option<sucadara::SyncPayload>>> =
            Arc::new(parking_lot::Mutex::new(None));
        {
            let sink = blocklist_payload.clone();
            tokio::spawn(async move {
                info!("Fetching Suricata rules + DNS/IP blocklists...");
                let (report, payload) = sucadara::fetch_all().await;
                info!(
                    "Blocklist fetch done: {} rules, {} domains, {} cidrs, {} ports ({} ok/{} failed)",
                    report.rules_parsed,
                    report.domains,
                    report.cidrs,
                    report.ports,
                    report.sources_ok,
                    report.sources_failed
                );
                *sink.lock() = Some(payload);
            });
        }

        Ok(Self {
            ebpf,
            storage,
            dpi,
            rules,
            correlation,
            self_defense,
            ipc,
            cmd_rx,
            shutdown,
            baseline,
            forensics,
            pcap_buffer,
            rootkit,
            intel,
            governor,
            trust,
            fastpath,
            prompt,
            enrichment,
            threat_blocklist,
            contextual,
            fim,
            privesc,
            desktop_sandbox,
            hotswap,
            power,
            event_count,
            last_status,
            blocklist_payload,
        })
    }

    async fn run(&mut self) -> Result<()> {
        let mut ring_rx = self.ebpf.subscribe();
        let mut tls_rx = self.ebpf.subscribe_tls();
        let mut lsm_rx = self.ebpf.subscribe_lsm();
        let mut rootkit_rx = self.ebpf.subscribe_rootkit();
        let mut privesc_rx = self.ebpf.subscribe_privesc();
        let mut corr_tick = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut baseline_tick = tokio::time::interval(std::time::Duration::from_secs(600));
        let mut forensics_tick = tokio::time::interval(std::time::Duration::from_secs(30));
        let mut rootkit_tick = tokio::time::interval(std::time::Duration::from_secs(60));
        let mut intel_tick = tokio::time::interval(std::time::Duration::from_secs(3600));
        let mut governor_tick = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut fastpath_tick = tokio::time::interval(std::time::Duration::from_secs(60));
        let mut prompt_tick = tokio::time::interval(std::time::Duration::from_secs(5));
        let mut blocklist_tick = tokio::time::interval(std::time::Duration::from_secs(60));

        loop {
            tokio::select! {
                biased;
                _ = self.shutdown.notified() => { info!("shutdown"); break; }
                Ok(data) = ring_rx.recv() => { self.on_raw_event(&data).await; }
                Ok(tls_data) = tls_rx.recv() => { self.on_tls_event(&tls_data).await; }
                Ok(lsm_data) = lsm_rx.recv() => { self.on_lsm_event(&lsm_data).await; }
                Ok(rk_data) = rootkit_rx.recv() => { self.on_rootkit_event(&rk_data).await; }
                Ok(pv_data) = privesc_rx.recv() => { self.on_privesc_event(&pv_data).await; }
                _ = corr_tick.tick() => { self.eval_correlations().await; }
                _ = baseline_tick.tick() => { self.tick_baseline().await; }
                _ = forensics_tick.tick() => { self.tick_forensics(); }
                _ = rootkit_tick.tick() => { self.tick_rootkit_scan(); }
                _ = intel_tick.tick() => {
                    // Feed sync performs blocking network I/O (3 feeds, up to
                    // ~90s of timeouts); it must not run on the main select
                    // loop or it starves IPC command handling and event
                    // processing for the whole duration.
                    let intel = self.intel.clone();
                    tokio::spawn(async move {
                        if let Err(e) = intel.sync_feeds().await {
                            warn!("periodic intel feed sync failed: {e:?}");
                        }
                    });
                }
                _ = governor_tick.tick() => { self.tick_governor(); }
                _ = fastpath_tick.tick() => { self.fastpath.purge_idle_flows(); }
                _ = prompt_tick.tick() => { self.prompt.check_timeouts(); }
                _ = blocklist_tick.tick() => { self.apply_blocklist_payload(); }
                Some(cmd) = self.cmd_rx.recv() => { self.handle_command(cmd); }
            }
        }
        self.cleanup();
        Ok(())
    }

    async fn on_raw_event(&self, raw: &[u8]) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if raw.len() < 16 {
            return;
        }
        match raw[0] {
            0 => self.on_packet(raw).await,
            1 => self.on_process_exec(raw).await,
            2 => self.on_file_access(raw).await,
            3 => self.on_connect(raw).await,
            4 => self.on_kill_event(raw).await,
            5 => self.on_unlink_event(raw).await,
            6 => self.on_tls_event(raw).await,
            30 => self.on_dpi_event(raw).await,
            _ => {}
        }
    }

    async fn on_packet(&self, raw: &[u8]) {
        if raw.len() < 40 {
            return;
        }
        let ts = u64::from_le_bytes(raw[8..16].try_into().unwrap_or([0; 8]));
        let src_ip = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let dst_ip = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        let src_port = u16::from_le_bytes(raw[24..26].try_into().unwrap_or([0; 2]));
        let dst_port = u16::from_le_bytes(raw[26..28].try_into().unwrap_or([0; 2]));
        let proto = raw[28];
        let pid = u32::from_le_bytes(raw[32..36].try_into().unwrap_or([0; 4]));
        let action = raw[36];
        let evt =
            ipc::build_packet_event(ts, src_ip, dst_ip, src_port, dst_port, proto, pid, action);
        self.storage.write_raw(&evt);
        self.ipc.broadcast_raw(&evt).await;
        self.pcap_buffer.push(raw, ts);
        let binary = if pid > 0 {
            crate::process::ProcessResolver::binary_path(pid).unwrap_or_else(|| "unknown".into())
        } else {
            "kernel".into()
        };
        if self.threat_blocklist.check_ports(src_port, dst_port) {
            let a = build_alert_bytes_rule(
                4000,
                3,
                &format!(
                    "blocked port traffic {}.{}.{}.{}:{}",
                    (dst_ip >> 24) & 0xFF,
                    (dst_ip >> 16) & 0xFF,
                    (dst_ip >> 8) & 0xFF,
                    dst_ip & 0xFF,
                    dst_port
                ),
            );
            self.storage.write_alert(&a);
            self.ipc.broadcast_raw(&a).await;
        }
        let _ = (src_ip, proto, action, binary);
    }

    async fn on_process_exec(&self, raw: &[u8]) {
        if raw.len() < 44 {
            return;
        }
        let pid = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let event_ppid = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        let uid = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
        // The sched_process_exec tracepoint does not expose the parent pid, so
        // prefer the real /proc value over the (zero) event field.
        let ppid = crate::process::ProcessResolver::ppid(pid).unwrap_or(event_ppid);
        let comm = if raw[28..44].iter().position(|b| *b == 0).unwrap_or(16) > 0 {
            String::from_utf8_lossy(&raw[28..44])
                .trim_end_matches('\0')
                .to_string()
        } else {
            String::new()
        };
        let binary =
            crate::process::ProcessResolver::binary_path(pid).unwrap_or_else(|| comm.clone());
        let cmdline =
            crate::process::ProcessResolver::cmdline(pid).unwrap_or_else(|| "unknown".into());
        let parent_binary = crate::process::ProcessResolver::binary_path(ppid);
        if let Some(ref pb) = parent_binary {
            self.baseline.record_exec(&binary, Some(pb));
        } else {
            self.baseline.record_exec(&binary, None);
        }
        if let Some(anomaly) = self
            .baseline
            .check_exec_anomaly(&binary, parent_binary.as_deref())
        {
            let a = build_alert_bytes_rule(8001, 2, &anomaly);
            self.storage.write_alert(&a);
            self.ipc.broadcast_raw(&a).await;
        }
        self.correlation.push_exec(pid, ppid, &binary, &cmdline);
        if let Some(pb) = &parent_binary {
            for rid in self.rules.check_process_anomaly(&binary, Some(pb)) {
                let a = build_alert_bytes_rule(rid, 3, "process anomaly");
                self.storage.write_alert(&a);
                self.ipc.broadcast_raw(&a).await;
            }
        }
        if self.ebpf.binary_blocked(&binary) {
            let a = build_alert_bytes_rule(9001, 4, &format!("blocked binary executed: {binary}"));
            self.storage.write_alert(&a);
            self.ipc.broadcast_raw(&a).await;
            let _ = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
        }
        let evt = ipc::build_process_exec_event(pid, ppid, uid, &binary, &cmdline);
        self.storage.write_raw(&evt);
        self.ipc.broadcast_raw(&evt).await;
    }

    async fn on_file_access(&self, raw: &[u8]) {
        if raw.len() < 92 {
            return;
        }
        let pid = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let uid = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        let mut fnbuf = String::new();
        if let Some(end) = raw[24..88].iter().position(|b| *b == 0) {
            if let Ok(s) = std::str::from_utf8(&raw[24..24 + end]) {
                fnbuf = s.to_string();
            }
        }
        let binary =
            crate::process::ProcessResolver::binary_path(pid).unwrap_or_else(|| "unknown".into());
        self.correlation.push_file(pid, &fnbuf);
        for rid in self.rules.check_file_access(&fnbuf, pid, true) {
            let a = build_alert_bytes_hids(rid, &binary, &fnbuf);
            self.storage.write_alert(&a);
            self.ipc.broadcast_raw(&a).await;
        }
        let evt = ipc::build_file_access_event(pid, uid, &binary, &fnbuf);
        self.storage.write_raw(&evt);
        self.ipc.broadcast_raw(&evt).await;
    }

    async fn on_connect(&self, raw: &[u8]) {
        if raw.len() < 32 {
            return;
        }
        let pid = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let uid = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        let dip = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
        let dp = u16::from_le_bytes(raw[28..30].try_into().unwrap_or([0; 2]));
        let proto = raw[30];
        crate::process::ProcessResolver::push_socket(pid, dip, dp, proto);
        self.correlation.push_connect(pid, dip, dp);
        self.baseline.record_connection(dip, dp);
        if let Some(anomaly) = self.baseline.check_connection_anomaly(dip, dp) {
            let a = build_alert_bytes_rule(8002, 2, &anomaly);
            self.storage.write_alert(&a);
            self.ipc.broadcast_raw(&a).await;
        }
        let binary =
            crate::process::ProcessResolver::binary_path(pid).unwrap_or_else(|| "unknown".into());
        let cmdline =
            crate::process::ProcessResolver::cmdline(pid).unwrap_or_else(|| "unknown".into());
        self.desktop_sandbox.resolve_pid(pid, &binary, &cmdline);
        if let Some(anomaly) = self.desktop_sandbox.check_network_anomaly(pid, &binary) {
            let a = build_alert_bytes_rule(1001, 3, &anomaly.description);
            self.storage.write_alert(&a);
            self.ipc.broadcast_raw(&a).await;
            info!("[SANDBOX] {}", anomaly.description);
        }
        let evt = ipc::build_connect_event(pid, uid, &binary, dip, dp, proto);
        self.storage.write_raw(&evt);
        self.ipc.broadcast_raw(&evt).await;

        let trust_status = self.trust.verify_binary(&binary, pid);
        if self.contextual.should_block_connection(pid, &binary) {
            info!("ContextualSecurity: dropping connection from PID {pid} ({binary})");
            let a = build_alert_bytes_rule(
                4003,
                2,
                &format!(
                    "Contextual block: {}.{}.{}.{}:{} by PID {pid}",
                    (dip >> 24) & 0xFF,
                    (dip >> 16) & 0xFF,
                    (dip >> 8) & 0xFF,
                    dip & 0xFF,
                    dp
                ),
            );
            self.storage.write_alert(&a);
            self.ipc.broadcast_raw(&a).await;
            return;
        }
        match trust_status {
            trust::TrustStatus::TrustedSystemPackage | trust::TrustStatus::TrustedBinary => {
                let _ = self.fastpath.mark_flow_safe(pid, dip, 0, dp, proto);
                info!("TrustEngine: PID {pid} {binary} trusted — flow offloaded");
            }
            trust::TrustStatus::Untrusted => {
                info!("TrustEngine: PID {pid} {binary} UNTRUSTED — creating user prompt");
                let (country_code, country_name) = self.enrichment.lookup_country(dip);
                let rdns_name = self.enrichment.lookup_rdns(dip).await;
                let ppid = crate::process::ProcessResolver::ppid(pid).unwrap_or(0);
                let parent_binary = crate::process::ProcessResolver::binary_path(ppid)
                    .unwrap_or_else(|| "unknown".into());
                let prompt_id = self.prompt.create_prompt(
                    pid,
                    ppid,
                    &binary,
                    &parent_binary,
                    dip,
                    dp,
                    proto,
                    &country_code,
                    &country_name,
                    &rdns_name,
                );
                let prompt_evt = ipc::build_connection_prompt_event(
                    prompt_id,
                    pid,
                    ppid,
                    &binary,
                    &parent_binary,
                    dip,
                    dp,
                    proto,
                    &country_code,
                    &country_name,
                    &rdns_name,
                    15,
                );
                self.ipc.broadcast_raw(&prompt_evt).await;
            }
            trust::TrustStatus::Unknown => {}
        }
    }

    async fn on_kill_event(&self, raw: &[u8]) {
        if raw.len() < 28 {
            return;
        }
        let attacker = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let target = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        let sig = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
        if let Some(evt) = self.self_defense.ingest_kill_attempt(attacker, target, sig) {
            let alert = build_self_defense_alert(&evt);
            self.storage.write_alert(&alert);
            self.ipc.broadcast_raw(&alert).await;
        }
    }

    async fn on_unlink_event(&self, raw: &[u8]) {
        if raw.len() < 120 {
            return;
        }
        let pid = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let mut path = String::new();
        if let Some(end) = raw[24..120].iter().position(|b| *b == 0) {
            if let Ok(s) = std::str::from_utf8(&raw[24..24 + end]) {
                path = s.to_string();
            }
        }
        if let Some(evt) = self.self_defense.ingest_unlink_attempt(pid, &path) {
            let alert = build_self_defense_alert(&evt);
            self.storage.write_alert(&alert);
            self.ipc.broadcast_raw(&alert).await;
        }
    }

    async fn on_tls_event(&self, raw: &[u8]) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if raw.len() < 24 {
            return;
        }
        let payload = if raw.len() > 28 { &raw[28..] } else { &[] };
        for m in self.dpi.scan_payload(payload) {
            let alert = build_alert_bytes_rule(m.rule_id, m.severity, &m.signature_name);
            self.storage.write_alert(&alert);
            self.ipc.broadcast_raw(&alert).await;
        }
    }

    /// Handle a fast-path DPI match from the kernel (KIND_DPI). The kernel has
    /// already passed or dropped the packet; here we just record and surface it.
    async fn on_dpi_event(&self, raw: &[u8]) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if raw.len() < 36 {
            return;
        }
        let rule_id = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        let src_ip = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
        let dst_ip = u32::from_le_bytes(raw[28..32].try_into().unwrap_or([0; 4]));
        let dst_port = u16::from_le_bytes(raw[32..34].try_into().unwrap_or([0; 2]));
        let proto = raw[34];
        let name = self
            .dpi
            .signature_name(rule_id)
            .unwrap_or("unknown pattern");
        let msg = format!(
            "DPI match rule={rule_id} ({name}) {}.{}.{}.{} -> {}.{}.{}.{}:{}{}",
            (src_ip >> 24) & 0xFF,
            (src_ip >> 16) & 0xFF,
            (src_ip >> 8) & 0xFF,
            src_ip & 0xFF,
            (dst_ip >> 24) & 0xFF,
            (dst_ip >> 16) & 0xFF,
            (dst_ip >> 8) & 0xFF,
            dst_ip & 0xFF,
            dst_port,
            if proto == 17 { "/udp" } else { "/tcp" }
        );
        let alert = build_alert_bytes_rule(5000 + rule_id, 2, &msg);
        self.storage.write_alert(&alert);
        self.ipc.broadcast_raw(&alert).await;
        info!("[DPI] {msg}");
    }

    async fn on_lsm_event(&self, raw: &[u8]) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if raw.len() < 132 {
            return;
        }
        let event_type = raw[24];
        let denied = raw[25];
        let pid = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        // LsmEvent layout: kind(0), ts(8..16), pid(16..20), uid(20..24),
        // event_type(24), denied(25), path(26..122), dst_ip(124..128),
        // dst_port(128..130). Note the path starts at byte 26.
        let path_end = raw[26..122].iter().position(|b| *b == 0).unwrap_or(96);
        let path = if path_end > 0 {
            String::from_utf8_lossy(&raw[26..26 + path_end]).to_string()
        } else {
            String::new()
        };
        let dst_ip = u32::from_le_bytes(raw[124..128].try_into().unwrap_or([0; 4]));
        let dst_port = u16::from_le_bytes(raw[128..130].try_into().unwrap_or([0; 2]));

        let event_name = match event_type {
            0 => "file_open",
            1 => "bprm_check",
            2 => "socket_connect",
            _ => "unknown",
        };

        if denied == 1 {
            let desc = match event_type {
                0 => format!("LSM blocked file open: {} (pid {})", path, pid),
                1 => format!("LSM blocked binary execution: pid {}", pid),
                2 => format!(
                    "LSM blocked connect: {}.{}.{}.{}:{} (pid {})",
                    (dst_ip >> 24) & 0xFF,
                    (dst_ip >> 16) & 0xFF,
                    (dst_ip >> 8) & 0xFF,
                    dst_ip & 0xFF,
                    dst_port,
                    pid
                ),
                _ => format!("LSM blocked unknown event type {}", event_type),
            };
            info!("[LSM_DENY] {desc}");
            let alert = build_alert_bytes_rule(9000 + event_type as u32, 4, &desc);
            self.storage.write_alert(&alert);
            self.ipc.broadcast_raw(&alert).await;
        } else {
            info!("[LSM_ALLOW] {} pid={} path={}", event_name, pid, path);
        }
    }

    async fn tick_baseline(&self) {
        if self.baseline.is_learning() {
            let progress = self.baseline.learning_progress();
            info!("Baseline learning progress: {:.1}%", progress * 100.0);
            if progress >= 1.0 {
                self.baseline.finish_learning();
                info!("Baseline learning period complete — switching to anomaly detection");
            }
        }
    }

    fn tick_forensics(&self) {
        info!(
            "Forensics: buffer frames={} anomalies={}",
            self.pcap_buffer.buffer_size(),
            self.baseline.anomaly_count()
        );
    }

    async fn on_privesc_event(&self, raw: &[u8]) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if raw.len() < 28 {
            return;
        }
        let pid = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let uid = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        match raw[0] {
            ebpf::KIND_SETUID => {
                let new_uid = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
                self.privesc.ingest_setuid_event(pid, uid, new_uid);
                let a = build_alert_bytes_rule(
                    2001,
                    4,
                    &format!("setuid escalation PID {} {}->{}", pid, uid, new_uid),
                );
                self.storage.write_alert(&a);
                self.ipc.broadcast_raw(&a).await;
                // A real uid escalation is the clearest privilege-escalation signal;
                // contain the process. (Informational capable/ptrace events do not
                // trigger containment — freezing processes for those is destructive.)
                containment::ContainmentManager::quarantine_pid(pid);
            }
            ebpf::KIND_PTRACE => {
                let target = u32::from_le_bytes(raw[28..32].try_into().unwrap_or([0; 4]));
                self.privesc.ingest_ptrace_attempt(pid, uid, target);
                let a =
                    build_alert_bytes_rule(2002, 4, &format!("ptrace PID {} -> {}", pid, target));
                self.storage.write_alert(&a);
                self.ipc.broadcast_raw(&a).await;
            }
            ebpf::KIND_CAP => {
                let capability = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
                self.privesc.ingest_capable_check(pid, uid, capability);
                let a = build_alert_bytes_rule(
                    2003,
                    3,
                    &format!("capable PID {} cap={}", pid, capability),
                );
                self.storage.write_alert(&a);
                self.ipc.broadcast_raw(&a).await;
            }
            _ => {}
        }
    }

    async fn on_rootkit_event(&self, raw: &[u8]) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if raw.len() < 60 {
            return;
        }
        let pid = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let _uid = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        match raw[0] {
            ebpf::KIND_MMAP => {
                if raw.len() < 56 {
                    return;
                }
                let prot = u32::from_le_bytes(raw[40..44].try_into().unwrap_or([0; 4]));
                let flags = u32::from_le_bytes(raw[44..48].try_into().unwrap_or([0; 4]));
                let len = u64::from_le_bytes(raw[32..40].try_into().unwrap_or([0; 8]));
                if let Some(finding) = self.rootkit.ingest_wx_mmap_event(pid, prot, flags, len) {
                    let desc = finding.description.clone();
                    let a = build_alert_bytes_rule(7001, 3, &desc);
                    self.storage.write_alert(&a);
                    self.ipc.broadcast_raw(&a).await;
                    info!("[ROOTKIT] {desc}");
                }
            }
            ebpf::KIND_MODULE => {
                if raw.len() < 92 {
                    return;
                }
                let name_end = raw[24..88].iter().position(|b| *b == 0).unwrap_or(64);
                let name = if name_end > 0 {
                    String::from_utf8_lossy(&raw[24..24 + name_end]).to_string()
                } else {
                    String::new()
                };
                let flags = u32::from_le_bytes(raw[88..92].try_into().unwrap_or([0; 4]));
                if let Some(finding) = self.rootkit.ingest_module_event(pid, &name, flags) {
                    let desc = finding.description.clone();
                    let a = build_alert_bytes_rule(7002, 3, &desc);
                    self.storage.write_alert(&a);
                    self.ipc.broadcast_raw(&a).await;
                    info!("[ROOTKIT] {desc}");
                }
            }
            ebpf::KIND_MEMFD => {
                let name_end = raw[28..60].iter().position(|b| *b == 0).unwrap_or(32);
                let name = if name_end > 0 {
                    String::from_utf8_lossy(&raw[28..28 + name_end]).to_string()
                } else {
                    String::new()
                };
                let flags = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
                if let Some(finding) = self.rootkit.ingest_memfd_event(pid, &name, flags) {
                    let desc = finding.description.clone();
                    let a = build_alert_bytes_rule(7000, 3, &desc);
                    self.storage.write_alert(&a);
                    self.ipc.broadcast_raw(&a).await;
                    info!("[ROOTKIT] {desc}");
                    if let Some(binary) = crate::process::ProcessResolver::binary_path(pid) {
                        match self.intel.scan_binary(&binary) {
                            Ok(matches) => {
                                for m in matches {
                                    let a = build_alert_bytes_rule(7003, 3, &m);
                                    self.storage.write_alert(&a);
                                    self.ipc.broadcast_raw(&a).await;
                                }
                            }
                            Err(e) => warn!("YARA scan skipped for {binary}: {e}"),
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn tick_rootkit_scan(&self) {
        let findings = self.rootkit.scan_hidden_pids();
        for finding in &findings {
            let desc = format!("[{}] {}", finding.alert_type, finding.description);
            let severity = if finding.hidden { 4u8 } else { 2u8 };
            let a = build_alert_bytes_rule(7004, severity, &desc);
            self.storage.write_alert(&a);
            info!("[ROOTKIT_SCAN] {desc}");
        }
        info!(
            "Rootkit scan complete: {} findings, {} total scans",
            findings.len(),
            self.rootkit.scan_count()
        );
    }

    fn tick_governor(&self) {
        let state = self.governor.tick();
        let pct = self.governor.daemon_cpu_pct() + self.governor.bpf_cpu_pct();
        if state != governor::GovernorState::Normal {
            info!(
                "Governor state: {:?} (cpu={:.1}%) sampling={} dpi_fast={}",
                state,
                pct,
                self.governor.is_sampling_enabled(),
                self.governor.is_dpi_fast_mode()
            );
        }
    }

    async fn eval_correlations(&self) {
        for alert in self.correlation.eval() {
            info!(
                "correlation: [{}] {} — {}",
                alert.pattern_id, alert.pattern_name, alert.description
            );
            let bytes = build_correlation_alert_bytes(&alert);
            self.storage.write_alert(&bytes);
            self.ipc.broadcast_raw(&bytes).await;
            if alert.severity >= 3 {
                containment::ContainmentManager::quarantine_pid(alert.root_pid);
                self.forensics.trigger_export(
                    alert.id,
                    alert.severity,
                    &format!(
                        "[{}] {} — {}",
                        alert.pattern_id, alert.pattern_name, alert.description
                    ),
                );
            }
        }
    }

    fn apply_blocklist_payload(&mut self) {
        let payload = self.blocklist_payload.lock().take();
        if let Some(payload) = payload {
            info!(
                "Applying blocklist to kernel maps: {} cidrs, {} domains, {} ports",
                payload.cidrs.len(),
                payload.domains.len(),
                payload.ports.len()
            );
            let c = self.ebpf.sync_blocked_cidrs(&payload.cidrs);
            let d = self.ebpf.sync_dns_domains(&payload.domains);
            let p = self.ebpf.sync_blocked_ports(&payload.ports);
            info!("Kernel sync complete: {c} cidrs, {d} domains, {p} ports in eBPF maps");
        }
    }

    fn handle_command(&mut self, cmd: ipc::DaemonCmd) {
        use ipc::DaemonCmd::*;
        match cmd {
            BlockIp(ip) => {
                if let Err(e) = self.ebpf.block_ip(ip) {
                    error!("block_ip: {e:?}")
                }
            }
            UnblockIp(ip) => {
                if let Err(e) = self.ebpf.unblock_ip(ip) {
                    error!("unblock_ip: {e:?}")
                }
            }
            BlockPort(port) => {
                if let Err(e) = self.ebpf.block_port(port) {
                    error!("block_port: {e:?}")
                }
                self.threat_blocklist.block_port(port);
            }
            UnblockPort(port) => {
                if let Err(e) = self.ebpf.unblock_port(port) {
                    error!("unblock_port: {e:?}")
                }
                self.threat_blocklist.unblock_port(port);
            }
            KillProcess(pid) => {
                // Confused-deputy hardening: never let a caller (even a
                // privileged one) terminate critical system processes.
                let daemon_pid = std::process::id();
                if pid == 0 || pid == 1 || pid == daemon_pid {
                    warn!("refusing to kill protected PID {pid}");
                } else {
                    let r = unsafe { libc::kill(pid as i32, libc::SIGKILL) };
                    if r == 0 {
                        info!("killed {pid}")
                    } else {
                        error!("kill {pid}: {}", std::io::Error::last_os_error())
                    }
                }
            }
            ReloadFilters => info!("reload filters"),
            ReloadRules => {
                if let Err(e) = self.rules.reload() {
                    error!("rule reload: {e:?}")
                }
            }
            Quarantine(pid) => {
                containment::ContainmentManager::quarantine_pid(pid);
            }
            Shutdown => self.shutdown.notify_waiters(),
            QueryLogs(_, _, _, _) => {}
            RunRootkitScan => {
                info!("Manual rootkit scan");
                self.tick_rootkit_scan();
            }
            SyncIntelFeeds => {
                info!("Intel feed sync");
                let i = self.intel.clone();
                tokio::spawn(async move {
                    let _ = i.sync_feeds().await;
                });
            }
            SubmitPromptDecision(prompt_id, action, scope) => {
                let act = match action.as_str() {
                    "allow_once" => prompt::PromptAction::AllowOnce,
                    "allow_always" => prompt::PromptAction::AllowAlways,
                    "block" => prompt::PromptAction::Block,
                    "block_always" => prompt::PromptAction::BlockAlways,
                    _ => prompt::PromptAction::Block,
                };
                let scp = match scope.as_str() {
                    "exact_ip" => prompt::PromptScope::ExactIp,
                    "domain" => prompt::PromptScope::Domain,
                    "port" => prompt::PromptScope::Port,
                    "process" => prompt::PromptScope::Process,
                    _ => prompt::PromptScope::ExactIp,
                };
                let _ = self.prompt.resolve_prompt(
                    prompt_id,
                    prompt::PromptDecision {
                        prompt_id,
                        action: act,
                        scope: scp,
                    },
                );
            }
            FlatpakList => {
                let a = self.desktop_sandbox.list_apps();
                info!("Flatpak: {} apps", a.len());
            }
            PowerStatus => info!(
                "Power: battery={} fim={}",
                self.power.is_on_battery(),
                self.power.is_fim_throttled()
            ),
            UpdateSettings(json) => info!("Settings: {json}"),
            RunDoctor => info!("Doctor requested"),
            Status => {
                self.apply_blocklist_payload();
                let total = self.event_count.load(std::sync::atomic::Ordering::Relaxed);
                let mut last = self.last_status.lock();
                let now = std::time::Instant::now();
                let eps = match *last {
                    Some((prev, prev_at)) => {
                        let dt = now.duration_since(prev_at).as_secs_f64();
                        if dt > 0.0 {
                            (total.saturating_sub(prev)) as f64 / dt
                        } else {
                            0.0
                        }
                    }
                    None => 0.0,
                };
                *last = Some((total, now));
                let cpu = self.governor.daemon_cpu_pct();
                let ram = read_vm_rss();
                let filters = self.ebpf.blocked_ips();
                let domains = self.ebpf.blocked_domain_count() as u32;
                let cidrs = filters.len() as u32;
                let ports = self.ebpf.blocked_port_count() as u32;
                let status =
                    ipc::build_status_event(&filters, cpu, ram, eps, domains, cidrs, ports);
                self.ipc.broadcast_sync(&status);
            }
        }
    }
    fn cleanup(&mut self) {
        self.ebpf.detach();
        self.storage.flush();
        std::fs::remove_file(ring0_common::socket_path()).ok();
    }
}

/// Resolve a config file path: prefer the system path, fall back to the bundled
/// config directory shipped with the repo.
fn bundled_config_path(name: &str) -> String {
    let system = format!("/etc/ring0/{name}");
    if std::path::Path::new(&system).exists() {
        return system;
    }
    let bundled = format!("{}/config/{name}", env!("CARGO_MANIFEST_DIR"));
    if std::path::Path::new(&bundled).exists() {
        return bundled;
    }
    system
}

fn read_vm_rss() -> u64 {
    let status = match std::fs::read_to_string("/proc/self/status") {
        Ok(s) => s,
        Err(_) => return 0,
    };
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: u64 = rest
                .split_whitespace()
                .next()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            return kb * 1024;
        }
    }
    0
}

fn build_alert_bytes_hids(rid: u32, binary: &str, path: &str) -> Vec<u8> {
    let ts = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or(0)
        .to_be_bytes();
    let mut buf = Vec::with_capacity(32 + 64 + 64);
    buf.extend_from_slice(&ts);
    buf.push(3);
    buf.extend_from_slice(&rid.to_be_bytes());
    let bb = binary.as_bytes();
    let bl = bb.len().min(64) as u8;
    buf.push(bl);
    buf.extend_from_slice(&bb[..bl as usize]);
    let pb = path.as_bytes();
    let pl = pb.len().min(64) as u8;
    buf.push(pl);
    buf.extend_from_slice(&pb[..pl as usize]);
    buf
}

fn build_alert_bytes_rule(rid: u32, sev: u8, msg: &str) -> Vec<u8> {
    let ts = chrono::Utc::now()
        .timestamp_nanos_opt()
        .unwrap_or(0)
        .to_be_bytes();
    let mut buf = Vec::with_capacity(32 + 64);
    buf.extend_from_slice(&ts);
    buf.push(sev);
    buf.extend_from_slice(&rid.to_be_bytes());
    let mb = msg.as_bytes();
    let ml = mb.len().min(64) as u8;
    buf.push(ml);
    buf.extend_from_slice(&mb[..ml as usize]);
    buf
}

fn build_self_defense_alert(evt: &self_defense::SelfDefenseEvent) -> Vec<u8> {
    let ts = evt.timestamp.to_be_bytes();
    let mut buf = Vec::with_capacity(32 + 64);
    buf.extend_from_slice(&ts);
    buf.push(3);
    buf.extend_from_slice(&0u32.to_be_bytes());
    let msg = format!("self-defense: PID {} {}", evt.attacker_pid, evt.syscall);
    let mb = msg.as_bytes();
    let ml = mb.len().min(64) as u8;
    buf.push(ml);
    buf.extend_from_slice(&mb[..ml as usize]);
    buf
}

fn build_correlation_alert_bytes(alert: &correlation::CorrelationAlert) -> Vec<u8> {
    let ts = alert.timestamp.to_be_bytes();
    let mut buf = Vec::with_capacity(64);
    buf.extend_from_slice(&ts);
    buf.push(alert.severity);
    buf.extend_from_slice(&alert.pattern_id.to_be_bytes());
    let msg = format!(
        "[{}] {} — {}",
        alert.mitre_technique, alert.pattern_name, alert.description
    );
    let mb = msg.as_bytes();
    let ml = mb.len().min(128) as u8;
    buf.push(ml);
    buf.extend_from_slice(&mb[..ml as usize]);
    buf
}
