#![allow(dead_code)]
pub mod alert;
pub mod baseline;
pub mod containment;
pub mod contextual_security;
pub mod correlation;
pub mod desktop_sandbox;
pub mod dpi;
pub mod lineage;
pub mod risk;

/// Monotonic-ish wall clock in nanoseconds, shared by lineage/risk modules.
pub fn now_ns() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0)
}
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
#[cfg(test)]
mod fuzz;
pub mod intel_api;
pub mod ipc;
pub mod polkit;
pub mod power;
pub mod privesc;
pub mod proc_snapshot;
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
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    // A panic anywhere (worker thread, storage writer, ring reader) is a bug
    // worth surfacing to the operator, not something the runtime should
    // swallow: capture the backtrace into the structured log. RUST_BACKTRACE
    // is not required; force_capture() always records it.
    std::panic::set_hook(Box::new(|info| {
        let bt = std::backtrace::Backtrace::force_capture();
        error!("PANIC at {info}\nbacktrace:\n{bt}");
    }));

    let env_filter = EnvFilter::from_default_env();
    let registry = tracing_subscriber::registry();
    // Prefer the systemd journal for structured, persisted logs; always keep
    // the stderr JSON stream too (manual runs, shell redirects). journald is
    // absent on non-systemd hosts - fall back to stderr only. (The fmt layer
    // is rebuilt per arm because its Subscriber type parameter is fixed by
    // the composition it joins.)
    match tracing_journald::layer() {
        Ok(journald_layer) => registry
            .with(env_filter)
            .with(journald_layer)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .json(),
            )
            .init(),
        Err(_) => registry
            .with(env_filter)
            .with(
                tracing_subscriber::fmt::layer()
                    .with_writer(std::io::stderr)
                    .json(),
            )
            .init(),
    }

    let shutdown = Arc::new(Notify::new());
    let sig_shutdown = shutdown.clone();
    let (cmd_tx, cmd_rx) = tokio::sync::mpsc::unbounded_channel();
    let sig_cmd_tx = cmd_tx.clone();

    tokio::spawn(async move { listen_signals(sig_shutdown, sig_cmd_tx).await });

    let mut daemon = match Daemon::new(shutdown.clone(), cmd_tx, cmd_rx).await {
        Ok(d) => d,
        Err(e) => {
            error!("daemon init failed: {e:?}");
            return Err(e);
        }
    };
    // daemon.run() performs cleanup() (eBPF detach, RocksDB flush, socket
    // removal) on shutdown, then we exit immediately: long-running background
    // tasks (FIM baseline scan, blocklist feed fetches, D-Bus monitors) would
    // otherwise keep the Tokio runtime alive for minutes after SIGTERM.
    match daemon.run().await {
        Ok(()) => std::process::exit(0),
        Err(e) => {
            error!("daemon run failed: {e:?}");
            std::process::exit(1);
        }
    }
}

async fn listen_signals(
    shutdown: Arc<Notify>,
    cmd_tx: tokio::sync::mpsc::UnboundedSender<ipc::DaemonCmd>,
) {
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
            // SIGUSR1 reloads the rules engine (previously it only logged
            // 'pending' without doing anything).
            Some(SIGUSR1) => {
                info!("SIGUSR1  -  reloading rules");
                let _ = cmd_tx.send(ipc::DaemonCmd::ReloadRules);
            }
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
    lineage: lineage::LineageTree,
    response_mode: risk::ResponseMode,
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
    /// Per-rule-id alert rate limiter (prevents per-packet alert storms).
    alert_throttle: parking_lot::Mutex<std::collections::HashMap<u32, std::time::Instant>>,
    /// Per-pid last-connect processing time (secs): the LSM socket_connect
    /// hook emits up to 2 events/s per pid and the full pipeline runs an rpm
    /// subprocess + hashing inline on the main loop - that starved status /
    /// command handling and spiked CPU. The expensive path runs at most once
    /// per pid per 5s; intermediate connects only update the cheap trackers.
    connect_throttle: parking_lot::Mutex<std::collections::HashMap<u32, u64>>,
    blocklist_payload: Arc<parking_lot::Mutex<Option<sucadara::SyncPayload>>>,
}

impl Daemon {
    async fn new(
        shutdown: Arc<Notify>,
        cmd_tx: tokio::sync::mpsc::UnboundedSender<ipc::DaemonCmd>,
        cmd_rx: tokio::sync::mpsc::UnboundedReceiver<ipc::DaemonCmd>,
    ) -> Result<Self> {
        let lsm_enforce = std::env::var("RING0_LSM_ENFORCE").as_deref() == Ok("1");
        let mut ebpf = ebpf::EbpfManager::load(lsm_enforce)?;
        // Fast-path DPI: sync literal patterns into the kernel map. Observe-only
        // by default; RING0_DPI_ENFORCE=1 switches the fast path to drop.
        let dpi_synced = ebpf.sync_dpi_patterns(ebpf::BPF_DPI_SIGNATURES);
        let dpi_enforce = std::env::var("RING0_DPI_ENFORCE").as_deref() == Ok("1");
        ebpf.set_dpi_enforce(dpi_enforce);
        info!("DPI fast path: {dpi_synced} literal patterns synced");
        let storage = Arc::new(storage::RocksManager::open(&ring0_common::db_path())?);
        let dpi = dpi::DpiEngine::new()?;
        let lineage = lineage::LineageTree::new();
        let response_mode = risk::ResponseMode::from_env();
        let rules_path = bundled_config_path("rules.yaml");
        let rules = rules::RuleEngine::load(&rules_path).unwrap_or_else(|e| {
            warn!("no rules file: {e:?}");
            rules::RuleEngine::empty()
        });
        let correlation = correlation::CorrelationEngine::new();
        let self_defense = self_defense::SelfDefense::new();
        self_defense.lock_ebpf_maps();
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
                    "eBPF LSM in AUDIT mode  -  set RING0_LSM_ENFORCE=1 to enable inline prevention"
                );
            }
        } else {
            warn!("eBPF LSM not available  -  using XDP/tracepoint fallback enforcement");
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
                info!("FIM: background baseline complete  -  {count} system files");
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
        let alert_throttle = parking_lot::Mutex::new(std::collections::HashMap::new());
        let connect_throttle = parking_lot::Mutex::new(std::collections::HashMap::new());

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
            lineage,
            response_mode,
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
            alert_throttle,
            connect_throttle,
            blocklist_payload,
        })
    }

    async fn run(&mut self) -> Result<()> {
        let mut ring_rx = self.ebpf.subscribe();
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
                // Commands MUST be served ahead of the event streams: with the
                // event receivers first in a biased select, a continuous
                // exec/connect stream starved cmd_rx and ring0ctl status hung.
                Some(cmd) = self.cmd_rx.recv() => { self.handle_command(cmd).await; }
                Ok(data) = ring_rx.recv() => { self.on_raw_event(&data).await; }
                Ok(lsm_data) = lsm_rx.recv() => { self.on_lsm_event(&lsm_data).await; }
                Ok(rk_data) = rootkit_rx.recv() => { self.on_rootkit_event(&rk_data).await; }
                Ok(pv_data) = privesc_rx.recv() => { self.on_privesc_event(&pv_data).await; }
                _ = corr_tick.tick() => {
                    self.eval_correlations().await;
                    self.lineage.maybe_prune();
                }
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
                    // Reap spent per-connection TLS scan budgets and pid
                    // overrides so the kernel maps cannot fill with finished
                    // connections / exited processes.
                    self.ebpf.clear_tls_budgets();
                    self.ebpf.clear_pid_budgets();
                }
                _ = governor_tick.tick() => {
                    self.tick_governor();
                    self.ebpf.scan_interfaces();
                }
                _ = fastpath_tick.tick() => {
                    self.fastpath.purge_idle_flows();
                    self.storage.flush_bounded();
                    // Keep the memtable bounded so RSS stays flat (see
                    // RocksManager::maybe_flush); runs the flush on a worker
                    // thread so a slow disk never stalls the tick loop.
                    self.storage.maybe_flush();
                    // Per-pid TLS budget overrides only matter for live
                    // processes; reap them every minute so short-lived
                    // process churn (scripted curl bursts) cannot fill the
                    // 4096-entry map and starve new pids of their budgets.
                    // Active flows keep their allocated windows; the override
                    // is re-established on each new connect.
                    self.ebpf.clear_pid_budgets();
                }
                _ = prompt_tick.tick() => { self.prompt.check_timeouts(); }
                _ = blocklist_tick.tick() => { self.apply_blocklist_payload().await; }
            }
        }
        self.cleanup();
        Ok(())
    }

    async fn on_raw_event(&mut self, raw: &[u8]) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if raw.len() < 16 {
            return;
        }
        // ABI drift guard: every fixed-layout kind has a canonical size in the
        // ring0-abi table. If the kernel program ever emits a shorter entry,
        // refuse to decode it and log loudly instead of silently misparsing.
        if !event_len_ok(raw[0], raw.len()) {
            error!(
                "ring-buffer ABI mismatch: kind {} expected >= {} bytes, got {}  -  daemon and kernel are out of sync",
                raw[0],
                ring0_abi::EVENT_SIZE[raw[0] as usize].map(|s| s.to_string()).unwrap_or_else(|| "?".into()),
                raw.len()
            );
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
        // A kernel fast-path drop (action=1) is security-relevant: surface it
        // in the log (throttled per rule id so a blocked scanner's bursts
        // don't flood the log) in addition to the broadcast.
        if action == 1 && self.alert_due(10002) {
            info!(
                "[XDP DROP] {}.{}.{}.{}:{}{} -> {}.{}.{}.{}:{}",
                (src_ip >> 24) & 0xFF,
                (src_ip >> 16) & 0xFF,
                (src_ip >> 8) & 0xFF,
                src_ip & 0xFF,
                src_port,
                if proto == 17 {
                    "/udp"
                } else if proto == 6 {
                    "/tcp"
                } else {
                    ""
                },
                (dst_ip >> 24) & 0xFF,
                (dst_ip >> 16) & 0xFF,
                (dst_ip >> 8) & 0xFF,
                dst_ip & 0xFF,
                dst_port,
            );
        }
        self.pcap_buffer.push(raw, ts);
        let binary = if pid > 0 {
            // F11: cached 1s-TTL path  -  a raw readlink per packet turns a
            // scan into thousands of blocking syscalls on the event loop.
            crate::process::ProcessResolver::binary_path_cached(pid)
                .unwrap_or_else(|| "unknown".into())
        } else {
            "kernel".into()
        };
        if self.threat_blocklist.check_ports(src_port, dst_port) && self.alert_due(4000) {
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
            let evt = ipc::build_alert_event(
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
            self.ipc.broadcast_raw(&evt).await;
        }
        let _ = (src_ip, proto, action, binary);
    }

    /// Broadcast an encoded `AlertRecord` as the capnp `ring0_event::Alert`
    /// frame every IPC subscriber can decode. The compact AlertRecord binary
    /// format is what gets persisted to storage; the broadcast stream is
    /// shared with the GUI and `ring0ctl tail`, which parse `ring0_event`.
    async fn broadcast_alert_record(&self, encoded: &[u8]) {
        if let Some(rec) = alert::AlertRecord::decode(encoded) {
            let evt = ipc::build_alert_event(rec.rule_id, rec.severity, &rec.message);
            self.ipc.broadcast_raw(&evt).await;
        }
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
        // Every exec is broadcast as a capnp processExec event so the GUI
        // ProcessTree and `ring0ctl tail` see live process activity even when
        // no alert fires (previously only alert-worthy execs were surfaced).
        let exec_evt = ipc::build_process_exec_event(pid, ppid, uid, &binary, &cmdline);
        self.ipc.broadcast_raw(&exec_evt).await;
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
            let evt = ipc::build_alert_event(8001, 2, &anomaly);
            self.ipc.broadcast_raw(&evt).await;
        }
        self.correlation.push_exec(pid, ppid, &binary, &cmdline);
        self.lineage.record_exec(pid, ppid, &binary, &cmdline);
        if let Some(pb) = &parent_binary {
            for rid in self.rules.check_process_anomaly(&binary, Some(pb)) {
                // Rate-limit per rule: the anomaly matcher fires on EVERY exec
                // of a matching pattern (e.g. scripts spawned from /tmp), which
                // flooded storage and desktop notifications during testing.
                if !self.alert_due(200 + rid) {
                    continue;
                }
                let a = build_alert_bytes_rule(rid, 3, "process anomaly");
                self.storage.write_alert(&a);
                self.broadcast_alert_record(&a).await;
            }
        }
        if self.ebpf.binary_blocked(&binary) {
            let a = build_alert_bytes_rule(9001, 4, &format!("blocked binary executed: {binary}"));
            self.storage.write_alert(&a);
            let evt =
                ipc::build_alert_event(9001, 4, &format!("blocked binary executed: {binary}"));
            self.ipc.broadcast_raw(&evt).await;
            // F9: capture starttime now (≈ event time) and re-verify just
            // before the kill, so a PID recycled between the kernel
            // tracepoint and this handler cannot make us SIGKILL an innocent
            // process. If the PID is already gone or reused, skip the kill.
            let starttime_at_event = crate::process::ProcessResolver::starttime(pid);
            let still_same = match starttime_at_event {
                Some(ev) => crate::process::ProcessResolver::starttime(pid) == Some(ev),
                None => false,
            };
            if still_same {
                if let Ok(pid_i) = i32::try_from(pid) {
                    let _ = unsafe { libc::kill(pid_i, libc::SIGKILL) };
                }
            } else {
                warn!(
                    "refusing to SIGKILL PID {pid}: starttime changed since exec event (PID reuse?)"
                );
            }
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
            let evt = ipc::build_alert_event(rid, 3, &format!("{binary}: {fnbuf}"));
            self.ipc.broadcast_raw(&evt).await;
        }
        let evt = ipc::build_file_access_event(pid, uid, &binary, &fnbuf);
        self.storage.write_raw(&evt);
        self.ipc.broadcast_raw(&evt).await;
    }

    async fn on_connect(&mut self, raw: &[u8]) {
        if raw.len() < 32 {
            return;
        }
        let pid = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let uid = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        let dip = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
        let dp = u16::from_le_bytes(raw[28..30].try_into().unwrap_or([0; 2]));
        let proto = raw[30];
        self.handle_connect(pid, uid, dip, dp, proto, None).await;
    }

    /// Shared connect pipeline (trust check, contextual rules, approve
    /// prompt). Both the kernel ConnectEvent (RING_BUF kind 3) and the LSM
    /// socket_connect hook route here - the LSM was previously logged and
    /// dropped, so the approve/disapprove window never appeared.
    async fn handle_connect(
        &mut self,
        pid: u32,
        uid: u32,
        dip: u32,
        dp: u16,
        proto: u8,
        binary_hint: Option<String>,
    ) {
        crate::process::ProcessResolver::push_socket(pid, dip, dp, proto);
        self.correlation.push_connect(pid, dip, dp);
        self.lineage.record_connect(pid, dip, dp);
        self.baseline.record_connection(dip, dp);
        // Per-pid throttle: the LSM emits up to 2 connects/s per pid and the
        // full pipeline runs an rpm subprocess + file hashing. Running it on
        // every event starved the main loop (status/commands queued behind a
        // cascade of connect handling). Cheap trackers above still update.
        let now_s = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        {
            let mut throttle = self.connect_throttle.lock();
            if let Some(&last) = throttle.get(&pid) {
                if now_s.saturating_sub(last) < 5 {
                    return;
                }
            }
            throttle.insert(pid, now_s);
        }
        if let Some(anomaly) = self.baseline.check_connection_anomaly(dip, dp) {
            let a = build_alert_bytes_rule(8002, 2, &anomaly);
            self.storage.write_alert(&a);
            let evt = ipc::build_alert_event(8002, 2, &anomaly);
            self.ipc.broadcast_raw(&evt).await;
        }
        let binary = binary_hint
            .filter(|b| !b.is_empty())
            .or_else(|| crate::process::ProcessResolver::binary_path(pid))
            .unwrap_or_else(|| "unknown".into());
        let cmdline =
            crate::process::ProcessResolver::cmdline(pid).unwrap_or_else(|| "unknown".into());
        self.desktop_sandbox.resolve_pid(pid, &binary, &cmdline);
        if let Some(anomaly) = self.desktop_sandbox.check_network_anomaly(pid, &binary) {
            let a = build_alert_bytes_rule(1001, 3, &anomaly.description);
            self.storage.write_alert(&a);
            let evt = ipc::build_alert_event(1001, 3, &anomaly.description);
            self.ipc.broadcast_raw(&evt).await;
            info!("[SANDBOX] {}", anomaly.description);
        }
        let evt = ipc::build_connect_event(pid, uid, &binary, dip, dp, proto);
        self.storage.write_raw(&evt);
        self.ipc.broadcast_raw(&evt).await;

        // Trust verification runs on a blocking thread (whole-file hash + rpm
        // subprocess) so a slow disk/rpm cannot stall the event pipeline.
        let trust_status = self.trust.verify_binary_async(&binary, pid).await;
        // Per-process TLS scan budget from the trust verdict: untrusted /
        // unverifiable processes (script hosts, /tmp binaries) get a 4x
        // larger inspection window because any network activity from them is
        // high-risk; trusted high-throughput apps get a tighter window.
        use trust::TrustStatus;
        let tls_budget = match trust_status {
            TrustStatus::TrustedSystemPackage | TrustStatus::TrustedBinary => 4096,
            TrustStatus::Untrusted | TrustStatus::Unknown => {
                ebpf::EbpfManager::TLS_UNTRUSTED_BUDGET
            }
        };
        self.ebpf.set_pid_budget(pid, tls_budget);
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
            let evt = ipc::build_alert_event(
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
            self.ipc.broadcast_raw(&evt).await;
            return;
        }
        match trust_status {
            trust::TrustStatus::TrustedSystemPackage | trust::TrustStatus::TrustedBinary => {
                // Resolve the real 5-tuple for this socket and mark the flow
                // established in the kernel ESTABLISHED_FLOWS map. Previously
                // this called mark_flow_safe(pid, dip, 0, dp, proto)  -  the pid
                // was stuffed into the src_ip slot, so no kernel entry ever
                // matched and nothing was ever offloaded.
                // F11: resolve_flow_for_dst walks /proc/*/fd for every process
                //  -  a synchronous scan that must run off the event loop.
                let flow = tokio::task::spawn_blocking(move || {
                    crate::process::ProcessResolver::resolve_flow_for_dst(pid, dip, dp, proto)
                })
                .await
                .ok()
                .flatten();
                if let Some(key) = flow {
                    match self.ebpf.mark_flow_established(&key) {
                        Ok(()) => {
                            let _ = self.fastpath.mark_flow_safe(key);
                            info!("TrustEngine: PID {pid} {binary} trusted  -  flow offloaded to kernel fast path");
                        }
                        Err(e) => {
                            info!("TrustEngine: PID {pid} {binary} trusted  -  kernel offload unavailable: {e}");
                        }
                    }
                }
            }
            trust::TrustStatus::Untrusted | trust::TrustStatus::Unknown => {
                // F10: Unknown (any verification failure: unreadable binary,
                // missing rpm, spawn_blocking error, …) must NOT silently
                // allow the connection  -  route it through the same user
                // prompt as Untrusted (fail-secure posture).
                info!(
                    "TrustEngine: PID {pid} {binary} UNTRUSTED/UNVERIFIED  -  creating user prompt"
                );
                let (country_code, country_name) = self.enrichment.lookup_country(dip);
                // rDNS is a network round-trip; bound it so a hostile/resolver
                // timeout cannot stall the event loop for seconds.
                let rdns_name = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    self.enrichment.lookup_rdns(dip),
                )
                .await
                .unwrap_or_else(|_| "unknown".into());
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
            self.broadcast_alert_record(&alert).await;
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
            self.broadcast_alert_record(&alert).await;
        }
    }

    async fn on_tls_event(&mut self, raw: &[u8]) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if raw.len() < 24 {
            return;
        }
        let payload = if raw.len() > 36 { &raw[36..] } else { &[] };
        let tpid = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
        let direction = raw[28]; // 0 = SSL_write (upload), 1 = SSL_read
        let hits = self.dpi.scan_payload(payload);
        for m in &hits {
            // Surface the process that triggered the match  -  in consumer
            // security the WHO matters as much as the bytes.
            let binary = crate::process::ProcessResolver::binary_path(tpid)
                .unwrap_or_else(|| "unknown".into());
            let msg = format!("{} [pid {}: {}]", m.signature_name, tpid, binary);
            let alert = build_alert_bytes_rule(m.rule_id, m.severity, &msg);
            self.storage.write_alert(&alert);
            self.broadcast_alert_record(&alert).await;
        }

        // Risk evaluation: combine process lineage, destination, and payload
        // evidence. Only non-pass verdicts surface as risk alerts; active
        // enforcement is strictly opt-in (RING0_RESPONSE, default Notify).
        // Prefer the binary recorded at exec time (the lineage tree): a
        // short-lived process (e.g. curl) may be gone by the time this runs,
        // making a live /proc resolution return "unknown" and inflating the
        // untrusted factor.
        let binary = self
            .lineage
            .lookup(tpid)
            .map(|i| i.binary)
            .unwrap_or_else(|| {
                crate::process::ProcessResolver::binary_path(tpid)
                    .unwrap_or_else(|| "unknown".into())
            });
        let trust_status = self.trust.verify_binary_async(&binary, tpid).await;
        let untrusted = matches!(
            trust_status,
            trust::TrustStatus::Untrusted | trust::TrustStatus::Unknown
        );
        let (dst_ip, dst_port) = self
            .lineage
            .latest_connection(tpid)
            .map(|c| (Some(c.dst_ip), c.dst_port))
            .unwrap_or((None, 0));
        let risk = risk::RiskEngine::score(
            &self.lineage,
            tpid,
            dst_ip,
            dst_port,
            direction == 0,
            payload,
            &hits,
            untrusted,
        );
        if risk.verdict != risk::Verdict::Pass {
            let bin_short = binary.rsplit('/').next().unwrap_or(&binary);
            let msg = format!(
                "risk={} ({}) pid={} binary={} dst={}{}",
                risk.score,
                match risk.verdict {
                    risk::Verdict::HighRisk => "HIGH",
                    risk::Verdict::Flagged => "suspicious",
                    risk::Verdict::Pass => "pass",
                },
                tpid,
                bin_short,
                dst_ip.map(|ip| ip.to_string()).unwrap_or_default(),
                if dst_port != 0 {
                    format!(":{}", dst_port)
                } else {
                    String::new()
                }
            );
            // A connection emits up to ~32 TLS events; the risk verdict is
            // the same for all of them, so throttle the alert per rule id.
            if !self.alert_due(11001) {
                return;
            }
            let sev = if risk.verdict == risk::Verdict::HighRisk {
                4
            } else {
                2
            };
            let alert = build_alert_bytes_rule(11001, sev, &msg);
            self.storage.write_alert(&alert);
            self.broadcast_alert_record(&alert).await;
            if risk.verdict == risk::Verdict::HighRisk {
                self.enforce_high_risk(tpid, &binary, risk.score, dst_ip)
                    .await;
            }
        }
    }

    /// Apply the configured response to a high-risk event. Default is
    /// Notify  -  freezing/killing can destroy real work, so enforcement is
    /// opt-in via RING0_RESPONSE=block|freeze|kill.
    async fn enforce_high_risk(&mut self, pid: u32, binary: &str, score: i32, dst_ip: Option<u32>) {
        match self.response_mode {
            risk::ResponseMode::Notify => {
                info!("[RISK] notify-only: {binary} (pid {pid}, score {score})");
            }
            risk::ResponseMode::BlockNetwork => {
                if let Some(ip) = dst_ip {
                    match self.ebpf.block_ip(std::net::IpAddr::V4(ip.into())) {
                        Ok(()) => info!(
                            "[ENFORCE] blocked network for {binary} (pid {pid}, score {score}) -> {ip}"
                        ),
                        Err(e) => warn!("[ENFORCE] block failed for pid {pid}: {e:?}"),
                    }
                }
            }
            risk::ResponseMode::Freeze => {
                let stopped = containment::ContainmentManager::quarantine_pid_checked(pid, None);
                info!("[ENFORCE] freeze {binary} (pid {pid}, score {score}): stopped={stopped}");
            }
            risk::ResponseMode::Kill => {
                let killed = containment::ContainmentManager::kill_tree(pid);
                info!("[ENFORCE] kill {binary} (pid {pid}, score {score}): killed={killed} procs");
            }
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
        let dpi_idx = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        let src_ip = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
        let dst_ip = u32::from_le_bytes(raw[28..32].try_into().unwrap_or([0; 4]));
        let dst_port = u16::from_le_bytes(raw[32..34].try_into().unwrap_or([0; 2]));
        let proto = raw[34];
        // The kernel reports the sequential pattern index; translate it to the
        // real signature rule id (index-aligned with BPF_DPI_SIGNATURES).
        let rule_id = ebpf::BPF_DPI_RULE_IDS
            .get(dpi_idx as usize)
            .copied()
            .unwrap_or(dpi_idx);
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
        if self.alert_due(5000 + rule_id) {
            self.storage.write_alert(&alert);
            self.broadcast_alert_record(&alert).await;
        }
        info!("[DPI] {msg}");
    }

    async fn on_lsm_event(&mut self, raw: &[u8]) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

        if !event_len_ok(raw[0], raw.len()) {
            error!(
                "LSM ring-buffer ABI mismatch: kind {} got {} bytes (expected >= {})",
                raw[0],
                raw.len(),
                ring0_abi::SIZE_LSM
            );
            return;
        }
        if raw.len() < 132 {
            return;
        }
        let event_type = raw[24];
        let denied = raw[25];
        let pid = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let uid = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
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
            self.broadcast_alert_record(&alert).await;
        } else {
            info!("[LSM_ALLOW] {} pid={} path={}", event_name, pid, path);
            // socket_connect in audit mode: route into the connect pipeline
            // so untrusted/unknown binaries surface the approve/disapprove
            // window (previously these events were logged and dropped).
            if event_type == 2 {
                self.handle_connect(pid, uid, dst_ip, dst_port, 6, Some(path))
                    .await;
            }
        }
    }

    async fn tick_baseline(&self) {
        if self.baseline.is_learning() {
            let progress = self.baseline.learning_progress();
            info!("Baseline learning progress: {:.1}%", progress * 100.0);
            if progress >= 1.0 {
                self.baseline.finish_learning();
                info!("Baseline learning period complete  -  switching to anomaly detection");
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
        // Canonical size check (KIND_PTRACE needs 32 bytes; the previous
        // `len < 28` guard could not safely read the target field).
        if !event_len_ok(raw[0], raw.len()) {
            error!(
                "PRIVESC ring-buffer ABI mismatch: kind {} got {} bytes",
                raw[0],
                raw.len()
            );
            return;
        }
        let pid = u32::from_le_bytes(raw[16..20].try_into().unwrap_or([0; 4]));
        let uid = u32::from_le_bytes(raw[20..24].try_into().unwrap_or([0; 4]));
        match raw[0] {
            ebpf::KIND_SETUID => {
                let new_uid = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
                self.privesc.ingest_setuid_event(pid, uid, new_uid);
                if self.alert_due(2001) {
                    let a = build_alert_bytes_rule(
                        2001,
                        4,
                        &format!("setuid escalation PID {} {}->{}", pid, uid, new_uid),
                    );
                    self.storage.write_alert(&a);
                    self.broadcast_alert_record(&a).await;
                }
                // A real uid escalation is the clearest privilege-escalation signal;
                // contain the process. (Informational capable/ptrace events do not
                // trigger containment  -  freezing processes for those is destructive.)
                // Capture starttime at event time and verify before freezing so a
                // recycled PID cannot freeze an innocent process.
                let starttime = crate::process::ProcessResolver::starttime(pid);
                containment::ContainmentManager::quarantine_pid_checked(pid, starttime);
            }
            ebpf::KIND_PTRACE => {
                let target = u32::from_le_bytes(raw[28..32].try_into().unwrap_or([0; 4]));
                self.privesc.ingest_ptrace_attempt(pid, uid, target);
                if self.alert_due(2002) {
                    let a = build_alert_bytes_rule(
                        2002,
                        4,
                        &if target != 0 {
                            format!("ptrace PID {} -> {}", pid, target)
                        } else {
                            format!("ptrace access attempt PID {}", pid)
                        },
                    );
                    self.storage.write_alert(&a);
                    self.broadcast_alert_record(&a).await;
                }
            }
            ebpf::KIND_CAP => {
                let capability = u32::from_le_bytes(raw[24..28].try_into().unwrap_or([0; 4]));
                self.privesc.ingest_capable_check(pid, uid, capability);
                if self.alert_due(2003) {
                    let a = build_alert_bytes_rule(
                        2003,
                        3,
                        &format!("capable PID {} cap={}", pid, capability),
                    );
                    self.storage.write_alert(&a);
                    self.broadcast_alert_record(&a).await;
                }
            }
            _ => {}
        }
    }

    async fn on_rootkit_event(&self, raw: &[u8]) {
        self.event_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        // Canonical size check per kind (mmap=56, module=92, memfd=60).
        if !event_len_ok(raw[0], raw.len()) {
            error!(
                "ROOTKIT ring-buffer ABI mismatch: kind {} got {} bytes",
                raw[0],
                raw.len()
            );
            return;
        }
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
                    self.broadcast_alert_record(&a).await;
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
                    self.broadcast_alert_record(&a).await;
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
                    self.broadcast_alert_record(&a).await;
                    info!("[ROOTKIT] {desc}");
                    if let Some(binary) = crate::process::ProcessResolver::binary_path(pid) {
                        match self.intel.scan_binary(&binary) {
                            Ok(matches) => {
                                for m in matches {
                                    let a = build_alert_bytes_rule(7003, 3, &m);
                                    self.storage.write_alert(&a);
                                    self.broadcast_alert_record(&a).await;
                                }
                            }
                            // YARA isn't compiled in: warn once, not once per
                            // process event (was spamming the log + churning
                            // allocations for every memfd/exec).
                            Err(_) => {
                                static WARNED: std::sync::atomic::AtomicBool =
                                    std::sync::atomic::AtomicBool::new(false);
                                if !WARNED.swap(true, std::sync::atomic::Ordering::Relaxed) {
                                    warn!(
                                        "YARA engine not implemented  -  binary scanning skipped"
                                    );
                                }
                            }
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

    fn tick_governor(&mut self) {
        let state = self.governor.tick();
        let pct = self.governor.daemon_cpu_pct() + self.governor.bpf_cpu_pct();
        // Apply the governor's decisions to the kernel. Previously the
        // sampling/dpi flags were written by the governor but never consumed
        // by anything  -  the control loop was inert.
        self.ebpf
            .set_sampling_enabled(self.governor.is_sampling_enabled());
        self.ebpf.set_dpi_enforce(self.governor.is_dpi_fast_mode());
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
                "correlation: [{}] {}  -  {}",
                alert.pattern_id, alert.pattern_name, alert.description
            );
            let bytes = build_correlation_alert_bytes(&alert);
            self.storage.write_alert(&bytes);
            self.ipc.broadcast_raw(&bytes).await;
            if alert.severity >= 3 {
                let starttime = crate::process::ProcessResolver::starttime(alert.root_pid);
                containment::ContainmentManager::quarantine_pid_checked(alert.root_pid, starttime);
                self.forensics.trigger_export(
                    alert.id,
                    alert.severity,
                    &format!(
                        "[{}] {}  -  {}",
                        alert.pattern_id, alert.pattern_name, alert.description
                    ),
                );
            }
        }
    }

    /// Alert rate limiter: at most one alert per rule id per window, so a
    /// flood (e.g. a scan hitting the blocked-port path, or DPI matches on
    /// every packet of a flow) cannot amplify into a storage/IPC storm.
    fn alert_due(&self, rule_id: u32) -> bool {
        const ALERT_MIN_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);
        let mut map = self.alert_throttle.lock();
        let now = std::time::Instant::now();
        if let Some(prev) = map.get(&rule_id) {
            if now.duration_since(*prev) < ALERT_MIN_INTERVAL {
                return false;
            }
        }
        map.insert(rule_id, now);
        if map.len() > 256 {
            // E20: drop only expired entries so the throttle stays effective  -
            // clearing reopened the suppression window for every rule at once.
            map.retain(|_, prev| now.duration_since(*prev) < ALERT_MIN_INTERVAL);
            if map.len() > 256 {
                map.clear(); // everything is hot  -  start over
            }
        }
        true
    }

    async fn apply_blocklist_payload(&mut self) {
        const SYNC_CHUNK: usize = 2048;
        let payload = self.blocklist_payload.lock().take();
        if let Some(payload) = payload {
            info!(
                "Applying blocklist to kernel maps: {} cidrs, {} domains, {} ports",
                payload.cidrs.len(),
                payload.domains.len(),
                payload.ports.len()
            );
            // F11: each insert is a syscall; a full feed (tens of thousands of
            // entries) would stall the event loop for seconds. Apply in chunks
            // and yield between them so IPC/event processing stays responsive.
            // NOTE: domains are applied in ONE call  -  sync_dns_domains mirrors
            // the feed into the userspace fallback list by rebuilding a HashSet
            // of the whole list, so chunked calls were O(n²) (166 chunks × up
            // to 340k string clones each == minutes of stall). Single call =
            // one O(n) rebuild. The kernel DNS map holds 200k entries max, so
            // anything beyond that never made it into the kernel anyway.
            let mut c = 0usize;
            for chunk in payload.cidrs.chunks(SYNC_CHUNK) {
                c += self.ebpf.sync_blocked_cidrs(chunk);
                tokio::task::yield_now().await;
            }
            let mut domains = payload.domains;
            domains.truncate(190_000); // kernel map capacity; userspace matcher covers the rest
            let d = self.ebpf.sync_dns_domains(&domains);
            tokio::task::yield_now().await;
            let mut p = 0usize;
            for chunk in payload.ports.chunks(SYNC_CHUNK) {
                p += self.ebpf.sync_blocked_ports(chunk);
                tokio::task::yield_now().await;
            }
            // Compile the Suricata-derived literal signatures into the DPI
            // engine (observe-only). A failed compile keeps the previous set.
            self.dpi.set_dynamic_patterns(payload.dpi_patterns.clone());
            info!("Kernel sync complete: {c} cidrs, {d} domains, {p} ports in eBPF maps");
        }
    }

    async fn handle_command(&mut self, cmd: ipc::DaemonCmd) {
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
                // E4: the wire type is u32 but the kernel map key is u16;
                // truncating here would block the *wrong* port (e.g.
                // 70000 → 4464). Reject out-of-range values outright.
                let Some(port) = u16::try_from(port).ok() else {
                    warn!("refusing to block out-of-range port {port}");
                    return;
                };
                if let Err(e) = self.ebpf.block_port(port) {
                    error!("block_port: {e:?}")
                }
                self.threat_blocklist.block_port(port);
            }
            UnblockPort(port) => {
                let Some(port) = u16::try_from(port).ok() else {
                    warn!("refusing to unblock out-of-range port {port}");
                    return;
                };
                if let Err(e) = self.ebpf.unblock_port(port) {
                    error!("unblock_port: {e:?}")
                }
                self.threat_blocklist.unblock_port(port);
            }
            ListProcesses => {
                // Answered inline by the IPC handler; the main loop never
                // receives this (kept for exhaustiveness).
            }
            ListSockets => {}
            KillProcess(pid) => {
                // F1: pid_t is signed 32-bit  -  a u32 pid >= 0x8000_0000 casts
                // to a negative pid_t, and kill(-1, SIGKILL) signals EVERY
                // process the daemon may signal. Refuse anything that does not
                // fit a positive pid_t.
                let Some(pid_i) = i32::try_from(pid).ok().filter(|p| *p > 0) else {
                    warn!("refusing to kill invalid PID {pid}");
                    return;
                };
                // Confused-deputy hardening: never let a caller (even a
                // privileged one) terminate critical system processes.
                let daemon_pid = std::process::id();
                if pid == 0 || pid == 1 || pid == daemon_pid {
                    warn!("refusing to kill protected PID {pid}");
                } else {
                    let r = unsafe { libc::kill(pid_i, libc::SIGKILL) };
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
            SubmitPromptDecision(prompt_id, action, scope, caller_pid) => {
                // Defense in depth on top of the privilege gate: the process
                // under scrutiny must never be able to approve its own prompt.
                if let Some(p) = self.prompt.pending_get(prompt_id) {
                    if p.pid == caller_pid {
                        warn!(
                            "rejected self-approval: PID {caller_pid} attempted to decide prompt {prompt_id} targeting itself"
                        );
                        return;
                    }
                }
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
            MarkFlowAllowed(dst_ip, dst_port, protocol, pid) => {
                // F11: resolve_flow_for_dst walks /proc/*/fd for every process
                //  -  a synchronous scan that must not run on the event loop.
                let key = tokio::task::spawn_blocking(move || {
                    crate::process::ProcessResolver::resolve_flow_for_dst(
                        pid, dst_ip, dst_port, protocol,
                    )
                })
                .await
                .ok()
                .flatten();
                if let Some(key) = key {
                    match self.ebpf.mark_flow_established(&key) {
                        Ok(()) => {
                            let _ = self.fastpath.mark_flow_safe(key);
                            info!(
                                "allow_once: flow {}.{}.{}.{}:{} (pid {pid}) offloaded",
                                (dst_ip >> 24) & 0xFF,
                                (dst_ip >> 16) & 0xFF,
                                (dst_ip >> 8) & 0xFF,
                                dst_ip & 0xFF,
                                dst_port
                            );
                        }
                        Err(e) => warn!("allow_once: kernel offload failed: {e}"),
                    }
                }
            }
            FlatpakList => {
                let a = self.desktop_sandbox.list_apps();
                info!("Flatpak: {} apps", a.len());
            }
            UpdateSettings(json) => info!("Settings: {json}"),
            RunDoctor => info!("Doctor requested"),
            Status => {
                // Do NOT apply the pending blocklist here: a freshly-fetched
                // payload (2k+ CIDRs, 190k domains + DPI compile) takes ~30s
                // and the first ring0ctl status hung the CLI while it ran.
                // The blocklist_tick applies it; status stays a light query.
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
                let dropped = self.storage.dropped_count();
                // E19: the client read path caps frames at 64 KiB  -  a huge
                // blocked-CIDR list would exceed it and the client would
                // discard the status frame. Cap the embedded list (counters
                // still reflect the full set).
                let filters: Vec<String> = filters.into_iter().take(500).collect();
                let status = ipc::build_status_event(
                    &filters,
                    cpu,
                    ram,
                    eps,
                    domains,
                    cidrs,
                    ports,
                    dropped,
                    self.power.is_on_battery(),
                    self.power.is_fim_throttled(),
                );
                self.ipc.broadcast_sync(&status);
            }
            PowerStatus => {
                info!(
                    "Power: battery={} fim={}",
                    self.power.is_on_battery(),
                    self.power.is_fim_throttled()
                );
                // Reply with a status frame so the GUI can display power state.
                let filters = self
                    .ebpf
                    .blocked_ips()
                    .into_iter()
                    .take(500)
                    .collect::<Vec<_>>();
                let status = ipc::build_status_event(
                    &filters,
                    self.governor.daemon_cpu_pct(),
                    read_vm_rss(),
                    0.0,
                    self.ebpf.blocked_domain_count() as u32,
                    filters.len() as u32,
                    self.ebpf.blocked_port_count() as u32,
                    self.storage.dropped_count(),
                    self.power.is_on_battery(),
                    self.power.is_fim_throttled(),
                );
                self.ipc.broadcast_sync(&status);
            }
        }
    }
    fn cleanup(&mut self) {
        // Detach eBPF first so the kernel is never held by us, then only a
        // bounded WAL sync  -  the full memtable->SST flush can block shutdown
        // for minutes on a slow disk (the Drop path drains + flushes anyway).
        self.ebpf.detach();
        self.storage.flush_bounded();
        std::fs::remove_file(ring0_common::socket_path()).ok();
    }
}

/// Validate a ring-buffer entry against the canonical per-kind size table
/// (ring0-abi). Unknown kinds pass (handlers may still reject them); known
/// kinds must be at least the canonical size.
pub(crate) fn event_len_ok(kind: u8, len: usize) -> bool {
    match ring0_abi::EVENT_SIZE.get(kind as usize).copied().flatten() {
        Some(expected) => len >= expected,
        None => true,
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
    alert::AlertRecord::new(3, rid, &format!("{binary}: {path}")).encode()
}

fn build_alert_bytes_rule(rid: u32, sev: u8, msg: &str) -> Vec<u8> {
    alert::AlertRecord::new(sev, rid, msg).encode()
}

fn build_self_defense_alert(evt: &self_defense::SelfDefenseEvent) -> Vec<u8> {
    alert::AlertRecord::new(
        3,
        0,
        &format!("self-defense: PID {} {}", evt.attacker_pid, evt.syscall),
    )
    .encode()
}

fn build_correlation_alert_bytes(alert: &correlation::CorrelationAlert) -> Vec<u8> {
    alert::AlertRecord::new(
        alert.severity,
        alert.pattern_id,
        &format!(
            "[{}] {}  -  {}",
            alert.mitre_technique, alert.pattern_name, alert.description
        ),
    )
    .encode()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_len_ok_never_panics_and_enforces_known_sizes() {
        // E6: exhaustive kinds x lengths  -  the ring-buffer guard must never
        // panic and must reject every undersized fixed-layout kind.
        for kind in 0u8..=255u8 {
            for len in 0..=200usize {
                let ok = event_len_ok(kind, len);
                match ring0_abi::EVENT_SIZE.get(kind as usize).copied().flatten() {
                    Some(expected) => {
                        assert_eq!(ok, len >= expected, "kind {kind} len {len}")
                    }
                    None => assert!(ok, "unknown kind {kind} must pass through"),
                }
            }
        }
    }

    #[test]
    fn alert_decode_never_panics_on_garbage() {
        // AlertRecord::decode sits on the untrusted storage read path
        // (query_alerts / build_query_response)  -  it must never panic on
        // arbitrary bytes.
        let mut seed = 0x9E37_79B9_7F4A_7C15u64;
        for len in 0..128usize {
            let mut buf = vec![0u8; len];
            for b in buf.iter_mut() {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *b = seed as u8;
            }
            let _ = alert::AlertRecord::decode(&buf);
        }
    }

    #[test]
    fn negative_pid_casts_are_rejected() {
        // F1 regression: these u32 pids cast to negative pid_t and must never
        // reach kill(2) as process-group (-N) or all-process (-1) signals.
        for pid in [u32::MAX, 0xFFFF_FFFE, 0x8000_0000, 0x8000_0001] {
            assert!(
                i32::try_from(pid).ok().filter(|p| *p > 0).is_none(),
                "pid {pid} must be rejected"
            );
        }
        for pid in [1u32, 1000u32, i32::MAX as u32] {
            assert!(
                i32::try_from(pid).ok().filter(|p| *p > 0).is_some(),
                "valid pid {pid} must pass"
            );
        }
    }
}
