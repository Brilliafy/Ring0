use std::io::{Read, Write};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::Parser;
use colored::*;
use ring0_common::proto as capnp_schema;

const SOCKET_PATH: &str = "/run/ring0d.sock";

fn socket_path() -> String {
    std::env::var("RING0_SOCKET").unwrap_or_else(|_| SOCKET_PATH.to_string())
}

#[derive(Parser)]
#[command(name = "ring0ctl", about = "Ring0 desktop security CLI")]
enum Cli {
    Status,
    Block {
        ip: String,
    },
    Unblock {
        ip: String,
    },
    Kill {
        pid: u32,
    },
    Tail,
    Query {
        #[arg(long, default_value = "5")]
        last: u64,
        #[arg(long, default_value = "0")]
        severity: u8,
        #[arg(long)]
        json: bool,
    },
    Doctor,
    FlatpakList,
    PowerStatus,
}

fn main() -> Result<()> {
    // Restore default SIGPIPE so piping output into `head`/`less` terminates
    // silently instead of panicking ("failed printing to stdout: Broken pipe").
    // SAFETY: signal(2) with SIG_DFL is async-signal-safe and has no aliasing
    // concerns at process start (single-threaded at this point).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    match cli {
        Cli::Status => cmd_status(),
        Cli::Block { ip } => cmd_block(&ip),
        Cli::Unblock { ip } => cmd_unblock(&ip),
        Cli::Kill { pid } => cmd_kill(pid),
        Cli::Tail => cmd_tail(),
        Cli::Query {
            last,
            severity,
            json,
        } => cmd_query(last, severity, json),
        Cli::Doctor => cmd_doctor(),
        Cli::FlatpakList => cmd_flatpak_list(),
        Cli::PowerStatus => cmd_power_status(),
    }
}

fn connect_timeout() -> Result<std::os::unix::net::UnixStream> {
    use std::net::Shutdown;
    let (mut tx, rx) = std::os::unix::net::UnixStream::pair()
        .context("failed to create socket pair for connect timeout")?;
    let socket_path = socket_path();
    let path_for_thread = socket_path.clone();
    let handle = std::thread::spawn(move || {
        let stream = std::os::unix::net::UnixStream::connect(&path_for_thread);
        let _ = tx.write_all(&[0u8; 1]);
        stream
    });
    let mut buf = [0u8; 1];
    let mut rx_ref = &rx;
    rx_ref.set_read_timeout(Some(Duration::from_secs(5)))?;
    match rx_ref.read_exact(&mut buf) {
        Ok(()) => {}
        Err(e) => {
            let _ = rx.shutdown(Shutdown::Both);
            anyhow::bail!("connection to {socket_path} timed out: {e}");
        }
    }
    drop(rx);
    match handle.join() {
        Ok(Ok(stream)) => {
            stream.set_read_timeout(Some(Duration::from_secs(10)))?;
            stream.set_write_timeout(Some(Duration::from_secs(5)))?;
            Ok(stream)
        }
        Ok(Err(e)) => Err(e).context("connection failed"),
        Err(_) => anyhow::bail!("connection thread panicked"),
    }
}

fn send_command(frame: &[u8]) -> Result<Vec<u8>> {
    let mut stream = connect_timeout()?;
    let len = (frame.len() as u32).to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(frame)?;
    stream.flush()?;
    let mut len_buf = [0u8; 4];
    let mut reader = std::io::BufReader::new(&stream);
    reader
        .read_exact(&mut len_buf)
        .context("failed to read response length")?;
    let resp_len = u32::from_le_bytes(len_buf) as usize;
    if resp_len == 0 || resp_len > 65536 {
        return Ok(Vec::new());
    }
    let mut resp = vec![0u8; resp_len];
    reader
        .read_exact(&mut resp)
        .context("failed to read response body")?;
    Ok(resp)
}

/// Send a fire-and-forget command frame, then wait for the daemon's ack.
///
/// Privileged commands are gated by polkit in the daemon: the daemon answers
/// with an `OK`/`DENIED` frame once the authorization (and possible desktop
/// dialog) has completed. We must keep the connection — and therefore our
/// /proc/<pid> entry — alive until then, or the polkit subject lookup races
/// our exit and the first command is spuriously denied. A 5-minute read
/// timeout covers the user taking their time with the dialog; a timeout
/// degrades gracefully (the command may still have been applied).
fn send_command_no_response(frame: &[u8]) -> Result<()> {
    let mut stream = connect_timeout()?;
    stream.set_read_timeout(Some(Duration::from_secs(300)))?;
    let len = (frame.len() as u32).to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(frame)?;
    stream.flush()?;
    // The socket also carries the daemon's broadcast event stream, so the
    // first frame we read may be a broadcast, not our ack. Keep reading until
    // an OK/DENIED ack appears (bounded to avoid an endless drain).
    let mut len_buf = [0u8; 4];
    for _ in 0..100_000 {
        match stream.read_exact(&mut len_buf) {
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                return Ok(()); // no ack — older daemon or non-privileged cmd
            }
            Err(e) => return Err(e).context("failed to read command ack"),
        }
        let resp_len = u32::from_le_bytes(len_buf) as usize;
        if resp_len == 0 || resp_len > 65536 {
            return Ok(());
        }
        let mut resp = vec![0u8; resp_len];
        stream
            .read_exact(&mut resp)
            .context("failed to read command ack body")?;
        if resp == b"OK" {
            return Ok(());
        }
        if resp == b"DENIED" {
            bail!("denied by the daemon (polkit authorization failed)");
        }
        // Otherwise it was a broadcast event frame — skip and keep reading.
    }
    bail!("no command ack received (broadcast flood?)")
}

/// Send the Status command and wait for the daemon's status broadcast event.
fn send_status_command() -> Result<String> {
    let mut message = capnp::message::Builder::new_default();
    message
        .init_root::<capnp_schema::daemon_command::Builder>()
        .setStatus(());
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message)?;

    let mut stream = connect_timeout()?;
    let len = (buf.len() as u32).to_le_bytes();
    stream.write_all(&len)?;
    stream.write_all(&buf)?;
    stream.flush()?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;

    let mut reader = std::io::BufReader::new(&stream);
    // The daemon replies to Status with a broadcast status event; other events
    // may interleave, so skip frames until one parses as a DaemonStatus.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if std::time::Instant::now() >= deadline {
            anyhow::bail!("timed out waiting for daemon status");
        }
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).is_err() {
            anyhow::bail!("disconnected while waiting for daemon status");
        }
        let msg_len = u32::from_le_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65536 {
            anyhow::bail!("invalid status frame length: {msg_len}");
        }
        let mut msg_buf = vec![0u8; msg_len];
        if reader.read_exact(&mut msg_buf).is_err() {
            anyhow::bail!("disconnected while reading daemon status");
        }
        if let Some(status) = format_status_capnp(&msg_buf) {
            return Ok(status);
        }
    }
}

fn cmd_status() -> Result<()> {
    match send_status_command() {
        Ok(status) => {
            println!("{}", "Daemon: Connected".green().bold());
            println!("{status}");
        }
        Err(e) => {
            println!("{}", "Daemon: Disconnected".red().bold());
            eprintln!("{e:#}");
        }
    }
    Ok(())
}

fn cmd_block(ip: &str) -> Result<()> {
    let _: std::net::IpAddr = ip
        .parse()
        .with_context(|| format!("invalid IP address: {ip}"))?;
    let mut message = capnp::message::Builder::new_default();
    message
        .init_root::<capnp_schema::daemon_command::Builder>()
        .setBlockIp(ip);
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message)?;
    send_command_no_response(&buf)?;
    println!("{} {ip}", "Blocked:".red().bold());
    Ok(())
}

fn cmd_unblock(ip: &str) -> Result<()> {
    let _: std::net::IpAddr = ip
        .parse()
        .with_context(|| format!("invalid IP address: {ip}"))?;
    let mut message = capnp::message::Builder::new_default();
    message
        .init_root::<capnp_schema::daemon_command::Builder>()
        .setUnblockIp(ip);
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message)?;
    send_command_no_response(&buf)?;
    println!("{} {ip}", "Unblocked:".green().bold());
    Ok(())
}

fn cmd_kill(pid: u32) -> Result<()> {
    let mut message = capnp::message::Builder::new_default();
    message
        .init_root::<capnp_schema::daemon_command::Builder>()
        .setKillProcess(pid);
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message)?;
    send_command_no_response(&buf)?;
    println!("{} PID {pid}", "Killed:".red().bold());
    Ok(())
}

fn cmd_tail() -> Result<()> {
    let stream = connect_timeout()?;
    stream
        .set_read_timeout(None)
        .context("failed to set infinite read timeout")?;
    let mut reader = std::io::BufReader::new(&stream);
    let mut len_buf = [0u8; 4];
    let start = std::time::Instant::now();
    loop {
        if reader.read_exact(&mut len_buf).is_err() {
            break;
        }
        let msg_len = u32::from_le_bytes(len_buf) as usize;
        if msg_len == 0 || msg_len > 65536 {
            break;
        }
        let mut msg_buf = vec![0u8; msg_len];
        if reader.read_exact(&mut msg_buf).is_err() {
            break;
        }
        if let Ok(line) = format_event_capnp(&msg_buf) {
            print!(
                "[{}] ",
                format!("{:.1}s", start.elapsed().as_secs_f64()).dimmed()
            );
            println!("{line}");
        }
    }
    eprintln!("{}", "disconnected from ring0d".yellow());
    Ok(())
}

fn cmd_query(last_minutes: u64, severity: u8, json_flag: bool) -> Result<()> {
    let now = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u64;
    let start = now.saturating_sub(last_minutes * 60 * 1_000_000_000);
    let mut message = capnp::message::Builder::new_default();
    {
        let cmd = message.init_root::<capnp_schema::daemon_command::Builder>();
        let mut q = cmd.initQueryLogs();
        q.setStartTimestamp(start);
        q.setEndTimestamp(now);
        q.setSeverityThreshold(severity);
        q.setLimit(500);
    }
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message)?;
    let resp = send_command(&buf)?;
    let resp_mut = resp;
    let mut bytes = &resp_mut[..];
    let reader = capnp::serialize::read_message_from_flat_slice(
        &mut bytes,
        capnp::message::ReaderOptions::new(),
    )
    .context("failed to parse query response")?;
    let qr = reader
        .get_root::<capnp_schema::query_response::Reader>()
        .context("failed to get query response root")?;
    let alerts = qr.getAlerts().context("no alerts in response")?;
    let count = qr.getCount();
    if json_flag {
        let mut results = Vec::new();
        for alert in alerts.iter() {
            results.push(serde_json::json!({"timestamp": alert.getTimestamp(), "rule_id": alert.getRuleId(), "signature": alert.getSignatureName().map(|s| s.to_str().unwrap_or("").to_string()).unwrap_or_default()}));
        }
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({"count": count, "alerts": results}))?
        );
    } else {
        println!("{}", format!("Found {count} alerts:").bold());
        println!("{}", "─".repeat(80));
        for alert in alerts.iter() {
            println!(
                "  {}\t{}\t{}",
                format!("{:>8}", alert.getRuleId()).cyan(),
                format_severity(alert.getSeverity().unwrap_or(capnp_schema::Severity::Low)),
                alert
                    .getSignatureName()
                    .map(|s| s.to_str().unwrap_or("").to_string())
                    .unwrap_or_default()
                    .white()
            );
        }
    }
    Ok(())
}

fn cmd_doctor() -> Result<()> {
    println!("{}", "Ring0 Diagnostic Suite".bold().white());
    use std::fs;
    use std::path::Path;
    let checks: Vec<(&str, Box<dyn Fn() -> bool>)> = vec![
        (
            "Kernel >= 5.8",
            Box::new(|| {
                let k = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
                let mut parts = k.trim().split('.');
                let major = parts
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let minor = parts
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                (major, minor) >= (5, 8)
            }),
        ),
        (
            "BTF vmlinux",
            Box::new(|| Path::new("/sys/kernel/btf/vmlinux").exists()),
        ),
        (
            "Cgroup v2",
            Box::new(|| Path::new("/sys/fs/cgroup/cgroup.controllers").exists()),
        ),
        (
            "Daemon socket",
            Box::new(|| Path::new("/run/ring0d.sock").exists()),
        ),
    ];
    for check in &checks {
        let pass = (check.1)();
        print!("[..] {} ... ", check.0);
        if pass {
            println!("{}", "PASS".green().bold());
        } else {
            println!("{}", "FAIL".red().bold());
        }
    }
    println!("{}", "Done.".green().bold());
    Ok(())
}

fn cmd_flatpak_list() -> Result<()> {
    let mut message = capnp::message::Builder::new_default();
    message
        .init_root::<capnp_schema::daemon_command::Builder>()
        .setFlatpakList(());
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message)?;
    send_command_no_response(&buf)?;
    println!("{}", "Flatpak list requested".cyan().bold());
    Ok(())
}

fn cmd_power_status() -> Result<()> {
    let mut message = capnp::message::Builder::new_default();
    message
        .init_root::<capnp_schema::daemon_command::Builder>()
        .setPowerStatus(());
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message)?;
    send_command_no_response(&buf)?;
    println!("{}", "Power status requested".cyan().bold());
    Ok(())
}

fn format_event_capnp(data: &[u8]) -> Result<String> {
    let mut data_mut = data;
    let reader = capnp::serialize::read_message_from_flat_slice(
        &mut data_mut,
        capnp::message::ReaderOptions::new(),
    )
    .context("capnp parse failed")?;
    let event = reader
        .get_root::<capnp_schema::ring0_event::Reader>()
        .context("capnp root failed")?;
    use capnp_schema::ring0_event::Which;
    match event
        .which()
        .map_err(|e| anyhow::anyhow!("capnp which failed: {e}"))?
    {
        Which::Packet(pkt) => {
            let p = pkt.map_err(|e| anyhow::anyhow!("packet read failed: {e}"))?;
            let src = ip_to_string(p.getSrcIp().map_err(|e| anyhow::anyhow!("src_ip: {e}"))?);
            let dst = ip_to_string(p.getDstIp().map_err(|e| anyhow::anyhow!("dst_ip: {e}"))?);
            let proto_id = p.getProtocol().unwrap_or(capnp_schema::Protocol::Tcp);
            let proto = match proto_id {
                capnp_schema::Protocol::Tcp => "TCP".cyan(),
                capnp_schema::Protocol::Udp => "UDP".yellow(),
                capnp_schema::Protocol::Icmp => "ICMP".red(),
            };
            let act = p.getAction().unwrap_or(capnp_schema::Action::Pass);
            let action = match act {
                capnp_schema::Action::Drop => "DROP".red().bold(),
                capnp_schema::Action::Alert => "ALERT".yellow().bold(),
                _ => "PASS".green(),
            };
            Ok(format!(
                "{} {}:{} → {}:{}  {}  pid={}",
                action,
                src,
                p.getSrcPort(),
                dst,
                p.getDstPort(),
                proto,
                p.getPid()
            ))
        }
        Which::ProcessExec(e) => {
            let p = e.map_err(|e| anyhow::anyhow!("exec read failed: {e}"))?;
            let binary = p
                .getBinaryPath()
                .ok()
                .and_then(|s| s.to_str().ok().map(|s| s.to_string()))
                .unwrap_or_default();
            let cmdline = p
                .getCommandLine()
                .ok()
                .and_then(|s| s.to_str().ok().map(|s| s.to_string()))
                .unwrap_or_default();
            Ok(format!(
                "{} pid={} ppid={} {} {}",
                "EXEC".cyan().bold(),
                p.getPid(),
                p.getPpid(),
                binary,
                cmdline
            ))
        }
        Which::Connect(c) => {
            let p = c.map_err(|e| anyhow::anyhow!("connect read failed: {e}"))?;
            let binary = p
                .getBinaryPath()
                .ok()
                .and_then(|s| s.to_str().ok().map(|s| s.to_string()))
                .unwrap_or_default();
            let dst = ip_to_string(p.getDstIp().map_err(|e| anyhow::anyhow!("dst_ip: {e}"))?);
            Ok(format!(
                "{} pid={} {} → {}:{}",
                "CONNECT".blue().bold(),
                p.getPid(),
                binary,
                dst,
                p.getDstPort()
            ))
        }
        Which::Alert(a) => {
            let alert = a.map_err(|e| anyhow::anyhow!("alert read failed: {e}"))?;
            let sig = alert
                .getSignatureName()
                .map(|s| s.to_str().unwrap_or("").to_string())
                .unwrap_or_default();
            Ok(format!(
                "{} rule={} {}",
                "ALERT".red().bold(),
                alert.getRuleId(),
                sig.white()
            ))
        }
        _ => Ok("unknown event".into()),
    }
}

fn ip_to_string(ip: capnp_schema::ip_addr::Reader<'_>) -> String {
    use capnp_schema::ip_addr::Which;
    match ip.which() {
        Ok(Which::V4(v)) => std::net::Ipv4Addr::from(v).to_string(),
        _ => "::".into(),
    }
}

fn format_severity(s: capnp_schema::Severity) -> colored::ColoredString {
    match s {
        capnp_schema::Severity::Low => "LOW".green(),
        capnp_schema::Severity::Med => "MED".yellow(),
        capnp_schema::Severity::High => "HIGH".red(),
        capnp_schema::Severity::Critical => "CRITICAL".red().bold(),
    }
}

/// Parse a ring0 event frame as a DaemonStatus and format it for display.
/// Returns None if the frame is a different event type.
fn format_status_capnp(data: &[u8]) -> Option<String> {
    let mut data_mut = data;
    let reader = capnp::serialize::read_message_from_flat_slice(
        &mut data_mut,
        capnp::message::ReaderOptions::new(),
    )
    .ok()?;
    let event = reader
        .get_root::<capnp_schema::ring0_event::Reader>()
        .ok()?;
    let status = match event.which().ok()? {
        capnp_schema::ring0_event::Which::Status(st) => st.ok()?,
        _ => return None,
    };
    let filters: Vec<String> = status
        .getActiveFilters()
        .ok()?
        .iter()
        .map(|f| {
            f.ok()
                .and_then(|r| r.to_str().ok())
                .unwrap_or("")
                .to_string()
        })
        .collect();
    Some(format!(
        "  CPU: {:.1}%   RAM: {:.1} MiB   Events/s: {:.1}\n  Blocked domains: {}   CIDRs: {}   Ports: {}\n  Active filters: {}",
        status.getCpuUsagePercent(),
        status.getRamUsageBytes() as f64 / (1024.0 * 1024.0),
        status.getEventsPerSec(),
        status.getBlockedDomains(),
        status.getBlockedCidrs(),
        status.getBlockedPorts(),
        filters.join(", ")
    ))
}
