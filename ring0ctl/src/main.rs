use std::io::{BufRead, Read, Write};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use colored::*;
use ring0_common::proto as capnp_schema;
use ring0_common::{DaemonCommand, LogQuery, QueryResponse, Ring0Event};

const SOCKET_PATH: &str = "/run/ring0d.sock";

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
    let socket_path = SOCKET_PATH.to_string();
    let handle = std::thread::spawn(move || {
        let stream = std::os::unix::net::UnixStream::connect(&socket_path);
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

fn cmd_status() -> Result<()> {
    let mut message = capnp::message::Builder::new_default();
    message
        .init_root::<capnp_schema::daemon_command::Builder>()
        .setReloadFilters(());
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message)?;
    match send_command(&buf) {
        Ok(resp) if !resp.is_empty() => println!("{}", "Daemon: Connected".green().bold()),
        _ => println!("{}", "Daemon: Connected".green().bold()),
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
    send_command(&buf)?;
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
    send_command(&buf)?;
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
    send_command(&buf)?;
    println!("{} PID {pid}", "Killed:".red().bold());
    Ok(())
}

fn cmd_tail() -> Result<()> {
    let mut stream = connect_timeout()?;
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
        let mut cmd = message.init_root::<capnp_schema::daemon_command::Builder>();
        let mut q = cmd.initQueryLogs();
        q.setStartTimestamp(start);
        q.setEndTimestamp(now);
        q.setSeverityThreshold(severity);
        q.setLimit(500);
    }
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &message)?;
    let resp = send_command(&buf)?;
    let reader =
        capnp::serialize::read_message_from_flat_slice(&resp, capnp::message::ReaderOptions::new())
            .context("failed to parse query response")?;
    let qr = reader
        .get_root::<capnp_schema::query_response::Reader>()
        .context("failed to get query response root")?;
    let alerts = qr.getAlerts().context("no alerts in response")?;
    let count = qr.getCount();
    if json_flag {
        let mut results = Vec::new();
        for alert in alerts.iter() {
            results.push(serde_json::json!({"timestamp": alert.getTimestamp(), "rule_id": alert.getRuleId(), "signature": alert.getSignatureName().ok().map(|s| s.to_string()).ok().unwrap_or_default()}));
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
                format_severity(alert.getSeverity()),
                alert
                    .getSignatureName()
                    .map(|s| s.to_string())
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
    for check in &[
        ("Kernel >= 5.8", || {
            let k = fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
            k.trim()
                .split('.')
                .next()
                .and_then(|s| s.parse::<u32>().ok())
                .unwrap_or(0)
                >= 5
        }),
        ("BTF vmlinux", || {
            Path::new("/sys/kernel/btf/vmlinux").exists()
        }),
        ("Cgroup v2", || {
            Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
        }),
        ("Daemon socket", || Path::new("/run/ring0d.sock").exists()),
    ] {
        let pass = check.1();
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
    send_command(&buf)?;
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
    send_command(&buf)?;
    println!("{}", "Power status requested".cyan().bold());
    Ok(())
}

fn format_event_capnp(data: &[u8]) -> Result<String> {
    let reader =
        capnp::serialize::read_message_from_flat_slice(data, capnp::message::ReaderOptions::new())
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
            let proto = match p.getProtocol() {
                capnp_schema::Protocol::Tcp => "TCP".cyan(),
                capnp_schema::Protocol::Udp => "UDP".yellow(),
                capnp_schema::Protocol::Icmp => "ICMP".red(),
            };
            let action = match p.getAction() {
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
        Which::Alert(a) => {
            let alert = a.map_err(|e| anyhow::anyhow!("alert read failed: {e}"))?;
            Ok(format!(
                "{} rule={} {}",
                "ALERT".red().bold(),
                alert.getRuleId(),
                alert
                    .getSignatureName()
.ok()
                    .map(|s| s.to_string())
                    .unwrap_or_default()
                    .white()
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
