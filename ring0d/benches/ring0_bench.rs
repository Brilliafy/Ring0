use ring0d::{dpi, process};
use std::net::IpAddr;

#[divan::bench]
fn bench_dpi_scan_sqli() -> Vec<dpi::DpiMatch> {
    let engine = dpi::DpiEngine::new().expect("DPI engine init");
    let payload = b"SELECT * FROM users WHERE id=1 OR '1'='1' UNION SELECT password FROM admins";
    engine.scan_payload(payload)
}

#[divan::bench]
fn bench_process_resolve() -> Option<process::ProcessInfo> {
    process::ProcessResolver::resolve_for_socket(
        443,
        IpAddr::V4(std::net::Ipv4Addr::new(142, 250, 80, 142)),
        80,
    )
}

#[divan::bench]
fn bench_capnp_serialize(b: &mut divan::Bencher) {
    use ring0_common::event_capnp as capnp_schema;

    b.bench_local(|| {
        let mut msg = capnp::message::Builder::new_default();
        let mut evt = msg.init_root::<capnp_schema::PacketEvent::Builder>();
        evt.setTimestamp(1_000_000_000);
        evt.setSrcPort(443);
        evt.setDstPort(80);
        let mut buf = Vec::new();
        capnp::serialize::write_message(&mut buf, &msg).expect("capnp serialize");
        buf
    });
}

fn main() {
    divan::main();
}
