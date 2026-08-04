//! Benchmarks for ring0's hot paths.
//!
//! NOTE: `ring0d` is a binary-only crate, so benches cannot import its internal
//! modules. Only benchmarks that exercise library crates (ring0-common) or
//! standalone logic live here.

#[divan::bench]
fn bench_capnp_serialize(b: divan::Bencher) {
    use ring0_common::proto as capnp_schema;

    b.bench_local(|| {
        let mut msg = capnp::message::Builder::new_default();
        let mut evt = msg.init_root::<capnp_schema::packet_event::Builder>();
        evt.setTimestamp(1_000_000_000);
        evt.setSrcPort(443);
        evt.setDstPort(80);
        let mut buf = Vec::new();
        capnp::serialize::write_message(&mut buf, &msg).expect("capnp serialize");
        buf
    });
}

#[divan::bench]
fn bench_capnp_deserialize(b: divan::Bencher) {
    use ring0_common::proto as capnp_schema;

    let mut msg = capnp::message::Builder::new_default();
    let mut evt = msg.init_root::<capnp_schema::packet_event::Builder>();
    evt.setTimestamp(1_000_000_000);
    evt.setSrcPort(443);
    evt.setDstPort(80);
    let mut buf = Vec::new();
    capnp::serialize::write_message(&mut buf, &msg).expect("capnp serialize");

    b.bench_local(|| {
        let mut bytes = &buf[..];
        let reader = capnp::serialize::read_message_from_flat_slice(
            &mut bytes,
            capnp::message::ReaderOptions::new(),
        )
        .expect("capnp deserialize");
        let evt = reader
            .get_root::<capnp_schema::packet_event::Reader>()
            .expect("capnp root");
        let _ = (evt.getTimestamp(), evt.getSrcPort(), evt.getDstPort());
    });
}

fn main() {
    divan::main();
}
