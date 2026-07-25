pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/event_capnp.rs"));
}

pub use proto::daemon_command::Owned as DaemonCommand;
pub use proto::log_query::Owned as LogQuery;
pub use proto::query_response::Owned as QueryResponse;
pub use proto::ring0_event::Owned as Ring0Event;

pub use proto::*;

pub const SOCKET_PATH: &str = "/run/ring0d.sock";
pub const DB_PATH: &str = "/var/lib/ring0";
pub const BPF_RINGBUF_SIZE: u32 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventKind {
    Packet,
    Process,
    Alert,
    Status,
}

pub const FILTER_IPV4_MAX_ENTRIES: u32 = 1024;
pub const FILTER_IPV6_MAX_ENTRIES: u32 = 256;
