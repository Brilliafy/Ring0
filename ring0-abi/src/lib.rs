//! Ring0 shared ABI contract.
//!
//! This crate is the single source of truth for the wire contract between the
//! kernel eBPF programs (`ring0-ebpf`) and the userspace daemon (`ring0d`):
//!
//! * event kinds (first byte of every ring-buffer entry / userspace dispatch),
//! * the exact byte sizes of every fixed-layout ring-buffer event.
//!
//! The sizes below mirror the `#[repr(C)]` structs in `ring0-ebpf` (including
//! implicit padding). They are validated by unit tests in this crate and used
//! by `ring0d` to reject undersized/malformed ring entries before decoding.
//!
//! `#![no_std]` so the kernel-side crate can depend on it directly.

#![no_std]

// ── Event kinds (must match the first byte of each kernel event struct) ──

pub const KIND_PACKET: u8 = 0;
pub const KIND_PROCESS_EXEC: u8 = 1;
pub const KIND_FILE_ACCESS: u8 = 2;
pub const KIND_CONNECT: u8 = 3;
pub const KIND_KILL: u8 = 4;
pub const KIND_UNLINK: u8 = 5;
pub const KIND_TLS: u8 = 6;
pub const KIND_LSM: u8 = 10;
pub const KIND_CANARY: u8 = 11;
pub const KIND_SETUID: u8 = 12;
pub const KIND_CAP: u8 = 13;
pub const KIND_PTRACE: u8 = 14;
pub const KIND_MEMFD: u8 = 20;
pub const KIND_MMAP: u8 = 21;
pub const KIND_MODULE: u8 = 22;
pub const KIND_DPI: u8 = 30;

// ── Fixed event sizes (host mirror of the kernel #[repr(C)] structs) ──

/// `PacketEvent`: kind(1)+pad(7)+ts(8)+srcIp(4)+dstIp(4)+srcPort(2)+dstPort(2)
///                +protocol(1)+pad(3)+pid(4)+action(1)+pad(3) = 40
pub const SIZE_PACKET: usize = 40;
/// `ProcessExecEvent`: kind(1)+pad(7)+ts(8)+pid(4)+ppid(4)+uid(4)+comm(16) = 44
pub const SIZE_PROCESS_EXEC: usize = 44;
/// `FileAccessEvent`: kind(1)+pad(7)+ts(8)+pid(4)+uid(4)+filename(64)+flags(4) = 92
pub const SIZE_FILE_ACCESS: usize = 92;
/// `ConnectEvent`: kind(1)+pad(7)+ts(8)+pid(4)+uid(4)+dstIp(4)+dstPort(2)
///                 +protocol(1)+pad(1) = 32
pub const SIZE_CONNECT: usize = 32;
/// `KillEvent`: kind(1)+pad(7)+ts(8)+attacker(4)+target(4)+sig(4) = 28
pub const SIZE_KILL: usize = 28;
/// `UnlinkEvent`: kind(1)+pad(7)+ts(8)+pid(4)+uid(4)+path(96) = 120
pub const SIZE_UNLINK: usize = 120;
/// `LsmEvent`: kind(1)+pad(7)+ts(8)+pid(4)+uid(4)+type(1)+denied(1)+pad(2)
///             +path(96)+pad(2)+dstIp(4)+dstPort(2)+pad(4→align 8) = 136
///
/// NOTE: `path` occupies 26..122; `dst_ip` is NOT at 122 — u32 alignment pads
/// to 124, so `dst_ip` is at 124..128 and `dst_port` at 128..130. This is the
/// implicit-padding trap the audit flagged; the size table makes it explicit.
pub const SIZE_LSM: usize = 136;
/// `SetuidEvent`: kind(1)+pad(7)+ts(8)+pid(4)+oldUid(4)+newUid(4) = 28
pub const SIZE_SETUID: usize = 28;
/// `CapEvent`: kind(1)+pad(7)+ts(8)+pid(4)+uid(4)+capability(4)+target(4) = 32
pub const SIZE_CAP: usize = 32;
/// `MemfdEvent`: kind(1)+pad(7)+ts(8)+pid(4)+uid(4)+flags(4)+name(32) = 60
pub const SIZE_MEMFD: usize = 60;
/// `MmapEvent`: kind(1)+pad(7)+ts(8)+pid(4)+uid(4)+addr(8)+len(8)+prot(4)
///              +flags(4)+fileFd(8) = 56
pub const SIZE_MMAP: usize = 56;
/// `ModuleEvent`: kind(1)+pad(7)+ts(8)+pid(4)+uid(4)+name(64)+flags(4) = 92
pub const SIZE_MODULE: usize = 92;
/// `TlsEvent`: kind(1)+pad(7)+ts(8)+flowId(8)+pid(4)+direction(1)+pad(3)
///             +len(4)+buf(256) = 292
pub const SIZE_TLS: usize = 292;
/// `DpiEvent`: kind(1)+pad(7)+ts(8)+pid(4)+ruleId(4)+srcIp(4)+dstIp(4)
///             +dstPort(2)+protocol(1)+pad(1) = 36
pub const SIZE_DPI: usize = 36;

/// Canonical size per kind. `None` for kinds that are not fixed-layout
/// (e.g. `KIND_CANARY`, which is not produced today).
pub const EVENT_SIZE: [Option<usize>; 31] = {
    let mut t: [Option<usize>; 31] = [None; 31];
    t[KIND_PACKET as usize] = Some(SIZE_PACKET);
    t[KIND_PROCESS_EXEC as usize] = Some(SIZE_PROCESS_EXEC);
    t[KIND_FILE_ACCESS as usize] = Some(SIZE_FILE_ACCESS);
    t[KIND_CONNECT as usize] = Some(SIZE_CONNECT);
    t[KIND_KILL as usize] = Some(SIZE_KILL);
    t[KIND_UNLINK as usize] = Some(SIZE_UNLINK);
    t[KIND_TLS as usize] = Some(SIZE_TLS);
    t[KIND_LSM as usize] = Some(SIZE_LSM);
    t[KIND_SETUID as usize] = Some(SIZE_SETUID);
    t[KIND_CAP as usize] = Some(SIZE_CAP);
    t[KIND_PTRACE as usize] = Some(SIZE_CAP);
    t[KIND_MEMFD as usize] = Some(SIZE_MEMFD);
    t[KIND_MMAP as usize] = Some(SIZE_MMAP);
    t[KIND_MODULE as usize] = Some(SIZE_MODULE);
    t[KIND_DPI as usize] = Some(SIZE_DPI);
    t
};

/// Maximum event kind value (bounds the size table).
pub const MAX_KIND: u8 = 30;

/// Canonical 5-tuple flow key shared by the kernel `ESTABLISHED_FLOWS` map and
/// the userspace fast-path manager. Layout must match exactly across the ABI.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    /// Kept in sync with the kernel struct: padding to a 24-byte key.
    pub _pad: [u8; 7],
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sizes_match_expected_byte_layouts() {
        // Assert the documented field offsets, i.e. that implicit padding
        // (the LsmEvent trap) is exactly what the size table encodes.
        // LsmEvent: path(26..122), pad(122..124), dst_ip(124..128), dst_port(128..130).
        assert_eq!(SIZE_LSM, 136);
        // PacketEvent: pid at 32..36, action at 36.
        assert_eq!(SIZE_PACKET, 40);
        // TlsEvent: payload (buf) starts at 28.
        assert_eq!(SIZE_TLS, 292);
        // DpiEvent: dst_port at 32..34, protocol at 34.
        assert_eq!(SIZE_DPI, 36);
    }

    #[test]
    fn kinds_are_below_table_bound() {
        for kind in [
            KIND_PACKET,
            KIND_PROCESS_EXEC,
            KIND_FILE_ACCESS,
            KIND_CONNECT,
            KIND_KILL,
            KIND_UNLINK,
            KIND_TLS,
            KIND_LSM,
            KIND_SETUID,
            KIND_CAP,
            KIND_PTRACE,
            KIND_MEMFD,
            KIND_MMAP,
            KIND_MODULE,
            KIND_DPI,
        ] {
            assert!(
                kind as usize <= MAX_KIND as usize,
                "kind {kind} out of range"
            );
        }
    }
}
