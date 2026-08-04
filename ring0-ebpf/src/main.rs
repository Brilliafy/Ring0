#![no_std]
#![no_main]
#![allow(unused_unsafe)]
//
// Kernel structs (e.g. `task_struct`) are intentionally NOT shipped in
// aya-ebpf-bindings for CO-RE portability. To read task fields from a program
// (e.g. an eBPF-native PID-set iterator), generate per-kernel bindings with
// `aya-tool generate task_struct > src/vmlinux.rs` and include! them.

use core::ptr;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{btf_tracepoint, classifier, lsm, map, uprobe, xdp},
    maps::{lpm_trie::Key, HashMap, LpmTrie, LruHashMap, RingBuf},
    programs::{BtfTracePointContext, LsmContext, ProbeContext, TcContext, XdpContext},
    EbpfContext,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

// ── Map definitions ──────────────────────────────────────────

#[map]
pub static BLOCKED_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(65536, 0);

#[map]
pub static BLOCKED_PORTS: HashMap<u16, u32> = HashMap::with_max_entries(256, 0);

#[map]
pub static DNS_DOMAIN_BLOCK: HashMap<u64, u8> = HashMap::with_max_entries(200000, 0);

#[map]
pub static RING_BUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub static BLOCKED_BINARIES: HashMap<[u8; 64], u8> = HashMap::with_max_entries(256, 0);

#[map]
pub static LSM_ENFORCE: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
pub static LSM_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
pub static ESTABLISHED_FLOWS: LruHashMap<FlowKey, u32> = LruHashMap::with_max_entries(65536, 0);

#[map]
pub static DNS_BLOCKLIST: LpmTrie<u64, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static APP_QOS_MAP: HashMap<QosRateKey, QosRateVal> = HashMap::with_max_entries(256, 0);

#[map]
pub static TARPITTED_FLOWS: HashMap<FlowKey, u8> = HashMap::with_max_entries(1024, 0);

#[map]
pub static ROOTKIT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
pub static PRIVESC_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

// ── DPI (in-kernel fast-path pattern matching) ──────────────────
//
// Patterns are literal byte substrings keyed by rule id. DPI_MODE key 1
// selects enforcement (drop on match); when unset the daemon observes only
// (emits a DPI event and passes the packet, never interrupting the flow).

#[map]
pub static DPI_PATTERNS: HashMap<u32, DpiPattern> = HashMap::with_max_entries(64, 0);

#[map]
pub static DPI_MODE: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

// ── Struct definitions ───────────────────────────────────────

#[repr(C)]
pub struct FlowKey {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    _pad: [u8; 7],
}

#[repr(C)]
pub struct QosRateKey {
    pub pid: u32,
    _pad: [u8; 4],
}

#[repr(C)]
pub struct QosRateVal {
    pub rate_bps: u64,
    pub tokens: u64,
    pub last_update_ns: u64,
}

// Event kinds (first byte of every ring buffer entry)
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

#[repr(C)]
pub struct PacketEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub protocol: u8,
    pub pid: u32,
    pub action: u8,
}

#[repr(C)]
pub struct ProcessExecEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}

#[repr(C)]
pub struct FileAccessEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub filename: [u8; 64],
    pub flags: u32,
}

#[repr(C)]
pub struct ConnectEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
}

#[repr(C)]
pub struct KillEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub attacker_pid: u32,
    pub target_pid: u32,
    pub sig: u32,
}

#[repr(C)]
pub struct UnlinkEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub path: [u8; 96],
}

#[repr(C)]
pub struct LsmEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub event_type: u8,
    pub denied: u8,
    pub path: [u8; 96],
    pub dst_ip: u32,
    pub dst_port: u16,
}

#[repr(C)]
pub struct SetuidEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub old_uid: u32,
    pub new_uid: u32,
}

#[repr(C)]
pub struct CapEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub capability: u32,
    pub target: u32,
}

#[repr(C)]
pub struct MemfdEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub flags: u32,
    pub name: [u8; 32],
}

#[repr(C)]
pub struct MmapEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub addr: u64,
    pub len: u64,
    pub prot: u32,
    pub flags: u32,
    pub file_fd: u64,
}

#[repr(C)]
pub struct ModuleEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub name: [u8; 64],
    pub flags: u32,
}

#[repr(C)]
pub struct TlsEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub direction: u8,
    pub len: u32,
    pub buf: [u8; 256],
}

#[repr(C)]
pub struct DpiPattern {
    pub len: u8,
    pub data: [u8; 32],
}

#[repr(C)]
pub struct DpiEvent {
    pub kind: u8,
    pub timestamp: u64,
    pub pid: u32,
    pub rule_id: u32,
    pub src_ip: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
}

// ── Helper functions ─────────────────────────────────────────

#[inline(always)]
unsafe fn read_u16(ptr: *const u8, off: usize) -> u16 {
    ptr::read_unaligned(ptr.add(off) as *const u16)
}
#[inline(always)]
unsafe fn read_u32(ptr: *const u8, off: usize) -> u32 {
    ptr::read_unaligned(ptr.add(off) as *const u32)
}

#[inline(always)]
fn ktime_get_ns() -> u64 {
    unsafe { aya_ebpf_bindings::helpers::bpf_ktime_get_ns() }
}

// ── IP/PORT blocking check ───────────────────────────────────

fn check_blocked(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> u32 {
    let drop = xdp_action::XDP_DROP;
    if unsafe { BLOCKED_IPS.get(&Key::new(32, src_ip)).is_some() }
        || unsafe { BLOCKED_IPS.get(&Key::new(32, dst_ip)).is_some() }
        || unsafe { BLOCKED_PORTS.get_ptr(&src_port).is_some() }
        || unsafe { BLOCKED_PORTS.get_ptr(&dst_port).is_some() }
    {
        return drop;
    }
    xdp_action::XDP_PASS
}

// ── DNS domain hash blocklist ──────────────────────────────

const FNV_OFFSET: u64 = 14695981039346656037;
const FNV_PRIME: u64 = 1099511628211;

#[inline(always)]
fn fnv1a(mut h: u64, b: u8) -> u64 {
    h ^= b as u64;
    h.wrapping_mul(FNV_PRIME)
}

#[inline(always)]
fn lowercase(b: u8) -> u8 {
    if (b'A'..=b'Z').contains(&b) {
        b + 32
    } else {
        b
    }
}

trait PktData {
    fn data(&self) -> usize;
    fn data_end(&self) -> usize;
}
impl PktData for XdpContext {
    fn data(&self) -> usize {
        self.data()
    }
    fn data_end(&self) -> usize {
        self.data_end()
    }
}
impl PktData for TcContext {
    fn data(&self) -> usize {
        self.data()
    }
    fn data_end(&self) -> usize {
        self.data_end()
    }
}

/// Parse the DNS query name at `qname_off` and check its hash (full name and
/// registrable last-two-labels) against the kernel domain blocklist.
/// Returns true when the query should be dropped.
unsafe fn dns_query_blocked<T: PktData>(ctx: &T, qname_off: usize) -> bool {
    let mut off = qname_off;
    let mut label_starts = [0u16; 8];
    let mut n_labels = 0usize;
    let mut full_hash = FNV_OFFSET;
    let mut first = true;
    let mut name_len = 0usize;

    while off < ctx.data_end() {
        let len = *(ctx.data() as *const u8).add(off) as usize;
        if len == 0 {
            break;
        }
        if len > 63 || n_labels >= 8 || name_len + len + 1 > 255 {
            return false;
        }
        if n_labels < 8 {
            label_starts[n_labels] = off as u16 + 1;
        }
        n_labels += 1;
        for i in 0..len {
            if off + 1 + i >= ctx.data_end() {
                return false;
            }
            let b = lowercase(*(ctx.data() as *const u8).add(off + 1 + i));
            if !first {
                full_hash = fnv1a(full_hash, b'.');
            }
            first = false;
            full_hash = fnv1a(full_hash, b);
            name_len += 1;
        }
        off += 1 + len;
    }

    if DNS_DOMAIN_BLOCK.get(&full_hash).is_some() {
        return true;
    }
    if n_labels >= 2 {
        let start = label_starts[n_labels - 2] as usize;
        let mut h = FNV_OFFSET;
        let mut first_l = true;
        let mut i = start;
        while i < off && i < ctx.data_end() {
            let b = lowercase(*(ctx.data() as *const u8).add(i));
            if b == 0 {
                break;
            }
            if !first_l {
                h = fnv1a(h, b'.');
            }
            first_l = false;
            h = fnv1a(h, b);
            i += 1;
        }
        if DNS_DOMAIN_BLOCK.get(&h).is_some() {
            return true;
        }
    }
    if n_labels >= 3 {
        let start = label_starts[n_labels - 3] as usize;
        let mut h = FNV_OFFSET;
        let mut first_l = true;
        let mut i = start;
        while i < off && i < ctx.data_end() {
            let b = lowercase(*(ctx.data() as *const u8).add(i));
            if b == 0 {
                break;
            }
            if !first_l {
                h = fnv1a(h, b'.');
            }
            first_l = false;
            h = fnv1a(h, b);
            i += 1;
        }
        if DNS_DOMAIN_BLOCK.get(&h).is_some() {
            return true;
        }
    }
    false
}

// ── DPI fast-path pattern scan ────────────────────────────────
//
// Scans the first SCAN_WINDOW bytes of a packet payload for the literal
// patterns in DPI_PATTERNS. Pure observation — never touches the flow other
// than optionally dropping in enforce mode.

#[inline(always)]
unsafe fn dpi_scan_packet(ctx: &XdpContext, payload_off: usize) -> u32 {
    const MAX_PATTERNS: u32 = 64;
    const SCAN_WINDOW: usize = 64;

    let mut rule_id = 0u32;
    let mut idx = 0u32;
    while idx < MAX_PATTERNS {
        if let Some(pat) = DPI_PATTERNS.get_ptr(&idx) {
            let plen = (*pat).len as usize;
            if plen > 0 && plen <= 32 {
                let mut off = 0usize;
                while off < SCAN_WINDOW {
                    let mut matched = true;
                    let mut k = 0usize;
                    while k < plen {
                        let pos = payload_off + off + k;
                        if pos >= ctx.data_end() {
                            matched = false;
                            break;
                        }
                        if *(ctx.data() as *const u8).add(pos) != (*pat).data[k] {
                            matched = false;
                            break;
                        }
                        k += 1;
                    }
                    if matched {
                        rule_id = idx;
                        break;
                    }
                    off += 1;
                }
                if rule_id != 0 {
                    break;
                }
            }
        }
        idx += 1;
    }
    rule_id
}

// ── XDP program ──────────────────────────────────────────────

#[xdp]
pub fn ring0_xdp(ctx: XdpContext) -> u32 {
    match unsafe { try_ring0_xdp(&ctx) } {
        Ok(a) => a,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

unsafe fn try_ring0_xdp(ctx: &XdpContext) -> Result<u32, u32> {
    let eth = ctx.data();
    if ctx.data_end() < eth + 14 {
        return Err(xdp_action::XDP_ABORTED);
    }
    if u16::from_be(read_u16(eth as *const u8, 12)) != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = eth + 14;
    if ctx.data_end() < ip + 20 {
        return Err(xdp_action::XDP_ABORTED);
    }
    let proto = *(ip as *const u8).add(9);
    let src_ip = u32::from_be(read_u32(ip as *const u8, 12));
    let dst_ip = u32::from_be(read_u32(ip as *const u8, 16));

    let (sp, dp) = if proto == 6 || proto == 17 {
        let l4 = ip + 20;
        if ctx.data_end() < l4 + 4 {
            return Err(xdp_action::XDP_ABORTED);
        }
        (
            u16::from_be(read_u16(l4 as *const u8, 0)),
            u16::from_be(read_u16(l4 as *const u8, 2)),
        )
    } else {
        (0, 0)
    };

    if check_blocked(src_ip, dst_ip, sp, dp) == xdp_action::XDP_DROP {
        return Ok(xdp_action::XDP_DROP);
    }

    let dns_match = if dp == 53 || sp == 53 {
        DNS_BLOCKLIST.get(&Key::new(32, dst_ip as u64)).is_some()
            || DNS_BLOCKLIST.get(&Key::new(32, src_ip as u64)).is_some()
    } else {
        false
    };
    if dns_match {
        return Ok(xdp_action::XDP_DROP);
    }

    // Kernel-level DNS domain blocklist (hashed FQDN lookup, sub-µs).
    if proto == 17 && dp == 53 {
        let dns = ip + 20 + 8;
        if ctx.data_end() >= dns + 12 + 1 {
            let qname = dns + 12;
            if unsafe { dns_query_blocked(ctx, qname) } {
                return Ok(xdp_action::XDP_DROP);
            }
        }
    }

    let flow_key = FlowKey {
        src_ip,
        dst_ip,
        src_port: sp,
        dst_port: dp,
        protocol: proto,
        _pad: [0u8; 7],
    };
    if ESTABLISHED_FLOWS.get_ptr(&flow_key).is_some() {
        return Ok(xdp_action::XDP_PASS);
    }

    // Fast-path DPI on the payload of new flows (no reassembly): literal
    // byte-pattern match, observe-and-pass by default; drop only in enforce
    // mode (DPI_MODE key 1).
    let dpi_payload_off = if proto == 6 {
        let l4 = ip + 20;
        if ctx.data_end() < l4 + 14 {
            0
        } else {
            // TCP data offset: high nibble of byte 12 in the TCP header.
            l4 + (((*(l4 as *const u8).add(12)) >> 4) as usize) * 4
        }
    } else if proto == 17 {
        let l4 = ip + 20;
        if ctx.data_end() < l4 + 8 {
            0
        } else {
            l4 + 8
        }
    } else {
        0
    };
    if dpi_payload_off > eth && dpi_payload_off < ctx.data_end() {
        let rule = dpi_scan_packet(ctx, dpi_payload_off);
        if rule != 0 {
            if DPI_MODE.get_ptr(&1).is_some() {
                return Ok(xdp_action::XDP_DROP);
            }
            if let Some(mut entry) = RING_BUF.reserve::<DpiEvent>(0) {
                entry.write(DpiEvent {
                    kind: KIND_DPI,
                    timestamp: ktime_get_ns(),
                    pid: 0,
                    rule_id: rule,
                    src_ip,
                    dst_ip,
                    dst_port: dp,
                    protocol: proto,
                });
                entry.submit(0);
            }
        }
    }

    if let Some(mut entry) = RING_BUF.reserve::<PacketEvent>(0) {
        entry.write(PacketEvent {
            kind: KIND_PACKET,
            timestamp: ktime_get_ns(),
            src_ip,
            dst_ip,
            src_port: sp,
            dst_port: dp,
            protocol: proto,
            pid: 0,
            action: 0,
        });
        entry.submit(0);
    }
    Ok(xdp_action::XDP_PASS)
}

// ── TC classifier ────────────────────────────────────────────

#[classifier]
pub fn ring0_tc(ctx: TcContext) -> i32 {
    match unsafe { try_ring0_tc(&ctx) } {
        Ok(a) => a,
        Err(_) => -1,
    }
}

unsafe fn try_ring0_tc(ctx: &TcContext) -> Result<i32, i32> {
    let eth = ctx.data();
    if ctx.data_end() < eth + 14 {
        return Err(-1);
    }
    if u16::from_be(read_u16(eth as *const u8, 12)) != 0x0800 {
        return Ok(0);
    }

    let ip = eth + 14;
    if ctx.data_end() < ip + 20 {
        return Err(-1);
    }
    let src_ip = u32::from_be(read_u32(ip as *const u8, 12));
    let dst_ip = u32::from_be(read_u32(ip as *const u8, 16));
    let proto = *(ip as *const u8).add(9);

    let (sp, dp) = if proto == 6 || proto == 17 {
        let l4 = ip + 20;
        if ctx.data_end() < l4 + 4 {
            return Err(-1);
        }
        (
            u16::from_be(read_u16(l4 as *const u8, 0)),
            u16::from_be(read_u16(l4 as *const u8, 2)),
        )
    } else {
        (0, 0)
    };

    let dns_match = if dp == 53 || sp == 53 {
        DNS_BLOCKLIST.get(&Key::new(32, dst_ip as u64)).is_some()
            || DNS_BLOCKLIST.get(&Key::new(32, src_ip as u64)).is_some()
    } else {
        false
    };
    if dns_match {
        return Ok(-1);
    }

    // Kernel-level DNS domain blocklist (hashed FQDN lookup, sub-µs).
    if proto == 17 && dp == 53 {
        let dns = ip + 20 + 8;
        if ctx.data_end() >= dns + 12 + 1 {
            let qname = dns + 12;
            if unsafe { dns_query_blocked(ctx, qname) } {
                return Ok(-1);
            }
        }
    }

    let flow_key = FlowKey {
        src_ip,
        dst_ip,
        src_port: sp,
        dst_port: dp,
        protocol: proto,
        _pad: [0u8; 7],
    };
    if ESTABLISHED_FLOWS.get_ptr(&flow_key).is_some() {
        return Ok(0);
    }

    if proto == 6 && unsafe { TARPITTED_FLOWS.get_ptr(&flow_key).is_some() } {
        let tcp = ip + 20;
        if ctx.data_end() >= tcp + 14 {
            let win = (tcp + 14) as *mut u16;
            *win = 0;
        }
        let _ = TARPITTED_FLOWS.insert(&flow_key, &1, 0);
        return Ok(-1);
    }

    if let Some(mut entry) = RING_BUF.reserve::<PacketEvent>(0) {
        entry.write(PacketEvent {
            kind: KIND_PACKET,
            timestamp: ktime_get_ns(),
            src_ip,
            dst_ip,
            src_port: sp,
            dst_port: dp,
            protocol: proto,
            pid: 0,
            action: 0,
        });
        entry.submit(0);
    }
    Ok(0)
}

// ── BTF tracepoints ──────────────────────────────────────────

#[btf_tracepoint(function = "sched_process_exec")]
pub fn ring0_sched_exec(_ctx: BtfTracePointContext) -> u32 {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() } as u32;
    let comm = unsafe { aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]) };
    if let Some(mut entry) = unsafe { RING_BUF.reserve::<ProcessExecEvent>(0) } {
        entry.write(ProcessExecEvent {
            kind: KIND_PROCESS_EXEC,
            timestamp: ktime_get_ns(),
            pid,
            ppid: 0,
            uid,
            comm,
        });
        entry.submit(0);
    }
    0
}

// ── Generic syscall-entry dispatcher ─────────────────────────
//
// The per-syscall `sys_enter_<name>` events (e.g. `sys_enter_openat`) are NOT
// real kernel tracepoints — they are dynamically-created trace events layered on
// top of the generic `sys_enter` tracepoint (see `kernel/trace/trace_syscalls.c`).
// Raw/btf tracepoint programs can therefore only attach to the generic
// `sys_enter` tracepoint; we dispatch on the syscall number and read the real
// syscall arguments from `struct pt_regs`.

#[cfg(bpf_target_arch = "x86_64")]
mod syscall_nrs {
    pub const __NR_OPENAT: u64 = 257;
    pub const __NR_CONNECT: u64 = 42;
    pub const __NR_KILL: u64 = 62;
    pub const __NR_UNLINKAT: u64 = 263;
    pub const __NR_SETUID: u64 = 105;
    pub const __NR_MEMFD_CREATE: u64 = 319;
    pub const __NR_MMAP: u64 = 9;
    pub const __NR_FINIT_MODULE: u64 = 313;
}

#[cfg(bpf_target_arch = "aarch64")]
mod syscall_nrs {
    pub const __NR_OPENAT: u64 = 56;
    pub const __NR_CONNECT: u64 = 203;
    pub const __NR_KILL: u64 = 129;
    pub const __NR_UNLINKAT: u64 = 35;
    pub const __NR_SETUID: u64 = 146;
    pub const __NR_MEMFD_CREATE: u64 = 219;
    pub const __NR_MMAP: u64 = 222;
    pub const __NR_FINIT_MODULE: u64 = 273;
}

/// Read the `n`th syscall argument (0-based) from the `pt_regs` captured at the
/// entry of the syscall. Uses `bpf_probe_read_kernel` so it stays verifier-safe.
#[inline(always)]
unsafe fn syscall_arg(regs: *const aya_ebpf::bindings::pt_regs, n: usize) -> u64 {
    #[cfg(bpf_target_arch = "x86_64")]
    {
        let field = match n {
            0 => core::ptr::addr_of!((*regs).rdi),
            1 => core::ptr::addr_of!((*regs).rsi),
            2 => core::ptr::addr_of!((*regs).rdx),
            3 => core::ptr::addr_of!((*regs).r10),
            4 => core::ptr::addr_of!((*regs).r8),
            5 => core::ptr::addr_of!((*regs).r9),
            _ => return 0,
        };
        aya_ebpf::helpers::bpf_probe_read_kernel(field).unwrap_or(0)
    }
    #[cfg(not(bpf_target_arch = "x86_64"))]
    {
        // pt_regs argument decoding is only implemented for x86_64 for now;
        // the syscall handlers are no-ops on other architectures.
        let _ = (regs, n);
        0
    }
}

#[inline(always)]
unsafe fn ring0_handle_openat(regs: *const aya_ebpf::bindings::pt_regs) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = aya_ebpf::helpers::bpf_get_current_uid_gid() as u32;
    let filename_ptr = syscall_arg(regs, 1) as *const u8;
    if filename_ptr.is_null() {
        return;
    }
    let mut filename = [0u8; 64];
    let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(filename_ptr, &mut filename);
    if path_matches_blocklist(&filename) && uid != 0 {
        if let Some(mut entry) = RING_BUF.reserve::<FileAccessEvent>(0) {
            entry.write(FileAccessEvent {
                kind: KIND_FILE_ACCESS,
                timestamp: ktime_get_ns(),
                pid,
                uid,
                filename,
                flags: 0,
            });
            entry.submit(0);
        }
    }
}

fn path_matches_blocklist(filename: &[u8; 64]) -> bool {
    let blocklist: [&[u8]; 6] = [
        b"/etc/shadow",
        b"/etc/sudoers",
        b".ssh/id_rsa",
        b".ssh/id_ed25519",
        b"/proc/kallsyms",
        b"/etc/passwd",
    ];
    for bl in &blocklist {
        let mut m = true;
        for i in 0..bl.len() {
            if i >= 64 || filename[i] != bl[i] {
                m = false;
                break;
            }
        }
        if m {
            return true;
        }
    }
    false
}

#[inline(always)]
unsafe fn ring0_handle_connect(regs: *const aya_ebpf::bindings::pt_regs) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = aya_ebpf::helpers::bpf_get_current_uid_gid() as u32;
    let addr_ptr = syscall_arg(regs, 1) as *const u8;
    // sockaddr_in: family (2) | port (2, big endian) | addr (4).
    if addr_ptr.is_null() {
        return;
    }
    let family = bpf_probe_read_user_u16(addr_ptr);
    if family != 2 {
        return;
    }
    let port = bpf_probe_read_net16(addr_ptr.add(2));
    let ip = bpf_probe_read_net32(addr_ptr.add(4));
    if let Some(mut entry) = RING_BUF.reserve::<ConnectEvent>(0) {
        entry.write(ConnectEvent {
            kind: KIND_CONNECT,
            timestamp: ktime_get_ns(),
            pid,
            uid,
            dst_ip: ip,
            dst_port: port,
            protocol: 6,
        });
        entry.submit(0);
    }
}

/// Read a u16 in network byte order from a user pointer, returning 0 on failure.
#[inline(always)]
unsafe fn bpf_probe_read_net16(ptr: *const u8) -> u16 {
    let raw: u16 = match aya_ebpf::helpers::bpf_probe_read_user::<u16>(ptr.cast()) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    u16::from_be(raw)
}

/// Read a u32 in network byte order from a user pointer, returning 0 on failure.
#[inline(always)]
unsafe fn bpf_probe_read_net32(ptr: *const u8) -> u32 {
    let raw: u32 = match aya_ebpf::helpers::bpf_probe_read_user::<u32>(ptr.cast()) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    u32::from_be(raw)
}

/// Read a u16 (host byte order, used for the AF_* family field) from a user
/// pointer, returning 0 on failure.
#[inline(always)]
unsafe fn bpf_probe_read_user_u16(ptr: *const u8) -> u16 {
    aya_ebpf::helpers::bpf_probe_read_user::<u16>(ptr.cast()).unwrap_or(0)
}

#[inline(always)]
unsafe fn ring0_handle_kill(regs: *const aya_ebpf::bindings::pt_regs) {
    let attacker = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let target_pid = syscall_arg(regs, 0) as u32;
    let sig = syscall_arg(regs, 1) as u32;
    if (sig == 9 || sig == 15) && target_pid > 0 {
        if let Some(mut entry) = RING_BUF.reserve::<KillEvent>(0) {
            entry.write(KillEvent {
                kind: KIND_KILL,
                timestamp: ktime_get_ns(),
                attacker_pid: attacker,
                target_pid,
                sig,
            });
            entry.submit(0);
        }
    }
}

fn path_matches_daemon(path: &[u8; 96]) -> bool {
    let daemon = b"/etc/ring0/rules.yaml\0";
    for i in 0..daemon.len() {
        if i >= 96 || path[i] != daemon[i] {
            return false;
        }
    }
    true
}

fn path_matches_socket(path: &[u8; 96]) -> bool {
    let sock = b"/run/ring0d.sock\0";
    for i in 0..sock.len() {
        if i >= 96 || path[i] != sock[i] {
            return false;
        }
    }
    true
}

#[inline(always)]
unsafe fn ring0_handle_unlinkat(regs: *const aya_ebpf::bindings::pt_regs) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = aya_ebpf::helpers::bpf_get_current_uid_gid() as u32;
    let name_ptr = syscall_arg(regs, 1) as *const u8;
    if name_ptr.is_null() {
        return;
    }
    let mut path = [0u8; 96];
    let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(name_ptr, &mut path);
    if uid != 0 && (path_matches_daemon(&path) || path_matches_socket(&path)) {
        if let Some(mut entry) = RING_BUF.reserve::<UnlinkEvent>(0) {
            entry.write(UnlinkEvent {
                kind: KIND_UNLINK,
                timestamp: ktime_get_ns(),
                pid,
                uid,
                path,
            });
            entry.submit(0);
        }
    }
}

#[btf_tracepoint(function = "sys_enter")]
pub fn ring0_sys_enter(ctx: BtfTracePointContext) -> u32 {
    #[cfg(bpf_target_arch = "x86_64")]
    {
        use self::syscall_nrs::*;
        let regs = ctx.arg::<*const aya_ebpf::bindings::pt_regs>(0);
        if regs.is_null() {
            return 0;
        }
        let id = ctx.arg::<i64>(1) as u64;
        unsafe {
            match id {
                __NR_OPENAT => ring0_handle_openat(regs),
                __NR_CONNECT => ring0_handle_connect(regs),
                __NR_KILL => ring0_handle_kill(regs),
                __NR_UNLINKAT => ring0_handle_unlinkat(regs),
                __NR_SETUID => ring0_handle_setuid(regs),
                __NR_MEMFD_CREATE => ring0_handle_memfd(regs),
                __NR_MMAP => ring0_handle_mmap(regs),
                __NR_FINIT_MODULE => ring0_handle_finit_module(regs),
                _ => {}
            }
        }
    }
    #[cfg(not(bpf_target_arch = "x86_64"))]
    {
        // Syscall argument decoding is only implemented for x86_64.
        let _ = ctx;
    }
    0
}

// ── LSM programs ─────────────────────────────────────────────

fn is_lsm_enforced() -> bool {
    unsafe { LSM_ENFORCE.get_ptr(&1).is_some() }
}

pub fn ring0_lsm_file_open(ctx: LsmContext) -> i32 {
    if !is_lsm_enforced() {
        return 0;
    }
    let pid = ctx.pid();
    let uid = ctx.uid();
    if uid == 0 {
        return 0;
    }
    // NOTE: resolving the full path of `struct file` in this non-sleepable LSM
    // hook would require `bpf_d_path`, which is only available to sleepable
    // hooks. File protection for the paths below is therefore enforced by the
    // `sys_enter_openat` tracepoint + the userspace rule engine instead.
    // (The previous code attempted to read a zeroed local buffer and was dead.)
    let _ = (pid, &ctx);
    0
}

fn binary_matches_blocklist(comm: &[u8; 16]) -> bool {
    let mut key = [0u8; 64];
    let n = if comm.len() < 16 { comm.len() } else { 16 };
    let mut i = 0;
    while i < n {
        key[i] = comm[i];
        i += 1;
    }
    unsafe { BLOCKED_BINARIES.get_ptr(&key).is_some() }
}

#[lsm(hook = "bprm_check")]
pub fn ring0_lsm_bprm_check(ctx: LsmContext) -> i32 {
    if !is_lsm_enforced() {
        return 0;
    }
    let pid = ctx.pid();
    let uid = ctx.uid();
    if uid == 0 {
        return 0;
    }
    let comm = unsafe { aya_ebpf::helpers::bpf_get_current_comm().unwrap_or([0u8; 16]) };
    if binary_matches_blocklist(&comm) {
        let evt = LsmEvent {
            kind: KIND_LSM,
            timestamp: ktime_get_ns(),
            pid,
            uid,
            event_type: 1,
            denied: 1,
            path: [0u8; 96],
            dst_ip: 0,
            dst_port: 0,
        };
        if let Some(mut buf) = unsafe { LSM_EVENTS.reserve::<LsmEvent>(0) } {
            buf.write(evt);
            buf.submit(0);
        }
        return -1;
    }
    0
}

#[lsm(hook = "socket_connect")]
pub fn ring0_lsm_socket_connect(ctx: LsmContext) -> i32 {
    if !is_lsm_enforced() {
        return 0;
    }
    let pid = ctx.pid();
    let sock = unsafe { ptr::read_unaligned(ctx.as_ptr() as *const *const u8) };
    if sock.is_null() {
        return 0;
    }
    let addr_ptr =
        unsafe { ptr::read_unaligned((ctx.as_ptr() as *const *const u8).add(8)) } as *const u8;
    if addr_ptr.is_null() {
        return 0;
    }
    if unsafe { ptr::read_unaligned(addr_ptr as *const u16) } != 2 {
        return 0;
    }
    let port = unsafe { u16::from_be(ptr::read_unaligned((addr_ptr.add(2)) as *const u16)) };
    let ip = unsafe { ptr::read_unaligned((addr_ptr.add(4)) as *const u32) };
    if unsafe { BLOCKED_IPS.get(&Key::new(32, ip)).is_some() }
        || unsafe { BLOCKED_PORTS.get_ptr(&port).is_some() }
    {
        let evt = LsmEvent {
            kind: KIND_LSM,
            timestamp: ktime_get_ns(),
            pid,
            uid: 0,
            event_type: 2,
            denied: 1,
            path: [0u8; 96],
            dst_ip: ip,
            dst_port: port,
        };
        if let Some(mut buf) = unsafe { LSM_EVENTS.reserve::<LsmEvent>(0) } {
            buf.write(evt);
            buf.submit(0);
        }
        return -1;
    }
    0
}

// ── Privilege escalation + rootkit detectors (sys_enter dispatch) ─

#[lsm(hook = "ptrace_access_check")]
pub fn ring0_lsm_ptrace(ctx: LsmContext) -> i32 {
    // Audit every ptrace_access_check; deny only in enforce mode. Always-on
    // denial breaks debuggers (gdb/strace) and core dumps for every user.
    let pid = ctx.pid();
    let uid = ctx.uid();
    let target = unsafe { ptr::read_unaligned(ctx.as_ptr() as *const u32) };
    let evt = CapEvent {
        kind: KIND_PTRACE,
        timestamp: ktime_get_ns(),
        pid,
        uid,
        capability: 0,
        target,
    };
    if let Some(mut buf) = unsafe { PRIVESC_EVENTS.reserve::<CapEvent>(0) } {
        buf.write(evt);
        buf.submit(0);
    }
    if is_lsm_enforced() {
        -1
    } else {
        0
    }
}

#[lsm(hook = "capable")]
pub fn ring0_lsm_capable(ctx: LsmContext) -> i32 {
    // Audit high-risk capability checks; deny only in enforce mode. Always-on
    // denial of CAP_NET_ADMIN/CAP_SYS_ADMIN/CAP_SYS_MODULE breaks networking
    // daemons, mount/container tooling and driver loading.
    let pid = ctx.pid();
    let uid = ctx.uid();
    let cap = unsafe { ptr::read_unaligned(ctx.as_ptr() as *const u32) };
    if cap == 21 || cap == 12 || cap == 17 {
        let evt = CapEvent {
            kind: KIND_CAP,
            timestamp: ktime_get_ns(),
            pid,
            uid,
            capability: cap,
            target: 0,
        };
        if let Some(mut buf) = unsafe { PRIVESC_EVENTS.reserve::<CapEvent>(0) } {
            buf.write(evt);
            buf.submit(0);
        }
        if is_lsm_enforced() {
            return -1;
        }
    }
    0
}

#[inline(always)]
unsafe fn ring0_handle_setuid(regs: *const aya_ebpf::bindings::pt_regs) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = aya_ebpf::helpers::bpf_get_current_uid_gid() as u32;
    let new_uid = syscall_arg(regs, 0) as u32;
    if new_uid == 0 && uid != 0 {
        let evt = SetuidEvent {
            kind: KIND_SETUID,
            timestamp: ktime_get_ns(),
            pid,
            old_uid: uid,
            new_uid,
        };
        if let Some(mut buf) = PRIVESC_EVENTS.reserve::<SetuidEvent>(0) {
            buf.write(evt);
            buf.submit(0);
        }
    }
}

#[inline(always)]
unsafe fn ring0_handle_memfd(regs: *const aya_ebpf::bindings::pt_regs) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = aya_ebpf::helpers::bpf_get_current_uid_gid() as u32;
    let name_ptr = syscall_arg(regs, 0) as *const u8;
    let flags = syscall_arg(regs, 1) as u32;
    let mut name = [0u8; 32];
    if !name_ptr.is_null() {
        let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(name_ptr, &mut name);
    }
    if let Some(mut entry) = ROOTKIT_EVENTS.reserve::<MemfdEvent>(0) {
        entry.write(MemfdEvent {
            kind: KIND_MEMFD,
            timestamp: ktime_get_ns(),
            pid,
            uid,
            flags,
            name,
        });
        entry.submit(0);
    }
}

#[inline(always)]
unsafe fn ring0_handle_mmap(regs: *const aya_ebpf::bindings::pt_regs) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = aya_ebpf::helpers::bpf_get_current_uid_gid() as u32;
    let addr = syscall_arg(regs, 0);
    let len = syscall_arg(regs, 1);
    let prot = syscall_arg(regs, 2) as u32;
    let flags = syscall_arg(regs, 3) as u32;
    let file_fd = syscall_arg(regs, 4);
    let is_wx = (prot & 2) != 0 && (prot & 4) != 0;
    let is_anon_exec = (flags & 0x20) != 0 && (prot & 4) != 0;
    if is_wx || (is_anon_exec && file_fd == 0xFFFFFFFFFFFFFFFFu64) {
        if let Some(mut entry) = ROOTKIT_EVENTS.reserve::<MmapEvent>(0) {
            entry.write(MmapEvent {
                kind: KIND_MMAP,
                timestamp: ktime_get_ns(),
                pid,
                uid,
                addr,
                len,
                prot,
                flags,
                file_fd,
            });
            entry.submit(0);
        }
    }
}

#[inline(always)]
unsafe fn ring0_handle_finit_module(regs: *const aya_ebpf::bindings::pt_regs) {
    let pid = (aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = aya_ebpf::helpers::bpf_get_current_uid_gid() as u32;
    let name_ptr = syscall_arg(regs, 1) as *const u8;
    let flags = syscall_arg(regs, 2) as u32;
    let mut name = [0u8; 64];
    if !name_ptr.is_null() {
        let _ = aya_ebpf::helpers::bpf_probe_read_user_str_bytes(name_ptr, &mut name);
    }
    if let Some(mut entry) = ROOTKIT_EVENTS.reserve::<ModuleEvent>(0) {
        entry.write(ModuleEvent {
            kind: KIND_MODULE,
            timestamp: ktime_get_ns(),
            pid,
            uid,
            name,
            flags,
        });
        entry.submit(0);
    }
}

// ── TLS uprobes ──────────────────────────────────────────────

fn capture_tls_event(ctx: &ProbeContext, direction: u8) {
    if let Some(mut entry) = unsafe { RING_BUF.reserve::<TlsEvent>(0) } {
        let pid = ctx.pid();
        let buf_ptr = ctx.arg::<*const u8>(1).unwrap_or(ptr::null());
        let raw_len = ctx.arg::<u32>(2).unwrap_or(0);
        let len = if raw_len > 256 { 256 } else { raw_len };
        let mut buf = [0u8; 256];
        if !buf_ptr.is_null() {
            // Read the TLS plaintext from user space with a probe-read helper.
            // Direct dereference of user pointers is rejected by the verifier.
            let _ = unsafe {
                aya_ebpf::helpers::bpf_probe_read_user_buf(buf_ptr, &mut buf[..len as usize])
            };
        }
        entry.write(TlsEvent {
            kind: KIND_TLS,
            timestamp: ktime_get_ns(),
            pid,
            direction,
            len,
            buf,
        });
        entry.submit(0);
    }
}

#[uprobe]
pub fn ring0_ssl_write(ctx: ProbeContext) {
    capture_tls_event(&ctx, 0);
}

#[uprobe]
pub fn ring0_ssl_read(ctx: ProbeContext) {
    capture_tls_event(&ctx, 1);
}
