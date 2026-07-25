#![no_std]
#![no_main]

use aya_ebpf::{
    bindings::xdp_action,
    macros::{classifier, lsm, map, tp_btf, xdp},
    maps::{lpm_trie::LpmKey, Array, HashMap, LpmTrie, RingBuf, LruHashMap},
    programs::{TcContext, XdpContext},
    EbpfContext,
};

#[map]
pub static BLOCKED_IPS: LpmTrie<u32, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static BLOCKED_PORTS: HashMap<u16, u32> = HashMap::with_max_entries(256, 0);

#[map]
pub static RING_BUF: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
pub static BLOCKED_BINARIES: HashMap<[u8; 64], u8> = HashMap::with_max_entries(256, 0);

#[map]
pub static LSM_ENFORCE: HashMap<u32, u8> = HashMap::with_max_entries(1, 0);

#[map]
pub static LSM_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[map]
pub static CANARY_INODES: HashMap<u64, u8> = HashMap::with_max_entries(256, 0);

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
    pub _pad: [u8; 4],
}

#[repr(C)]
pub struct QosRateVal {
    pub rate_bps: u64,
    pub tokens: u64,
    pub last_update_ns: u64,
}

#[map]
pub static ESTABLISHED_FLOWS: LruHashMap<FlowKey, u32> = LruHashMap::with_max_entries(65536, 0);

#[map]
pub static DNS_BLOCKLIST: LpmTrie<u64, u8> = LpmTrie::with_max_entries(1024, 0);

#[map]
pub static APP_QOS_MAP: HashMap<QosRateKey, QosRateVal> = HashMap::with_max_entries(256, 0);

#[map]
pub static TARPITTED_FLOWS: HashMap<FlowKey, u8> = HashMap::with_max_entries(1024, 0);

#[repr(C)]
pub struct PacketEvent {
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
    pub timestamp: u64,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: [u8; 16],
}
#[repr(C)]
pub struct FileAccessEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub filename: [u8; 64],
    pub flags: u32,
}
#[repr(C)]
pub struct ConnectEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub dst_ip: u32,
    pub dst_port: u16,
    pub protocol: u8,
}
#[repr(C)]
pub struct KillEvent {
    pub timestamp: u64,
    pub attacker_pid: u32,
    pub target_pid: u32,
    pub sig: u32,
}
#[repr(C)]
pub struct UnlinkEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub path: [u8; 96],
}
#[repr(C)]
pub struct LsmEvent {
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
    pub timestamp: u64,
    pub pid: u32,
    pub old_uid: u32,
    pub new_uid: u32,
}

#[repr(C)]
pub struct CapEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub capability: u32,
}

#[map]
pub static PRIVESC_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

const TARGET_DAEMON_PID: u32 = 0;
const DAEMON_PATHS: &[u8] = b"/etc/ring0/rules.yaml\0";
const SOCKET_PATH_BYTES: &[u8] = b"/run/ring0d.sock\0";

#[inline(always)]
unsafe fn read_u16(ptr: *const u8, off: usize) -> u16 {
    core::ptr::read_unaligned(ptr.add(off) as *const u16)
}
#[inline(always)]
unsafe fn read_u32(ptr: *const u8, off: usize) -> u32 {
    core::ptr::read_unaligned(ptr.add(off) as *const u32)
}

fn check_blocked(src_ip: u32, dst_ip: u32, src_port: u16, dst_port: u16) -> u32 {
    unsafe {
        if BLOCKED_IPS
            .get(&LpmKey {
                prefix_len: 32,
                data: src_ip,
            })
            .is_some()
        {
            return xdp_action::XDP_DROP;
        }
        if BLOCKED_IPS
            .get(&LpmKey {
                prefix_len: 32,
                data: dst_ip,
            })
            .is_some()
        {
            return xdp_action::XDP_DROP;
        }
        if BLOCKED_PORTS.get(&src_port).is_some() || BLOCKED_PORTS.get(&dst_port).is_some() {
            return xdp_action::XDP_DROP;
        }
    }
    xdp_action::XDP_PASS
}

#[xdp]
pub fn ring0_xdp(ctx: XdpContext) -> u32 {
    match unsafe { try_ring0_xdp(&ctx) } {
        Ok(a) => a,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}
unsafe fn try_ring0_xdp(ctx: &XdpContext) -> Result<u32, u32> {
    let eth = ctx.data().ok_or(xdp_action::XDP_ABORTED)?;
    if ctx.data_end() < eth + 14 {
        return Err(xdp_action::XDP_ABORTED);
    }
    if u16::from_be(read_u16(eth, 12)) != 0x0800 {
        return Ok(xdp_action::XDP_PASS);
    }
    let ip = eth + 14;
    if ctx.data_end() < ip + 20 {
        return Err(xdp_action::XDP_ABORTED);
    }
    let proto = *ip.add(9);
    let src_ip = u32::from_be(read_u32(ip, 12));
    let dst_ip = u32::from_be(read_u32(ip, 16));
    let (sp, d) = if proto == 6 || proto == 17 {
        let l4 = ip + 20;
        if ctx.data_end() < l4 + 4 {
            return Err(xdp_action::XDP_ABORTED);
        }
        (u16::from_be(read_u16(l4, 0)), u16::from_be(read_u16(l4, 2)))
    } else {
        (0, 0)
    };
    if check_blocked(src_ip, dst_ip, sp, d) == xdp_action::XDP_DROP {
        return Ok(xdp_action::XDP_DROP);
    }
    let dns_match = if d == 53 || sp == 53 {
        unsafe { DNS_BLOCKLIST.get(&LpmKey { prefix_len: 32, data: dst_ip }).is_some() || DNS_BLOCKLIST.get(&LpmKey { prefix_len: 32, data: src_ip }).is_some() }
    } else { false };
    if dns_match {
        return Ok(xdp_action::XDP_DROP);
    }
    let flow_key = FlowKey {
        src_ip,
        dst_ip,
        src_port: sp,
        dst_port: d,
        protocol: proto,
        _pad: [0u8; 7],
    };
    if unsafe { ESTABLISHED_FLOWS.get(&flow_key).is_some() } {
        return Ok(xdp_action::XDP_PASS);
    }
    if let Some(ring) = RING_BUF.reserve::<PacketEvent>() {
        ring.write(PacketEvent {
            timestamp: ctx.start_time(),
            src_ip,
            dst_ip,
            src_port: sp,
            dst_port: d,
            protocol: proto,
            pid: 0,
            action: 0,
        })
    }
    Ok(xdp_action::XDP_PASS)
}

#[classifier]
pub fn ring0_tc(ctx: TcContext) -> i32 {
    match unsafe { try_ring0_tc(&ctx) } {
        Ok(a) => a,
        Err(_) => -1,
    }
}
unsafe fn try_ring0_tc(ctx: &TcContext) -> Result<i32, i32> {
    let eth = ctx.data().ok_or(-1)?;
    if ctx.data_end() < eth + 14 {
        return Err(-1);
    }
    if u16::from_be(read_u16(eth, 12)) != 0x0800 {
        return Ok(0);
    }
    let ip = eth + 14;
    if ctx.data_end() < ip + 20 {
        return Err(-1);
    }
    let src_ip = u32::from_be(read_u32(ip, 12));
    let dst_ip = u32::from_be(read_u32(ip, 16));
    let proto = *ip.add(9);
    let (sp, d) = if proto == 6 || proto == 17 {
        let l4 = ip + 20;
        if ctx.data_end() < l4 + 4 {
            return Err(-1);
        }
        (u16::from_be(read_u16(l4, 0)), u16::from_be(read_u16(l4, 2)))
    } else {
        (0, 0)
    };
    let dns_match = if d == 53 || sp == 53 {
        unsafe { DNS_BLOCKLIST.get(&LpmKey { prefix_len: 32, data: dst_ip }).is_some() || DNS_BLOCKLIST.get(&LpmKey { prefix_len: 32, data: src_ip }).is_some() }
    } else { false };
    if dns_match {
        return Ok(-1);
    }
    if proto == 6 || proto == 17 {
        let qos_key = QosRateKey { pid: 0, _pad: [0u8; 4] };
        if unsafe { APP_QOS_MAP.get(&qos_key).is_some() } {
            if let Some(val) = unsafe { APP_QOS_MAP.get(&qos_key) } {
                let pkt_len = ctx.len() as u64;
                if val.tokens < pkt_len {
                    return Ok(-1);
                }
            }
        }
    }
    let flow_key = FlowKey {
        src_ip,
        dst_ip,
        src_port: sp,
        dst_port: d,
        protocol: proto,
        _pad: [0u8; 7],
    };
    if unsafe { ESTABLISHED_FLOWS.get(&flow_key).is_some() } {
        return Ok(0);
    }
    if proto == 6 && unsafe { TARPITTED_FLOWS.get(&flow_key).is_some() } {
        let tcp = ip + 20;
        if ctx.data_end() >= tcp + 14 {
            unsafe {
                let win = tcp.add(14) as *mut u16;
                *win = 0;
            }
        }
        unsafe { TARPITTED_FLOWS.insert(&flow_key, &1, 0); }
        return Ok(-1);
    }
    if let Some(ring) = RING_BUF.reserve::<PacketEvent>() {
        ring.write(PacketEvent {
            timestamp: ctx.start_time(),
            src_ip,
            dst_ip,
            src_port: sp,
            dst_port: d,
            protocol: proto,
            pid: 0,
            action: 0,
        })
    }
    Ok(0)
}

#[tp_btf(name = "sched_process_exec")]
pub fn ring0_sched_exec(ctx: *const u8) -> u32 {
    if let Some(ring) = unsafe { RING_BUF.reserve::<ProcessExecEvent>() } {
        let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
        let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
        let mut comm = [0u8; 16];
        unsafe {
            aya_ebpf::helpers::bpf_get_current_comm(&mut comm as *mut _ as *mut u8, 16);
        }
        ring.write(ProcessExecEvent {
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            pid,
            ppid: 0,
            uid,
            comm,
        })
    }
    0
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

#[tp_btf(name = "sys_enter_openat")]
pub fn ring0_openat(ctx: *const u8) -> u32 {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let filename_ptr = unsafe { core::ptr::read_unaligned((ctx as *const *const u8).add(2)) };
    if filename_ptr.is_null() {
        return 0;
    }
    let mut filename = [0u8; 64];
    unsafe {
        aya_ebpf::helpers::bpf_probe_read_user_str(
            &mut filename as *mut _ as *mut u8,
            64,
            filename_ptr,
        );
    }
    if path_matches_blocklist(&filename) && uid != 0 {
        if let Some(ring) = unsafe { RING_BUF.reserve::<FileAccessEvent>() } {
            ring.write(FileAccessEvent {
                timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
                pid,
                uid,
                filename,
                flags: 0,
            })
        }
    }
    0
}

#[tp_btf(name = "sys_enter_connect")]
pub fn ring0_connect(ctx: *const u8) -> u32 {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let addr_ptr = unsafe { core::ptr::read_unaligned((ctx as *const *const u8).add(2)) };
    if addr_ptr.is_null() || unsafe { core::ptr::read_unaligned(addr_ptr as *const u16) } != 2 {
        return 0;
    }
    let port = unsafe { u16::from_be(core::ptr::read_unaligned((addr_ptr.add(2)) as *const u16)) };
    let ip = unsafe { core::ptr::read_unaligned((addr_ptr.add(4)) as *const u32) };
    if let Some(ring) = unsafe { RING_BUF.reserve::<ConnectEvent>() } {
        ring.write(ConnectEvent {
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            pid,
            uid,
            dst_ip: ip,
            dst_port: port,
            protocol: 6,
        })
    }
    0
}

#[tp_btf(name = "sys_enter_kill")]
pub fn ring0_kill(ctx: *const u8) -> u32 {
    let attacker = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let target_pid = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(1)) };
    let sig = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(2)) };
    if (sig == 9 || sig == 15) && target_pid > 0 {
        if let Some(ring) = unsafe { RING_BUF.reserve::<KillEvent>() } {
            ring.write(KillEvent {
                timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
                attacker_pid: attacker,
                target_pid,
                sig,
            })
        }
    }
    0
}

fn path_matches_daemon(path: &[u8; 96]) -> bool {
    for i in 0..DAEMON_PATHS.len() {
        if i >= 96 || path[i] != DAEMON_PATHS[i] {
            return false;
        }
    }
    true
}
fn path_matches_socket(path: &[u8; 96]) -> bool {
    for i in 0..SOCKET_PATH_BYTES.len() {
        if i >= 96 || path[i] != SOCKET_PATH_BYTES[i] {
            return false;
        }
    }
    true
}

#[tp_btf(name = "sys_enter_unlinkat")]
pub fn ring0_unlinkat(ctx: *const u8) -> u32 {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let name_ptr = unsafe { core::ptr::read_unaligned((ctx as *const *const u8).add(2)) };
    if name_ptr.is_null() {
        return 0;
    }
    let mut path = [0u8; 96];
    unsafe {
        aya_ebpf::helpers::bpf_probe_read_user_str(&mut path as *mut _ as *mut u8, 96, name_ptr);
    }
    if uid != 0 && (path_matches_daemon(&path) || path_matches_socket(&path)) {
        if let Some(ring) = unsafe { RING_BUF.reserve::<UnlinkEvent>() } {
            ring.write(UnlinkEvent {
                timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
                pid,
                uid,
                path,
            })
        }
    }
    0
}

fn is_lsm_enforced() -> bool {
    unsafe { LSM_ENFORCE.get(&1).is_some() }
}

fn path_matches_protected(filename: &[u8; 96]) -> bool {
    let protected: [&[u8]; 6] = [
        b"/etc/shadow",
        b"/etc/sudoers",
        b"/etc/passwd",
        b"/run/ring0d.sock",
        b"/etc/ring0/rules.yaml",
        b".ssh/id_",
    ];
    for p in &protected {
        let mut m = true;
        for i in 0..p.len() {
            if i >= 96 || filename[i] != p[i] {
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

#[lsm(function = "security_file_open")]
pub fn ring0_lsm_file_open(ctx: *const u8) -> i32 {
    if !is_lsm_enforced() {
        return 0;
    }
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    if uid == 0 {
        return 0;
    }
    let file = unsafe { core::ptr::read_unaligned(ctx as *const *const u8) };
    if file.is_null() {
        return 0;
    }
    let mut path_buf = [0u8; 96];
    let ret =
        unsafe { aya_ebpf::helpers::bpf_d_path(file, &mut path_buf as *mut _ as *mut u8, 96) };
    if ret <= 0 {
        return 0;
    }
    if path_matches_protected(&path_buf) {
        let evt = LsmEvent {
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            pid,
            uid,
            event_type: 0,
            denied: 1,
            path: path_buf,
            dst_ip: 0,
            dst_port: 0,
        };
        if let Some(buf) = unsafe { LSM_EVENTS.reserve::<LsmEvent>() } {
            buf.write(evt);
        }
        return -1;
    }
    0
}

fn binary_matches_blocklist(comm: &[u8; 16]) -> bool {
    let mut comm_buf = [0u8; 64];
    let copy_len = if comm.len() < 16 { comm.len() } else { 16 };
    let mut i = 0;
    while i < copy_len {
        comm_buf[i] = comm[i];
        i += 1;
    }
    unsafe { BLOCKED_BINARIES.get(&comm_buf).is_some() }
}

#[lsm(function = "security_bprm_check")]
pub fn ring0_lsm_bprm_check(ctx: *const u8) -> i32 {
    if !is_lsm_enforced() {
        return 0;
    }
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    if uid == 0 {
        return 0;
    }
    let mut comm = [0u8; 16];
    unsafe {
        aya_ebpf::helpers::bpf_get_current_comm(&mut comm as *mut _ as *mut u8, 16);
    }
    if binary_matches_blocklist(&comm) {
        let evt = LsmEvent {
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            pid,
            uid,
            event_type: 1,
            denied: 1,
            path: [0u8; 96],
            dst_ip: 0,
            dst_port: 0,
        };
        if let Some(buf) = unsafe { LSM_EVENTS.reserve::<LsmEvent>() } {
            buf.write(evt);
        }
        return -1;
    }
    0
}

#[lsm(function = "security_socket_connect")]
pub fn ring0_lsm_socket_connect(ctx: *const u8) -> i32 {
    if !is_lsm_enforced() {
        return 0;
    }
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let sock = unsafe { core::ptr::read_unaligned(ctx as *const *const u8) };
    if sock.is_null() {
        return 0;
    }
    let addr_ptr =
        unsafe { core::ptr::read_unaligned((ctx as *const *const u8).add(8)) } as *const u8;
    if addr_ptr.is_null() {
        return 0;
    }
    let family = unsafe { core::ptr::read_unaligned(addr_ptr as *const u16) };
    if family != 2 {
        return 0;
    }
    let port = unsafe { u16::from_be(core::ptr::read_unaligned((addr_ptr.add(2)) as *const u16)) };
    let ip = unsafe { core::ptr::read_unaligned((addr_ptr.add(4)) as *const u32) };
    if unsafe {
        BLOCKED_IPS
            .get(&LpmKey {
                prefix_len: 32,
                data: ip,
            })
            .is_some()
    } || unsafe { BLOCKED_PORTS.get(&port).is_some() }
    {
        let evt = LsmEvent {
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            pid,
            uid: 0,
            event_type: 2,
            denied: 1,
            path: [0u8; 96],
            dst_ip: ip,
            dst_port: port,
        };
        if let Some(buf) = unsafe { LSM_EVENTS.reserve::<LsmEvent>() } {
            buf.write(evt);
        }
        return -1;
    }
    0
}

fn is_canary_inode(inode: u64) -> bool {
    unsafe { CANARY_INODES.get(&inode).is_some() }
}

#[repr(C)]
pub struct CanaryEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub inode: u64,
    pub event_type: u8,
    pub comm: [u8; 16],
}

#[map]
pub static CANARY_EVENTS: RingBuf = RingBuf::with_byte_size(32 * 1024, 0);

#[tp_btf(name = "sys_enter_openat")]
pub fn ring0_canary_openat(ctx: *const u8) -> u32 {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let mut comm = [0u8; 16];
    unsafe {
        aya_ebpf::helpers::bpf_get_current_comm(&mut comm as *mut _ as *mut u8, 16);
    }
    if uid == 0 {
        return 0;
    }
    0
}

#[repr(C)]
pub struct MemfdEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub flags: u32,
    pub name: [u8; 32],
}

#[repr(C)]
pub struct MmapEvent {
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
    pub timestamp: u64,
    pub pid: u32,
    pub uid: u32,
    pub name: [u8; 64],
    pub flags: u32,
}

#[map]
pub static ROOTKIT_EVENTS: RingBuf = RingBuf::with_byte_size(64 * 1024, 0);

#[tp_btf(name = "sys_enter_memfd_create")]
pub fn ring0_memfd_create(ctx: *const u8) -> u32 {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let name_ptr = unsafe { core::ptr::read_unaligned((ctx as *const *const u8).add(1)) };
    let flags = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(2)) };
    let mut name = [0u8; 32];
    if !name_ptr.is_null() {
        unsafe {
            aya_ebpf::helpers::bpf_probe_read_user_str(
                &mut name as *mut _ as *mut u8,
                32,
                name_ptr,
            );
        }
    }
    if let Some(ring) = unsafe { ROOTKIT_EVENTS.reserve::<MemfdEvent>() } {
        ring.write(MemfdEvent {
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            pid,
            uid,
            flags,
            name,
        })
    }
    0
}

#[tp_btf(name = "sys_enter_mmap")]
pub fn ring0_mmap(ctx: *const u8) -> u32 {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let addr = unsafe { core::ptr::read_unaligned((ctx as *const u64).add(1)) };
    let len = unsafe { core::ptr::read_unaligned((ctx as *const u64).add(2)) };
    let prot = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(2)) };
    let flags = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(3)) };
    let file_fd = unsafe { core::ptr::read_unaligned((ctx as *const u64).add(6)) };
    let prot_write = 2;
    let prot_exec = 4;
    let map_anonymous = 0x20;
    let is_wx = (prot & prot_write) != 0 && (prot & prot_exec) != 0;
    let is_anon_exec = (flags & map_anonymous) != 0 && (prot & prot_exec) != 0;
    if is_wx || (is_anon_exec && file_fd == 0xFFFFFFFFFFFFFFFFu64) {
        if let Some(ring) = unsafe { ROOTKIT_EVENTS.reserve::<MmapEvent>() } {
            ring.write(MmapEvent {
                timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
                pid,
                uid,
                addr,
                len,
                prot,
                flags,
                file_fd,
            })
        }
    }
    0
}

#[tp_btf(name = "sys_enter_finit_module")]
pub fn ring0_finit_module(ctx: *const u8) -> u32 {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let name_ptr = unsafe { core::ptr::read_unaligned((ctx as *const *const u8).add(2)) };
    let flags = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(3)) };
    let mut name = [0u8; 64];
    if !name_ptr.is_null() {
        unsafe {
            aya_ebpf::helpers::bpf_probe_read_user_str(
                &mut name as *mut _ as *mut u8,
                64,
                name_ptr,
            );
        }
    }
    if let Some(ring) = unsafe { ROOTKIT_EVENTS.reserve::<ModuleEvent>() } {
            ring.write(ModuleEvent {
                timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
                pid,
                uid,
                name,
                flags,
            })
        }
    }
    0
}

#[tp_btf(name = "sys_enter_unlinkat")]
pub fn ring0_canary_unlinkat(ctx: *const u8) -> u32 {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let dir_fd = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(1)) };
    let name_ptr = unsafe { core::ptr::read_unaligned((ctx as *const *const u8).add(2)) };
    let flags = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(3)) };
    if uid == 0 || name_ptr.is_null() {
        return 0;
    }
    let mut path = [0u8; 96];
    unsafe {
        aya_ebpf::helpers::bpf_probe_read_user_str(&mut path as *mut _ as *mut u8, 96, name_ptr);
    }
    let mut comm = [0u8; 16];
    unsafe { aya_ebpf::helpers::bpf_get_current_comm(&mut comm as *mut _ as *mut u8, 16); }
    if is_canary_inode(0) {
        let evt = CanaryEvent {
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            pid,
            uid,
            inode: 0,
            event_type: 1,
            comm,
        };
        if let Some(ring) = unsafe { CANARY_EVENTS.reserve::<CanaryEvent>() } {
            ring.write(evt);
        }
    }
    0
}

#[lsm(function = "security_ptrace_access_check")]
pub fn ring0_lsm_ptrace(ctx: *const u8) -> i32 {
    if !is_lsm_enforced() {
        return 0;
    }
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let target = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(1)) };
    let mut comm = [0u8; 16];
    unsafe { aya_ebpf::helpers::bpf_get_current_comm(&mut comm as *mut _ as *mut u8, 16); }
    let evt = CapEvent {
        timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
        pid,
        uid,
        capability: target,
    };
    if let Some(buf) = unsafe { PRIVESC_EVENTS.reserve::<CapEvent>() } {
        buf.write(evt);
    }
    return -1;
}

#[lsm(function = "security_capable")]
pub fn ring0_lsm_capable(ctx: *const u8) -> i32 {
    if !is_lsm_enforced() {
        return 0;
    }
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let cap = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(1)) };
    if cap == 21 || cap == 12 || cap == 17 {
        let evt = CapEvent {
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            pid,
            uid,
            capability: cap,
        };
        if let Some(buf) = unsafe { PRIVESC_EVENTS.reserve::<CapEvent>() } {
            buf.write(evt);
        }
        return -1;
    }
    0
}

#[tp_btf(name = "sys_enter_setuid")]
pub fn ring0_setuid(ctx: *const u8) -> u32 {
    let pid = unsafe { aya_ebpf::helpers::bpf_get_current_pid_tgid() >> 32 } as u32;
    let uid = unsafe { aya_ebpf::helpers::bpf_get_current_uid_gid() >> 32 } as u32;
    let new_uid = unsafe { core::ptr::read_unaligned((ctx as *const u32).add(1)) };
    if new_uid == 0 && uid != 0 {
        let evt = SetuidEvent {
            timestamp: unsafe { aya_ebpf::helpers::bpf_ktime_get_ns() },
            pid,
            old_uid: uid,
            new_uid,
        };
        if let Some(ring) = unsafe { PRIVESC_EVENTS.reserve::<SetuidEvent>() } {
            ring.write(evt);
        }
    }
    0
}
