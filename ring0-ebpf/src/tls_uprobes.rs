use aya_ebpf::{macros::uprobe, maps::RingBuf, programs::ProbeContext};

#[repr(C)]
pub struct TlsEvent {
    pub timestamp: u64,
    pub pid: u32,
    pub direction: u8,
    pub len: u32,
    pub buf: [u8; 256],
}

fn capture_tls_event(ctx: &ProbeContext, direction: u8) {
    if let Some(ring) = unsafe { RingBuf::get(&crate::RING_BUF) } {
        if let Some(evt) = ring.reserve::<TlsEvent>() {
            let pid = ctx.pid();
            let buf_ptr = ctx.arg(1).unwrap_or(0) as *const u8;
            let raw_len = ctx.arg(2).unwrap_or(0) as u32;
            let len = if raw_len > 256 { 256 } else { raw_len };
            let mut buf = [0u8; 256];
            if !buf_ptr.is_null() {
                for i in 0..len as usize {
                    buf[i] = unsafe { *buf_ptr.add(i) };
                }
            }
            evt.write(TlsEvent {
                timestamp: ctx.start_time(),
                pid,
                direction,
                len,
                buf,
            });
        }
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
