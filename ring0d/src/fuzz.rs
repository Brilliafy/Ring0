//! Deterministic in-process fuzzing of the untrusted decode paths.
//!
//! The IPC command parser accepts bytes from ANY local process (the socket is
//! world-readable in the permissive fallback); alert records are decoded from
//! the persistence layer; kernel ring events are decoded from the eBPF
//! buffers. Any panic or OOB access in these paths is a denial-of-service or
//! memory-safety bug, so they are exercised with structured random input.
//!
//! This is a seeded PRNG fuzz (xorshift64*) that runs under plain `cargo
//! test` - no nightly, no cargo-fuzz - so it is part of normal CI. For deeper
//! coverage, the same entry points can be wrapped in libFuzzer targets
//! (see README "Fuzzing").

use crate::ipc::parse_command_frame;

/// xorshift64* - small, deterministic, no_std-style PRNG.
struct XorShift(u64);

impl XorShift {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }

    fn next_u8(&mut self) -> u8 {
        (self.next_u64() >> 56) as u8
    }

    /// Fill a byte buffer with pseudo-random bytes, occasionally producing
    /// structured fragments (length-prefix-like heads, all-zeros, text).
    fn fill(&mut self, buf: &mut [u8], structured: bool) {
        let mut i = 0usize;
        while i < buf.len() {
            let b = match self.next_u8() {
                // ~1/16 chance of a structured byte (length prefix head, text)
                _ if structured && self.next_u8() < 16 => match self.next_u8() % 6 {
                    0 => 0x00,
                    1 => 0x01,
                    2 => b'A',
                    3 => 0x7f,
                    4 => 0xff,
                    _ => b' ',
                },
                b => b,
            };
            buf[i] = b;
            i += 1;
        }
    }
}

fn fuzz_parse_command_frame(rng: &mut XorShift, iters: usize) {
    let mut buf = vec![0u8; 65536];
    for i in 0..iters {
        let len = (rng.next_u64() % 70000) as usize;
        let structured = i % 3 != 0; // 1/3 fully random, rest structured
        let n = len.min(buf.len());
        let slice = &mut buf[..n];
        rng.fill(slice, structured);
        // Every input must be rejected gracefully: Err (parse) or Ok (a
        // valid command that later passes through privilege checks). A panic
        // here fails the test.
        let _ = parse_command_frame(slice, 42);
    }
}

fn fuzz_alert_record_decode(rng: &mut XorShift, iters: usize) {
    let mut buf = vec![0u8; 256];
    for i in 0..iters {
        let len = (rng.next_u64() % 260) as usize;
        let n = len.min(buf.len());
        let slice = &mut buf[..n];
        rng.fill(slice, i % 2 == 0);
        let _ = crate::alert::AlertRecord::decode(slice);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fuzz_command_frame_never_panics() {
        // capnp parse ~0.3ms/input - keep the count CI-friendly.
        for seed in [1u64, 0xdeadbeef, 0x9e3779b97f4a7c15, 42, 0xffffffffffffffff] {
            let mut rng = XorShift(seed);
            fuzz_parse_command_frame(&mut rng, 10_000);
        }
    }

    #[test]
    fn fuzz_alert_record_never_panics() {
        for seed in [7u64, 0x1234, 0xcafebabe, 0x55, 0x1111_2222_3333_4444] {
            let mut rng = XorShift(seed);
            fuzz_alert_record_decode(&mut rng, 200_000);
        }
    }

    #[test]
    fn fuzz_kernel_abi_guard_never_panics() {
        // The eBPF ring events are trusted-ish (kernel-generated) but the
        // ABI guard must never itself panic on a truncated/oversized frame.
        use crate::event_len_ok;
        for seed in [3u64, 0xabcdef, 0x7777, 0x1111_2222_3333_4444, 0x99] {
            let mut rng = XorShift(seed);
            let mut buf = vec![0u8; 512];
            for _ in 0..200_000 {
                let n = (rng.next_u64() % 520) as usize;
                let len = n.min(buf.len());
                rng.fill(&mut buf[..len], false);
                let _ = event_len_ok(buf[0], len);
            }
        }
    }
}
