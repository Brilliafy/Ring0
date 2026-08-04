fn main() -> aya_build::Result<()> {
    // Emit `--cfg bpf_target_arch="..."` so `#[cfg(bpf_target_arch = "x86_64")]`
    // gates in this crate select the correct architecture (see aya-ebpf).
    aya_build::emit_bpf_target_arch_cfg()
}
