# Ring0 — Linux eBPF Security Command Center

High-performance NIDS/HIDS with live threat response.

## Architecture

```
┌─────────────────────────────────────────────────┐
│ ring0-gui  (Qt6/QML, unprivileged)             │
│     │ Cap'n Proto over Unix socket             │
├─────────────────────────────────────────────────┤
│ ring0d     (root daemon, Tokio async)          │
│  ├─ eBPF    XDP/TC/uprobe ring buffer consumer │
│  ├─ DPI     Hyperscan SIMD pattern matching    │
│  ├─ Storage RocksDB (LSM-Tree, column families)│
│  └─ IPC     Unix socket server                 │
├─────────────────────────────────────────────────┤
│ ring0-ebpf (#![no_std], Aya)                   │
│  ├─ XDP     L3/L4 fast-path drop               │
│  ├─ TC      Ingress/egress monitor             │
│  └─ Uprobe  libssl.so plaintext capture        │
└─────────────────────────────────────────────────┘
```

## Build

```bash
# Build eBPF programs
cargo xtask build

# Build daemon, CLI, GUI
cargo build -p ring0d -p ring0ctl
cmake -S ring0-gui -B ring0-gui/build && cmake --build ring0-gui/build
```

## Run

> `cargo` lives in `~/.cargo/bin`, which root's `secure_path` excludes — so `sudo cargo` fails.
> Build as your user, then run the binary directly as root (it is self-contained):

```bash
# Run daemon (requires root + CAP_BPF)
cargo build -p ring0d
sudo env RUST_LOG=info ./target/debug/ring0d

# GUI (connect daemon first)
./ring0-gui/build/ring0-gui

# CLI
./target/debug/ring0ctl status
```

## Crates

| Crate | Role |
|---|---|
| `ring0-ebpf` | Kernel-space eBPF programs (XDP, TC, uprobes) |
| `ring0d` | Root daemon — BPF loader, DPI, storage, IPC |
| `ring0-gui` | Qt6/QML desktop UI (RingZero) |
| `ring0-common` | Shared types, constants, Cap'n Proto bindings |
| `xtask` | eBPF build task runner |
