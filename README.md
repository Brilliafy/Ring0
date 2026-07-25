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

# Run daemon (requires root + CAP_BPF)
sudo cargo xtask run

# Build GUI
cargo build -p ring0-gui
```

## Crates

| Crate | Role |
|---|---|
| `ring0-ebpf` | Kernel-space eBPF programs (XDP, TC, uprobes) |
| `ring0d` | Root daemon — BPF loader, DPI, storage, IPC |
| `ring0-gui` | Qt6/QML desktop UI (RingZero) |
| `ring0-common` | Shared types, constants, Cap'n Proto bindings |
| `xtask` | eBPF build task runner |
