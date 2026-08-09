# Ring0  -  Linux eBPF Security Command Center

A high-performance host-based NIDS/HIDS for the Linux desktop. Ring0 inspects
TLS plaintext at the `SSL_read`/`SSL_write` boundary, tracks process lineage
in userspace, scores every connection with a heuristic risk engine, and can
optionally enforce (block/freeze/kill)  -  all with a kernel fast path that is
deliberately cheap enough to run on a consumer laptop without making the
machine feel slow.

```
┌───────────────────────────────────────────────────────────────┐
│ ring0-gui (Qt6/QML, unprivileged)      ring0ctl (CLI)         │
│      │  Cap'n Proto over Unix socket (+ polkit for privesc)   │
├───────────────────────────────────────────────────────────────┤
│ ring0d  (root daemon, Tokio async)                            │
│   ├─ Lineage tree        pid → {ppid, binary, cmdline, cwd}   │
│   ├─ Trust engine        RPM DB verification + memoization    │
│   ├─ DPI engine          28k+ signatures, single O(n) pass    │
│   ├─ Risk engine         score = w_process+w_network+w_payload│
│   ├─ Storage             RocksDB (bounded memtable, WAL-only) │
│   └─ IPC                 Unix socket + polkit gating          │
├───────────────────────────────────────────────────────────────┤
│ ring0-ebpf (#![no_std], Aya)                                  │
│   ├─ XDP  physical-NIC fast-path block (IP/CIDR/port)         │
│   ├─ TC   physical-NIC classifier                             │
│   ├─ Uprobe  TLS plaintext capture, per-connection budget     │
│   └─ Tracepoint  sched_process_exec (lineage feed)            │
└───────────────────────────────────────────────────────────────┘
```

---

## 1. How the whole thing works

The pipeline is a 4-stage cascade. Each stage enriches the signal; the risk
engine decides what (if anything) to do.

```
 telemetry capture ──► lineage & trust ──► risk scoring ──► opt-in enforcement
 (kernel eBPF)        (userspace state)   (decision matrix)  (notify by default)
```

**Stage 1  -  capture.** eBPF programs in the kernel observe traffic with a
strict cost budget (see §5): XDP/TC drop only what is *explicitly blocked*;
TLS uprobes capture only the *interesting prefix* of each connection; the
exec tracepoint feeds the process tree.

**Stage 2  -  context.** Every TLS event is enriched with **who** is talking:
the process binary, its ancestry chain, its trust verdict (RPM-verified or
not), and the destination. *A payload alone rarely tells you something is
malicious  -  context does.*

**Stage 3  -  scoring.** A linear scoring model combines process, network, and
payload evidence into one number. Thresholds map the score to a verdict.

**Stage 4  -  response.** By default high-risk events only alert (freezing or
killing a process can destroy hours of unsaved work). Enforcement is
strictly opt-in via `RING0_RESPONSE`.

---

## 2. Telemetry capture (the kernel)

### 2.1 XDP / TC fast path  -  physical NICs only

Attached to **physical interfaces only** (those with a
`/sys/class/net/<name>/device` symlink  -  PCI/USB NICs). Tunnel interfaces
(`wg*`, `tun*`, `veth*`, `docker0`, `br*`) are **never** filtered, so a
WireGuard VPN's decrypted inner traffic is never dropped against the
blocklist, and the outer encrypted UDP is only ever dropped by *your*
explicit user blocks.

`check_blocked(src_ip, dst_ip, src_port, dst_port)` drops a packet when any
of:

| Condition | Meaning |
|---|---|
| `src_ip` ∈ `BLOCKED_IPS` | Inbound traffic **from** a feed-listed or user-blocked source |
| `dst_ip` ∈ `USER_BLOCKED_IPS` | Outbound to an address **you** explicitly blocked |
| `src_port`/`dst_port` ∈ `BLOCKED_PORTS` | Either endpoint uses a blocked port |

Feed CIDRs (spamhaus-drop, et-compromised, …) are *inbound-threat lists*:
they populate `BLOCKED_IPS` only, so legitimate outbound connections to a
VPN server or service whose hosting IP happens to be listed still work. Your
`ring0ctl block` command writes to **both** maps (explicit intent is enforced
both ways).

### 2.2 TLS plaintext capture  -  the "interesting prefix" model

Uprobes on `SSL_write`/`SSL_read` capture plaintext **before** encryption.
Attached to every `libssl.so` on the machine (system + conda/homebrew
copies), because bundled-libssl apps (anaconda curl, …) would otherwise be
invisible.

The kernel keeps a **per-connection byte budget** keyed by `(pid, SSL*)`:

```
new connection ──► emit plaintext events until ~8 KB captured ──► silent
                     │                                              │
                     ├─ HTTP request boundary (GET/POST/…) detected  │
                     │   → budget re-armed (Keep-Alive / HTTP-2      │
                     │     connection reuse stays visible)           │
                     └─ after the budget: re-arm a fresh 8 KB window │
                        every ~16 MiB transferred (strided sampling) │
                        → long flows get periodic oversight          │
```

**Why this model?** The interesting bytes of any flow are its start:
protocol headers, the request, the first bytes of the response, executable
magic bytes. Everything after that is bulk transfer  -  "just download data".
Scanning a 144 MB download's *entire* body would burn CPU for no detection
value; scanning its first ~8 KB costs ~33 events and catches the signal.

The per-process budget is **trust-aware**: the daemon writes
`TLS_PID_BUDGET` overrides from the trust engine  -  untrusted/unknown
processes (script hosts, `/tmp` binaries) get a 32 KB window (4×), trusted
high-throughput apps get 4 KB. A `flow_id` field in every event
(`(pid << 32) | ssl_low32`) future-proofs the schema for flow-addressed
userspace control.

The system-wide **`sys_enter` tracepoint** (every syscall dispatcher +
openat/connect/mmap probes) is **opt-in** (`RING0_SYSCALL_MONITOR=1`). It is
powerful (rootkit/privesc telemetry) but runs on *every* syscall on the
machine; gating it off by default keeps the daemon's kernel footprint
minimal and predictable.

### 2.3 Exec tracepoint & LSM

`sched_process_exec` feeds the lineage tree. LSM `socket_connect` enforces
user port/IP blocks; `ptrace_access_check` and `capable` hooks are attached
only with `RING0_LSM_ENFORCE=1` (they emit audit events on very hot paths).

---

## 3. Correlation & state engine (userspace)

### 3.1 Process lineage tree

Every exec records `{pid, ppid, binary, cmdline, cwd}`. `ancestry(pid)`
walks the ppid chain to answer *"who is this really from?"*  -  a `python3`
one-liner exec'd by `bash` from `/tmp` is a very different signal than the
same bytes from `/usr/lib64/firefox/firefox`. The tree is bounded (32k
entries) and pruned by `/proc` liveness checks.

### 3.2 Trust engine

Binaries in trusted paths are verified against the **RPM database**
(`rpm -qf` + `rpm -qVf`). Results are memoized by `(path, size, mtime)` so
verification happens once per unchanged binary. Bare command names
(`curl`) are resolved via `PATH`, so short-lived processes are scored
against their real binary instead of being flagged "unknown".

### 3.3 DPI engine  -  single-pass O(n)

All signatures (20 built-in + up to **28,581 Suricata-derived** literals
extracted from `emerging-all.rules`) are compiled into **one** hyperscan
database. Each payload is scanned in a **single O(n) pass** with a shared
scratch buffer  -  not one scan per signature. The userspace scan ceiling
(2000 payloads/sec) is a pure flood safety valve; steady-state cost scales
with *connection starts*, not throughput.

---

## 4. Risk scoring engine  -  the math

### 4.1 The model

Each connection receives a linear score:

```
score = w_process + w_network + w_payload
```

### 4.2 The criteria (weights)

| Category | Factor | Weight |
|---|---|---|
| Process | Binary path under `/tmp`, `/dev/shm`, `/var/tmp`, `/proc`, `/dev`, home cache | +30 |
| Process | Binary untrusted/unverifiable (fails RPM verification) | +25 |
| Process | Parent/ancestor is a script host (`bash`, `python`, `perl`, `curl`, …) | +20 |
| Network | Destination never seen before (no recent connection record) | +15 |
| Network | Non-standard outbound port (not 80/443/8080/8443) | +15 |
| Payload | Hyperscan match severity 4 (critical) | +50 |
| Payload | Hyperscan match severity 3 (high) | +25 |
| Payload | File magic (`\x7fELF`, `MZ`, `PK`, `#!`) in an **upload** | +30 |
| Payload | File magic in a **download** (informational) | +10 |

### 4.3 Verdict thresholds

```
score < 40    → PASS      (log passively)
40 ≤ score < 70 → FLAGGED  ("Suspicious Activity")
score ≥ 70    → HIGH RISK (alert; enforcement only if configured)
```

### 4.4 Examples

| Scenario | Process | Network | Payload | Score | Verdict |
|---|---|---|---|---|---|
| Firefox downloads an ELF from a known site | 0 | 0 | +10 | 10 | PASS |
| `curl` (trusted) to a new host, sev-3 match | 0 | +15 | +25 | 40 | FLAGGED |
| `/tmp/python3` exfil POST, sev-4 match, magic in upload | 30+25+20 | +15+15 | +50+30 | 185 | HIGH RISK |

### 4.5 Enforcement is opt-in

```
RING0_RESPONSE=notify   (default)  → alert + desktop notification
RING0_RESPONSE=block    → block the destination IP in XDP
RING0_RESPONSE=freeze   → SIGSTOP / cgroup-freeze the process
RING0_RESPONSE=kill     → kill the process tree
```

The default is `notify` on purpose: automatic freeze/kill can destroy real
work. The risk engine flags; **you** decide whether it may act.

---

## 5. Performance engineering

| Optimization | Why |
|---|---|
| Single-pass hyperscan | O(n) per payload, one scratch, no per-signature scans |
| Per-connection TLS budget (8 KB) | A 144 MB download → ~33 events, not ~500k |
| Request-boundary budget reset | Keep-Alive/HTTP-2 reuse stays visible at same cost |
| 16 MiB strided re-sampling | Long flows get oversight at ~0.7 events/sec |
| `sys_enter` opt-in | No per-syscall hook by default (was ~19% syscall overhead) |
| openat 8-byte precheck | Full filename probe only for blocked-path candidates |
| Physical-NIC-only attach | No double-filtering of VPN/bridge traffic |
| Raw events not persisted | The `events` CF had zero readers; dropping it removed the RSS "leak" + disk hammer |
| Bounded RocksDB memtable (16 MB) | Shutdown flush is WAL-only → SIGTERM in ~1 s |
| Change-gated governor logs | Was 17k log lines/day; now logs on state change only |

Measured on this machine (i5-9300H, spinning disk): 500k `getpid` overhead
dropped from **118 ns → 30 ns** per syscall; openat from **3 µs → 1.4 µs**;
daemon RSS stable at ~214 MB under live traffic; SIGTERM shutdown ~1 s.

---

## 6. Configuration

| Env var | Default | Meaning |
|---|---|---|
| `RING0_SOCKET` | `/run/ring0d.sock` | IPC socket path |
| `RING0_DB` | `/var/lib/ring0` | RocksDB path |
| `RUST_LOG` | `info` | tracing filter (`debug` for more) |
| `RING0_SYSCALL_MONITOR` | unset | `1` attaches the per-syscall `sys_enter` monitor |
| `RING0_LSM_ENFORCE` | unset | `1` attaches ptrace/capable LSM hooks + enables inline denial |
| `RING0_RESPONSE` | `notify` | `block` / `freeze` / `kill` for high-risk verdicts |
| `RING0_EVENT_LOG` | unset | `1` persists raw events to RocksDB (off by default) |

---

## 7. Build & run

> `cargo` lives in `~/.cargo/bin`, which root's `secure_path` excludes  -  build
> as your user, then run the binary directly as root (it is self-contained).

```bash
# Build eBPF programs (pinned nightly, see xtask)
cargo xtask build

# Build daemon + CLI
cargo build -p ring0d -p ring0ctl

# Build GUI
cmake -S ring0-gui -B ring0-gui/build && cmake --build ring0-gui/build
```

```bash
# Run the daemon (requires root + CAP_BPF; SELinux enforcing is fine)
sudo env RUST_LOG=info ./target/debug/ring0d

./target/debug/ring0ctl status        # verify it's up
./target/debug/ring0ctl tail          # live EXEC/CONNECT/ALERT stream
./target/debug/ring0ctl block 1.2.3.4 # block an IP (polkit-gated)
./ring0-gui/build/ring0-gui           # desktop UI
```

The daemon is **not** installed as a systemd service by design  -  run it when
you want it. Stability is the priority: the kernel footprint is minimal,
enforcement is opt-in, and every hot path is bounded.

---

## 7.5 Security model & hardening

### Threat model

Ring0 defends a single-user desktop against **malware and remote scanners**:

- **Inbound** scanners/exploits (feed CIDRs, port blocks) - blocked at the NIC
  by the XDP/TC fast path (TCP inbound only; UDP/ICMP are never feed-dropped
  so VPN tunnels survive - see §2.1).
- **Malicious local processes** (a downloaded binary phoning home): observed
  via exec/connect/TLS capture, scored by the risk engine (§4), and - only
  when `RING0_RESPONSE` is set - contained (freeze/kill).

**Out of scope by design**: network crypto, disk encryption, or any
anti-forensics guarantees. The eBPF programs are best-effort telemetry, not a
hardened firewall or a mandatory-access-control system.

### Privilege boundaries

| Component | Privilege | Why |
|---|---|---|
| `ring0-gui`, `ring0ctl` | unprivileged (Ring 3) | management/telemetry only |
| `ring0d` | root (CAP_BPF, CAP_NET_ADMIN, CAP_KILL) | loads eBPF, owns the socket |
| eBPF programs | kernel, verifier-vetted | minimal, bounded, no loops |

The GUI/CLI never gain privileges themselves: destructive commands
(`kill`, `block`) are **polkit-gated** (`com.ring0.security.control`,
`auth_admin_keep`) and the daemon re-checks the caller's credentials per
command. A compromised GUI therefore cannot silently freeze processes without
a desktop auth prompt.

### IPC protocol & trust

- Unix datagram stream socket (`/run/ring0d.sock`), 4-byte length-prefixed
  Cap'n Proto frames.
- **Frame bounds**: length `0 < len ≤ 65536` enforced before any parse;
  capnp `ReaderOptions` limits traversal; `QueryLogs.limit` is clamped to
  1000 so an unprivileged peer cannot force an unbounded RocksDB scan.
- **Caller identity** is read per-connection from `SO_PEERCRED` (pid/uid/gid)
  - not parsed from the message - and privileged commands are authorized
  against it (root or `ring0` group bypass; everyone else goes through
  polkitd).
- **Kill hardening**: pid must fit positive `pid_t` (a raw u32 `>= 0x8000_0000`
  would cast to `kill(-1, …)`, signalling every process); pid 0/1/self are
  refused (confused-deputy protection).
- **Socket swap protection**: the daemon binds, then fstat-compares the path
  to the bound inode before chown/chmod - a symlink swap refuses the chmod.

### Binary hardening

Verified on release builds (`readelf`):

- **Full RELRO** (`BIND_NOW`, `FLAGS_1: NOW`) - GOT is read-only after load.
- **PIE** (`Type: DYN`) - ASLR applies to the executable itself.
- **NX** - non-executable stack/heap (kernel default).
- **Rust memory safety** - bounds-checked slices; `unsafe` is limited to
  `libc` FFI with documented contracts + `aya::Pod` impls for plain-old-data.

Deliberate trade-offs: Rust's stable toolchain has **no stack protector** (the
nightly `-Z stack-protector`/`-Z sanitizer=cfi` flags exist but force nightly
builds for the whole daemon). Given bounds-checked code and no
manually-managed buffers, the marginal value is low; revisit if a C ABI
surface is ever added.

### Fuzzing

`ring0d/src/fuzz.rs` runs a seeded PRNG harness under plain `cargo test`
(no nightly, CI-safe) against the three untrusted decode paths:
`parse_command_frame` (IPC), `AlertRecord::decode` (persistence), and the
kernel ABI guard. ~2.6M iterations across seeds in ~25s, zero panics.
For deeper coverage, the same entry points can be wrapped in libFuzzer
targets:

```bash
# (nightly toolchain) add a fuzz/ workspace; feed random frames to
# parse_command_frame + random bytes to the decoders.
```

---

## 8. Crates

| Crate | Role |
|---|---|
| `ring0-ebpf` | Kernel-space eBPF programs (XDP, TC, uprobes, tracepoints) |
| `ring0-abi` | Shared wire contract: event kinds + fixed ring-buffer layouts |
| `ring0d` | Root daemon  -  BPF loader, lineage, trust, DPI, risk, storage, IPC |
| `ring0ctl` | CLI  -  status, tail, query, block/unblock, kill, doctor |
| `ring0-gui` | Qt6/QML desktop UI (RingZero) |
| `ring0-common` | Shared types + Cap'n Proto bindings |
| `xtask` | eBPF build task runner (pinned nightly-2025-05-01, LLVM 20) |

---

## 9. Known limitations

- **IPv6 is not filtered** by the XDP/TC fast path (IPv4 + VLAN only); the
  daemon warns at load.
- **`lsm/bprm_check`** fails to attach on some kernels ("unknown BTF type
  `bpf_lsm_bprm_check`")  -  a kernel-BTF limitation, harmless.
- **HTTP/2 headers are HPACK-compressed**, so UA-based signatures won't match
  on HTTP/2 streams the way they do on HTTP/1.1 plaintext.
- **Bundled/static TLS stacks** that don't call a system `libssl`
  `SSL_write`/`SSL_read` symbol are invisible to the uprobes.
- Enforcement (freeze/kill) is opt-in and never the default  -  see §4.5.
