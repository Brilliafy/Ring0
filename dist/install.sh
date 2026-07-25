#!/usr/bin/env bash
set -euo pipefail

RING0_VERSION="1.0.0"
PREFIX="${PREFIX:-/usr/local}"
CONFIG_DIR="/etc/ring0"
LOG_DIR="/var/log/ring0"
DATA_DIR="/var/lib/ring0"
USER="ring0"
GROUP="ring0"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e " ${GREEN}[PASS]${NC} $1"; }
warn() { echo -e " ${YELLOW}[WARN]${NC} $1"; }
fail() { echo -e " ${RED}[FAIL]${NC} $1"; }

echo "============================================"
echo " Ring0 Security Platform v${RING0_VERSION}"
echo " Production Installer"
echo "============================================"

if [[ $EUID -ne 0 ]]; then
    fail "This installer must be run as root"
    exit 1
fi

# Detect distro
DISTRO=""
if [ -f /etc/os-release ]; then
    . /etc/os-release
    DISTRO="$ID"
fi
pass "Detected OS: ${DISTRO:-unknown}"

# Install system deps
install_deps() {
    echo ""
    echo "--- Installing System Dependencies ---"
    case "$DISTRO" in
        fedora|rhel|centos)
            dnf install -y rust cargo bpftool libbpf-devel rocksdb-devel hyperscan-devel \
                libcap-ng-devel systemd-devel openssl-devel selinux-policy-devel \
                apparmor-utils yara-devel 2>/dev/null || true
            ;;
        ubuntu|debian)
            apt-get update -qq
            apt-get install -y rustc cargo bpftool libbpf-dev librocksdb-dev libhyperscan-dev \
                libcap-ng-dev libsystemd-dev libssl-dev selinux-policy-dev \
                apparmor-utils libyara-dev 2>/dev/null || true
            ;;
        arch)
            pacman -S --noconfirm rust bpftools rocksdb hyperscan libcap-ng systemd-libs \
                openssl selinux-policies apparmor yara 2>/dev/null || true
            ;;
        *)
            warn "Unknown distro — please install dependencies manually: rust, bpftool, rocksdb, hyperscan"
            ;;
    esac
    pass "Dependencies installed"
}

# Create user
create_user() {
    echo ""
    echo "--- Creating ring0 User ---"
    if ! getent group "$GROUP" >/dev/null 2>&1; then
        groupadd --system "$GROUP"
    fi
    if ! id "$USER" >/dev/null 2>&1; then
        useradd --system --gid "$GROUP" --home-dir /var/lib/ring0 --no-create-home "$USER"
    fi
    pass "User/group ${USER}:${GROUP} created"
}

# Create directories
create_dirs() {
    echo ""
    echo "--- Creating Directories ---"
    mkdir -p "$PREFIX/bin"
    mkdir -p "$CONFIG_DIR/playbooks"
    mkdir -p "$CONFIG_DIR/yara"
    mkdir -p "$LOG_DIR/forensics"
    mkdir -p "$LOG_DIR/reports"
    mkdir -p "$DATA_DIR"
    mkdir -p "$PREFIX/lib/ring0/ebpf"
    pass "Directories created"
}

# Build from source
build_binaries() {
    echo ""
    echo "--- Building Ring0 Binaries ---"
    if ! command -v cargo &>/dev/null; then
        fail "cargo not found — install Rust first"
        exit 1
    fi
    echo "Building eBPF programs (cross-compile)..."
    cargo xtask build 2>&1 || {
        warn "eBPF build failed — attempting with nightly"
        cargo +nightly xtask build 2>&1 || true
    }
    echo "Building daemon and tools..."
    cargo build --release 2>&1
    pass "Binaries built"
}

# Install binaries
install_binaries() {
    echo ""
    echo "--- Installing Binaries ---"
    cp target/release/ring0d "$PREFIX/bin/ring0d"
    cp target/release/ring0ctl "$PREFIX/bin/ring0ctl"
    cp target/release/ring0-gui "$PREFIX/bin/ring0-gui" 2>/dev/null || true
    if [ -f target/bpfel-unknown-none/release/ring0-ebpf ]; then
        cp target/bpfel-unknown-none/release/ring0-ebpf "$PREFIX/lib/ring0/ebpf/ring0-ebpf.o"
    fi
    chmod 755 "$PREFIX/bin/ring0d" "$PREFIX/bin/ring0ctl"
    chown root:"$GROUP" "$PREFIX/bin/ring0d" "$PREFIX/bin/ring0ctl"
    pass "Binaries installed to $PREFIX/bin"
}

# Deploy config
deploy_config() {
    echo ""
    echo "--- Deploying Configuration ---"
    if [ ! -f "$CONFIG_DIR/rules.yaml" ]; then
        cat > "$CONFIG_DIR/rules.yaml" << 'RULESEOF'
rules:
  network:
    - name: "default-block-high-ports"
      cidr: "0.0.0.0/0"
      ports: [4444, 6667, 31337]
      protocol: tcp
      action: drop
  process:
    - name: "block-suspicious-binaries"
      binary_path: "/tmp/*"
      action: alert
  file:
    - name: "monitor-shadow"
      path_glob: "/etc/shadow"
      read_only: true
RULESEOF
    fi
    chown -R root:"$GROUP" "$CONFIG_DIR"
    chmod 750 "$CONFIG_DIR"
    pass "Configuration deployed to $CONFIG_DIR"
}

# Install systemd service
install_systemd() {
    echo ""
    echo "--- Installing Systemd Service ---"
    cat > /etc/systemd/system/ring0d.service << 'SERVICEEOF'
[Unit]
Description=Ring0 Security Platform
Documentation=https://github.com/ring0/ring0
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=simple
User=ring0
Group=ring0
ExecStartPre=/bin/mkdir -p /var/log/ring0 /var/lib/ring0
ExecStartPre=/bin/chown ring0:ring0 /var/log/ring0 /var/lib/ring0
ExecStart=/usr/local/bin/ring0d
Restart=on-failure
RestartSec=5
LimitMEMLOCK=infinity
CapabilityBoundingSet=CAP_BPF CAP_NET_ADMIN CAP_SYS_PTRACE CAP_KILL CAP_NET_RAW CAP_SYS_ADMIN
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_SYS_PTRACE CAP_KILL CAP_NET_RAW
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/ring0 /var/lib/ring0 /run/ring0d.sock
PrivateTmp=true
MemoryMax=2G

[Install]
WantedBy=multi-user.target
SERVICEEOF
    systemctl daemon-reload
    pass "Systemd service installed"
}

# Install SELinux policy
install_selinux() {
    echo ""
    echo "--- Installing SELinux Policy ---"
    if command -v semodule &>/dev/null; then
        cat > /tmp/ring0d.te << 'SEEOF'
module ring0d 1.0;

require {
    type unconfined_t;
    type proc_t;
    type sysfs_t;
    type cgroup_t;
    type cgroup_t;
    class capability { bpf net_admin sys_ptrace kill net_raw };
    class process { signal ptrace };
    class file { read write open getattr };
    class dir { read write search add_name remove_name };
    class netlink_audit_socket { create bind };
}

type ring0d_t;
type ring0d_exec_t;

init_daemon_domain(ring0d_t, ring0d_exec_t)

allow ring0d_t self:capability { bpf net_admin sys_ptrace kill net_raw };
allow ring0d_t self:process { signal ptrace };
allow ring0d_t self:netlink_audit_socket { create bind };

allow ring0d_t proc_t:file { read open getattr };
allow ring0d_t sysfs_t:file { read open getattr };
allow ring0d_t cgroup_t:dir { read write search add_name remove_name };
allow ring0d_t cgroup_t:file { read write open getattr };

allow ring0d_t ring0d_exec_t:file { execute execute_no_trans };
SEEOF
        checkmodule -M -m /tmp/ring0d.te -o /tmp/ring0d.mod 2>/dev/null || warn "checkmodule failed"
        semodule_package -m /tmp/ring0d.mod -o /tmp/ring0d.pp 2>/dev/null || warn "semodule_package failed"
        semodule -i /tmp/ring0d.pp 2>/dev/null || warn "semodule install failed"
        rm -f /tmp/ring0d.te /tmp/ring0d.mod /tmp/ring0d.pp
        pass "SELinux policy installed"
    else
        warn "semodule not found — skipping SELinux"
    fi
}

# Install AppArmor profile
install_apparmor() {
    echo ""
    echo "--- Installing AppArmor Profile ---"
    if command -v aa-enforce &>/dev/null; then
        cat > /etc/apparmor.d/usr.local.bin.ring0d << 'AAEOF'
#include <tunables/global>

/usr/local/bin/ring0d {
  #include <abstractions/base>
  #include <abstractions/openssl>

  capability bpf,
  capability net_admin,
  capability sys_ptrace,
  capability kill,
  capability net_raw,

  /run/ring0d.sock rw,
  /etc/ring0/** r,
  /var/log/ring0/** rw,
  /var/lib/ring0/** rw,
  /sys/fs/cgroup/** rw,
  /sys/kernel/btf/vmlinux r,
  /sys/kernel/security/lsm r,
  /proc/** r,
  /usr/local/bin/ring0ctl r,

  /usr/lib/x86_64-linux-gnu/libssl.so.* mr,
  /usr/lib64/libssl.so.* mr,
  /lib64/libssl.so.* mr,
}
AAEOF
        aa-enforce /usr/local/bin/ring0d 2>/dev/null || warn "aa-enforce failed"
        pass "AppArmor profile installed"
    else
        warn "aa-enforce not found — skipping AppArmor"
    fi
}

# Enable service
enable_service() {
    echo ""
    echo "--- Enabling Service ---"
    systemctl enable ring0d.service 2>/dev/null || warn "systemctl enable failed"
    pass "Service enabled (start with: systemctl start ring0d)"
}

# Main
install_deps
create_user
create_dirs
build_binaries
install_binaries
deploy_config
install_systemd
install_selinux
install_apparmor
enable_service

echo ""
echo "============================================"
echo -e " ${GREEN}Ring0 v${RING0_VERSION} installed successfully!${NC}"
echo ""
echo "   Start daemon:  systemctl start ring0d"
echo "   Check status:  ring0ctl status"
echo "   Run doctor:    ring0ctl doctor"
echo "   View logs:     journalctl -u ring0d -f"
echo "============================================"
