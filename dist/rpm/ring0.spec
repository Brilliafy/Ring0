%global rust_toolchain rust
%global crate_name ring0

Name:           ring0
Version:        0.1.0
Release:        1%{?dist}
Summary:        Linux eBPF Security Command Center

License:        MIT
URL:            https://github.com/ring0/ring0
Source0:        %{crate_name}-%{version}.tar.gz

BuildRequires:  %{rust_toolchain} >= 1.85
BuildRequires:  cargo
BuildRequires:  clang
BuildRequires:  llvm-devel
BuildRequires:  kernel-devel
BuildRequires:  libpcap-devel
BuildRequires:  cmake
BuildRequires:  systemd
BuildRequires:  qt6-qtbase-devel
BuildRequires:  qt6-qtdeclarative-devel
BuildRequires:  hyperscan-devel
BuildRequires:  rocksdb-devel
BuildRequires:  capnproto-devel

Requires:       systemd
Requires:       kernel >= 5.10
Requires:       libcap-ng-utils
Requires:       %{name}-ebpf = %{version}-%{release}
Requires:       %{name}-common = %{version}-%{release}

%description
Ring0 is a high-performance Linux NIDS/HIDS with live threat response
using eBPF, Hyperscan DPI, and RocksDB storage.

%package ebpf
Summary: Ring0 eBPF kernel programs
Requires: kernel >= 5.10

%description ebpf
eBPF XDP, TC classifier, and libssl uprobe programs for Ring0.

%package common
Summary: Ring0 shared library and IPC types

%description common
Shared data structures, Cap'n Proto bindings, and constants.

%package daemon
Summary: Ring0 root daemon (ring0d)
Requires: %{name}-ebpf = %{version}-%{release}
Requires: %{name}-common = %{version}-%{release}
Requires(pre): systemd

%description daemon
Ring0 root daemon service — loads eBPF, runs DPI, writes to RocksDB.

%package gui
Summary: RingZero Qt6 GUI frontend
Requires: %{name}-common = %{version}-%{release}
Requires: qt6-qtbase
Requires: qt6-qtdeclarative

%description gui
RingZero dark-mode desktop dashboard for Ring0.

%package cli
Summary: ring0ctl CLI for headless control
Requires: %{name}-common = %{version}-%{release}

%description cli
Terminal-native control and monitoring tool for Ring0.

%prep
%setup -q -n %{crate_name}-%{version}

%build
# Build eBPF programs
cargo xtask build

# Build user-space binaries
export CFLAGS="%{optflags}"
export LDFLAGS="%{__global_ldflags}"
cargo build --release \
    -p ring0d \
    -p ring0ctl \
    -p ring0-gui \
    -p ring0-common

%install
# Daemon binary
install -Dm0755 target/release/ring0d %{buildroot}%{_bindir}/ring0d
# CLI binary
install -Dm0755 target/release/ring0ctl %{buildroot}%{_bindir}/ring0ctl
# GUI binary
install -Dm0755 target/release/ring0-gui %{buildroot}%{_bindir}/ring0-gui
# eBPF object
install -Dm0644 target/bpfel-unknown-none/release/ring0-ebpf \
    %{buildroot}%{_datadir}/ring0/ring0-ebpf.o
# Systemd unit
install -Dm0644 dist/ring0d.service %{buildroot}%{_unitdir}/ring0d.service
# Shared library
install -Dm0755 target/release/libring0_common.so \
    %{buildroot}%{_libdir}/libring0_common.so 2>/dev/null || true
# IPC schema
install -Dm0644 schema/event.capnp %{buildroot}%{_datadir}/ring0/event.capnp

%post daemon
%systemd_post ring0d.service

%preun daemon
%systemd_preun ring0d.service

%postun daemon
%systemd_postun_with_restart ring0d.service

%files ebpf
%{_datadir}/ring0/ring0-ebpf.o

%files common
%{_datadir}/ring0/event.capnp

%files daemon
%{_bindir}/ring0d
%{_unitdir}/ring0d.service

%files gui
%{_bindir}/ring0-gui

%files cli
%{_bindir}/ring0ctl

%changelog
* Fri Jul 24 2026 Ring0 Team <dev@ring0.io> - 0.1.0-1
- Initial Fedora package
- eBPF XDP/TC/uprobe programs
- ring0d daemon with Hyperscan DPI and RocksDB storage
- ring0ctl CLI and RingZero GUI
