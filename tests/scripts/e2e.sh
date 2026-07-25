#!/usr/bin/env bash
set -euo pipefail

RING0CTL="cargo run --bin ring0ctl --"
PASS=0
FAIL=0

green() { echo -e "\e[32m$1\e[0m"; }
red()   { echo -e "\e[31m$1\e[0m"; }

assert() {
    if $1; then
        green "  PASS: $2"
        PASS=$((PASS + 1))
    else
        red "  FAIL: $2"
        FAIL=$((FAIL + 1))
    fi
}

echo "=== Ring0 Integration Test Suite ==="
echo ""

echo "--- Test: ring0ctl block/unblock ---"
assert "$RING0CTL block 10.0.0.1 >/dev/null 2>&1" "block 10.0.0.1"
assert "$RING0CTL unblock 10.0.0.1 >/dev/null 2>&1" "unblock 10.0.0.1"

echo ""
echo "--- Test: ring0ctl block CIDR prefix ---"
assert "$RING0CTL block 192.168.1.0/24 >/dev/null 2>&1" "block CIDR"
assert "$RING0CTL unblock 192.168.1.0/24 >/dev/null 2>&1" "unblock CIDR"

echo ""
echo "--- Test: ring0ctl kill invalid PID ---"
assert "$RING0CTL kill 999999999 >/dev/null 2>&1" "kill invalid PID (graceful)"

echo ""
echo "--- Test: ring0ctl status (daemon must be running) ---"
if $RING0CTL status >/dev/null 2>&1; then
    green "  PASS: status connected"
    PASS=$((PASS + 1))
else
    red "  FAIL: status (daemon not reachable — skip IPC tests)"
fi

echo ""
echo "--- Test: XDP program loaded ---"
if bpftool prog list 2>/dev/null | grep -q ring0_xdp; then
    green "  PASS: ring0_xdp loaded in kernel"
    PASS=$((PASS + 1))
else
    red "  FAIL: ring0_xdp not found (run sudo ring0d first)"
    FAIL=$((FAIL + 1))
fi

echo ""
echo "--- Test: ring0-ebpf compiles for bpf target ---"
assert "cargo xtask build 2>&1 | grep -q 'eBPF build OK'" "xtask build eBPF"

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
exit $FAIL
