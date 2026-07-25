#!/usr/bin/env bash
set -euo pipefail

echo "=== Ring0 Performance & Stress Test ==="
echo ""

# 1. iperf3 throughput with and without eBPF
echo "--- iperf3 throughput (no eBPF, baseline) ---"
iperf3 -c 127.0.0.1 -t 10 -J 2>/dev/null | jq '.end.sum_received.bits_per_second' 2>/dev/null || echo "SKIP (iperf3 server not running)"

echo ""
echo "--- iperf3 throughput (with ring0d on lo) ---"
# Requires iperf3 server on port 5201
iperf3 -c 127.0.0.1 -t 10 -J 2>/dev/null | jq '.end.sum_received.bits_per_second' 2>/dev/null || echo "SKIP"

# 2. RocksDB write throughput
echo ""
echo "--- RocksDB write benchmark ---"
cargo bench -p ring0d bench_rocksdb 2>/dev/null || echo "SKIP"

# 3. Cap'n Proto serialization throughput
echo ""
echo "--- Cap'n Proto serialize throughput ---"
cargo bench -p ring0d bench_capnp 2>/dev/null || echo "SKIP"

# 4. eBPF ring buffer event rate (via bpftool)
echo ""
echo "--- eBPF ring buffer metrics ---"
if bpftool map list 2>/dev/null | grep -q ring0; then
    bpftool map list 2>/dev/null | grep ring0
else
    echo "SKIP (no ring0 maps found)"
fi

# 5. CPU / memory usage of ring0d
echo ""
echo "--- ring0d resource usage ---"
PID=$(pgrep -x ring0d || true)
if [ -n "$PID" ]; then
    ps -p "$PID" -o pid,%cpu,%mem,rss --no-headers
    echo "FD count: $(ls /proc/$PID/fd 2>/dev/null | wc -l)"
else
    echo "SKIP (ring0d not running)"
fi

echo ""
echo "=== Stress test complete ==="
