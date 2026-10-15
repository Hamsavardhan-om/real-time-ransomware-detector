#!/bin/bash
set -e
mkdir -p /tmp/ransom_test
rm -f /tmp/ransom_test/events.jsonl /tmp/ransom_test/*.txt*

./ebpf/sensor_loader --watch-dir /tmp/ransom_test --jsonl /tmp/ransom_test/events.jsonl --no-stdout &
SENSOR_PID=$!
sleep 1

python3 workloads/smoke_test.py

sleep 1
kill -INT $SENSOR_PID 2>/dev/null || true
wait $SENSOR_PID 2>/dev/null || true

echo "=== Captured Events ==="
cat /tmp/ransom_test/events.jsonl
