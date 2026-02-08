#!/bin/bash
# Test TLS plaintext capture
# Run as: sudo bash test-tls.sh

set -e

AGENT=./target/debug/busted
LOG=/tmp/busted-test.log

echo "=== Starting busted agent ==="
$AGENT --verbose 2>&1 | tee $LOG &
AGENT_PID=$!

# Wait until eBPF programs are loaded
echo "Waiting for eBPF programs to load..."
for i in $(seq 1 30); do
    if grep -q "All eBPF programs loaded" $LOG 2>/dev/null; then
        echo "Agent ready after ${i}s"
        break
    fi
    sleep 1
done

if ! grep -q "All eBPF programs loaded" $LOG 2>/dev/null; then
    echo "ERROR: Agent did not finish loading. Log so far:"
    cat $LOG
    kill $AGENT_PID 2>/dev/null
    exit 1
fi

# Show what probes attached
echo ""
echo "=== Attached probes ==="
grep -iE "attached|uprobe|uretprobe|TLS|libssl|not found" $LOG || echo "(none)"
echo ""

# Check kernel uprobe registrations
echo "=== Kernel uprobes (SSL) ==="
cat /sys/kernel/debug/tracing/uprobe_events 2>/dev/null | grep -i ssl || echo "(none registered)"
echo ""

# Make a test request
echo "=== Sending curl to api.openai.com ==="
curl -s -X POST https://api.openai.com/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer sk-test123" \
  -d '{"model":"gpt-4","messages":[{"role":"user","content":"hello"}]}' > /dev/null 2>&1 || true

echo "=== Waiting for events (5s)... ==="
sleep 5

echo ""
echo "=== TLS-related log lines ==="
grep -iE "TLS|tls_data|ssl_write|ssl_read|first-chunk|boring" $LOG || echo "(none)"

echo ""
echo "=== ALL log lines after 'loaded successfully' ==="
sed -n '/All eBPF programs loaded/,$p' $LOG

echo ""
echo "=== Stopping agent ==="
kill $AGENT_PID 2>/dev/null
wait $AGENT_PID 2>/dev/null || true
rm -f /tmp/busted.sock $LOG
echo "Done."
