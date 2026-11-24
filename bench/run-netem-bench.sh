#!/usr/bin/env bash
set -euo pipefail

/app/target/release/wisp-wt-relay \
  --wt-bind 127.0.0.1:4433 \
  --ws-bind 127.0.0.1:4434 \
  --dev-http-bind 127.0.0.1:4435 \
  --self-signed \
  --allow-any-origin \
  --allow-loopback \
  >/tmp/relay.log 2>&1 &
RELAY_PID=$!
trap 'kill $RELAY_PID 2>/dev/null || true; tc qdisc del dev lo root 2>/dev/null || true' EXIT

CERT_HEX=""
for _ in $(seq 1 50); do
  if [ -f /tmp/relay.log ]; then
    CERT_HEX=$(sed -E 's/\x1b\[[0-9;]*m//g' /tmp/relay.log | grep -oE 'sha256_hex=[0-9a-f]+' | head -n1 | cut -d= -f2 || true)
    if [ -n "$CERT_HEX" ]; then
      break
    fi
  fi
  sleep 0.1
done

if [ -z "$CERT_HEX" ]; then
  echo "Failed to extract sha256_hex from /tmp/relay.log:" >&2
  cat /tmp/relay.log >&2
  exit 1
fi

setup_netem() {
  local loss="$1"
  tc qdisc del dev lo root 2>/dev/null || true
  tc qdisc add dev lo root handle 1: prio
  if [ "$loss" = "0" ]; then
    tc qdisc add dev lo parent 1:3 handle 30: netem delay 30ms
  else
    tc qdisc add dev lo parent 1:3 handle 30: netem delay 30ms loss "${loss}%"
  fi
  # Match UDP/4433 (WT) and TCP/4434 (WS) on both sport and dport, leaving origin 9000 unimpaired.
  tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip protocol 17 0xff match ip dport 4433 0xffff flowid 1:3
  tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip protocol 17 0xff match ip sport 4433 0xffff flowid 1:3
  tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip protocol 6 0xff match ip dport 4434 0xffff flowid 1:3
  tc filter add dev lo protocol ip parent 1:0 prio 1 u32 match ip protocol 6 0xff match ip sport 4434 0xffff flowid 1:3
}

for LOSS in 0 1 2 3; do
  echo "=== LOSS=${LOSS}% (30ms one-way / ~60ms RTT) ==="
  setup_netem "$LOSS"
  /app/target/release/wisp-wt-bench \
    --wt-addr 127.0.0.1:4433 \
    --ws-addr 127.0.0.1:4434 \
    --origin-addr 127.0.0.1:9000 \
    --cert-sha256-hex "$CERT_HEX" \
    --start-origin \
    --json
  tc -s qdisc show dev lo | grep -E "qdisc netem|Sent "
done
