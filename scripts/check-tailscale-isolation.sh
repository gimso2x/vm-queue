#!/usr/bin/env bash
set -euo pipefail

PORT=8790
AUTO_DOWN=0
NETMAP_FILE=""
STATUS_FILE=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --port)
      PORT="${2:-}"
      shift 2
      ;;
    --auto-down)
      AUTO_DOWN=1
      shift
      ;;
    --netmap-file)
      NETMAP_FILE="${2:-}"
      shift 2
      ;;
    --status-file)
      STATUS_FILE="${2:-}"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [--port 8790] [--auto-down] [--netmap-file PATH] [--status-file PATH]"
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -n "$NETMAP_FILE" ]]; then
  NETMAP_JSON="$(cat "$NETMAP_FILE")"
else
  NETMAP_JSON="$(sudo tailscale debug netmap)"
fi

if [[ -n "$STATUS_FILE" ]]; then
  STATUS_JSON="$(cat "$STATUS_FILE")"
else
  STATUS_JSON="$(tailscale status --json)"
fi

set +e
CHECK_OUT="$(
  TARGET_PORT="$PORT" NETMAP_JSON="$NETMAP_JSON" STATUS_JSON="$STATUS_JSON" python3 - << 'PY'
import json
import os
import sys

port = int(os.environ["TARGET_PORT"])
netmap = json.loads(os.environ["NETMAP_JSON"])
status = json.loads(os.environ["STATUS_JSON"])

pf = netmap.get("PacketFilter") or []
if not pf:
    print("FAIL: PacketFilter is empty")
    sys.exit(1)

for idx, rule in enumerate(pf):
    srcs = rule.get("Srcs") or []
    for src in srcs:
        if src in ("0.0.0.0/0", "::/0"):
            print(f"FAIL: PacketFilter[{idx}] allows wildcard source {src}")
            sys.exit(1)

worker_ips = set()
for peer in (status.get("Peer") or {}).values():
    tags = peer.get("Tags") or []
    if "tag:worker" in tags:
        for ip in peer.get("TailscaleIPs") or []:
            worker_ips.add(f"{ip}/32" if ":" not in ip else f"{ip}/128")

def is_worker_rule(rule: dict) -> bool:
    srcs = set(rule.get("Srcs") or [])
    if worker_ips and (srcs & worker_ips):
        return True
    dsts = rule.get("Dsts") or []
    # Also verify non-wildcard restricted rules do not expose admin ports
    return any(
        d.get("Ports", {}).get("First") != 0 or d.get("Ports", {}).get("Last") != 65535
        for d in dsts
    )

worker_port_seen = False
for idx, rule in enumerate(pf):
    if not is_worker_rule(rule):
        continue
    protos = set(rule.get("IPProto") or [])
    if protos and protos != {6}:
        print(f"FAIL: PacketFilter[{idx}] worker rule allows non-TCP protocols {sorted(protos)}")
        sys.exit(1)
    for dst in rule.get("Dsts") or []:
        ports = dst.get("Ports") or {}
        first = ports.get("First")
        last = ports.get("Last")
        if first != port or last != port:
            print(f"FAIL: PacketFilter[{idx}] exposes unexpected port range {first}-{last} (expected {port})")
            sys.exit(1)
        worker_port_seen = True

if worker_ips and not worker_port_seen:
    print(f"FAIL: tag:worker peers present ({len(worker_ips)} IPs) but no tcp:{port} PacketFilter rule found")
    sys.exit(1)

print(f"PASS: PacketFilter_count={len(pf)}, wildcard_srcs=0, worker_tcp_port={port}, worker_ips={len(worker_ips)}")
PY
)"
STATUS=$?
set -e

echo "$CHECK_OUT"
if [[ $STATUS -ne 0 ]]; then
  if [[ $AUTO_DOWN -eq 1 ]]; then
    echo "Isolation check failed; executing sudo tailscale down" >&2
    sudo tailscale down || true
  fi
  exit "$STATUS"
fi
