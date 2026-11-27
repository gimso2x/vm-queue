#!/usr/bin/env bash
set -euo pipefail

CHECK_ONLY=0
ENV_FILE="$HOME/services/vm-queue/.env"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check-only)
      CHECK_ONLY=1
      shift
      ;;
    -h|--help)
      echo "Usage: $0 [--check-only] [path/to/.env]"
      exit 0
      ;;
    *)
      ENV_FILE="$1"
      shift
      ;;
  esac
done

if [[ ! -f "$ENV_FILE" ]]; then
  echo "Error: env file not found: $ENV_FILE" >&2
  exit 2
fi

TOKEN="$(sed -n 's/^VM_QUEUE_WORKER_TOKEN=//p' "$ENV_FILE" | head -n 1 | tr -d '\r\n')"
if [[ -z "$TOKEN" ]]; then
  echo "Error: VM_QUEUE_WORKER_TOKEN is missing or empty in $ENV_FILE" >&2
  exit 1
fi

if [[ "$TOKEN" =~ ^[Bb][Ee][Aa][Rr][Ee][Rr][[:space:]] ]] || [[ "$TOKEN" =~ ^VM_QUEUE_ ]]; then
  echo "Error: VM_QUEUE_WORKER_TOKEN contains an unexpected prefix" >&2
  exit 1
fi

if [[ "$TOKEN" == *"<"* ]] || [[ "$TOKEN" == *">"* ]] || [[ "$TOKEN" == *\"* ]] || [[ "$TOKEN" == *"'"* ]]; then
  echo "Error: VM_QUEUE_WORKER_TOKEN contains brackets or quotes" >&2
  exit 1
fi

if [[ "$TOKEN" =~ [[:space:]] ]]; then
  echo "Error: VM_QUEUE_WORKER_TOKEN contains whitespace" >&2
  exit 1
fi

LEN=${#TOKEN}
if [[ $LEN -lt 24 ]]; then
  echo "Error: VM_QUEUE_WORKER_TOKEN is too short (len=$LEN)" >&2
  exit 1
fi

if [[ $CHECK_ONLY -eq 1 ]]; then
  echo "OK len=$LEN"
  exit 0
fi

printf '%s\n' "$TOKEN"
