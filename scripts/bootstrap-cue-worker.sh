#!/usr/bin/env bash
set -euo pipefail

INSTALL_BUN=0
INSTALL_OMP=0
INSTALL_FREQTRADE=0
INSTALL_PLAYWRIGHT=0

usage() {
  cat << 'EOF'
Usage: bootstrap-cue-worker.sh [--bun] [--omp] [--freqtrade] [--playwright] [--all] [--help]

Install optional toolchains for the vm-queue Python worker on ephemeral x86_64 VMs.
Default when no toolchain flag is given: --bun
EOF
}

if [[ $# -eq 0 ]]; then
  INSTALL_BUN=1
fi

while [[ $# -gt 0 ]]; do
  case "$1" in
    --bun)
      INSTALL_BUN=1
      shift
      ;;
    --omp)
      INSTALL_OMP=1
      shift
      ;;
    --freqtrade)
      INSTALL_FREQTRADE=1
      shift
      ;;
    --playwright)
      INSTALL_PLAYWRIGHT=1
      shift
      ;;
    --all)
      INSTALL_BUN=1
      INSTALL_OMP=1
      INSTALL_FREQTRADE=1
      INSTALL_PLAYWRIGHT=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

ARCH="$(uname -m)"
if [[ "$ARCH" != "x86_64" ]]; then
  echo "Warning: expected x86_64 worker VM, detected arch=$ARCH" >&2
fi

if [[ $INSTALL_BUN -eq 1 ]]; then
  if command -v bun >/dev/null 2>&1 || [[ -x "$HOME/.bun/bin/bun" ]]; then
    echo "bun already installed"
  else
    echo "Installing bun..."
    curl -fsSL https://bun.sh/install | bash
  fi
fi

if [[ $INSTALL_OMP -eq 1 ]]; then
  mkdir -p "$HOME/.local/bin"
  TMP_OMP_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_OMP_DIR"' EXIT
  BASE_URL="https://github.com/can1357/oh-my-pi/releases/latest/download"
  echo "Downloading omp-linux-x64 and SHA256SUMS.txt..."
  curl -fsSL "$BASE_URL/omp-linux-x64" -o "$TMP_OMP_DIR/omp-linux-x64"
  curl -fsSL "$BASE_URL/SHA256SUMS.txt" -o "$TMP_OMP_DIR/SHA256SUMS.txt"
  (
    cd "$TMP_OMP_DIR"
    grep 'omp-linux-x64$' SHA256SUMS.txt | sha256sum -c -
  )
  install -m 0755 "$TMP_OMP_DIR/omp-linux-x64" "$HOME/.local/bin/omp"
  rm -rf "$TMP_OMP_DIR"
  trap - EXIT
  echo "Installed omp to $HOME/.local/bin/omp"
fi

if [[ $INSTALL_FREQTRADE -eq 1 ]]; then
  UV_BIN="$(command -v uv || true)"
  if [[ -z "$UV_BIN" && -x "$HOME/.local/bin/uv" ]]; then
    UV_BIN="$HOME/.local/bin/uv"
  fi
  if [[ -z "$UV_BIN" ]]; then
    echo "Installing uv..."
    curl -fsSL https://astral.sh/uv/install.sh | sh
    UV_BIN="$HOME/.local/bin/uv"
  fi
  FT_VENV="/tmp/vmq-ft-venv"
  echo "Creating freqtrade venv at $FT_VENV..."
  "$UV_BIN" venv --python 3.12 "$FT_VENV"
  "$UV_BIN" pip install --python "$FT_VENV/bin/python" freqtrade
  "$FT_VENV/bin/freqtrade" --version
fi

if [[ $INSTALL_PLAYWRIGHT -eq 1 ]]; then
  echo "Installing Playwright Chromium browser..."
  if command -v npx >/dev/null 2>&1; then
    npx --yes playwright install chromium
  elif command -v bunx >/dev/null 2>&1 || [[ -x "$HOME/.bun/bin/bunx" ]]; then
    BUNX_BIN="$(command -v bunx || echo "$HOME/.bun/bin/bunx")"
    "$BUNX_BIN" playwright install chromium
  else
    echo "Error: npx or bunx is required to install Playwright Chromium" >&2
    exit 1
  fi
fi

echo "bootstrap-cue-worker completed."
