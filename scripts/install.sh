#!/bin/sh
set -eu

plugin_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
version=$(sed -n 's/^version = "\([^"]*\)"/\1/p' "$plugin_root/herdr-plugin.toml" | head -n 1)

case "$(uname -s)" in
  Darwin) platform=darwin ;;
  Linux) platform=linux ;;
  *) echo "Process Guard supports Linux and macOS." >&2; exit 1 ;;
esac

case "$(uname -m)" in
  arm64|aarch64) architecture=arm64 ;;
  x86_64|amd64) architecture=amd64 ;;
  *) echo "Unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

mkdir -p "$plugin_root/bin"
archive="herdr-process-guard_${version}_${platform}_${architecture}"
url="https://github.com/Grafton-Apparel/herdr-process-guard/releases/download/v${version}/${archive}.tar.gz"
checksum_url="$url.sha256"
temporary_directory=$(mktemp -d "${TMPDIR:-/tmp}/herdr-process-guard.XXXXXX")
trap 'rm -rf "$temporary_directory"' EXIT HUP INT TERM

if command -v curl >/dev/null 2>&1 \
  && curl -fsSL "$url" -o "$temporary_directory/$archive.tar.gz" \
  && curl -fsSL "$checksum_url" -o "$temporary_directory/$archive.tar.gz.sha256"; then
  if command -v sha256sum >/dev/null 2>&1; then
    checksum_command="sha256sum"
  elif command -v shasum >/dev/null 2>&1; then
    checksum_command="shasum -a 256"
  else
    echo "Install sha256sum or shasum to verify Process Guard releases." >&2
    exit 1
  fi
  if ! (cd "$temporary_directory" && $checksum_command -c "$archive.tar.gz.sha256"); then
    echo "Process Guard release checksum verification failed." >&2
    exit 1
  fi
  tar -xzf "$temporary_directory/$archive.tar.gz" -C "$temporary_directory"
  cp "$temporary_directory/$archive/herdr-process-guard" "$plugin_root/bin/herdr-process-guard"
  chmod 0755 "$plugin_root/bin/herdr-process-guard"
  echo "Installed Process Guard $version for $platform/$architecture."
  exit 0
fi

if ! command -v go >/dev/null 2>&1; then
  echo "No matching release archive was available and Go was not found." >&2
  echo "Install Go 1.24+ or install a tagged Process Guard release." >&2
  exit 1
fi

echo "Release archive unavailable; building Process Guard from source."
cd "$plugin_root"
go build -trimpath -o bin/herdr-process-guard ./cmd/herdr-process-guard
