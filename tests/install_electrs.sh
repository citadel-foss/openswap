#!/usr/bin/env bash
# Downloads the electrs 0.9.11 binary the Electrum integration tests spawn and
# prints its path. Point ELECTRS_EXEC at it:
#
#   export ELECTRS_EXEC="$(tests/install_electrs.sh)"
#
# This replaces electrsd's `download` feature, whose build script fetched the
# same archive but needs `zip` 0.6, and every 0.6.x release of `zip` is yanked.
# The archives and SHA-256 sums are the ones electrsd 0.28 pins in its `sha256`
# file, so the binary is identical to the one the feature used to provide.
#
# Usage: tests/install_electrs.sh [install-dir]   (default: target/electrs)
# Re-running is cheap: an already verified install is reused.
set -euo pipefail

VERSION=v0.9.11
BASE_URL=https://github.com/RCasatta/electrsd/releases/download/electrs_releases

case "$(uname -s)-$(uname -m)" in
    Linux-x86_64)  OS=linux; SHA256=2b2f8aef35cd8e16e109b948a903d010aa472f6cdf2147d47e01fd95cd1785da ;;
    Darwin-x86_64|Darwin-arm64)
                   OS=macos; SHA256=b794287a5d98e590deadf07a3eb391cc1a53ef160c8cdcb8e6b14d856c7b181d ;;
    *) echo "no prebuilt electrs $VERSION for $(uname -s)-$(uname -m); build electrs and set ELECTRS_EXEC" >&2; exit 1 ;;
esac

cd "$(dirname "$0")/.."
DEST="${1:-target/electrs}"
ARCHIVE="electrs_${OS}_${VERSION}.zip"
EXE="$DEST/electrs_${OS}_${VERSION}/electrs"

sha256() {
    if command -v sha256sum >/dev/null; then sha256sum "$1"; else shasum -a 256 "$1"; fi | cut -d' ' -f1
}

if [ ! -x "$EXE" ] || [ "$(cat "$DEST/$ARCHIVE.sha256" 2>/dev/null)" != "$SHA256" ]; then
    mkdir -p "$DEST"
    curl --fail --silent --show-error --location --retry 3 "$BASE_URL/$ARCHIVE" -o "$DEST/$ARCHIVE"
    actual="$(sha256 "$DEST/$ARCHIVE")"
    if [ "$actual" != "$SHA256" ]; then
        rm -f "$DEST/$ARCHIVE"
        echo "checksum mismatch for $ARCHIVE: expected $SHA256, got $actual" >&2
        exit 1
    fi
    rm -rf "$DEST/electrs_${OS}_${VERSION}"
    if command -v unzip >/dev/null; then
        unzip -q -o "$DEST/$ARCHIVE" -d "$DEST/electrs_${OS}_${VERSION}"
    else
        python3 -m zipfile -e "$DEST/$ARCHIVE" "$DEST/electrs_${OS}_${VERSION}"
    fi
    chmod +x "$EXE"
    echo "$SHA256" > "$DEST/$ARCHIVE.sha256"
    rm -f "$DEST/$ARCHIVE"
fi

echo "$(cd "$(dirname "$EXE")" && pwd)/electrs"
