#!/usr/bin/env bash
#
# Build the SigViewer AppImage on a manylinux CPython base (Option C).
# ===================================================================
# python-appimage downloads the OLDEST manylinux base for the requested Python
# version (glibc ≤ 2.17/2.28 — older than Ubuntu 20.04's 2.31), pip-installs
# requirements.txt into it, bundles this recipe (.desktop / icon / entrypoint)
# plus the application sources, and packs the AppImage.
#
# No PPA, no from-source compile, no Docker required. Just:
#   pip install python-appimage
#   ./build.sh
#
# Override the Python version with:  PYVER=3.11 ./build.sh
#
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
SRC="$(cd "$HERE/../src" && pwd)"        # project root: the .py and .ui live here
RECIPE="$HERE/SigViewer"             # recipe folder (desktop/icon/reqs/entrypoint)
PYVER="${PYVER:-3.10}"

command -v python-appimage >/dev/null 2>&1 || {
    echo "python-appimage not found. Install it with: pip install python-appimage" >&2
    exit 1
}

# Application sources bundled into the AppImage under $APPDIR/sigviewer_app/.
APP_FILES=(
    check_eu_signatures.py
    qt_compat.py
    signature_viewer_core.py
    viewer_pyqt5.py
    signature_viewer.ui
)

STAGE="$HERE/sigviewer_app"
rm -rf "$STAGE"; mkdir -p "$STAGE"
for f in "${APP_FILES[@]}"; do
    cp "$SRC/$f" "$STAGE/"
done

echo "▶ Building SigViewer AppImage (manylinux Python $PYVER)…"
# Positional RECIPE must come before -x (which is nargs="+" and greedy).
# -p : Python version (python-appimage fetches the oldest manylinux base)
# -x : extra data — the staged app dir, copied to $APPDIR/sigviewer_app/
python-appimage build app -p "$PYVER" "$RECIPE" -x "$STAGE"

rm -rf "$STAGE"

OUT="SigViewer-$(uname -m).AppImage"
chmod +x "$OUT" 2>/dev/null || true
echo "✔ Built: $OUT"
echo "  Verify glibc floor:  ./verify-glibc.sh $OUT 2.31"
