#!/usr/bin/env bash
#
# Assert that nothing inside an AppImage needs a glibc symbol newer than the
# target (default 2.31 = Ubuntu 20.04 LTS). Exits non-zero on failure, so it
# can gate a CI build.
#
#   ./verify-glibc.sh SigViewer-x86_64.AppImage 2.31
#
set -euo pipefail

APPIMAGE="${1:?usage: verify-glibc.sh <AppImage> [max_glibc=2.31]}"
MAX="${2:-2.31}"

command -v objdump >/dev/null 2>&1 || { echo "objdump not found (apt install binutils)"; exit 2; }

APPIMAGE_ABS="$(readlink -f "$APPIMAGE")"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
cd "$TMP"

# Extract without needing FUSE.
"$APPIMAGE_ABS" --appimage-extract >/dev/null

# Collect every GLIBC_x.y version referenced by any bundled ELF (libs + bins).
mapfile -t versions < <(
    find squashfs-root -type f \( -name '*.so' -o -name '*.so.*' -o -perm -u+x \) -print0 \
    | xargs -0 -r objdump -T 2>/dev/null \
    | grep -oE 'GLIBC_[0-9]+\.[0-9]+(\.[0-9]+)?' \
    | sed 's/GLIBC_//' | sort -uV
)

if [ "${#versions[@]}" -eq 0 ]; then
    echo "No GLIBC symbol versions found (statically linked or extraction failed)."
    exit 0
fi

echo "GLIBC versions referenced inside $APPIMAGE:"
printf '  %s\n' "${versions[@]}"

worst="${versions[-1]}"
largest="$(printf '%s\n%s\n' "$worst" "$MAX" | sort -V | tail -1)"

echo "Highest required: GLIBC_$worst   (target ceiling: GLIBC_$MAX)"
if [ "$largest" = "$MAX" ]; then
    echo "✔ OK — compatible with glibc $MAX (Ubuntu 20.04 LTS and newer)."
else
    echo "FAIL — needs glibc newer than $MAX (offending: $worst)." >&2
    echo "  Rebuild on an older base, or find which lib pulls the new symbol with:" >&2
    echo "    find squashfs-root -name '*.so*' | xargs objdump -T | grep GLIBC_$worst" >&2
    exit 1
fi
