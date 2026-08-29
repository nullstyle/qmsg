#!/bin/sh
# Release smoke: build and test the PACKED tarball of a ref, not the
# checkout. A zon/code drift inside the tree compiles fine from a
# warm checkout cache while the published artifact is broken — this
# gate exists because that shipped (v0.1.9 and v0.2.0 tarballs failed
# to compile their auth path against their own paseto pin; found by
# the mruby-quic consumer, reproduced cold).
#
# Usage: tools/tarball-smoke.sh [ref]   (default: HEAD)
set -e
REF="${1:-HEAD}"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
git archive "$REF" | tar -x -C "$WORK"
cd "$WORK"
export COPYFILE_DISABLE=1
export ZIG_GLOBAL_CACHE_DIR="$WORK/.global-cache"
echo "tarball-smoke: cold build+test of $REF in $WORK"
mise exec -- zig build test --summary all --cache-dir "$WORK/.cache"
echo "tarball-smoke: $REF OK"
