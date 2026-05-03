#!/usr/bin/env bash
# End-to-end local smoke. Run from the repo root after `cargo build --release`.
set -euo pipefail

BIN="$(cd "$(dirname "$0")/.." && pwd)/target/release/gyt"
[ -x "$BIN" ] || { echo "build the release binary first: cargo build --release"; exit 1; }

WORK=$(mktemp -d)
trap 'cd / && rm -rf "$WORK"' EXIT
cd "$WORK"

export GYT_AUTHOR_NAME="Smoke Test"
export GYT_AUTHOR_EMAIL="smoke@example"

echo "[1/9] init"
"$BIN" init >/dev/null
test -d .gyt/objects
test -f .gyt/HEAD
grep -q 'ref: refs/heads/main' .gyt/HEAD

echo "[2/9] add + commit"
echo hello > a.txt
echo world > b.txt
"$BIN" add . >/dev/null
"$BIN" commit -m "first" --ai claude-opus-4-7 --reviewer "C <c@x>" >/dev/null
test -f .gyt/refs/heads/main

echo "[3/9] log shows commit"
"$BIN" log | head -1 | grep -q first

echo "[4/9] status clean"
out=$("$BIN" status)
echo "$out" | grep -qi clean

echo "[5/9] modify -> diff -> add -> status -> commit"
echo MOD > a.txt
"$BIN" diff | grep -q "^-hello"
"$BIN" diff | grep -q "^+MOD"
"$BIN" add a.txt >/dev/null
"$BIN" commit -m "second" >/dev/null
"$BIN" log | head -1 | grep -q second

echo "[6/9] branch + switch + tag"
"$BIN" branch feature
"$BIN" switch feature
"$BIN" branch | grep -q '^\* feature'
"$BIN" tag v1.0
"$BIN" tag | grep -q v1.0

echo "[7/9] stash push/pop"
echo dirty > a.txt
"$BIN" stash push -m wip >/dev/null
test "$(cat a.txt)" = "MOD"   # stash reset workdir to HEAD
"$BIN" stash pop >/dev/null
test "$(cat a.txt)" = "dirty"

echo "[8/9] reset --hard rejected"
if "$BIN" reset --hard HEAD 2>/dev/null; then
  echo "FAIL: reset --hard should be rejected" >&2; exit 1
fi

echo "[9/9] no hooks dir"
test ! -d .gyt/hooks

echo "smoke: all 9 checks passed"
