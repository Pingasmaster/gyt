#!/usr/bin/env bash
# Comprehensive end-to-end smoke test for all gyt features.
# Run from repo root after `cargo build --release`.
set -euo pipefail

BIN="$(cd "$(dirname "$0")/.." && pwd)/target/release/gyt"
[ -x "$BIN" ] || { echo "build the release binary first: cargo build --release"; exit 1; }

WORK=$(mktemp -d)
trap 'cd / && rm -rf "$WORK"' EXIT
cd "$WORK"

export GYT_AUTHOR_NAME="Smoke Test"
export GYT_AUTHOR_EMAIL="smoke@example"
PASS=0
FAIL=0

pass() { PASS=$((PASS+1)); }
fail() { echo "FAIL: $1"; FAIL=$((FAIL+1)); }

echo "=== gyt comprehensive smoke test ==="

# ── 1. init ──────────────────────────────────────────────────────────
echo "[1] init"
"$BIN" init >/dev/null
test -d .gyt/objects || fail "objects dir missing"
test -f .gyt/HEAD || fail "HEAD missing"
grep -q 'ref: refs/heads/main' .gyt/HEAD || fail "HEAD target wrong"
pass

# ── 2. add + commit ──────────────────────────────────────────────────
echo "[2] add + commit"
echo hello > a.txt
echo world > b.txt
"$BIN" add . >/dev/null
"$BIN" commit -m "first" --ai claude-opus-4-7 --reviewer "C <c@x>" >/dev/null
test -f .gyt/refs/heads/main || fail "branch ref missing"
pass

# ── 3. log ──────────────────────────────────────────────────────────
echo "[3] log"
# log output format: commit <hash> on first line, message appears later
"$BIN" log | head -1 | grep -q '^commit \|^\* commit \|^[0-9a-f]\{8\}' || fail "log missing commit header"
"$BIN" log | grep -q first || fail "log missing first commit message"
pass

# ── 4. status clean ─────────────────────────────────────────────────
echo "[4] status clean"
out=$("$BIN" status)
echo "$out" | grep -qi clean || fail "status not clean"
pass

# ── 5. diff ─────────────────────────────────────────────────────────
echo "[5] diff"
echo MOD > a.txt
"$BIN" diff | grep -q "^-hello" || fail "diff missing -hello"
"$BIN" diff | grep -q "^+MOD" || fail "diff missing +MOD"
# diff --stat
stat_out=$("$BIN" diff --stat)
echo "$stat_out" | grep -q "a.txt" || fail "diff --stat missing filename"
echo "$stat_out" | grep -q "|" || fail "diff --stat missing bar"
pass

# ── 6. add -A ──────────────────────────────────────────────────────
echo "[6] add -A"
# Delete b.txt and create c.txt, then add -A
rm b.txt
echo new > c.txt
"$BIN" add -A >/dev/null
"$BIN" commit -m "second" >/dev/null
"$BIN" log --oneline | head -1 | grep -q second || fail "commit after add -A failed"
pass

# ── 7. branch + switch + tag ──────────────────────────────────────
echo "[7] branch + switch + tag"
"$BIN" branch feature
"$BIN" switch feature
"$BIN" branch | grep -q '^* feature' || fail "not on feature branch"
"$BIN" tag v1.0
"$BIN" tag | grep -q v1.0 || fail "tag not listed"
"$BIN" switch main
pass

# ── 8. log --all --graph ───────────────────────────────────────────
echo "[8] log --all --graph"
log_out=$("$BIN" log --all --oneline --graph)
echo "$log_out" | grep -q '^*' || fail "log --graph missing asterisk"
echo "$log_out" | grep -q first || fail "log --all missing first commit"
echo "$log_out" | grep -q second || fail "log --all missing second commit"
pass

# ── 9. stash push/pop ─────────────────────────────────────────────
echo "[9] stash push/pop"
echo dirty > a.txt
"$BIN" stash push -m wip >/dev/null
test "$(cat a.txt)" = "MOD" || fail "stash did not reset workdir"
"$BIN" stash pop >/dev/null
test "$(cat a.txt)" = "dirty" || fail "stash pop did not restore"
pass

# ── 10. clean ─────────────────────────────────────────────────────
echo "[10] clean"
echo untracked > junk.txt
"$BIN" clean -n | grep -q "would remove.*junk.txt" || fail "clean -n didn't show junk.txt"
test -f junk.txt || fail "clean -n removed file"
"$BIN" clean >/dev/null
test ! -f junk.txt || fail "clean didn't remove junk.txt"
pass

# ── 11. commit --allow-empty ──────────────────────────────────────
echo "[11] commit --allow-empty"
"$BIN" commit --allow-empty -m "empty" >/dev/null
"$BIN" log --oneline | head -1 | grep -q empty || fail "allow-empty commit not in log"
pass

# ── 12. reset --hard works (was rejected pre-1.0; now restores workdir) ─
echo "[12] reset --hard restores workdir"
# a.txt at HEAD was committed as "MOD" in step 6; scribble on it then
# reset --hard HEAD — the file should be restored to the committed value.
echo "scratch-line" >> a.txt
"$BIN" reset --hard HEAD >/dev/null 2>&1 || fail "reset --hard should succeed"
restored_a=$(cat a.txt)
[ "$restored_a" = "MOD" ] || fail "reset --hard did not restore a.txt (got '$restored_a')"
pass

# ── 13. remote + config ───────────────────────────────────────────
echo "[13] remote + config"
"$BIN" config --list | grep -q "user.name=Smoke Test" || fail "config --list missing user.name"
"$BIN" config --get user.name | grep -q "Smoke Test" || fail "config --get user.name failed"
"$BIN" remote -v >/dev/null 2>&1 || true  # no remotes configured, should just work
pass

# ── 14. serve + clone (end-to-end wire protocol) ────────────────
echo "[14] serve + clone"
# Start server on a random port, serve from $WORK/srv
mkdir -p "$WORK/srv/myrepo.gyt"
# Copy our current .gyt to the server's repo
cp -r .gyt "$WORK/srv/myrepo.gyt/"
PORT=11999
"$BIN" serve --listen "127.0.0.1:$PORT" --repos "$WORK/srv" &
SERVER_PID=$!
sleep 0.3

# Clone from the server
mkdir -p "$WORK/clonetarget"
cd "$WORK/clonetarget"
"$BIN" clone --insecure "http://127.0.0.1:$PORT/myrepo.gyt/" . 2>&1 || fail "clone failed"
# Verify clone has all commits
"$BIN" log --oneline | grep -q first || fail "clone missing 'first' commit"
"$BIN" log --oneline | grep -q second || fail "clone missing 'second' commit"
kill $SERVER_PID 2>/dev/null || true
wait $SERVER_PID 2>/dev/null || true
pass

# ── summary ────────────────────────────────────────────────────────
echo ""
echo "=== results: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then exit 1; fi
