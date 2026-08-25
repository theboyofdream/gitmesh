#!/bin/sh
set -e
cd "$(dirname "$0")/.."
BIN=$PWD/gitmesh
T=$(mktemp -d /tmp/gitmesh-test.XXXXXX)

cleanup() {
    [ -n "${SHARE_PID}" ] && kill $SHARE_PID 2>/dev/null
    rm -rf "$T"
}
trap cleanup EXIT INT TERM

P1="$T/alice-proj"
P2="$T/bob-proj"
mkdir -p "$P1/sub" "$P2"

echo "hello v1" > "$P1/a.txt"
echo "world" > "$P1/sub/b.txt"
dd if=/dev/urandom of="$P1/big.bin" bs=1024 count=200 2>/dev/null

echo "== start sharer (bob) =="
(cd "$P2" && HOME="$T/home-bob" GITMESH_TCP_PORT=42999 "$BIN" share) > "$T/share.log" 2>&1 &
SHARE_PID=$!
sleep 1

echo "== status (alice) =="
(cd "$P1" && HOME="$T/home-alice" "$BIN" status)

echo "== push initial tree =="
(cd "$P1" && printf 'y\n' | HOME="$T/home-alice" "$BIN" send "127.0.0.1:42999")

for f in a.txt sub/b.txt big.bin .gitmesh/index; do
    [ -f "$P2/$f" ] || { echo "FAIL: $P2/$f missing"; exit 1; }
done
cmp -s "$P1/a.txt" "$P2/a.txt" || { echo "FAIL: a.txt differs"; exit 1; }
cmp -s "$P1/big.bin" "$P2/big.bin" || { echo "FAIL: big.bin differs"; exit 1; }
echo "push OK"

echo "== incremental push: modify + add + delete =="
echo "hello v2" > "$P1/a.txt"
echo "brand new" > "$P1/new.txt"
rm "$P1/sub/b.txt"
(cd "$P1" && printf 'y\n' | HOME="$T/home-alice" "$BIN" send "127.0.0.1:42999")

grep -q "hello v2" "$P2/a.txt" || { echo "FAIL: a.txt not updated"; exit 1; }
[ -f "$P2/new.txt" ] || { echo "FAIL: new.txt missing"; exit 1; }
[ ! -f "$P2/sub/b.txt" ] || { echo "FAIL: b.txt should be deleted"; exit 1; }
echo "incremental OK"

echo "== no-op push =="
out=$(cd "$P1" && HOME="$T/home-alice" "$BIN" send "127.0.0.1:42999")
echo "$out" | grep -q "nothing to send" || { echo "FAIL: expected no-op"; exit 1; }
echo "no-op OK"

echo "== pull =="
echo "edited by bob" > "$P2/a.txt"
rm "$P1/new.txt"
(cd "$P1" && printf 'y\n' | HOME="$T/home-alice" "$BIN" receive "127.0.0.1:42999")
cmp -s "$P1/a.txt" "$P2/a.txt" || { echo "FAIL: pull did not update a.txt"; exit 1; }
[ -f "$P1/new.txt" ] || { echo "FAIL: pull did not restore new.txt"; exit 1; }
echo "pull OK"

echo "== conflict guard =="
echo "alice local edit" > "$P1/a.txt"
sleep 0.1
echo "bob concurrent edit" > "$P2/a.txt"
touch "$P2/.gitmesh/index"   # ensure index mtime older than edit
out=$(cd "$P1" && printf 'y\n' | HOME="$T/home-alice" "$BIN" send "127.0.0.1:42999" || true)
echo "$out"
grep -q "conflict" "$T/share.log" || { echo "note: no conflict reported (check)"; }
grep -q "bob concurrent edit" "$P2/a.txt" || { echo "FAIL: peer edit clobbered"; exit 1; }
echo "conflict guard OK"

echo "ALL TESTS PASSED"
