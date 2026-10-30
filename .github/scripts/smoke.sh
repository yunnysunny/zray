#!/bin/sh
# Startup smoke test for CI: feed zray a few configs and check that every
# misconfiguration is rejected with the expected message and that a valid
# config reaches the event loop and logs its mode. The binary may be built
# for a foreign architecture; pass the emulator after it:
#
#   .github/scripts/smoke.sh zig-out/bin/zray              # native
#   .github/scripts/smoke.sh out/bin/zray qemu-mipsel      # under qemu-user
set -eu

zray=$1
shift
runner=$*

tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
cfg="$tmp/config.json"
log="$tmp/log"

# run <json>: start zray on that config; leaves $rc and $log. rc=124 means
# it was still running after 3 s, i.e. startup succeeded and the event loop
# was reached. No `timeout`, so this also runs on a busybox router.
run() {
    printf '%s\n' "$1" > "$cfg"
    set +e
    $runner "$zray" "$cfg" > "$log" 2>&1 &
    pid=$!
    sleep 3
    if kill -0 "$pid" 2>/dev/null; then
        kill "$pid"
        wait "$pid" 2>/dev/null
        rc=124
    else
        wait "$pid"
        rc=$?
    fi
    set -e
}

expect_reject() { # <json> <expected log substring>
    run "$1"
    if [ "$rc" -eq 0 ] || [ "$rc" -eq 124 ] || ! grep -qF -- "$2" "$log"; then
        echo "FAIL: expected rejection mentioning '$2' (rc=$rc), config: $1"
        cat "$log"
        exit 1
    fi
    echo "ok: rejected ($2)"
}

expect_start() { # <json> <expected log substring>
    run "$1"
    if [ "$rc" -ne 124 ] || ! grep -qF -- "$2" "$log"; then
        echo "FAIL: expected startup logging '$2' (rc=$rc), config: $1"
        cat "$log"
        exit 1
    fi
    echo "ok: started ($2)"
}

pk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA # 32 zero bytes, base64url
uuid=00000000-0000-0000-0000-000000000000
# An IP literal as server keeps startup free of DNS.
base="\"listen\":\"127.0.0.1:18080\",\"server\":\"127.0.0.1\",\"uuid\":\"$uuid\""

expect_reject "{$base}" 'public_key is required'
expect_reject "{$base,\"publickey\":\"$pk\"}" 'UnknownField'
expect_reject "{$base,\"public_key\":\"not-a-key\"}" 'bad public_key'
expect_reject "{$base,\"security\":\"plain\"}" 'InvalidEnumTag'
expect_reject "{$base,\"security\":\"tls\"}" 'tls_verify is required'
expect_reject "{$base,\"security\":\"tls\",\"tls_verify\":\"ca\"}" 'not implemented'
expect_reject "{$base,\"security\":\"tls\",\"tls_verify\":\"none\",\"public_key\":\"$pk\"}" 'only valid with security = "reality"'

expect_start "{$base,\"public_key\":\"$pk\",\"short_id\":\"0123abcd\"}" 'mode reality (short_id 0123abcd)'
expect_start "{$base,\"security\":\"tls\",\"tls_verify\":\"none\"}" 'mode tls, verify NONE'

echo "smoke: all checks passed"
