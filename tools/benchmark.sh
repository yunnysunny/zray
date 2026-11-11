#!/bin/sh
# Use the SAME sufficiently large HTTPS object/server for every comparison.
set -eu
url=${1:?usage: benchmark.sh HTTPS_URL [socks5h://127.0.0.1:1080] [connections]}
proxy=${2:-socks5h://127.0.0.1:1080}
connections=${3:-1}
case "$connections" in ''|*[!0-9]*|0) exit 2;; esac
command -v curl >/dev/null
printf 'proxy=%s connections=%s\n' "$proxy" "$connections"
pids=''
i=0
while [ "$i" -lt "$connections" ]; do
    i=$((i + 1))
    curl --silent --show-error --fail --proxy "$proxy" --output /dev/null \
        --max-time 180 --write-out 'bytes=%{size_download} seconds=%{time_total} bytes_per_second=%{speed_download}\n' "$url" &
    pids="$pids $!"
done
result=0
for pid in $pids; do wait "$pid" || result=1; done
exit "$result"
