# Relay performance controls

Existing node credentials and routing fields keep their meanings. Merge controls
into the top level of the existing JSON configuration.

## Diagnostics

`stats_interval_s` defaults to 60 seconds; set it to 0 to disable periodic output.
Counters are cumulative read/write calls, epoll waits/modifications and active
connection counts. Calls that return EAGAIN still count as calls.

Use `tools/benchmark.sh HTTPS_URL socks5h://127.0.0.1:1080 1` for one connection,
or change the final argument to 4 for concurrent transfers. Use the same large
object, node and socket-buffer settings for every comparison; repeat and observe
CPU usage separately. The script reports bytes, seconds and bytes/second for each
transfer, not a hardware benchmark or an expected speedup.
