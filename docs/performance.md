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

## Bounded event progress

Each readable event advances at most 16 ordinary reads, stopping on backpressure,
EOF, protocol-state changes or no progress. This reduces repeated epoll wakeups
without allowing one ready stream to drain indefinitely.

## Network workers

`workers` defaults to **1**, retaining one network event loop on the main thread.
Set it to 0 to choose automatically (at most four CPUs), or 2..16 to request a
specific worker count. The actual count cannot exceed `max_connections`.
`max_connections` is a process-wide total, divided among worker pools including
any remainder. A full pool stops accepting until a slot is released.

Each connection belongs to one worker; extra workers help independent concurrent
connections and do not divide one TCP stream across cores. Diagnostics are
cumulative per worker. Shared listeners use EPOLLEXCLUSIVE when available.

The build still uses the original ReleaseSmall preference. Only the compiler's
single-thread-only assumption is removed so configured workers can run.
