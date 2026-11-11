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

## Vision direct relay

Splice is enabled automatically for eligible Vision direct traffic, with no
configuration switch. Remove any old `splice` JSON field before restarting.
Upload and download switch independently after the Vision direct command and
all prior protocol buffers have drained. Each direction owns a lazy nonblocking
pipe. The per-event transfer budget is 256 KiB; destination backpressure retains
pending bytes before any further source read. EOF is propagated after buffers
and pipes drain, preserving the reverse direction.

Pipe pairs share a process-wide atomic budget derived from the fd soft limit.
Startup reserves existing descriptors, three sockets per connection slot, worker
epolls and temporary headroom. If `/proc/self/fd` or the limit cannot be read,
splice is skipped. Budget exhaustion falls back before allocating; closing a pipe
or a failed allocation returns its quota. Idle pipes stay with their connection.

Pipe allocation failures and unsupported source splice calls fall back to copying
before source data is consumed. Statistics include syscall counts and transferred
bytes; close logs show spliced upload/download totals. Plain inner HTTP traffic
usually remains inside outer TLS and is not eligible for this direct path.

A known Xray freedom peer limitation prevents certification of end-to-end VLESS
half-close with that peer; direct Conn/epoll half-close is tested separately.
