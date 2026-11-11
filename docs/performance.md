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
epolls, enabled crypto session and executor event descriptors and temporary headroom. If `/proc/self/fd` or the limit cannot be read,
splice is skipped. Budget exhaustion falls back before allocating; closing a pipe
or a failed allocation returns its quota. Idle pipes stay with their connection.

Pipe allocation failures and unsupported source splice calls fall back to copying
before source data is consumed. Statistics include syscall counts and transferred
bytes; close logs show spliced upload/download totals. Plain inner HTTP traffic
usually remains inside outer TLS and is not eligible for this direct path.

A known Xray freedom peer limitation prevents certification of end-to-end VLESS
half-close with that peer; direct Conn/epoll half-close is tested separately.

## Kernel crypto (explicit opt-in)

See [README configuration](../README.md#kernel-crypto-backends) for the complete
JSON settings, defaults, environment override and payload-size semantics.
`crypto_backend` defaults to `"off"`; `auto` tries devcrypto, AF_ALG and software
in order. Both interfaces request AES-GCM by generic algorithm name; the kernel
chooses its implementation. Availability is checked on the first eligible key,
without a board, CPU-feature or driver-name gate.

Requests must satisfy the inclusive `crypto_min_bytes` / `crypto_max_bytes` range
(default 4096..32768), measured as AEAD plaintext bytes. AES-128/256-GCM is
supported; ChaCha20 stays in software. Each session is checked against software
for encryption, decryption and rejection of a corrupted tag. At most 64 keys are
cached per executing context and 128 sessions process-wide.

`crypto_kernel`, `crypto_fallback` and `crypto_badmac` count successful kernel
operations, fallback events and authentication failures. Kernel completion does
not prove hardware execution: the selected implementation can use software or
CPU instructions. Throughput and backend behavior need testing on the target.
No NEON AES/GHASH implementation or performance compiler options are added.

## Async kernel requests

`crypto_async` defaults to true. Explicitly enabling a kernel crypto backend on
Linux creates one crypto executor per network worker. Set `crypto_async` false
for synchronous comparison. With `workers: 1` and `crypto_backend: "off"`, the
main thread runs the single network loop without additional threads.

Complete TLS operations publish through bounded per-connection jobs and eventfd
notifications. Sockets pause while the executor owns their TLS state and buffers;
close/reuse waits for completion. Only records within the configured byte limits
are delegated. Diagnostics read atomically published backend counts.

Async mode does not split a record across cores. Outer handshakes and small
records continue through the ordinary TLS path; Vision direct traffic bypasses
outer record encryption. `crypto_completed` counts completed jobs, including
those that fell back to software. See the [worker example](../README.md#async-crypto-and-worker-counts).
