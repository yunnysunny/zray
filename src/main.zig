//! zray: minimal REALITY (VLESS + xtls-rprx-vision) client for routers.
//!
//!   zray [config.json]      (default: ./config.json)
//!
//! Linux only; single thread; epoll; fixed memory (connection pool sized by
//! `max_connections`).

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;
const reality = @import("tls/reality.zig");

pub const version = "0.4.0";

/// How the upstream is authenticated. Chosen explicitly so a mistyped or
/// missing `public_key` fails at startup instead of quietly downgrading a
/// REALITY node to plain TLS.
const Security = enum { reality, tls };

/// Certificate check for `security = "tls"`. `ca` (system bundle) and `pin`
/// (SPKI SHA-256) are reserved for a later release; until then plain TLS
/// must opt into `none` explicitly.
const TlsVerify = enum { ca, pin, none };

const Network = enum { tcp, ws };
const FlowName = enum { none, @"xtls-rprx-vision" };

/// One entry of `outbounds`. Same meaning as the top-level node fields.
const OutboundConfig = struct {
    tag: []const u8 = "",
    server: []const u8,
    port: u16 = 443,
    bootstrap_dns: ?[]const u8 = null,
    sni: []const u8 = "",
    security: Security = .reality,
    public_key: []const u8 = "",
    short_id: []const u8 = "",
    tls_verify: ?TlsVerify = null,
    uuid: []const u8,
    /// Default: xtls-rprx-vision for tcp (original behaviour), none for ws.
    flow: ?FlowName = null,
    network: Network = .tcp,
    ws_path: []const u8 = "/",
    /// HTTP Host header; default: sni (or server).
    ws_host: []const u8 = "",
    /// Tag of another outbound to tunnel this one's TCP connection through.
    dialer: []const u8 = "",
};

const RuleConfig = struct {
    domain_suffix: []const []const u8,
    /// Outbound tags, tried in order (failover).
    outbound: []const []const u8,
};

const FileConfig = struct {
    /// Multi-node form. When set, the top-level node fields must be absent.
    outbounds: ?[]const OutboundConfig = null,
    rules: []const RuleConfig = &.{},
    /// Tags for traffic no rule matches; default: the first outbound.
    default: []const []const u8 = &.{},
    fail_backoff_s: u64 = 30,
    /// SOCKS5 inbound; empty string disables it.
    listen: []const u8 = "127.0.0.1:1080",
    /// Transparent inbound for netfilter REDIRECT (iptables -j REDIRECT /
    /// nft redirect to); empty string disables it.
    redirect: []const u8 = "",
    sniff: bool = true,
    server: []const u8 = "",
    port: u16 = 443,
    /// Nameserver ("1.2.3.4", "1.2.3.4:53", "[2001:db8::1]:53") queried
    /// directly over UDP to resolve `server` at startup, bypassing
    /// /etc/resolv.conf. Set it when the local resolver (chinadns-ng,
    /// dnsmasq + DoT, ...) itself routes through this tunnel, otherwise the
    /// two services wait on each other at boot. Empty: system resolver.
    bootstrap_dns: []const u8 = "",
    sni: []const u8 = "",
    /// "reality" (default; existing configs keep working) or "tls" for an
    /// ordinary VLESS + TLS node.
    security: Security = .reality,
    /// REALITY server public key (base64url). Required with security =
    /// "reality", rejected with "tls".
    public_key: []const u8 = "",
    /// REALITY only.
    short_id: []const u8 = "",
    /// security = "tls" only, and then mandatory: how the server certificate
    /// is checked. Only "none" (equivalent to allowInsecure) is implemented.
    tls_verify: ?TlsVerify = null,
    uuid: []const u8 = "",
    flow: ?FlowName = null,
    network: Network = .tcp,
    ws_path: []const u8 = "/",
    ws_host: []const u8 = "",
    max_connections: u32 = 128,
    handshake_timeout_s: u64 = 15,
    idle_timeout_s: u64 = 600,
    connect_timeout_s: u64 = 5,
    sock_buf: i32 = 0,
};

const Upstream = union(enum) {
    reality: reality.Config,
    /// Plain TLS 1.3; the payload is the certificate check in force.
    tls: TlsVerify,
};

const UpstreamError = error{
    MissingPublicKey,
    RealityFieldsInTlsMode,
    MissingTlsVerify,
    TlsVerifyNotImplemented,
    InvalidPublicKey,
    InvalidShortId,
};

/// Pick the upstream mode from the config. Every misconfiguration is an
/// error; it never falls through to a weaker mode than the one the config
/// names (a REALITY config with a mistyped `public_key` must not become
/// unverified plain TLS). Pure so it can be unit-tested on any host.
fn selectUpstream(c: anytype) UpstreamError!Upstream {
    switch (c.security) {
        .reality => {
            if (c.public_key.len == 0) return error.MissingPublicKey;
            return .{ .reality = .{
                .server_public_key = try reality.Config.publicKeyFromBase64(c.public_key),
                .short_id = try reality.Config.shortIdFromHex(c.short_id),
            } };
        },
        .tls => {
            if (c.public_key.len != 0 or c.short_id.len != 0) return error.RealityFieldsInTlsMode;
            const verify = c.tls_verify orelse return error.MissingTlsVerify;
            return switch (verify) {
                .none => .{ .tls = verify },
                .ca, .pin => error.TlsVerifyNotImplemented,
            };
        },
    }
}

fn upstreamErrorMessage(e: UpstreamError) []const u8 {
    return switch (e) {
        error.MissingPublicKey => "public_key is required with security = \"reality\" (use security = \"tls\" for a plain VLESS+TLS node)",
        error.RealityFieldsInTlsMode => "public_key / short_id are only valid with security = \"reality\"",
        error.MissingTlsVerify => "tls_verify is required with security = \"tls\"; set it to \"none\" to skip certificate verification (like allowInsecure)",
        error.TlsVerifyNotImplemented => "tls_verify \"ca\" / \"pin\" are not implemented yet; only \"none\" is available",
        error.InvalidPublicKey => "bad public_key",
        error.InvalidShortId => "bad short_id",
    };
}

pub fn main(init: std.process.Init) !void {
    if (builtin.os.tag != .linux) {
        var buf: [256]u8 = undefined;
        var w: Io.File.Writer = .init(.stdout(), init.io, &buf);
        try w.interface.print("zray {s}: the proxy service runs on Linux only (built for {s}-{s}). Use `zig build probe` here.\n", .{ version, @tagName(builtin.cpu.arch), @tagName(builtin.os.tag) });
        try w.interface.flush();
        return;
    }
    return linuxMain(init);
}

fn linuxMain(init: std.process.Init) !void {
    const sys = @import("linux/sys.zig");
    const conn = @import("linux/conn.zig");
    const vless = @import("proxy/vless.zig");

    const arena = init.arena.allocator();
    var args = try init.minimal.args.iterateAllocator(init.gpa);
    defer args.deinit();
    _ = args.next();
    const cfg_path = args.next() orelse "config.json";

    const text = Io.Dir.cwd().readFileAlloc(init.io, cfg_path, arena, .limited(64 * 1024)) catch |e| {
        sys.log("cannot read {s}: {s}", .{ cfg_path, @errorName(e) });
        return e;
    };
    // Unknown keys are an error: the config is small and a misspelled key
    // must not silently fall back to a default.
    const parsed = std.json.parseFromSliceLeaky(FileConfig, arena, text, .{}) catch |e| {
        sys.log("bad config: {s}", .{@errorName(e)});
        return e;
    };

    const node_cfgs: []const OutboundConfig = parsed.outbounds orelse &.{.{
        .server = parsed.server,
        .port = parsed.port,
        .sni = parsed.sni,
        .security = parsed.security,
        .public_key = parsed.public_key,
        .short_id = parsed.short_id,
        .tls_verify = parsed.tls_verify,
        .uuid = parsed.uuid,
        .flow = parsed.flow,
        .network = parsed.network,
        .ws_path = parsed.ws_path,
        .ws_host = parsed.ws_host,
    }};
    if (parsed.outbounds != null and (parsed.server.len != 0 or parsed.uuid.len != 0)) {
        sys.log("bad config: use either top-level server/uuid or outbounds, not both", .{});
        return error.BadConfig;
    }
    if (parsed.connect_timeout_s == 0) {
        sys.log("bad config: connect_timeout_s must be >= 1", .{});
        return error.BadConfig;
    }
    if (node_cfgs.len == 0 or node_cfgs.len > conn.max_outbounds) {
        sys.log("bad config: need 1..{d} outbounds", .{conn.max_outbounds});
        return error.BadConfig;
    }

    const obs = try arena.alloc(conn.Outbound, node_cfgs.len);
    // Hop listeners: one local SOCKS5 port per outbound used as a dialer.
    var hop_fd: [conn.max_outbounds]?sys.fd_t = @splat(null);
    for (node_cfgs, 0..) |oc, i| {
        const upstream = selectUpstream(oc) catch |e| {
            sys.log("bad config ({s}): {s}", .{ oc.tag, upstreamErrorMessage(e) });
            return e;
        };
        if (oc.server.len == 0 or oc.server.len > 255) return error.BadConfig;
        const vision_on = if (oc.flow) |f| f == .@"xtls-rprx-vision" else oc.network == .tcp;
        if (vision_on and oc.network == .ws) {
            sys.log("bad config ({s}): xtls-rprx-vision does not work over ws; set flow \"none\"", .{oc.tag});
            return error.BadConfig;
        }
        const sni = if (oc.sni.len > 0) oc.sni else oc.server;
        var ob: conn.Outbound = .{
            .tag = oc.tag,
            .addr = undefined,
            .sni = sni,
            .reality = switch (upstream) {
                .reality => |rc| rc,
                .tls => null,
            },
            .uuid = vless.parseUuid(oc.uuid) catch |e| {
                sys.log("bad uuid ({s})", .{oc.tag});
                return e;
            },
            .vision = vision_on,
            .ws = oc.network == .ws,
            .ws_path = oc.ws_path,
            .ws_host = if (oc.ws_host.len > 0) oc.ws_host else sni,
        };
        if (oc.dialer.len > 0) {
            const d = tagIndex(node_cfgs, oc.dialer) orelse {
                sys.log("bad config ({s}): unknown dialer {s}", .{ oc.tag, oc.dialer });
                return error.BadConfig;
            };
            if (d >= i) {
                sys.log("bad config ({s}): dialer {s} must be listed before it", .{ oc.tag, oc.dialer });
                return error.BadConfig;
            }
            if (hop_fd[d] == null) hop_fd[d] = try listenOn("127.0.0.1:0");
            ob.addr = try sys.localAddr(hop_fd[d].?);
            ob.hop_host = oc.server;
            ob.hop_port = oc.port;
        } else {
            // Resolve once at startup (routers rarely change upstreams).
            ob.addr = resolveServer(init.io, oc.server, oc.port, oc.bootstrap_dns orelse parsed.bootstrap_dns) catch |e| {
                sys.log("cannot resolve {s}: {s}", .{ oc.server, @errorName(e) });
                return e;
            };
        }
        obs[i] = ob;
    }

    const rules = try arena.alloc(conn.Rule, parsed.rules.len);
    for (parsed.rules, 0..) |r, i| rules[i] = .{ .suffixes = r.domain_suffix, .group = try tagsToGroup(arena, node_cfgs, r.outbound) };
    const default_group: []const u8 = if (parsed.default.len > 0) try tagsToGroup(arena, node_cfgs, parsed.default) else &.{0};

    const cfg: conn.Config = .{
        .outbounds = obs,
        .rules = rules,
        .default_group = default_group,
        .handshake_timeout_s = parsed.handshake_timeout_s,
        .idle_timeout_s = parsed.idle_timeout_s,
        .connect_timeout_s = parsed.connect_timeout_s,
        .sock_buf = parsed.sock_buf,
        .sniff = parsed.sniff,
        .fail_backoff_s = parsed.fail_backoff_s,
    };

    if (parsed.listen.len == 0 and parsed.redirect.len == 0) {
        sys.log("nothing to listen on: set listen and/or redirect", .{});
        return error.BadListen;
    }
    sys.ignoreSigpipe();
    const ep = try sys.epollCreate();
    const socks_token: u64 = std.math.maxInt(u64);
    const redirect_token: u64 = std.math.maxInt(u64) - 1;
    const hop_token_base: u64 = std.math.maxInt(u64) - 2;
    const socks_fd: ?sys.fd_t = if (parsed.listen.len > 0) try listenOn(parsed.listen) else null;
    const redirect_fd: ?sys.fd_t = if (parsed.redirect.len > 0) try listenOn(parsed.redirect) else null;
    if (socks_fd) |fd| try sys.epollAdd(ep, fd, sys.EPOLL.IN, socks_token);
    for (hop_fd, 0..) |h, i| if (h) |fd| try sys.epollAdd(ep, fd, sys.EPOLL.IN, hop_token_base - i);
    if (redirect_fd) |fd| try sys.epollAdd(ep, fd, sys.EPOLL.IN, redirect_token);

    const conns = try std.heap.page_allocator.alloc(conn.Conn, parsed.max_connections);
    var loop = conn.Loop.init(ep, &cfg, conns);
    sys.log("zray {s} socks5 [{s}] redirect [{s}] sniff {}, {d} outbounds, {d} rules, {d} slots x {d} KiB = {d} KiB", .{
        version, parsed.listen, parsed.redirect, parsed.sniff, obs.len, rules.len, parsed.max_connections, @sizeOf(conn.Conn) / 1024, (@sizeOf(conn.Conn) * parsed.max_connections) / 1024,
    });
    for (obs, node_cfgs) |ob, oc| {
        // Keep the "mode ..." phrases: the startup smoke test matches them,
        // and the TLS line is the allowInsecure warning operators need.
        if (ob.reality != null) {
            sys.log("outbound {s}: {s}:{d} sni {s} mode reality (short_id {s}){s}{s}{s}{s}", .{
                if (ob.tag.len > 0) ob.tag else "-",
                oc.server,
                oc.port,
                ob.sni,
                if (oc.short_id.len > 0) oc.short_id else "-",
                if (ob.vision) " vision" else "",
                if (ob.ws) " ws " else "",
                if (ob.ws) ob.ws_path else "",
                if (oc.dialer.len > 0) " via hop" else "",
            });
        } else {
            sys.log("outbound {s}: {s}:{d} sni {s} mode tls, verify NONE -- WARNING: server certificate not verified; an on-path attacker can impersonate the server, read the VLESS uuid and all tunnelled traffic{s}{s}{s}{s}", .{
                if (ob.tag.len > 0) ob.tag else "-",
                oc.server,
                oc.port,
                ob.sni,
                if (ob.vision) " vision" else "",
                if (ob.ws) " ws " else "",
                if (ob.ws) ob.ws_path else "",
                if (oc.dialer.len > 0) " via hop" else "",
            });
        }
    }

    var events: [64]sys.Event = undefined;
    var last_sweep = sys.monotonicSeconds();
    while (true) {
        const n = sys.epollWait(ep, &events, 1000) catch |e| {
            sys.log("epoll_wait: {s}", .{@errorName(e)});
            continue;
        };
        for (events[0..n]) |ev| {
            if (ev.data.u64 == socks_token or ev.data.u64 == redirect_token) {
                const is_socks = ev.data.u64 == socks_token;
                const lfd = if (is_socks) socks_fd.? else redirect_fd.?;
                while (true) {
                    const fd = sys.accept(lfd) catch break;
                    loop.accept(fd, if (is_socks) .socks5 else .redirect, null);
                }
            } else if (ev.data.u64 > hop_token_base - conn.max_outbounds and ev.data.u64 <= hop_token_base) {
                const i: u8 = @intCast(hop_token_base - ev.data.u64);
                while (true) {
                    const fd = sys.accept(hop_fd[i].?) catch break;
                    loop.accept(fd, .socks5, i);
                }
            } else {
                loop.handle(ev.data.u64, ev.events);
            }
        }
        const now = sys.monotonicSeconds();
        if (now != last_sweep) {
            last_sweep = now;
            loop.sweep();
        }
    }
}

fn tagIndex(nodes: []const OutboundConfig, tag: []const u8) ?u8 {
    for (nodes, 0..) |n, i| if (std.mem.eql(u8, n.tag, tag)) return @intCast(i);
    return null;
}

fn tagsToGroup(arena: std.mem.Allocator, nodes: []const OutboundConfig, tags: []const []const u8) ![]const u8 {
    const max_outbounds = @import("linux/conn.zig").max_outbounds;
    if (tags.len == 0 or tags.len > max_outbounds) {
        @import("linux/sys.zig").log("bad config: an outbound group needs 1..{d} tags", .{max_outbounds});
        return error.BadConfig;
    }
    const g = try arena.alloc(u8, tags.len);
    for (tags, 0..) |t, i| g[i] = tagIndex(nodes, t) orelse {
        @import("linux/sys.zig").log("bad config: unknown outbound tag {s}", .{t});
        return error.BadConfig;
    };
    return g;
}

fn listenOn(spec: []const u8) !@import("linux/sys.zig").fd_t {
    const sys = @import("linux/sys.zig");
    const colon = std.mem.lastIndexOfScalar(u8, spec, ':') orelse return error.BadListen;
    const addr = try sys.SockAddr.parseIp(spec[0..colon], try std.fmt.parseInt(u16, spec[colon + 1 ..], 10));
    const fd = try sys.tcpSocket(addr.family());
    sys.setReuseAddr(fd);
    sys.bind(fd, &addr) catch |e| {
        sys.log("cannot bind {s}: {s}", .{ spec, @errorName(e) });
        return e;
    };
    try sys.listen(fd, 128);
    return fd;
}

/// IP literal or DNS name -> socket address (blocking, startup only).
/// With `bootstrap_dns` set, that nameserver is asked first; the system
/// resolver is only a fallback.
fn resolveServer(io: Io, host: []const u8, port: u16, bootstrap_dns: []const u8) !@import("linux/sys.zig").SockAddr {
    const sys = @import("linux/sys.zig");
    if (sys.SockAddr.parseIp(host, port)) |a| return a else |_| {}
    if (bootstrap_dns.len > 0) {
        const ns = parseHostPort(bootstrap_dns, 53) catch {
            sys.log("bad bootstrap_dns {s}", .{bootstrap_dns});
            return error.BadBootstrapDns;
        };
        if (resolveVia(ns, host, port)) |a| {
            return a;
        } else |e| {
            sys.log("bootstrap_dns {s}: cannot resolve {s}: {s}; trying system resolver", .{ bootstrap_dns, host, @errorName(e) });
        }
    }
    return resolveSystem(io, host, port);
}

/// "ip", "ip:port" or "[ip6]:port".
fn parseHostPort(spec: []const u8, default_port: u16) !@import("linux/sys.zig").SockAddr {
    const sys = @import("linux/sys.zig");
    if (spec.len > 0 and spec[0] == '[') {
        const close = std.mem.indexOfScalar(u8, spec, ']') orelse return error.BadAddress;
        const rest = spec[close + 1 ..];
        if (rest.len == 0) return sys.SockAddr.parseIp(spec[1..close], default_port);
        if (rest[0] != ':') return error.BadAddress;
        return sys.SockAddr.parseIp(spec[1..close], try std.fmt.parseInt(u16, rest[1..], 10));
    }
    // One colon: v4:port. None or several: bare v4 / v6 literal.
    if (std.mem.count(u8, spec, ":") == 1) {
        const colon = std.mem.indexOfScalar(u8, spec, ':').?;
        return sys.SockAddr.parseIp(spec[0..colon], try std.fmt.parseInt(u16, spec[colon + 1 ..], 10));
    }
    return sys.SockAddr.parseIp(spec, default_port);
}

/// Blocking A lookup straight at `ns` over UDP: 3 attempts, 2 s each.
fn resolveVia(ns: @import("linux/sys.zig").SockAddr, host: []const u8, port: u16) !@import("linux/sys.zig").SockAddr {
    const sys = @import("linux/sys.zig");
    const dns = @import("proxy/dns.zig");
    const fd = try sys.udpSocket(ns.family());
    defer sys.close(fd);
    var query: [dns.max_message]u8 = undefined;
    var reply: [dns.max_message]u8 = undefined;
    var attempt: usize = 0;
    while (attempt < 3) : (attempt += 1) {
        var id_bytes: [2]u8 = undefined;
        sys.randomBytes(&id_bytes);
        const id = std.mem.readInt(u16, &id_bytes, .big);
        const qlen = try dns.encodeQuery(&query, id, host);
        _ = try sys.sendTo(fd, query[0..qlen], &ns);
        if (!try sys.pollIn(fd, 2000)) continue;
        const d = sys.recvFrom(fd, &reply) catch continue;
        const ip = dns.firstA(reply[0..d.len], id) catch |e| switch (e) {
            error.WrongId => continue,
            else => return e,
        };
        sys.log("resolved {s} -> {d}.{d}.{d}.{d} via bootstrap_dns", .{ host, ip[0], ip[1], ip[2], ip[3] });
        return sys.SockAddr.fromIpv4(ip, port);
    }
    return error.Timeout;
}

fn resolveSystem(io: Io, host: []const u8, port: u16) !@import("linux/sys.zig").SockAddr {
    const sys = @import("linux/sys.zig");
    const hn = try Io.net.HostName.init(host);
    var buf: [16]Io.net.HostName.LookupResult = undefined;
    var q: Io.Queue(Io.net.HostName.LookupResult) = .init(&buf);
    try hn.lookup(io, &q, .{ .port = port, .family = .ip4 });
    var got: [16]Io.net.HostName.LookupResult = undefined;
    const n = try q.get(io, &got, 0);
    for (got[0..n]) |r| switch (r) {
        .address => |a| switch (a) {
            .ip4 => |v4| return sys.SockAddr.fromIpv4(v4.bytes, port),
            .ip6 => |v6| return sys.SockAddr.fromIpv6(v6.bytes, port),
        },
        .canonical_name => {},
    };
    return error.NoAddress;
}

// A valid base64url X25519 key: 32 zero bytes.
const test_pk = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn testConfig(overrides: anytype) FileConfig {
    var c: FileConfig = .{ .server = "example.com", .uuid = "00000000-0000-0000-0000-000000000000" };
    inline for (@typeInfo(@TypeOf(overrides)).@"struct".field_names) |name| @field(c, name) = @field(overrides, name);
    return c;
}

test "reality is the default and needs public_key" {
    const up = try selectUpstream(testConfig(.{ .public_key = test_pk, .short_id = "0123abcd" }));
    try std.testing.expect(up == .reality);
    try std.testing.expectEqualSlices(u8, &.{ 0x01, 0x23, 0xab, 0xcd, 0, 0, 0, 0 }, &up.reality.short_id);

    // A missing (or mistyped) public_key must fail, never downgrade to plain TLS.
    try std.testing.expectError(error.MissingPublicKey, selectUpstream(testConfig(.{})));
    try std.testing.expectError(error.InvalidPublicKey, selectUpstream(testConfig(.{ .public_key = "nope" })));
    try std.testing.expectError(error.InvalidShortId, selectUpstream(testConfig(.{ .public_key = test_pk, .short_id = "abc" })));
}

test "plain tls must opt into tls_verify explicitly" {
    try std.testing.expectError(error.MissingTlsVerify, selectUpstream(testConfig(.{ .security = .tls })));
    try std.testing.expectError(error.TlsVerifyNotImplemented, selectUpstream(testConfig(.{ .security = .tls, .tls_verify = .ca })));
    try std.testing.expectError(error.TlsVerifyNotImplemented, selectUpstream(testConfig(.{ .security = .tls, .tls_verify = .pin })));
    try std.testing.expectError(error.RealityFieldsInTlsMode, selectUpstream(testConfig(.{ .security = .tls, .tls_verify = .none, .public_key = test_pk })));
    try std.testing.expectError(error.RealityFieldsInTlsMode, selectUpstream(testConfig(.{ .security = .tls, .tls_verify = .none, .short_id = "01" })));

    const up = try selectUpstream(testConfig(.{ .security = .tls, .tls_verify = .none }));
    try std.testing.expectEqual(Upstream{ .tls = .none }, up);
}

test "config json: enums parse from strings, unknown keys are rejected" {
    const a = std.testing.allocator;
    const ok = try std.json.parseFromSlice(FileConfig, a,
        \\{"server":"x","uuid":"u","security":"tls","tls_verify":"none"}
    , .{});
    defer ok.deinit();
    try std.testing.expectEqual(Security.tls, ok.value.security);
    try std.testing.expectEqual(@as(?TlsVerify, .none), ok.value.tls_verify);

    // The exact typo the review was worried about.
    try std.testing.expectError(error.UnknownField, std.json.parseFromSlice(FileConfig, a,
        \\{"server":"x","uuid":"u","publickey":"abc"}
    , .{}));
    try std.testing.expectError(error.InvalidEnumTag, std.json.parseFromSlice(FileConfig, a,
        \\{"server":"x","uuid":"u","security":"plain"}
    , .{}));
}
