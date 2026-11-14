//! Chrome ClientHello profile (BoringSSL as shipped in Chrome 127+).
//!
//! Reproduces what matters for JA3/JA4-style fingerprinting:
//!   * 15 cipher suites behind one GREASE suite,
//!   * GREASE in supported_groups / key_share / supported_versions,
//!   * an empty GREASE extension first and a one-byte GREASE extension last,
//!   * compress_certificate (brotli), ALPS (17613), GREASE ECH (65037),
//!   * the remaining extensions in a random order per ClientHello, like
//!     BoringSSL's extension permutation (RFC 8701 values from the seed).
//!
//! The negotiable set is still TLS 1.3 + x25519 (+ X25519MLKEM768 when a
//! public key is supplied): everything else is offered for looks only; the
//! handshake code rejects a server that picks any of it.
//!
//! Expected JA4 with ML-KEM and ALPN h2,http/1.1: t13d1516h2_8daaf6152771_d8a2da3f94cd.

const std = @import("std");
const tls = std.crypto.tls;
const hello = @import("hello.zig");

fn suite(v: u16) tls.CipherSuite {
    return @fromBackingInt(v);
}
fn group(v: u16) tls.NamedGroup {
    return @fromBackingInt(v);
}
fn version(v: u16) tls.ProtocolVersion {
    return @fromBackingInt(v);
}

/// Chrome's cipher list minus the leading GREASE suite.
pub const chrome_suites = [_]tls.CipherSuite{
    .AES_128_GCM_SHA256,                  .AES_256_GCM_SHA384,                        .CHACHA20_POLY1305_SHA256,
    .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, .ECDHE_RSA_WITH_AES_128_GCM_SHA256,         .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    .ECDHE_RSA_WITH_AES_256_GCM_SHA384,   .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256, .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
    .ECDHE_RSA_WITH_AES_128_CBC_SHA,      .ECDHE_RSA_WITH_AES_256_CBC_SHA,            .RSA_WITH_AES_128_GCM_SHA256,
    .RSA_WITH_AES_256_GCM_SHA384,         .RSA_WITH_AES_128_CBC_SHA,                  .RSA_WITH_AES_256_CBC_SHA,
};

pub const x25519_ml_kem768: tls.NamedGroup = .x25519_ml_kem768;
/// ML-KEM-768 encapsulation key (1184) followed by the x25519 public key (32).
pub const ml_kem_key_share_len = 1184 + 32;

const sig_algs = [_]tls.SignatureScheme{
    .ecdsa_secp256r1_sha256,
    .rsa_pss_rsae_sha256,
    .rsa_pkcs1_sha256,
    .ecdsa_secp384r1_sha384,
    .rsa_pss_rsae_sha384,
    .rsa_pkcs1_sha384,
    .rsa_pss_rsae_sha512,
    .rsa_pkcs1_sha512,
};
const psk_modes = [_]tls.PskKeyExchangeMode{.psk_dhe_ke};
pub const alpn_h2_http11 = [_][]const u8{ "h2", "http/1.1" };
pub const alpn_http11 = [_][]const u8{"http/1.1"};

/// GREASE value for seed byte `b`: 0x?a?a with the same high nibble twice.
fn grease(b: u8) u16 {
    const hi: u16 = (b & 0xf0) | 0x0a;
    return (hi << 8) | hi;
}

pub const max_extensions = 19;
const ech_max_len = 1 + 4 + 1 + 2 + 32 + 2 + 240;

/// All storage the extension list points into. Build in place and keep it
/// alive (and unmoved) until the ClientHello has been encoded.
pub const Chrome = struct {
    suites: [1 + chrome_suites.len]tls.CipherSuite,
    groups: [5]tls.NamedGroup,
    groups_len: u8,
    versions: [3]tls.ProtocolVersion,
    key_shares: [3]hello.KeyShareEntry,
    key_shares_len: u8,
    grease_ks: [1]u8,
    ech: [ech_max_len]u8,
    ech_len: u16,
    exts: [max_extensions]hello.Extension,
    exts_len: u8,

    pub const Input = struct {
        sni: []const u8,
        x25519_public: *const [32]u8,
        /// `ml_kem_key_share_len` bytes, or null to offer x25519 only.
        ml_kem_public: ?[]const u8 = null,
        alpn: []const []const u8 = &alpn_h2_http11,
        /// Advertise compress_certificate (brotli). Chrome does; we cannot
        /// decompress, so only offer it to servers known not to compress
        /// (Go/REALITY). Off for origins such as Cloudflare.
        compress_certificate: bool = true,
    };

    pub fn build(self: *Chrome, rand: std.Random, in: Input) void {
        var seed: [16]u8 = undefined;
        rand.bytes(&seed);
        // BoringSSL keeps the two GREASE extensions distinct.
        if ((seed[2] & 0xf0) == (seed[3] & 0xf0)) seed[3] ^= 0x10;

        self.suites[0] = suite(grease(seed[0]));
        self.suites[1..].* = chrome_suites;

        self.groups_len = 0;
        self.addGroup(group(grease(seed[1])));
        if (in.ml_kem_public != null) self.addGroup(x25519_ml_kem768);
        self.addGroup(.x25519);
        self.addGroup(.secp256r1);
        self.addGroup(.secp384r1);

        self.versions = .{ version(grease(seed[4])), .tls_1_3, .tls_1_2 };

        self.grease_ks = .{0};
        self.key_shares_len = 0;
        self.addKeyShare(.{ .group = group(grease(seed[1])), .public_key = &self.grease_ks });
        if (in.ml_kem_public) |pk| self.addKeyShare(.{ .group = x25519_ml_kem768, .public_key = pk });
        self.addKeyShare(.{ .group = .x25519, .public_key = in.x25519_public });

        self.buildEch(rand, seed[6]);

        // Extensions BoringSSL permutes (everything but the GREASE pair).
        var body = [_]hello.Extension{
            .{ .server_name = in.sni },
            .{ .raw = .{ .type = 0x0017 } }, // extended_master_secret
            .{ .raw = .{ .type = 0xff01, .data = &.{0} } }, // renegotiation_info
            .{ .supported_groups = self.groups[0..self.groups_len] },
            .{ .raw = .{ .type = 0x000b, .data = &.{ 1, 0 } } }, // ec_point_formats
            .{ .raw = .{ .type = 0x0023 } }, // session_ticket
            .{ .alpn = in.alpn },
            .{ .raw = .{ .type = 0x0005, .data = &.{ 1, 0, 0, 0, 0 } } }, // status_request
            .{ .signature_algorithms = &sig_algs },
            .{ .raw = .{ .type = 0x0012 } }, // signed_certificate_timestamp
            .{ .key_share = self.key_shares[0..self.key_shares_len] },
            .{ .psk_key_exchange_modes = &psk_modes },
            .{ .supported_versions = self.versions[0..] },
            // compress_certificate: brotli; replaced by a harmless duplicate-free
            // extension when disabled so the slot count stays fixed.
            if (in.compress_certificate) .{ .raw = .{ .type = 0x001b, .data = &.{ 2, 0, 2 } } } else .{ .record_size_limit = 0x4001 },
            .{ .raw = .{ .type = 0x44cd, .data = &.{ 0, 3, 2, 'h', '2' } } }, // application_settings (ALPS)
            .{ .raw = .{ .type = 0xfe0d, .data = self.ech[0..self.ech_len] } }, // encrypted_client_hello (GREASE)
        };
        rand.shuffle(hello.Extension, &body);

        self.exts[0] = .{ .raw = .{ .type = grease(seed[2]) } };
        self.exts[1 .. 1 + body.len].* = body;
        self.exts[1 + body.len] = .{ .raw = .{ .type = grease(seed[3]), .data = &.{0} } };
        self.exts_len = body.len + 2;
    }

    pub fn cipherSuites(self: *const Chrome) []const tls.CipherSuite {
        return &self.suites;
    }

    pub fn extensions(self: *const Chrome) []const hello.Extension {
        return self.exts[0..self.exts_len];
    }

    fn addGroup(self: *Chrome, g: tls.NamedGroup) void {
        self.groups[self.groups_len] = g;
        self.groups_len += 1;
    }

    fn addKeyShare(self: *Chrome, e: hello.KeyShareEntry) void {
        self.key_shares[self.key_shares_len] = e;
        self.key_shares_len += 1;
    }

    /// GREASE ECH (draft-ietf-tls-esni, ClientHelloOuter):
    /// type(0) | kdf 0x0001 | aead 0x0001 | config_id | enc<32> | payload<n>
    /// with an ephemeral X25519 public key as `enc` and a random payload of 144..240 bytes
    /// in 32-byte steps, mirroring BoringSSL.
    fn buildEch(self: *Chrome, rand: std.Random, config_seed: u8) void {
        var n: usize = 0;
        self.ech[n] = 0;
        n += 1;
        self.ech[n..][0..4].* = .{ 0, 1, 0, 1 };
        n += 4;
        self.ech[n] = config_seed;
        n += 1;
        self.ech[n..][0..2].* = .{ 0, 32 };
        n += 2;
        // DHKEM(X25519) enc is the sender's ephemeral public key. Generating
        // it has the same wire distribution as HPKE SetupSender; arbitrary
        // random bytes (even with the high bit cleared) do not.
        var ephemeral_secret: [32]u8 = undefined;
        rand.bytes(&ephemeral_secret);
        defer std.crypto.secureZero(u8, &ephemeral_secret);
        self.ech[n..][0..32].* = std.crypto.dh.X25519.recoverPublicKey(ephemeral_secret);
        n += 32;
        const payload_len: usize = 144 + 32 * @as(usize, rand.uintLessThan(u8, 4));
        self.ech[n..][0..2].* = .{ 0, @intCast(payload_len) };
        n += 2;
        rand.bytes(self.ech[n..][0..payload_len]);
        n += payload_len;
        self.ech_len = @intCast(n);
    }
};

const testing = std.testing;

test "chrome profile shape" {
    var prng = std.Random.DefaultPrng.init(7);
    var fp: Chrome = undefined;
    const pk: [32]u8 = @splat(9);
    fp.build(prng.random(), .{ .sni = "example.com", .x25519_public = &pk });

    try testing.expectEqual(@as(usize, 16), fp.cipherSuites().len);
    try testing.expectEqual(@as(usize, 18), fp.extensions().len);
    // GREASE bookends
    const first = fp.extensions()[0].raw;
    const last = fp.extensions()[17].raw;
    try testing.expect(first.type & 0x0f0f == 0x0a0a and first.data.len == 0);
    try testing.expect(last.type & 0x0f0f == 0x0a0a and last.data.len == 1);
    try testing.expect(first.type != last.type);
    try testing.expect(@backingInt(fp.cipherSuites()[0]) & 0x0f0f == 0x0a0a);
    try testing.expectEqual(@as(usize, 4), fp.groups_len);
    try testing.expectEqual(@as(usize, 2), fp.key_shares_len);

    // Every expected extension type appears exactly once in the body.
    const want = [_]u16{ 0, 0x17, 0xff01, 0x0a, 0x0b, 0x23, 0x10, 0x05, 0x0d, 0x12, 0x33, 0x2d, 0x2b, 0x1b, 0x44cd, 0xfe0d };
    for (want) |t| {
        var count: usize = 0;
        for (fp.extensions()[1..17]) |e| {
            const ty: u16 = switch (e) {
                .server_name => 0,
                .supported_groups => 0x0a,
                .alpn => 0x10,
                .signature_algorithms => 0x0d,
                .key_share => 0x33,
                .psk_key_exchange_modes => 0x2d,
                .supported_versions => 0x2b,
                .raw => |r| r.type,
                else => 0xffff,
            };
            if (ty == t) count += 1;
        }
        try testing.expectEqual(@as(usize, 1), count);
    }

    // It must still encode.
    var buf: [2048]u8 = undefined;
    const sid: [32]u8 = @splat(0);
    const enc = try hello.encode(&buf, .{
        .random = @splat(1),
        .session_id = &sid,
        .cipher_suites = fp.cipherSuites(),
        .extensions = fp.extensions(),
    });
    try testing.expect(enc.msg.len > 400 and enc.msg.len < 800);
}

test "ml-kem profile" {
    var prng = std.Random.DefaultPrng.init(1);
    var fp: Chrome = undefined;
    const pk: [32]u8 = @splat(9);
    const kem: [ml_kem_key_share_len]u8 = @splat(3);
    fp.build(prng.random(), .{ .sni = "a", .x25519_public = &pk, .ml_kem_public = &kem });
    try testing.expectEqual(@as(usize, 5), fp.groups_len);
    try testing.expectEqual(@as(usize, 3), fp.key_shares_len);
    try testing.expect(fp.key_shares[1].group == .x25519_ml_kem768);
    try testing.expectEqual(@as(usize, ml_kem_key_share_len), fp.key_shares[1].public_key.len);
}

test "GREASE ECH enc is an X25519 public key matching a known vector" {
    const vector = @import("testdata/rfc8448.zig");
    const Source = struct {
        fn fill(_: *@This(), bytes: []u8) void {
            for (bytes, 0..) |*b, i| b.* = vector.client_priv[i % vector.client_priv.len];
        }
    };
    var source: Source = .{};
    var fp: Chrome = undefined;
    fp.buildEch(std.Random.init(&source, Source.fill), 0x42);
    try testing.expectEqualSlices(u8, &.{ 0, 0, 1, 0, 1, 0x42, 0, 32 }, fp.ech[0..8]);
    // Comparing the whole known public key also rejects a "fix" that merely
    // masks the high bit of random bytes instead of generating a key.
    try testing.expectEqualSlices(u8, &vector.client_pub, fp.ech[8..40]);
    const payload_len = std.mem.readInt(u16, fp.ech[40..42], .big);
    try testing.expect(payload_len >= 144 and payload_len <= 240 and (payload_len - 144) % 32 == 0);
    try testing.expectEqual(@as(usize, 42) + payload_len, fp.ech_len);
}
