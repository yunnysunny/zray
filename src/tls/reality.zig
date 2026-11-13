//! REALITY client authentication (github.com/XTLS/REALITY), wire-compatible
//! with xray-core's `transport/internet/reality`.
//!
//! Client side, in order:
//!
//!   1. ClientHello is serialized with a zeroed 32-byte session_id.
//!   2. auth_key = HKDF-SHA256(ikm = X25519(ephemeral_sk, server_pk),
//!                             salt = ClientHello.random[0..20], info = "REALITY")
//!   3. session_id = AEAD-Seal(key = auth_key, nonce = random[20..32],
//!                             plaintext = version(3) | 0 | unix_time_be32 | short_id(8),
//!                             aad = whole ClientHello handshake message)
//!      AEAD is AES-256-GCM when the first real cipher suite offered is
//!      AES-GCM, otherwise ChaCha20-Poly1305 (mirrors Go's aesgcmPreferred).
//!   4. The server's leaf certificate is ed25519 and its signature field is
//!      HMAC-SHA512(auth_key, ed25519_public_key). We check exactly that
//!      instead of walking a CA chain.
//!
//! If any byte differs the server silently proxies us to the real site, so
//! every step here is checked against a simulated server in the tests.

const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const mem = std.mem;
const X25519 = crypto.dh.X25519;
const Sha256 = crypto.hash.sha2.Sha256;
const Sha512 = crypto.hash.sha2.Sha512;
const HmacSha256 = crypto.auth.hmac.Hmac(Sha256);
const HmacSha512 = crypto.auth.hmac.Hmac(Sha512);
const Hkdf = crypto.kdf.hkdf.Hkdf(HmacSha256);
const Aes256Gcm = crypto.aead.aes_gcm.Aes256Gcm;
const ChaCha20Poly1305 = crypto.aead.chacha_poly.ChaCha20Poly1305;

const hello = @import("hello.zig");
const client = @import("client.zig");

pub const Config = struct {
    /// Server's X25519 public key (`publicKey` in the Xray client config).
    server_public_key: [32]u8,
    /// Up to 8 bytes, zero-padded on the right (`shortId`).
    short_id: [8]u8 = @splat(0),
    /// Advertised client version; servers may enforce a minimum.
    version: [3]u8 = .{ 25, 1, 30 },

    /// Parse the hex `shortId` string from an Xray config (0..16 hex chars).
    pub fn shortIdFromHex(hex: []const u8) error{InvalidShortId}![8]u8 {
        if (hex.len > 16 or hex.len % 2 != 0) return error.InvalidShortId;
        var out: [8]u8 = @splat(0);
        _ = std.fmt.hexToBytes(out[0 .. hex.len / 2], hex) catch return error.InvalidShortId;
        return out;
    }

    /// Parse the base64url (no padding) `publicKey` string from an Xray config.
    pub fn publicKeyFromBase64(s: []const u8) error{InvalidPublicKey}![32]u8 {
        var out: [32]u8 = undefined;
        const dec = std.base64.url_safe_no_pad.Decoder;
        const n = dec.calcSizeForSlice(s) catch return error.InvalidPublicKey;
        if (n != 32) return error.InvalidPublicKey;
        dec.decode(&out, s) catch return error.InvalidPublicKey;
        return out;
    }
};

pub const Error = error{
    /// session_id slot is not 32 bytes (ClientHello built without one).
    SessionIdNotReserved,
    /// X25519 with the server key produced the identity element.
    WeakServerKey,
    /// ClientHello could not be parsed for its cipher suite list.
    MalformedClientHello,
};

pub const Aead = enum { aes_256_gcm, chacha20_poly1305 };

/// Go's `aesgcmPreferred`: scan offered suites, decide on the first that is
/// either AES-GCM (-> true) or ChaCha20 (-> false). GREASE etc. are skipped.
pub fn preferredAead(cipher_suites: []const tls.CipherSuite) Aead {
    for (cipher_suites) |cs| switch (cs) {
        .AES_128_GCM_SHA256,
        .AES_256_GCM_SHA384,
        .ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        .ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
        .ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
        => return .aes_256_gcm,
        .CHACHA20_POLY1305_SHA256,
        .ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
        .ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
        => return .chacha20_poly1305,
        else => {},
    };
    return .chacha20_poly1305;
}

pub const Reality = struct {
    cfg: Config,
    /// Unix time (seconds) stamped into the session_id. Set before the hook runs.
    now: i64,
    /// Derived during the hook; needed later to verify the certificate.
    auth_key: [32]u8 = undefined,
    /// Set if the hook failed; `client.clientHello` cannot report it directly.
    err: ?Error = null,

    pub fn init(cfg: Config, now: i64) Reality {
        return .{ .cfg = cfg, .now = now };
    }

    /// Hook for `client.Client.clientHello`.
    pub fn helloHook(r: *Reality) client.HelloHook {
        return .{ .ctx = r, .run = &hookRun };
    }

    /// Verifier for `client.Options`.
    pub fn verifier(r: *Reality) client.Verifier {
        return .{ .ctx = r, .verify = &verifyRun };
    }

    fn hookRun(ctx: ?*anyopaque, enc: hello.Encoded, ecdh_secret: *const [32]u8) void {
        const r: *Reality = @ptrCast(@alignCast(ctx.?));
        r.err = null;
        r.fill(enc, ecdh_secret) catch |e| {
            r.err = e;
        };
    }

    fn fill(r: *Reality, enc: hello.Encoded, ecdh_secret: *const [32]u8) Error!void {
        if (enc.session_id.len != 32) return error.SessionIdNotReserved;
        const aead = try aeadFromHello(enc.msg);

        const shared = X25519.scalarmult(ecdh_secret.*, r.cfg.server_public_key) catch return error.WeakServerKey;
        r.auth_key = deriveAuthKey(shared, enc.random[0..20]);

        var plaintext: [16]u8 = undefined;
        plaintext[0..3].* = r.cfg.version;
        plaintext[3] = 0;
        mem.writeInt(u32, plaintext[4..8], @intCast(@as(u64, @bitCast(r.now)) & 0xffff_ffff), .big);
        plaintext[8..16].* = r.cfg.short_id;

        // AAD is the whole ClientHello with the session_id zeroed. The output
        // slot lives inside the AAD, so seal into a scratch buffer first; the
        // AEADs MAC the AAD at different points relative to writing ciphertext.
        @memset(enc.session_id, 0);
        const nonce = enc.random[20..32].*;
        var sealed: [32]u8 = undefined;
        seal(aead, r.auth_key, nonce, &plaintext, enc.msg, &sealed);
        @memcpy(enc.session_id, &sealed);
    }

    fn verifyRun(ctx: ?*anyopaque, input: client.VerifyInput) error{CertificateRejected}!void {
        const r: *Reality = @ptrCast(@alignCast(ctx.?));
        if (r.err != null) return error.CertificateRejected;
        if (input.leaf.pub_key_algo != .curveEd25519) return error.CertificateRejected;
        const pub_key = input.leaf.pubKey();
        const sig = input.leaf.signature();
        if (pub_key.len != 32 or sig.len != HmacSha512.mac_length) return error.CertificateRejected;

        var expected: [HmacSha512.mac_length]u8 = undefined;
        HmacSha512.create(&expected, pub_key, &r.auth_key);
        if (!crypto.timing_safe.eql([HmacSha512.mac_length]u8, expected, sig[0..HmacSha512.mac_length].*))
            return error.CertificateRejected;
    }
};

pub fn deriveAuthKey(shared: [32]u8, salt: *const [20]u8) [32]u8 {
    const prk = Hkdf.extract(salt, &shared);
    var out: [32]u8 = undefined;
    Hkdf.expand(&out, "REALITY", prk);
    return out;
}

fn seal(aead: Aead, key: [32]u8, nonce: [12]u8, plaintext: *const [16]u8, aad: []const u8, out: *[32]u8) void {
    switch (aead) {
        .aes_256_gcm => Aes256Gcm.encrypt(out[0..16], out[16..32], plaintext, aad, nonce, key),
        .chacha20_poly1305 => ChaCha20Poly1305.encrypt(out[0..16], out[16..32], plaintext, aad, nonce, key),
    }
}

/// Server-side counterpart, used in tests and useful for diagnostics.
pub fn open(aead: Aead, key: [32]u8, nonce: [12]u8, session_id: *const [32]u8, aad: []const u8) ?[16]u8 {
    var out: [16]u8 = undefined;
    switch (aead) {
        .aes_256_gcm => Aes256Gcm.decrypt(&out, session_id[0..16], session_id[16..32].*, aad, nonce, key) catch return null,
        .chacha20_poly1305 => ChaCha20Poly1305.decrypt(&out, session_id[0..16], session_id[16..32].*, aad, nonce, key) catch return null,
    }
    return out;
}

/// Read the cipher_suites vector out of a serialized ClientHello message.
fn aeadFromHello(msg: []const u8) Error!Aead {
    // type(1) len(3) version(2) random(32) sid_len(1) sid(32)
    const sid_len_at = 4 + 2 + 32;
    if (msg.len < sid_len_at + 1) return error.MalformedClientHello;
    const sid_len = msg[sid_len_at];
    var pos: usize = sid_len_at + 1 + sid_len;
    if (msg.len < pos + 2) return error.MalformedClientHello;
    const suites_len = mem.readInt(u16, msg[pos..][0..2], .big);
    pos += 2;
    if (suites_len % 2 != 0 or msg.len < pos + suites_len) return error.MalformedClientHello;

    var suites_buf: [64]tls.CipherSuite = undefined;
    const n = @min(suites_len / 2, suites_buf.len);
    for (0..n) |i| suites_buf[i] = @fromBackingInt(mem.readInt(u16, msg[pos + 2 * i ..][0..2], .big));
    return preferredAead(suites_buf[0..n]);
}

// ---------------------------------------------------------------------------
// Tests

const testing = std.testing;
const Certificate = crypto.Certificate;

const server_sk: [32]u8 = @splat(0x42);
const client_seed: [32]u8 = @splat(0x17);

fn testConfig() Config {
    const server_kp = X25519.KeyPair.generateDeterministic(server_sk);
    return .{
        .server_public_key = server_kp.public_key,
        .short_id = Config.shortIdFromHex("0123456789abcdef") catch unreachable,
        .version = .{ 25, 1, 30 },
    };
}

fn buildHello(buf: []u8, r: *Reality, suites: []const tls.CipherSuite, kp: X25519.KeyPair) !hello.Encoded {
    const shares = [_]hello.KeyShareEntry{.{ .group = .x25519, .public_key = &kp.public_key }};
    const groups = [_]tls.NamedGroup{.x25519};
    const versions = [_]tls.ProtocolVersion{.tls_1_3};
    const exts = [_]hello.Extension{
        .{ .server_name = "www.example.com" },
        .{ .supported_groups = &groups },
        .{ .key_share = &shares },
        .{ .supported_versions = &versions },
    };
    const zero_sid: [32]u8 = @splat(0);
    var random: [32]u8 = undefined;
    for (&random, 0..) |*b, i| b.* = @intCast(0xa0 + i);
    const enc = try hello.encode(buf, .{
        .random = random,
        .session_id = &zero_sid,
        .cipher_suites = suites,
        .extensions = &exts,
    });
    r.helloHook().run(r, enc, &kp.secret_key);
    return enc;
}

/// What the REALITY server does with an incoming ClientHello.
fn serverDecrypt(enc: hello.Encoded, client_pub: [32]u8, aead: Aead) !struct { auth_key: [32]u8, plain: [16]u8 } {
    const shared = try X25519.scalarmult(server_sk, client_pub);
    const auth_key = deriveAuthKey(shared, enc.random[0..20]);
    var aad_buf: [4096]u8 = undefined;
    @memcpy(aad_buf[0..enc.msg.len], enc.msg);
    @memset(aad_buf[hello.Encoded.session_id_offset..][0..32], 0);
    const plain = open(aead, auth_key, enc.random[20..32].*, enc.session_id[0..32], aad_buf[0..enc.msg.len]) orelse
        return error.AuthFailed;
    return .{ .auth_key = auth_key, .plain = plain };
}

test "session_id round-trips through a simulated server (AES-GCM)" {
    var r = Reality.init(testConfig(), 0x6711_2233);
    const kp = X25519.KeyPair.generateDeterministic(client_seed);
    var buf: [512]u8 = undefined;
    const suites = [_]tls.CipherSuite{ @fromBackingInt(0x0a0a), .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256 };
    const enc = try buildHello(&buf, &r, &suites, kp);
    try testing.expectEqual(@as(?Error, null), r.err);

    const got = try serverDecrypt(enc, kp.public_key, .aes_256_gcm);
    try testing.expectEqualSlices(u8, &r.auth_key, &got.auth_key);
    try testing.expectEqualSlices(u8, &.{ 25, 1, 30, 0 }, got.plain[0..4]);
    try testing.expectEqual(@as(u32, 0x6711_2233), mem.readInt(u32, got.plain[4..8], .big));
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }, got.plain[8..16]);

    // Wrong AEAD choice must fail, as must a tampered ClientHello.
    try testing.expectError(error.AuthFailed, serverDecrypt(enc, kp.public_key, .chacha20_poly1305));
    enc.msg[enc.msg.len - 1] ^= 1;
    try testing.expectError(error.AuthFailed, serverDecrypt(enc, kp.public_key, .aes_256_gcm));
}

test "ChaCha20 is selected when it is the first real suite" {
    var r = Reality.init(testConfig(), 1_700_000_000);
    const kp = X25519.KeyPair.generateDeterministic(client_seed);
    var buf: [512]u8 = undefined;
    const suites = [_]tls.CipherSuite{ @fromBackingInt(0x1a1a), .CHACHA20_POLY1305_SHA256, .AES_128_GCM_SHA256 };
    const enc = try buildHello(&buf, &r, &suites, kp);
    try testing.expectEqual(@as(?Error, null), r.err);
    const got = try serverDecrypt(enc, kp.public_key, .chacha20_poly1305);
    try testing.expectEqual(@as(u32, 1_700_000_000), mem.readInt(u32, got.plain[4..8], .big));
}

test "missing session_id reservation is reported" {
    var r = Reality.init(testConfig(), 0);
    const kp = X25519.KeyPair.generateDeterministic(client_seed);
    var buf: [512]u8 = undefined;
    const shares = [_]hello.KeyShareEntry{.{ .group = .x25519, .public_key = &kp.public_key }};
    const exts = [_]hello.Extension{.{ .key_share = &shares }};
    const suites = [_]tls.CipherSuite{.AES_128_GCM_SHA256};
    const enc = try hello.encode(&buf, .{ .random = @splat(1), .cipher_suites = &suites, .extensions = &exts });
    r.helloHook().run(&r, enc, &kp.secret_key);
    try testing.expectEqual(@as(?Error, error.SessionIdNotReserved), r.err);
}

// ed25519 self-signed cert generated with openssl; the signature field (last
// 64 bytes) is replaced at test time with the REALITY HMAC.
const ed25519_cert_der = blk: {
    @setEvalBranchQuota(20000);
    var out: [276]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "308201103081c3a00302010202140dd980186a4748a2023449b9333e2a799c02beb6300506032b657030173115301306035504030c0c7265616c6974792e74657374301e170d3236313031373032343033325a170d3336313031343032343033325a30173115301306035504030c0c7265616c6974792e74657374302a300506032b6570032100d32d741f68c3b3faeddcd8ec44f6674c3502834cf444fda11f9d32a3307879e3a321301f301d0603551d0e04160414ac06af209194b27bb76229e7aac038ef8ba2a6b3300506032b6570034100c68a1b5e3912886939b40fb8d680f311f4277bbea2bd045a3f13a7884535604160f4ef271d807da95207a40210a8241c355ff6469b2fc0f2cd99aef459e49308") catch unreachable;
    break :blk out;
};

test "certificate verifier accepts HMAC-signed ed25519 cert and rejects others" {
    var r = Reality.init(testConfig(), 0);
    r.auth_key = @splat(0x5c);

    var der = ed25519_cert_der;
    var parsed = try Certificate.parse(.{ .buffer = &der, .index = 0 });
    try testing.expect(parsed.pub_key_algo == .curveEd25519);
    try testing.expectEqual(@as(usize, 64), parsed.signature().len);

    // Genuine openssl signature: not ours.
    const chain = @import("handshake.zig").Certificate{ .request_context = &.{}, .list = &.{} };
    try testing.expectError(error.CertificateRejected, r.verifier().verify(&r, .{ .leaf = parsed, .chain = chain }));

    // Patch in HMAC-SHA512(auth_key, pubkey) as the server does.
    var mac: [64]u8 = undefined;
    HmacSha512.create(&mac, parsed.pubKey(), &r.auth_key);
    @memcpy(der[der.len - 64 ..], &mac);
    parsed = try Certificate.parse(.{ .buffer = &der, .index = 0 });
    try r.verifier().verify(&r, .{ .leaf = parsed, .chain = chain });

    // Different auth_key (e.g. wrong server key) -> reject.
    r.auth_key = @splat(0x5d);
    try testing.expectError(error.CertificateRejected, r.verifier().verify(&r, .{ .leaf = parsed, .chain = chain }));
}

test "config parsing helpers" {
    try testing.expectEqualSlices(u8, &.{ 0xab, 0xcd, 0, 0, 0, 0, 0, 0 }, &(try Config.shortIdFromHex("abcd")));
    try testing.expectEqualSlices(u8, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }, &(try Config.shortIdFromHex("")));
    try testing.expectError(error.InvalidShortId, Config.shortIdFromHex("abc"));
    try testing.expectError(error.InvalidShortId, Config.shortIdFromHex("0123456789abcdef00"));

    const kp = X25519.KeyPair.generateDeterministic(server_sk);
    var b64: [43]u8 = undefined;
    _ = std.base64.url_safe_no_pad.Encoder.encode(&b64, &kp.public_key);
    try testing.expectEqualSlices(u8, &kp.public_key, &(try Config.publicKeyFromBase64(&b64)));
    try testing.expectError(error.InvalidPublicKey, Config.publicKeyFromBase64("short"));
}

test "preferredAead mirrors Go" {
    try testing.expectEqual(Aead.aes_256_gcm, preferredAead(&.{ @fromBackingInt(0x0a0a), .AES_128_GCM_SHA256, .CHACHA20_POLY1305_SHA256 }));
    try testing.expectEqual(Aead.chacha20_poly1305, preferredAead(&.{ .CHACHA20_POLY1305_SHA256, .AES_128_GCM_SHA256 }));
    try testing.expectEqual(Aead.chacha20_poly1305, preferredAead(&.{}));
}

test "REALITY authenticates the standalone share when hybrid keys are independent" {
    var r = Reality.init(testConfig(), 0x6711_2233);
    var hs_buf: [2048]u8 = undefined;
    var c = client.Client.init(.{
        .entropy = @splat(0x11),
        .hybrid_seed = @as([64]u8, @splat(0x22)) ++ @as([32]u8, @splat(0x33)),
        .verifier = r.verifier(),
        .handshake_buf = &hs_buf,
    });
    var prng = std.Random.DefaultPrng.init(42);
    var fp: @import("fingerprint.zig").Chrome = undefined;
    fp.build(prng.random(), .{ .sni = "example.com", .x25519_public = c.publicKey(), .ml_kem_public = c.mlKemPublicKey() });
    var buf: [4096]u8 = undefined;
    const wire = try c.clientHello(&buf, .{
        .random = undefined,
        .session_id = &@as([32]u8, @splat(0)),
        .cipher_suites = fp.cipherSuites(),
        .extensions = fp.extensions(),
    }, r.helloHook());
    try testing.expectEqual(@as(?Error, null), r.err);
    const msg = buf[5..wire.len];
    const enc: hello.Encoded = .{
        .msg = msg,
        .random = msg[hello.Encoded.random_offset..][0..32],
        .session_id = msg[hello.Encoded.session_id_offset..][0..32],
    };
    const got = try serverDecrypt(enc, c.publicKey().*, .aes_256_gcm);
    try testing.expectEqualSlices(u8, &r.auth_key, &got.auth_key);
    try testing.expectEqualSlices(u8, &r.cfg.short_id, got.plain[8..16]);
    const hybrid = c.mlKemPublicKey().?;
    try testing.expectError(error.AuthFailed, serverDecrypt(enc, hybrid[hybrid.len - 32 ..][0..32].*, .aes_256_gcm));
}
