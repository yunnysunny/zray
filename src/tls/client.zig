//! Sans-I/O TLS 1.3 client state machine.
//!
//! The caller owns the socket and the event loop; this type only transforms
//! bytes:
//!
//!   var c = Client.init(.{ ... });
//!   const first_flight = try c.clientHello(&hello_buf, params, hook);   // send this
//!   ... for each complete record read from the socket:
//!   const r = try c.handleRecord(record, &out_buf);
//!   if (r.to_send.len > 0) send(r.to_send);
//!   if (r.app_data.len > 0) deliver(r.app_data);
//!   ... once r.event == .handshake_complete:
//!   const rec = try c.encrypt(payload, &out_buf); send(rec);
//!
//! Supported: TLS 1.3 only, x25519 key share, AES-GCM / ChaCha20-Poly1305,
//! server auth via a pluggable `Verifier`, KeyUpdate, close_notify.
//! Not supported (by design): TLS 1.2, HelloRetryRequest, PSK/0-RTT,
//! client certificates, post-handshake CertificateRequest.

const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const mem = std.mem;
const X25519 = crypto.dh.X25519;
const MLKem768 = crypto.kem.ml_kem.MLKem768;
const Certificate = crypto.Certificate;

const hello = @import("hello.zig");
const ks = @import("key_schedule.zig");
const record = @import("record.zig");
const handshake = @import("handshake.zig");
const signature = @import("signature.zig");

pub const Error = hello.Error || record.Error || handshake.Error || signature.Error || error{
    /// Message or record not valid in the current state.
    UnexpectedMessage,
    /// Server echoed a different session_id than we sent.
    SessionIdMismatch,
    /// Server selected a cipher suite or group we did not offer.
    IllegalSelection,
    /// Peer sent a fatal alert; see `last_alert`.
    FatalAlert,
    /// ECDH produced the identity element (bogus server key share).
    WeakKeyShare,
    /// Certificate could not be parsed or has an unusable public key.
    BadCertificate,
    /// `Verifier` rejected the certificate.
    CertificateRejected,
    /// Server Finished.verify_data mismatch.
    BadFinished,
    /// Called a method on a client that is not in the right state.
    InvalidState,
};

pub const State = enum {
    start,
    wait_server_hello,
    wait_encrypted_extensions,
    wait_certificate,
    wait_certificate_verify,
    wait_finished,
    connected,
    closed,
    failed,
};

pub const Event = enum {
    none,
    handshake_complete,
    /// Peer sent close_notify; `handleRecord` will refuse further input.
    close_notify,
    /// Peer sent a warning alert; connection continues.
    warning_alert,
};

pub const Result = struct {
    /// Bytes the caller must transmit (slice into the `out` buffer).
    to_send: []const u8 = &.{},
    /// Decrypted application data (slice into the record buffer).
    app_data: []u8 = &.{},
    event: Event = .none,
};

/// Certificate verification policy. Called once with the parsed leaf.
pub const Verifier = struct {
    ctx: ?*anyopaque = null,
    verify: *const fn (ctx: ?*anyopaque, input: VerifyInput) error{CertificateRejected}!void,

    /// Accepts anything. Tests only.
    pub const insecure: Verifier = .{ .verify = &acceptAll };
    fn acceptAll(_: ?*anyopaque, _: VerifyInput) error{CertificateRejected}!void {}
};

pub const VerifyInput = struct {
    /// Parsed end-entity certificate (borrows the handshake buffer).
    leaf: Certificate.Parsed,
    /// Full Certificate message for callers that want the chain.
    chain: handshake.Certificate,
};

/// Called after the ClientHello is serialized and before it is hashed/sent.
/// REALITY uses it to fill `enc.session_id`; `ecdh_secret` is the x25519
/// private key whose public half is in the key_share extension.
pub const HelloHook = struct {
    ctx: ?*anyopaque = null,
    run: *const fn (ctx: ?*anyopaque, enc: hello.Encoded, ecdh_secret: *const [32]u8) void,
};

pub const Options = struct {
    /// 64 bytes of CSPRNG output: [0..32] ClientHello.random, [32..64] x25519 seed.
    entropy: [64]u8,
    /// 64 more bytes of CSPRNG output to also offer X25519MLKEM768. Only the
    /// seed is kept; the ML-KEM key pair is re-derived when the server picks it.
    ml_kem_seed: ?[64]u8 = null,
    verifier: Verifier,
    /// Handshake reassembly buffer. Must hold the largest single handshake
    /// message (the Certificate chain); 8 KiB is plenty for REALITY's single
    /// ed25519 cert, 16 KiB for most public sites.
    handshake_buf: []u8,
    /// Chrome sends a dummy ChangeCipherSpec before its encrypted Finished
    /// (middlebox compatibility). Off reproduces RFC 8448 byte-for-byte.
    send_ccs: bool = true,
};

/// Minimum `out` buffer size for `handleRecord`: CCS + sealed Finished with
/// the largest digest, or a sealed KeyUpdate.
pub const min_out_len = 6 + record.sealedLen(4 + 48);

const max_digest = 48;

/// Hash-agnostic wrapper over the two key schedules a Chrome-like client can
/// end up with. Both are fed the ClientHello; one survives ServerHello.
const Schedule = union(enum) {
    sha256: ks.Sha256,
    sha384: ks.Sha384,

    fn update(s: *Schedule, msg: []const u8) void {
        switch (s.*) {
            inline else => |*k| k.update(msg),
        }
    }

    fn digestLen(s: *const Schedule) usize {
        return switch (s.*) {
            inline else => |*k| @TypeOf(k.*).digest_length,
        };
    }

    fn transcriptHash(s: *const Schedule, out: *[max_digest]u8) []const u8 {
        switch (s.*) {
            inline else => |*k| {
                const h = k.transcriptHash();
                @memcpy(out[0..h.len], &h);
                return out[0..h.len];
            },
        }
    }
};

pub const Client = struct {
    state: State = .start,
    write_closed: bool = false,
    read_closed: bool = false,
    opts: Options,

    x25519: X25519.KeyPair,
    /// X25519MLKEM768 key_share payload (ML-KEM-768 ek || x25519 pk), valid
    /// when `opts.ml_kem_seed` is set.
    ml_kem_share: [MLKem768.PublicKey.encoded_length + 32]u8 = undefined,
    session_id: [32]u8 = undefined,
    session_id_len: u8 = 0,
    offered_suites: [16]tls.CipherSuite = undefined,
    offered_suites_len: u8 = 0,

    // Before ServerHello both schedules track the transcript.
    sched256: ks.Sha256,
    sched384: ks.Sha384,
    sched: Schedule = undefined,
    suite: record.Suite = undefined,
    /// Key exchange group the server selected.
    group: tls.NamedGroup = undefined,

    // Fixed-size secret storage, used up to the suite's digest length.
    client_hs_secret: [max_digest]u8 = undefined,
    server_hs_secret: [max_digest]u8 = undefined,
    client_ap_secret: [max_digest]u8 = undefined,
    server_ap_secret: [max_digest]u8 = undefined,

    read: ?record.Cipher = null,
    write: ?record.Cipher = null,

    reasm: handshake.Reassembler,
    server_key: signature.PublicKey = undefined,

    alpn_buf: [255]u8 = undefined,
    alpn_len: u8 = 0,
    last_alert: ?tls.Alert = null,

    pub fn init(opts: Options) Client {
        var c: Client = .{
            .opts = opts,
            .x25519 = X25519.KeyPair.generateDeterministic(opts.entropy[32..64].*),
            .sched256 = ks.Sha256.init(),
            .sched384 = ks.Sha384.init(),
            .reasm = handshake.Reassembler.init(opts.handshake_buf),
        };
        if (opts.ml_kem_seed) |seed| {
            // generateDeterministic only fails on a seed-derived non-canonical
            // key, which cannot happen for ML-KEM key generation.
            const kp = MLKem768.KeyPair.generateDeterministic(seed) catch unreachable;
            c.ml_kem_share[0..MLKem768.PublicKey.encoded_length].* = kp.public_key.toBytes();
            c.ml_kem_share[MLKem768.PublicKey.encoded_length..].* = c.x25519.public_key;
        }
        return c;
    }

    /// X25519MLKEM768 key_share payload, or null if not offered.
    pub fn mlKemPublicKey(c: *const Client) ?[]const u8 {
        return if (c.opts.ml_kem_seed != null) &c.ml_kem_share else null;
    }

    pub fn random(c: *const Client) *const [32]u8 {
        return c.opts.entropy[0..32];
    }

    /// x25519 public key to place in the key_share extension.
    pub fn publicKey(c: *const Client) *const [32]u8 {
        return &c.x25519.public_key;
    }

    /// Negotiated ALPN protocol, empty if none.
    pub fn alpn(c: *const Client) []const u8 {
        return c.alpn_buf[0..c.alpn_len];
    }

    /// Serialize the ClientHello from `params` into `buf` (record header
    /// included) and return the bytes to send. `params.random` is replaced
    /// by the client's random; `params.extensions` must contain a key_share
    /// entry whose public key is `publicKey()`.
    pub fn clientHello(c: *Client, buf: []u8, params_in: hello.Params, hook: ?HelloHook) Error![]const u8 {
        if (c.state != .start) return error.InvalidState;
        if (buf.len < record.header_len) return error.BufferTooSmall;
        if (params_in.session_id.len > 32 or params_in.cipher_suites.len > c.offered_suites.len) return error.InvalidParameter;

        var params = params_in;
        params.random = c.random().*;
        const enc = try hello.encode(buf[record.header_len..], params);
        if (hook) |h| h.run(h.ctx, enc, &c.x25519.secret_key);

        c.session_id_len = @intCast(enc.session_id.len);
        @memcpy(c.session_id[0..enc.session_id.len], enc.session_id);
        c.offered_suites_len = @intCast(params.cipher_suites.len);
        @memcpy(c.offered_suites[0..params.cipher_suites.len], params.cipher_suites);

        c.sched256.update(enc.msg);
        c.sched384.update(enc.msg);

        _ = enc.recordHeader(buf[0..record.header_len]);
        c.state = .wait_server_hello;
        return buf[0 .. record.header_len + enc.msg.len];
    }

    /// Process one complete record (`rec` = header + body, decrypted in
    /// place). `out` receives anything that must be sent back.
    pub fn handleRecord(c: *Client, rec: []u8, out: []u8) Error!Result {
        if (c.read_closed) return error.InvalidState;
        switch (c.state) {
            .start, .closed, .failed => return error.InvalidState,
            else => {},
        }
        errdefer c.state = .failed;

        if (rec.len < record.header_len) return error.UnexpectedRecord;
        const hdr = record.Header.parse(rec[0..record.header_len]);
        if (rec.len != record.header_len + hdr.len) return error.UnexpectedRecord;
        const body = rec[record.header_len..];

        switch (hdr.content_type) {
            .change_cipher_spec => {
                // Middlebox-compat dummy; legal only during the handshake.
                if (c.state == .connected or body.len != 1 or body[0] != 1) return error.UnexpectedMessage;
                return .{};
            },
            .alert => {
                if (c.read != null) return error.UnexpectedMessage; // must be encrypted now
                return c.handleAlert(body);
            },
            .handshake => {
                if (c.state != .wait_server_hello) return error.UnexpectedMessage;
                try c.reasm.push(body);
                return c.drainHandshake(out);
            },
            .application_data => {
                const rd: *record.Cipher = if (c.read) |*rd| rd else return error.UnexpectedMessage;
                const opened = try rd.open(rec);
                switch (opened.content_type) {
                    .handshake => {
                        if (opened.data.len == 0) return error.UnexpectedMessage;
                        try c.reasm.push(opened.data);
                        return c.drainHandshake(out);
                    },
                    .application_data => {
                        if (c.state != .connected) return error.UnexpectedMessage;
                        return .{ .app_data = opened.data };
                    },
                    .alert => return c.handleAlert(opened.data),
                    else => return error.UnexpectedMessage,
                }
            },
            else => return error.UnexpectedRecord,
        }
    }

    /// Encrypt application data into a record. Connected state only.
    pub fn encrypt(c: *Client, data: []const u8, out: []u8) Error![]u8 {
        if (c.state != .connected or c.write_closed) return error.InvalidState;
        return c.write.?.seal(.application_data, data, out);
    }

    /// Produce close_notify and close writing; peer input remains readable.
    pub fn close(c: *Client, out: []u8) Error![]u8 {
        if (c.state != .connected or c.write_closed) return error.InvalidState;
        const rec = try c.write.?.seal(.alert, &tls.close_notify_alert, out);
        c.write_closed = true;
        if (c.read_closed) c.state = .closed;
        return rec;
    }

    // -----------------------------------------------------------------------

    fn handleAlert(c: *Client, body: []const u8) Error!Result {
        if (body.len != 2) return error.UnexpectedMessage;
        const alert: tls.Alert = .{ .level = @fromBackingInt(body[0]), .description = @fromBackingInt(body[1]) };
        c.last_alert = alert;
        if (alert.description == .close_notify) {
            c.read_closed = true;
            if (c.write_closed) c.state = .closed;
            return .{ .event = .close_notify };
        }
        if (alert.level == .warning and alert.description == .user_canceled) return .{ .event = .warning_alert };
        return error.FatalAlert;
    }

    fn drainHandshake(c: *Client, out: []u8) Error!Result {
        var result: Result = .{};
        var out_pos: usize = 0;
        while (try c.reasm.next()) |msg| {
            const sent = try c.handleHandshake(msg, out[out_pos..]);
            out_pos += sent.len;
            if (c.state == .connected and result.event == .none and sent.len > 0) result.event = .handshake_complete;
        }
        result.to_send = out[0..out_pos];
        return result;
    }

    /// Returns bytes to send (may be empty).
    fn handleHandshake(c: *Client, msg: handshake.Message, out: []u8) Error![]const u8 {
        switch (c.state) {
            .wait_server_hello => {
                if (msg.type != .server_hello) return error.UnexpectedMessage;
                try c.onServerHello(msg);
                if (!c.reasm.isEmpty()) return error.UnexpectedMessage; // nothing may trail SH in plaintext
            },
            .wait_encrypted_extensions => {
                if (msg.type != .encrypted_extensions) return error.UnexpectedMessage;
                const ee = try handshake.EncryptedExtensions.parse(msg.body);
                if (ee.alpn) |p| {
                    if (p.len > c.alpn_buf.len) return error.IllegalParameter;
                    @memcpy(c.alpn_buf[0..p.len], p);
                    c.alpn_len = @intCast(p.len);
                }
                c.sched.update(msg.raw);
                c.state = .wait_certificate;
            },
            .wait_certificate => {
                if (msg.type != .certificate) return error.UnexpectedMessage;
                try c.onCertificate(msg);
            },
            .wait_certificate_verify => {
                if (msg.type != .certificate_verify) return error.UnexpectedMessage;
                try c.onCertificateVerify(msg);
            },
            .wait_finished => {
                if (msg.type != .finished) return error.UnexpectedMessage;
                return c.onServerFinished(msg, out);
            },
            .connected => switch (msg.type) {
                .new_session_ticket => {}, // no resumption support; ignore
                .key_update => return c.onKeyUpdate(msg, out),
                else => return error.UnexpectedMessage,
            },
            else => return error.InvalidState,
        }
        return &.{};
    }

    fn onServerHello(c: *Client, msg: handshake.Message) Error!void {
        const sh = try handshake.ServerHello.parse(msg.body);
        if (!mem.eql(u8, sh.session_id_echo, c.session_id[0..c.session_id_len])) return error.SessionIdMismatch;

        var offered = false;
        for (c.offered_suites[0..c.offered_suites_len]) |s| offered = offered or s == sh.cipher_suite;
        if (!offered) return error.IllegalSelection;
        c.suite = record.Suite.fromCipherSuite(sh.cipher_suite) orelse return error.IllegalSelection;

        c.group = sh.key_share.group;
        var shared_buf: [MLKem768.shared_length + X25519.shared_length]u8 = undefined;
        var shared: []const u8 = undefined;
        switch (sh.key_share.group) {
            .x25519 => {
                if (sh.key_share.public_key.len != X25519.public_length) return error.IllegalParameter;
                shared_buf[0..32].* = X25519.scalarmult(c.x25519.secret_key, sh.key_share.public_key[0..32].*) catch
                    return error.WeakKeyShare;
                shared = shared_buf[0..32];
            },
            .x25519_ml_kem768 => {
                // Server sends ML-KEM ciphertext (1088) || x25519 public (32);
                // shared secret is ML-KEM ss || x25519 ss (RFC draft-ietf-tls-ecdhe-mlkem).
                const seed = c.opts.ml_kem_seed orelse return error.IllegalSelection;
                const ctl = MLKem768.ciphertext_length;
                if (sh.key_share.public_key.len != ctl + X25519.public_length) return error.IllegalParameter;
                const kp = MLKem768.KeyPair.generateDeterministic(seed) catch unreachable;
                shared_buf[0..MLKem768.shared_length].* = kp.secret_key.decaps(sh.key_share.public_key[0..ctl]) catch
                    return error.IllegalParameter;
                shared_buf[MLKem768.shared_length..].* = X25519.scalarmult(c.x25519.secret_key, sh.key_share.public_key[ctl..][0..32].*) catch
                    return error.WeakKeyShare;
                shared = &shared_buf;
            },
            else => return error.IllegalSelection,
        }

        c.sched = switch (c.suite) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => .{ .sha256 = c.sched256 },
            .aes_256_gcm_sha384 => .{ .sha384 = c.sched384 },
        };
        c.sched.update(msg.raw);

        switch (c.sched) {
            inline else => |*k| {
                const KS = @TypeOf(k.*);
                k.setSharedSecret(shared);
                const hs = k.handshakeTraffic();
                @memcpy(c.client_hs_secret[0..KS.digest_length], &hs.client);
                @memcpy(c.server_hs_secret[0..KS.digest_length], &hs.server);
                c.installKeys(KS, hs.client, hs.server);
            },
        }
        c.state = .wait_encrypted_extensions;
    }

    fn installKeys(c: *Client, comptime KS: type, client_secret: KS.Secret, server_secret: KS.Secret) void {
        switch (c.suite) {
            inline else => |s| {
                const Aead = record.Suite.Aead(s);
                const ck = KS.trafficKeys(Aead, client_secret);
                const sk = KS.trafficKeys(Aead, server_secret);
                c.write = record.Cipher.init(s, &ck.key, &ck.iv);
                c.read = record.Cipher.init(s, &sk.key, &sk.iv);
            },
        }
    }

    fn onCertificate(c: *Client, msg: handshake.Message) Error!void {
        const cert = try handshake.Certificate.parse(msg.body);
        if (cert.request_context.len != 0) return error.IllegalParameter;
        const leaf = try cert.leaf();
        const parsed = Certificate.parse(.{ .buffer = leaf.der, .index = 0 }) catch return error.BadCertificate;
        c.server_key = signature.PublicKey.fromParsed(parsed) catch return error.BadCertificate;

        const v = c.opts.verifier;
        v.verify(v.ctx, .{ .leaf = parsed, .chain = cert }) catch return error.CertificateRejected;

        c.sched.update(msg.raw);
        c.state = .wait_certificate_verify;
    }

    fn onCertificateVerify(c: *Client, msg: handshake.Message) Error!void {
        const cv = try handshake.CertificateVerify.parse(msg.body);
        var hbuf: [max_digest]u8 = undefined;
        const th = c.sched.transcriptHash(&hbuf);
        var content: [handshake.CertificateVerify.max_signed_content_len]u8 = undefined;
        const signed = try handshake.CertificateVerify.signedContent(th, &content);
        try c.server_key.verify(cv.scheme, cv.signature, &.{signed});

        c.sched.update(msg.raw);
        c.state = .wait_finished;
    }

    fn onServerFinished(c: *Client, msg: handshake.Message, out: []u8) Error![]const u8 {
        const fin = try handshake.Finished.parse(msg.body);
        var pos: usize = 0;

        switch (c.sched) {
            inline else => |*k| {
                const KS = @TypeOf(k.*);
                const server_hs = c.server_hs_secret[0..KS.digest_length].*;
                const client_hs = c.client_hs_secret[0..KS.digest_length].*;

                if (!KS.checkVerifyData(server_hs, k.transcriptHash(), fin.verify_data)) return error.BadFinished;
                k.update(msg.raw);

                // Application secrets are derived from the transcript through
                // server Finished, before our own Finished is added.
                const ap = k.applicationTraffic();
                @memcpy(c.client_ap_secret[0..KS.digest_length], &ap.client);
                @memcpy(c.server_ap_secret[0..KS.digest_length], &ap.server);

                const verify = KS.verifyData(client_hs, k.transcriptHash());
                var fin_buf: [4 + max_digest]u8 = undefined;
                const fin_msg = try handshake.Finished.encode(&verify, &fin_buf);
                k.update(fin_msg);

                if (c.opts.send_ccs) {
                    if (out.len < 6) return error.BufferTooSmall;
                    out[0..6].* = .{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
                    pos = 6;
                }
                const sealed = try c.write.?.seal(.handshake, fin_msg, out[pos..]);
                pos += sealed.len;

                c.installKeys(KS, ap.client, ap.server);
            },
        }
        c.state = .connected;
        return out[0..pos];
    }

    fn onKeyUpdate(c: *Client, msg: handshake.Message, out: []u8) Error![]const u8 {
        if (msg.body.len != 1) return error.DecodeError;
        const request: tls.KeyUpdateRequest = @fromBackingInt(msg.body[0]);
        var sent: []const u8 = &.{};

        switch (c.sched) {
            inline else => |*k| {
                const KS = @TypeOf(k.*);
                // Server's write keys roll forward immediately.
                const next_server = KS.nextTrafficSecret(c.server_ap_secret[0..KS.digest_length].*);
                @memcpy(c.server_ap_secret[0..KS.digest_length], &next_server);

                switch (request) {
                    .update_not_requested => {},
                    .update_requested => {
                        // Reply under the current write keys, then roll ours.
                        const reply = [_]u8{ @backingInt(tls.HandshakeType.key_update), 0, 0, 1, @backingInt(tls.KeyUpdateRequest.update_not_requested) };
                        sent = try c.write.?.seal(.handshake, &reply, out);
                        const next_client = KS.nextTrafficSecret(c.client_ap_secret[0..KS.digest_length].*);
                        @memcpy(c.client_ap_secret[0..KS.digest_length], &next_client);
                    },
                    _ => return error.IllegalParameter,
                }
                c.installKeys(KS, c.client_ap_secret[0..KS.digest_length].*, c.server_ap_secret[0..KS.digest_length].*);
            },
        }
        return sent;
    }
};

// ---------------------------------------------------------------------------
// Tests: replay the RFC 8448 ?3 handshake deterministically.

const testing = std.testing;
const rfc8448 = @import("testdata/rfc8448.zig");

fn rfcClient(hs_buf: []u8) Client {
    return Client.init(.{
        .entropy = rfc8448.client_hello[6..38].* ++ rfc8448.client_priv,
        .verifier = Verifier.insecure,
        .handshake_buf = hs_buf,
        .send_ccs = false,
    });
}

fn recordOf(comptime content_type: u8, comptime version: u16, comptime payload: anytype) [5 + payload.len]u8 {
    const hdr = [5]u8{ content_type, @intCast(version >> 8), @intCast(version & 0xff), @intCast(payload.len >> 8), @intCast(payload.len & 0xff) };
    return hdr ++ payload;
}

test "RFC 8448 full handshake reproduces client records byte-for-byte" {
    var hs_buf: [2048]u8 = undefined;
    var c = rfcClient(&hs_buf);
    try testing.expectEqualSlices(u8, &rfc8448.client_pub, c.publicKey());

    var hello_buf: [512]u8 = undefined;
    const ch = try c.clientHello(&hello_buf, hello.rfc8448Params(), null);
    try testing.expectEqualSlices(u8, &recordOf(0x16, 0x0301, rfc8448.client_hello), ch);
    try testing.expectEqual(State.wait_server_hello, c.state);

    var out: [256]u8 = undefined;

    var sh = recordOf(0x16, 0x0303, rfc8448.server_hello);
    const r1 = try c.handleRecord(&sh, &out);
    try testing.expectEqual(@as(usize, 0), r1.to_send.len);
    try testing.expectEqual(State.wait_encrypted_extensions, c.state);

    var flight = rfc8448.server_hs_record;
    const r2 = try c.handleRecord(&flight, &out);
    try testing.expectEqual(Event.handshake_complete, r2.event);
    try testing.expectEqual(State.connected, c.state);
    try testing.expectEqualSlices(u8, &rfc8448.client_fin_record, r2.to_send);
    try testing.expectEqual(@as(usize, 0), c.alpn().len);

    // Client application data.
    var payload: [50]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i);
    const app = try c.encrypt(&payload, &out);
    try testing.expectEqualSlices(u8, &rfc8448.client_app_record, app);

    // Server: NewSessionTicket (ignored), application data, close_notify.
    var ticket = rfc8448.ticket_record;
    const r3 = try c.handleRecord(&ticket, &out);
    try testing.expectEqual(@as(usize, 0), r3.app_data.len);
    try testing.expectEqual(Event.none, r3.event);

    var sapp = rfc8448.server_app_record;
    const r4 = try c.handleRecord(&sapp, &out);
    try testing.expectEqualSlices(u8, &payload, r4.app_data);

    const alert = try c.close(&out);
    try testing.expectEqualSlices(u8, &rfc8448.client_alert_record, alert);
    try testing.expect(c.write_closed);
    try testing.expectEqual(State.connected, c.state);
    try testing.expectError(error.InvalidState, c.encrypt(&payload, &out));
    var server_alert = rfc8448.server_alert_record;
    const r5 = try c.handleRecord(&server_alert, &out);
    try testing.expectEqual(Event.close_notify, r5.event);
    try testing.expectEqual(State.closed, c.state);
}

test "server Finished tampering is detected" {
    var hs_buf: [2048]u8 = undefined;
    var c = rfcClient(&hs_buf);
    var hello_buf: [512]u8 = undefined;
    _ = try c.clientHello(&hello_buf, hello.rfc8448Params(), null);
    var out: [256]u8 = undefined;
    var sh = recordOf(0x16, 0x0303, rfc8448.server_hello);
    _ = try c.handleRecord(&sh, &out);

    // Re-encrypt the flight with the last byte of Finished flipped.
    var flight = rfc8448.enc_ext ++ rfc8448.certificate ++ rfc8448.cert_verify ++ rfc8448.s_finished_msg;
    flight[flight.len - 1] ^= 0x01;
    var w = record.Cipher.init(.aes_128_gcm_sha256, &rfc8448.s_hs_key, &rfc8448.s_hs_iv);
    var rec_buf: [1024]u8 = undefined;
    const rec = try w.seal(.handshake, &flight, &rec_buf);
    try testing.expectError(error.BadFinished, c.handleRecord(rec, &out));
    try testing.expectEqual(State.failed, c.state);
}

test "CertificateVerify tampering is detected" {
    var hs_buf: [2048]u8 = undefined;
    var c = rfcClient(&hs_buf);
    var hello_buf: [512]u8 = undefined;
    _ = try c.clientHello(&hello_buf, hello.rfc8448Params(), null);
    var out: [256]u8 = undefined;
    var sh = recordOf(0x16, 0x0303, rfc8448.server_hello);
    _ = try c.handleRecord(&sh, &out);

    var cv = rfc8448.cert_verify;
    cv[cv.len - 1] ^= 0x01;
    const flight = rfc8448.enc_ext ++ rfc8448.certificate ++ cv ++ rfc8448.s_finished_msg;
    var w = record.Cipher.init(.aes_128_gcm_sha256, &rfc8448.s_hs_key, &rfc8448.s_hs_iv);
    var rec_buf: [1024]u8 = undefined;
    const rec = try w.seal(.handshake, &flight, &rec_buf);
    try testing.expectError(error.BadSignature, c.handleRecord(rec, &out));
}

test "verifier rejection aborts the handshake" {
    const Reject = struct {
        fn verify(_: ?*anyopaque, _: VerifyInput) error{CertificateRejected}!void {
            return error.CertificateRejected;
        }
    };
    var hs_buf: [2048]u8 = undefined;
    var c = Client.init(.{
        .entropy = rfc8448.client_hello[6..38].* ++ rfc8448.client_priv,
        .verifier = .{ .verify = &Reject.verify },
        .handshake_buf = &hs_buf,
        .send_ccs = false,
    });
    var hello_buf: [512]u8 = undefined;
    _ = try c.clientHello(&hello_buf, hello.rfc8448Params(), null);
    var out: [256]u8 = undefined;
    var sh = recordOf(0x16, 0x0303, rfc8448.server_hello);
    _ = try c.handleRecord(&sh, &out);
    var flight = rfc8448.server_hs_record;
    try testing.expectError(error.CertificateRejected, c.handleRecord(&flight, &out));
}

test "flight split across records and interleaved CCS" {
    var hs_buf: [2048]u8 = undefined;
    var c = rfcClient(&hs_buf);
    var hello_buf: [512]u8 = undefined;
    _ = try c.clientHello(&hello_buf, hello.rfc8448Params(), null);
    var out: [256]u8 = undefined;
    var sh = recordOf(0x16, 0x0303, rfc8448.server_hello);
    _ = try c.handleRecord(&sh, &out);

    var ccs = [_]u8{ 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 };
    _ = try c.handleRecord(&ccs, &out);

    const flight = rfc8448.enc_ext ++ rfc8448.certificate ++ rfc8448.cert_verify ++ rfc8448.s_finished_msg;
    var w = record.Cipher.init(.aes_128_gcm_sha256, &rfc8448.s_hs_key, &rfc8448.s_hs_iv);
    var rec_buf: [1024]u8 = undefined;
    // Three records cut at arbitrary points, including mid-Certificate.
    const cuts = [_]usize{ 0, 57, 300, flight.len };
    var i: usize = 0;
    while (i + 1 < cuts.len) : (i += 1) {
        const rec = try w.seal(.handshake, flight[cuts[i]..cuts[i + 1]], &rec_buf);
        const r = try c.handleRecord(rec, &out);
        if (i + 2 == cuts.len) {
            try testing.expectEqual(Event.handshake_complete, r.event);
        } else {
            try testing.expectEqual(Event.none, r.event);
            try testing.expectEqual(@as(usize, 0), r.to_send.len);
        }
    }
    try testing.expectEqual(State.connected, c.state);
}

test "KeyUpdate with update_requested rolls both directions" {
    var hs_buf: [2048]u8 = undefined;
    var c = rfcClient(&hs_buf);
    var hello_buf: [512]u8 = undefined;
    _ = try c.clientHello(&hello_buf, hello.rfc8448Params(), null);
    var out: [256]u8 = undefined;
    var sh = recordOf(0x16, 0x0303, rfc8448.server_hello);
    _ = try c.handleRecord(&sh, &out);
    var flight = rfc8448.server_hs_record;
    _ = try c.handleRecord(&flight, &out);

    // Server-side mirror of application keys.
    const KS = ks.Sha256;
    var srv_w = record.Cipher.init(.aes_128_gcm_sha256, &rfc8448.s_ap_key, &rfc8448.s_ap_iv);
    const ku = [_]u8{ 0x18, 0, 0, 1, 1 };
    var rec_buf: [128]u8 = undefined;
    const rec = try srv_w.seal(.handshake, &ku, &rec_buf);
    const r = try c.handleRecord(rec, &out);
    try testing.expect(r.to_send.len > 0);

    // Our reply decrypts under the *old* client keys and is a KeyUpdate(not_requested).
    var srv_r = record.Cipher.init(.aes_128_gcm_sha256, &rfc8448.c_ap_key, &rfc8448.c_ap_iv);
    var reply: [128]u8 = undefined;
    @memcpy(reply[0..r.to_send.len], r.to_send);
    const o = try srv_r.open(reply[0..r.to_send.len]);
    try testing.expectEqualSlices(u8, &.{ 0x18, 0, 0, 1, 0 }, o.data);

    // Subsequent app data uses next-generation keys on both sides.
    const next_c = KS.nextTrafficSecret(rfc8448.c_ap_traffic);
    const next_s = KS.nextTrafficSecret(rfc8448.s_ap_traffic);
    const ck = KS.trafficKeys(record.Suite.Aead(.aes_128_gcm_sha256), next_c);
    const sk = KS.trafficKeys(record.Suite.Aead(.aes_128_gcm_sha256), next_s);

    const app = try c.encrypt("ping", &out);
    var srv_r2 = record.Cipher.init(.aes_128_gcm_sha256, &ck.key, &ck.iv);
    var app_copy: [64]u8 = undefined;
    @memcpy(app_copy[0..app.len], app);
    try testing.expectEqualSlices(u8, "ping", (try srv_r2.open(app_copy[0..app.len])).data);

    var srv_w2 = record.Cipher.init(.aes_128_gcm_sha256, &sk.key, &sk.iv);
    const srec = try srv_w2.seal(.application_data, "pong", &rec_buf);
    const r2 = try c.handleRecord(srec, &out);
    try testing.expectEqualSlices(u8, "pong", r2.app_data);
}
