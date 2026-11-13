//! TLS 1.3 record layer (RFC 8446 §5): record header, AEAD protection with
//! per-record nonces, and TLSInnerPlaintext framing.
//!
//! One `Direction` holds the write (or read) state for a single direction:
//! key, IV and the 64-bit sequence number. `Cipher` is the runtime-dispatched
//! union over the three suites a Chrome fingerprint advertises.

const std = @import("std");
const crypto = std.crypto;
const tls = crypto.tls;
const mem = std.mem;
const kernel_crypto = @import("../linux/kernel_crypto.zig");

pub const header_len = tls.record_header_len;
/// Max TLSInnerPlaintext content length.
pub const max_plaintext = tls.max_ciphertext_inner_record_len;
/// Max TLSCiphertext.length.
pub const max_ciphertext = tls.max_ciphertext_len;
/// Largest wire record (header + max ciphertext).
pub const max_record = tls.max_ciphertext_record_len;

pub const Suite = enum {
    aes_128_gcm_sha256,
    aes_256_gcm_sha384,
    chacha20_poly1305_sha256,

    pub fn fromCipherSuite(cs: tls.CipherSuite) ?Suite {
        return switch (cs) {
            .AES_128_GCM_SHA256 => .aes_128_gcm_sha256,
            .AES_256_GCM_SHA384 => .aes_256_gcm_sha384,
            .CHACHA20_POLY1305_SHA256 => .chacha20_poly1305_sha256,
            else => null,
        };
    }

    pub fn toCipherSuite(s: Suite) tls.CipherSuite {
        return switch (s) {
            .aes_128_gcm_sha256 => .AES_128_GCM_SHA256,
            .aes_256_gcm_sha384 => .AES_256_GCM_SHA384,
            .chacha20_poly1305_sha256 => .CHACHA20_POLY1305_SHA256,
        };
    }

    pub fn Aead(comptime s: Suite) type {
        return switch (s) {
            .aes_128_gcm_sha256 => crypto.aead.aes_gcm.Aes128Gcm,
            .aes_256_gcm_sha384 => crypto.aead.aes_gcm.Aes256Gcm,
            .chacha20_poly1305_sha256 => crypto.aead.chacha_poly.ChaCha20Poly1305,
        };
    }

    pub fn Hash(comptime s: Suite) type {
        return switch (s) {
            .aes_128_gcm_sha256, .chacha20_poly1305_sha256 => crypto.hash.sha2.Sha256,
            .aes_256_gcm_sha384 => crypto.hash.sha2.Sha384,
        };
    }
};

pub const Header = struct {
    content_type: tls.ContentType,
    legacy_version: u16,
    len: u16,

    pub fn parse(bytes: *const [header_len]u8) Header {
        return .{
            .content_type = @fromBackingInt(bytes[0]),
            .legacy_version = mem.readInt(u16, bytes[1..3], .big),
            .len = mem.readInt(u16, bytes[3..5], .big),
        };
    }

    pub fn write(h: Header, out: *[header_len]u8) void {
        out[0] = @backingInt(h.content_type);
        mem.writeInt(u16, out[1..3], h.legacy_version, .big);
        mem.writeInt(u16, out[3..5], h.len, .big);
    }
};

pub const Error = error{
    /// Output buffer too small for header + ciphertext + tag.
    BufferTooSmall,
    /// Plaintext exceeds 2^14 bytes; caller must fragment.
    RecordTooLarge,
    /// Sequence number exhausted; a KeyUpdate is required before sending more.
    SequenceOverflow,
    /// AEAD tag mismatch or malformed TLSInnerPlaintext.
    BadRecordMac,
    /// Record is not application_data / wrong length to be a protected record.
    UnexpectedRecord,
};

pub const Opened = struct {
    content_type: tls.ContentType,
    /// Decrypted content (view into the record buffer passed to `open`).
    data: []u8,
};

/// Single-direction traffic state for one AEAD.
pub fn Direction(comptime AeadType: type) type {
    return struct {
        pub const Aead = AeadType;
        pub const key_length = Aead.key_length;
        pub const nonce_length = Aead.nonce_length;
        pub const tag_length = Aead.tag_length;

        const Self = @This();

        key: [key_length]u8,
        iv: [nonce_length]u8,
        seq: u64 = 0,

        pub fn init(key: [key_length]u8, iv: [nonce_length]u8) Self {
            return .{ .key = key, .iv = iv };
        }

        /// Per-record nonce: IV XOR left-padded big-endian sequence number.
        pub fn nonce(self: *const Self) [nonce_length]u8 {
            var n = self.iv;
            var seq_be: [8]u8 = undefined;
            mem.writeInt(u64, &seq_be, self.seq, .big);
            for (n[nonce_length - 8 ..], seq_be) |*b, s| b.* ^= s;
            return n;
        }

        fn advance(self: *Self) Error!void {
            if (self.seq == std.math.maxInt(u64)) return error.SequenceOverflow;
            self.seq += 1;
        }

        /// Encrypt `plaintext` of `content_type` into a complete record
        /// (header included) in `out`. Returns the record slice.
        pub fn seal(self: *Self, content_type: tls.ContentType, plaintext: []const u8, out: []u8) Error![]u8 {
            if (plaintext.len > max_plaintext) return error.RecordTooLarge;
            const inner_len = plaintext.len + 1;
            const total = header_len + inner_len + tag_length;
            if (out.len < total) return error.BufferTooSmall;

            const hdr: Header = .{
                .content_type = .application_data,
                .legacy_version = @backingInt(tls.ProtocolVersion.tls_1_2),
                .len = @intCast(inner_len + tag_length),
            };
            hdr.write(out[0..header_len]);

            // Build TLSInnerPlaintext in place: content || type (no padding).
            const body = out[header_len..][0..inner_len];
            @memcpy(body[0..plaintext.len], plaintext);
            body[plaintext.len] = @backingInt(content_type);

            const tag = out[header_len + inner_len ..][0..tag_length];
            const accelerated = if (comptime Aead == crypto.aead.aes_gcm.Aes128Gcm or Aead == crypto.aead.aes_gcm.Aes256Gcm)
                if (kernel_crypto.current) |ctx| ctx.crypt(&self.key, self.nonce(), out[0..header_len], body, out[header_len..total], false) else .software
            else
                kernel_crypto.Outcome.software;
            if (accelerated != .success) Aead.encrypt(body, tag, body, out[0..header_len], self.nonce(), self.key);
            try self.advance();
            return out[0..total];
        }

        /// Decrypt a complete protected record in place. `record` must start
        /// with the 5-byte header and be exactly header + length bytes.
        pub fn open(self: *Self, record: []u8) Error!Opened {
            if (record.len < header_len) return error.UnexpectedRecord;
            const hdr = Header.parse(record[0..header_len]);
            if (hdr.content_type != .application_data) return error.UnexpectedRecord;
            if (record.len != header_len + hdr.len) return error.UnexpectedRecord;
            if (hdr.len < tag_length + 1 or hdr.len > max_ciphertext) return error.UnexpectedRecord;

            const inner_len = hdr.len - tag_length;
            const body = record[header_len..][0..inner_len];
            const tag = record[header_len + inner_len ..][0..tag_length].*;
            const accelerated = if (comptime Aead == crypto.aead.aes_gcm.Aes128Gcm or Aead == crypto.aead.aes_gcm.Aes256Gcm)
                if (kernel_crypto.current) |ctx| ctx.crypt(&self.key, self.nonce(), record[0..header_len], record[header_len..], body, true) else .software
            else
                kernel_crypto.Outcome.software;
            switch (accelerated) {
                .success => {},
                .authentication_failed => return error.BadRecordMac,
                .software => Aead.decrypt(body, body, tag, record[0..header_len], self.nonce(), self.key) catch return error.BadRecordMac,
            }
            try self.advance();

            // Strip zero padding; last non-zero byte is the content type.
            var end = body.len;
            while (end > 0 and body[end - 1] == 0) end -= 1;
            if (end == 0) return error.BadRecordMac;
            return .{
                .content_type = @fromBackingInt(body[end - 1]),
                .data = body[0 .. end - 1],
            };
        }
    };
}

/// Runtime-selected direction state over the supported suites.
pub const Cipher = union(Suite) {
    aes_128_gcm_sha256: Direction(Suite.Aead(.aes_128_gcm_sha256)),
    aes_256_gcm_sha384: Direction(Suite.Aead(.aes_256_gcm_sha384)),
    chacha20_poly1305_sha256: Direction(Suite.Aead(.chacha20_poly1305_sha256)),

    /// `key`/`iv` are the HKDF outputs for this suite; lengths are checked.
    pub fn init(suite: Suite, key: []const u8, iv: []const u8) Cipher {
        switch (suite) {
            inline else => |s| {
                const D = Direction(Suite.Aead(s));
                std.debug.assert(key.len == D.key_length and iv.len == D.nonce_length);
                return @unionInit(Cipher, @tagName(s), D.init(key[0..D.key_length].*, iv[0..D.nonce_length].*));
            },
        }
    }

    pub fn seal(self: *Cipher, content_type: tls.ContentType, plaintext: []const u8, out: []u8) Error![]u8 {
        return switch (self.*) {
            inline else => |*d| d.seal(content_type, plaintext, out),
        };
    }

    pub fn open(self: *Cipher, record: []u8) Error!Opened {
        return switch (self.*) {
            inline else => |*d| d.open(record),
        };
    }

    pub fn seq(self: *const Cipher) u64 {
        return switch (self.*) {
            inline else => |*d| d.seq,
        };
    }

    pub fn tagLength(self: *const Cipher) usize {
        return switch (self.*) {
            inline else => |*d| @TypeOf(d.*).tag_length,
        };
    }
};

/// Largest record `seal` can produce for `plaintext_len` bytes with any suite.
pub fn sealedLen(plaintext_len: usize) usize {
    return header_len + plaintext_len + 1 + 16;
}

// ---------------------------------------------------------------------------
// Tests: RFC 8448 §3, TLS_AES_128_GCM_SHA256.

const testing = std.testing;
const rfc8448 = @import("testdata/rfc8448.zig");

test "open server handshake flight (679-byte record)" {
    var c = Cipher.init(.aes_128_gcm_sha256, &rfc8448.s_hs_key, &rfc8448.s_hs_iv);
    var rec = rfc8448.server_hs_record;
    const o = try c.open(&rec);
    try testing.expectEqual(tls.ContentType.handshake, o.content_type);

    const expected = rfc8448.enc_ext ++ rfc8448.certificate ++ rfc8448.cert_verify ++ rfc8448.s_finished_msg;
    try testing.expectEqualSlices(u8, &expected, o.data);
    try testing.expectEqual(@as(u64, 1), c.seq());
}

test "seal client Finished matches RFC record" {
    var c = Cipher.init(.aes_128_gcm_sha256, &rfc8448.c_hs_key, &rfc8448.c_hs_iv);
    var out: [128]u8 = undefined;
    const rec = try c.seal(.handshake, &rfc8448.c_finished_msg, &out);
    try testing.expectEqualSlices(u8, &rfc8448.client_fin_record, rec);
}

test "server application records across sequence numbers" {
    var c = Cipher.init(.aes_128_gcm_sha256, &rfc8448.s_ap_key, &rfc8448.s_ap_iv);

    var r0 = rfc8448.ticket_record;
    const o0 = try c.open(&r0);
    try testing.expectEqual(tls.ContentType.handshake, o0.content_type);
    try testing.expectEqualSlices(u8, &rfc8448.new_session_ticket, o0.data);

    var r1 = rfc8448.server_app_record;
    const o1 = try c.open(&r1);
    try testing.expectEqual(tls.ContentType.application_data, o1.content_type);
    try testing.expectEqual(@as(usize, 50), o1.data.len);
    for (o1.data, 0..) |b, i| try testing.expectEqual(@as(u8, @intCast(i)), b);

    var r2 = rfc8448.server_alert_record;
    const o2 = try c.open(&r2);
    try testing.expectEqual(tls.ContentType.alert, o2.content_type);
    try testing.expectEqualSlices(u8, &.{ 0x01, 0x00 }, o2.data);
}

test "client application + alert records seal identically" {
    var c = Cipher.init(.aes_128_gcm_sha256, &rfc8448.c_ap_key, &rfc8448.c_ap_iv);
    var out: [128]u8 = undefined;

    var payload: [50]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @intCast(i);
    const r0 = try c.seal(.application_data, &payload, &out);
    try testing.expectEqualSlices(u8, &rfc8448.client_app_record, r0);

    const r1 = try c.seal(.alert, &.{ 0x01, 0x00 }, &out);
    try testing.expectEqualSlices(u8, &rfc8448.client_alert_record, r1);
}

test "tampered record is rejected" {
    var c = Cipher.init(.aes_128_gcm_sha256, &rfc8448.s_hs_key, &rfc8448.s_hs_iv);
    var rec = rfc8448.server_hs_record;
    rec[100] ^= 1;
    try testing.expectError(error.BadRecordMac, c.open(&rec));
    // Failed open must not consume a sequence number.
    try testing.expectEqual(@as(u64, 0), c.seq());
}

test "wrong sequence number fails authentication" {
    var c = Cipher.init(.aes_128_gcm_sha256, &rfc8448.s_ap_key, &rfc8448.s_ap_iv);
    var rec = rfc8448.server_app_record; // this one is seq 1
    try testing.expectError(error.BadRecordMac, c.open(&rec));
}

test "padding is stripped on open" {
    const key: [32]u8 = @splat(7);
    const iv: [12]u8 = @splat(9);
    var c = Cipher.init(.chacha20_poly1305_sha256, &key, &iv);
    var d = c;
    // Hand-build a padded inner plaintext: "hi" || 0x17 || 00 00 00
    var out: [64]u8 = undefined;
    const inner = [_]u8{ 'h', 'i', 0x17, 0, 0, 0 };
    const hdr: Header = .{ .content_type = .application_data, .legacy_version = 0x0303, .len = inner.len + 16 };
    hdr.write(out[0..5]);
    const body = out[5..][0..inner.len];
    @memcpy(body, &inner);
    const Aead = Suite.Aead(.chacha20_poly1305_sha256);
    Aead.encrypt(body, out[5 + inner.len ..][0..16], body, out[0..5], c.chacha20_poly1305_sha256.nonce(), c.chacha20_poly1305_sha256.key);

    const o = try d.open(out[0 .. 5 + inner.len + 16]);
    try testing.expectEqual(tls.ContentType.application_data, o.content_type);
    try testing.expectEqualSlices(u8, "hi", o.data);
}

test "size limits" {
    const key: [32]u8 = @splat(1);
    const iv: [12]u8 = @splat(2);
    var c = Cipher.init(.aes_256_gcm_sha384, &key, &iv);
    var small: [10]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, c.seal(.application_data, "hello", &small));
    const big: [max_plaintext + 1]u8 = @splat(0);
    var out: [max_record]u8 = undefined;
    try testing.expectError(error.RecordTooLarge, c.seal(.application_data, &big, &out));
}
