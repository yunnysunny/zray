#!/usr/bin/env python3
"""Offline mixed-inbound integration test through a local TLS/VLESS server.

Usage: python3 tools/httptest.py zig-out/bin/zray
Requires Python 3 and openssl; no external server or network access is needed.
"""
import concurrent.futures
import json
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time


def exact(conn, size):
    data = b""
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        assert chunk, "unexpected EOF"
        data += chunk
    return data


def head(conn):
    data = b""
    while not data.endswith(b"\r\n\r\n"):
        data += exact(conn, 1)
        assert len(data) <= 16384
    return data


def listener():
    conn = socket.socket()
    conn.bind(("127.0.0.1", 0))
    conn.listen()
    conn.settimeout(8)
    return conn


def serve(server, context, expected_host, expected_port, expected_request, response):
    raw, _ = server.accept()
    with raw, context.wrap_socket(raw, server_side=True) as conn:
        conn.settimeout(8)
        assert exact(conn, 1) == b"\x00"
        assert exact(conn, 16) == bytes(16)
        options = exact(conn, 1)[0]
        exact(conn, options)
        assert exact(conn, 1) == b"\x01", "VLESS TCP command"
        port = struct.unpack("!H", exact(conn, 2))[0]
        kind = exact(conn, 1)[0]
        if kind == 2:
            host = exact(conn, exact(conn, 1)[0]).decode()
        else:
            host = socket.inet_ntop(socket.AF_INET if kind == 1 else socket.AF_INET6,
                                    exact(conn, 4 if kind == 1 else 16))
        assert (host, port) == (expected_host, expected_port), (host, port)
        continued = b"Expect: 100-continue\r\n" in expected_request
        prefix = b""
        if continued:
            prefix = head(conn)
            conn.sendall(b"\x00\x00HTTP/1.1 100 Continue\r\n\r\n")
        received = prefix + exact(conn, len(expected_request) - len(prefix))
        assert received == expected_request, (received[:200], expected_request[:200])
        # Plain requests must stop at the request body boundary, including when
        # a second request is pipelined in the same client write.
        conn.settimeout(0.15)
        try:
            extra = conn.recv(1)
        except socket.timeout:
            extra = b""
        assert not extra, f"unexpected bytes forwarded: {extra!r}"
        conn.sendall((b"" if continued else b"\x00\x00") + response)


def run(binary):
    if not hasattr(ssl, "TLSVersion") or not ssl.HAS_TLSv1_3:
        raise RuntimeError("Use Python 3.8+ built with TLS 1.3 support")
    with tempfile.TemporaryDirectory(prefix="zray-http-") as tmp:
        tmp = Path(tmp)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                        "-keyout", str(tmp / "key.pem"), "-out", str(tmp / "cert.pem"),
                        "-days", "1", "-subj", "/CN=localhost"],
                       check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(tmp / "cert.pem", tmp / "key.pem")
        with listener() as server, listener() as reserved:
            proxy_port = reserved.getsockname()[1]
            reserved.close()
            cfg = {"listen": f"127.0.0.1:{proxy_port}", "server": "127.0.0.1",
                   "port": server.getsockname()[1], "sni": "localhost", "security": "tls",
                   "tls_verify": "none", "flow": "none", "uuid": "00000000-0000-0000-0000-000000000000",
                   "workers": 1}
            (tmp / "config.json").write_text(json.dumps(cfg))
            with (tmp / "zray.log").open("w+") as log:
                proc = subprocess.Popen([binary, str(tmp / "config.json")], stdout=log, stderr=log)
                try:
                    for _ in range(100):
                        assert proc.poll() is None, "zray exited during startup"
                        try:
                            with socket.create_connection(("127.0.0.1", proxy_port), timeout=0.1):
                                break
                        except OSError:
                            time.sleep(0.02)
                    else:
                        raise AssertionError("listener did not start")
                    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                        def case(name, wire, host, port, request, response, greeting=None):
                            future = pool.submit(serve, server, context, host, port, request, response)
                            with socket.create_connection(("127.0.0.1", proxy_port), timeout=8) as client:
                                client.settimeout(8)
                                if greeting:
                                    client.sendall(b"\x05\x01\x00")
                                    assert exact(client, 2) == b"\x05\x00"
                                # Force a split in the first protocol identifier.
                                client.sendall(wire[:1])
                                time.sleep(0.01)
                                if b"Expect: 100-continue\r\n" in wire:
                                    end = wire.index(b"\r\n\r\n") + 4
                                    client.sendall(wire[1:end])
                                    assert head(client) == b"HTTP/1.1 100 Continue\r\n\r\n"
                                    client.sendall(wire[end:])
                                else:
                                    client.sendall(wire[1:])
                                if greeting:
                                    assert exact(client, 10)[:2] == b"\x05\x00"
                                elif wire.startswith(b"CONNECT"):
                                    assert head(client) == b"HTTP/1.1 200 Connection established\r\n\r\n"
                                result = b""
                                while True:
                                    part = client.recv(65536)
                                    if not part:
                                        break
                                    result += part
                                assert result == response, (name, result[:200])
                            future.result(timeout=10)
                            print(f"ok: {name}")

                        payload = b"\x16\x03\x01opaque tunnel bytes\x00"
                        case("CONNECT IPv6 and early tunnel bytes",
                             b"CONNECT [::1]:443 HTTP/1.1\r\nHost: [::1]:443\r\n\r\n" + payload,
                             "::1", 443, payload, b"tunnel response")
                        response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
                        case("HTTP GET rewrite and pipeline boundary",
                             b"GET http://example.com/path?q=1 HTTP/1.1\r\nHost: wrong.example\r\nProxy-Authorization: Basic secret\r\n\r\nGET http://other.example/ HTTP/1.1\r\n\r\n",
                             "example.com", 80,
                             b"GET /path?q=1 HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n", response)
                        body = b"x" * 40000
                        case("HTTP POST streaming Content-Length body",
                             b"POST http://127.0.0.1:8080/upload HTTP/1.1\r\nContent-Length: 40000\r\n\r\n" + body,
                             "127.0.0.1", 8080,
                             b"POST /upload HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nContent-Length: 40000\r\nConnection: close\r\n\r\n" + body, response)
                        case("HTTP Expect 100-continue before upload",
                             b"POST http://example.com/ HTTP/1.1\r\nContent-Length: 4\r\nExpect: 100-continue\r\n\r\nbody",
                             "example.com", 80,
                             b"POST / HTTP/1.1\r\nHost: example.com\r\nContent-Length: 4\r\nExpect: 100-continue\r\nConnection: close\r\n\r\nbody", response)
                        chunks = b"9c40\r\n" + body + b"\r\n0\r\nX-End: yes\r\n\r\n"
                        case("HTTP chunked upload and trailer boundary",
                             b"POST http://example.com/ HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n" + chunks + b"GET http://other/ HTTP/1.1\r\n\r\n",
                             "example.com", 80,
                             b"POST / HTTP/1.1\r\nHost: example.com\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n" + chunks, response)
                        case("SOCKS5 regression on same listener",
                             b"\x05\x01\x00\x03\x0bexample.com\x01\xbb" + payload,
                             "example.com", 443, payload, b"SOCKS response", greeting=True)
                    for wire, status in [
                        (b"GET http://x/ HTTP/1.1\r\nContent-Length: -1\r\n\r\n", b"400"),
                        (b"GET / HTTP/1.1\r\nHost: x\r\n\r\n", b"501"),
                        (b"GET http://x/ HTTP/1.1\r\nX: " + b"x" * 8192, b"431"),
                    ]:
                        with socket.create_connection(("127.0.0.1", proxy_port), timeout=8) as client:
                            client.settimeout(8)
                            client.sendall(wire)
                            assert head(client).split()[1] == status
                    print("ok: HTTP 400 / 501 / 431 errors")
                except BaseException:
                    log.flush()
                    log.seek(0)
                    print(log.read(), file=sys.stderr)
                    raise
                finally:
                    proc.terminate()
                    proc.wait(timeout=5)


if __name__ == "__main__":
    run(str(Path(sys.argv[1]).resolve()))
