#!/usr/bin/env python3
"""Built-in intercepting proxy for the live monitor.

A small HTTPS forward proxy: the Codex CLI is started with HTTPS_PROXY pointing here and
CODEX_CA_CERTIFICATE pointing at a throw-away certificate authority that lives only for
this session. Every CONNECT tunnel is terminated with a certificate signed by that CA and
re-encrypted towards the real server. Bytes are relayed unchanged in both directions; the
Codex responses WebSocket is additionally decoded (masking, fragmentation and
permessage-deflate) and every complete message is handed to a callback, in memory. Nothing
is written to disk except the CA files in a private temporary directory, which are deleted
when the proxy stops.

Needs the `cryptography` package for the certificates (pip install cryptography). The
standard library does the TLS, HTTP parsing, WebSocket decoding and zlib inflation.
"""
from __future__ import annotations

import atexit
import datetime as _dt
import ipaddress
import json
import re
import shutil
import socket
import socketserver
import ssl
import struct
import tempfile
import threading
import time
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
    HAVE_CRYPTO = True
except Exception:  # pragma: no cover - depends on the environment
    HAVE_CRYPTO = False

RESPONSES_PATH = "/backend-api/codex/responses"
MAX_HEAD = 64 * 1024
MAX_WS_MESSAGE = 64 * 1024 * 1024
CONNECT_RE = re.compile(r"^CONNECT\s+(\[[^\]]+\]|[^\s:]+):(\d+)\s+HTTP/1\.[01]\s*$")
STATUS_RE = re.compile(r"^HTTP/1\.[01]\s+(\d{3})")


def have_crypto() -> bool:
    return HAVE_CRYPTO


class WsError(Exception):
    """The WebSocket byte stream could not be decoded (relaying continues regardless)."""


@dataclass
class WsMessage:
    """One complete WebSocket message on a watched connection."""
    direction: str  # "c2s" (client to server) or "s2c" (server to client)
    text: str
    ts: float
    conn: int


# ---------------------------------------------------------------- certificates
class CertAuthority:
    """A throw-away CA (EC P-256) plus per-host leaf certificates, all in one private temp dir."""

    def __init__(self, days: int = 30) -> None:
        if not HAVE_CRYPTO:
            raise RuntimeError("the live monitor needs the cryptography package: pip install cryptography")
        self.dir = Path(tempfile.mkdtemp(prefix="crd-ca-"))
        atexit.register(shutil.rmtree, str(self.dir), True)  # last resort if close() is never called
        self.cert_path = self.dir / "ca.pem"
        self._lock = threading.Lock()
        self._contexts: Dict[str, ssl.SSLContext] = {}
        now = _dt.datetime.now(_dt.timezone.utc)
        self._not_before = now - _dt.timedelta(days=1)
        self._not_after = now + _dt.timedelta(days=days)
        self._key = ec.generate_private_key(ec.SECP256R1())
        self._name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "codex-routing-detector throw-away CA"),
                                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "codex-routing-detector (session only)")])
        cert = (x509.CertificateBuilder()
                .subject_name(self._name).issuer_name(self._name)
                .public_key(self._key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(self._not_before).not_valid_after(self._not_after)
                .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
                .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                             content_commitment=False, key_encipherment=False,
                                             data_encipherment=False, key_agreement=False,
                                             encipher_only=False, decipher_only=False), critical=True)
                .add_extension(x509.SubjectKeyIdentifier.from_public_key(self._key.public_key()), critical=False)
                .sign(self._key, hashes.SHA256()))
        self._cert = cert
        self.cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    def context_for(self, host: str) -> ssl.SSLContext:
        """Server-side TLS context presenting a leaf certificate for `host` (cached)."""
        host = host.strip("[]").lower()
        with self._lock:
            ctx = self._contexts.get(host)
            if ctx is not None:
                return ctx
            key = ec.generate_private_key(ec.SECP256R1())
            try:
                san: x509.GeneralName = x509.IPAddress(ipaddress.ip_address(host))
            except ValueError:
                san = x509.DNSName(host)
            leaf = (x509.CertificateBuilder()
                    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, host[:64])]))
                    .issuer_name(self._name)
                    .public_key(key.public_key()).serial_number(x509.random_serial_number())
                    .not_valid_before(self._not_before).not_valid_after(self._not_after)
                    .add_extension(x509.SubjectAlternativeName([san]), critical=False)
                    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                    .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=True, key_cert_sign=False,
                                                 crl_sign=False, content_commitment=False, data_encipherment=False,
                                                 key_agreement=False, encipher_only=False, decipher_only=False),
                                   critical=True)
                    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
                    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(self._key.public_key()),
                                   critical=False)
                    .sign(self._key, hashes.SHA256()))
            safe = re.sub(r"[^A-Za-z0-9.-]+", "_", host)
            cert_file = self.dir / f"{safe}.pem"
            cert_file.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)
                                  + self._cert.public_bytes(serialization.Encoding.PEM))
            key_file = self.dir / f"{safe}.key"
            key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
            try:
                ctx.set_alpn_protocols(["http/1.1"])  # keep the client on HTTP/1.1 so the head can be read
            except NotImplementedError:  # pragma: no cover
                pass
            self._contexts[host] = ctx
            return ctx

    def close(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


# ------------------------------------------------------------------ websocket
def unmask(payload: bytes, key: bytes) -> bytes:
    n = len(payload)
    if n == 0:
        return b""
    k = (key * (n // 4 + 1))[:n]
    return (int.from_bytes(payload, "little") ^ int.from_bytes(k, "little")).to_bytes(n, "little")


class WsParser:
    """Reassembles WebSocket messages (RFC 6455) from a byte stream, inflating
    permessage-deflate messages (RFC 7692) when the extension was negotiated."""

    def __init__(self, deflate: bool = False, reset_context: bool = False) -> None:
        self.deflate = deflate
        self.reset_context = reset_context
        self._buf = bytearray()
        self._frag: List[bytes] = []
        self._frag_op: Optional[int] = None
        self._frag_rsv1 = False
        self._inflater = zlib.decompressobj(-15) if deflate else None

    def feed(self, data: bytes) -> List[Tuple[int, bytes]]:
        """Return the complete data messages (opcode, payload) finished by these bytes.
        Control frames are skipped. Raises WsError when the stream cannot be decoded."""
        self._buf += data
        out: List[Tuple[int, bytes]] = []
        while True:
            fr = self._next_frame()
            if fr is None:
                return out
            fin, rsv1, op, payload = fr
            if op >= 8:
                continue  # ping, pong, close: never fragmented, nothing to reassemble
            if op != 0:
                if self._frag_op is not None:
                    raise WsError("new message started inside a fragmented one")
                self._frag_op, self._frag, self._frag_rsv1 = op, [payload], rsv1
            else:
                if self._frag_op is None:
                    raise WsError("continuation frame without a first frame")
                self._frag.append(payload)
            if sum(len(p) for p in self._frag) > MAX_WS_MESSAGE:
                raise WsError("message larger than the limit")
            if fin:
                body = b"".join(self._frag)
                op, comp = self._frag_op, self._frag_rsv1
                self._frag_op, self._frag, self._frag_rsv1 = None, [], False
                if comp:
                    if self._inflater is None:
                        raise WsError("compressed message but permessage-deflate was not negotiated")
                    try:
                        body = self._inflater.decompress(body + b"\x00\x00\xff\xff")
                    except zlib.error as e:
                        raise WsError(f"inflate failed: {e}")
                    if self.reset_context:
                        self._inflater = zlib.decompressobj(-15)
                out.append((op, body))

    def _next_frame(self) -> Optional[Tuple[bool, bool, int, bytes]]:
        b = self._buf
        if len(b) < 2:
            return None
        b0, b1 = b[0], b[1]
        fin, rsv1, op = bool(b0 & 0x80), bool(b0 & 0x40), b0 & 0x0F
        if b0 & 0x30:
            raise WsError("reserved bits RSV2/RSV3 set")
        masked, ln, pos = bool(b1 & 0x80), b1 & 0x7F, 2
        if ln == 126:
            if len(b) < 4:
                return None
            ln, pos = struct.unpack(">H", bytes(b[2:4]))[0], 4
        elif ln == 127:
            if len(b) < 10:
                return None
            ln, pos = struct.unpack(">Q", bytes(b[2:10]))[0], 10
        if ln > MAX_WS_MESSAGE:
            raise WsError("frame larger than the limit")
        key = b""
        if masked:
            if len(b) < pos + 4:
                return None
            key, pos = bytes(b[pos:pos + 4]), pos + 4
        if len(b) < pos + ln:
            return None
        payload = bytes(b[pos:pos + ln])
        del b[:pos + ln]
        if masked:
            payload = unmask(payload, key)
        return fin, rsv1, op, payload


# ---------------------------------------------------------------------- HTTP
def read_head(sock: socket.socket, limit: int = MAX_HEAD) -> Tuple[bytes, bytes]:
    """Read up to and including the blank line that ends an HTTP head. Returns (head, rest)."""
    buf = bytearray()
    while True:
        i = buf.find(b"\r\n\r\n")
        if i >= 0:
            return bytes(buf[:i + 4]), bytes(buf[i + 4:])
        if len(buf) > limit:
            raise ValueError("HTTP head too large")
        chunk = sock.recv(16384)
        if not chunk:
            raise ConnectionError("connection closed while reading the HTTP head")
        buf += chunk


def parse_head(head: bytes) -> Tuple[str, Dict[str, str]]:
    """(first line, lower-cased headers). Repeated headers are joined with ', '."""
    lines = head.decode("latin-1").split("\r\n")
    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            k, v = k.strip().lower(), v.strip()
            headers[k] = (headers[k] + ", " + v) if k in headers else v
    return lines[0], headers


def deflate_params(ext_header: str) -> Tuple[bool, bool, bool]:
    """(negotiated, client_no_context_takeover, server_no_context_takeover) from the server's
    Sec-WebSocket-Extensions response header."""
    low = ext_header.lower()
    on = "permessage-deflate" in low
    return on, on and "client_no_context_takeover" in low, on and "server_no_context_takeover" in low


# --------------------------------------------------------------------- proxy
def _close(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


class _Server(socketserver.ThreadingTCPServer):
    daemon_threads = True
    block_on_close = False  # stop() closes the relay sockets itself; never wait on handler threads
    allow_reuse_address = True
    proxy: "InterceptProxy"


class SseParser:
    """Decode HTTP chunk framing and SSE events while the original bytes pass through."""

    def __init__(self, on_event: Callable[[str], None], chunked: bool) -> None:
        self.on_event = on_event
        self.chunked = chunked
        self.wire = bytearray()
        self.lines = bytearray()
        self.data: List[str] = []
        self.event = ""
        self.remaining = 0
        self.state = "size"
        self.done = False

    def _body(self, part: bytes) -> None:
        self.lines.extend(part)
        if len(self.lines) > MAX_WS_MESSAGE:
            self.lines.clear()
            self.data.clear()
            raise ValueError("SSE line exceeds limit")
        while b"\n" in self.lines:
            raw, _, tail = self.lines.partition(b"\n")
            self.lines = bytearray(tail)
            line = raw.rstrip(b"\r").decode("utf-8", "replace")
            if not line:
                if self.data:
                    payload = "\n".join(self.data)
                    if payload != "[DONE]":
                        try:
                            obj = json.loads(payload)
                            if isinstance(obj, dict):
                                if self.event and not obj.get("type"):
                                    obj["type"] = self.event
                                self.on_event(json.dumps(obj))
                        except ValueError:
                            pass
                self.data.clear()
                self.event = ""
            elif line.startswith("data:"):
                self.data.append(line[5:].lstrip(" "))
            elif line.startswith("event:"):
                self.event = line[6:].strip()

    def feed(self, part: bytes) -> None:
        if not self.chunked:
            self._body(part)
            return
        self.wire.extend(part)
        while not self.done:
            if self.state == "size":
                idx = self.wire.find(b"\r\n")
                if idx < 0:
                    break
                self.remaining = int(bytes(self.wire[:idx]).split(b";", 1)[0], 16)
                del self.wire[:idx + 2]
                if self.remaining == 0:
                    self.done = True
                    break
                self.state = "body"
            elif self.state == "body":
                if not self.wire:
                    break
                n = min(self.remaining, len(self.wire))
                self._body(bytes(self.wire[:n]))
                del self.wire[:n]
                self.remaining -= n
                if self.remaining == 0:
                    self.state = "tail"
            else:
                if len(self.wire) < 2:
                    break
                if self.wire[:2] != b"\r\n":
                    raise ValueError("invalid HTTP chunk terminator")
                del self.wire[:2]
                self.state = "size"
        if len(self.wire) > MAX_HEAD:
            raise ValueError("HTTP chunk header exceeds limit")


class InterceptProxy:
    """Listens on 127.0.0.1 only. `on_message(WsMessage)` gets every decoded message of a
    WebSocket whose request path starts with `watch_path`; `on_event(name, info)` gets
    "connect", "ws_open", "ws_close", "parse_lost" and "error" notices for the details view."""

    def __init__(self, ca: CertAuthority, on_message: Callable[[WsMessage], None],
                 on_event: Optional[Callable[[str, dict], None]] = None, watch_path: str = RESPONSES_PATH,
                 upstream_context: Optional[ssl.SSLContext] = None, connect_timeout: float = 20.0,
                 upstream_proxy: Optional[Tuple[str, int]] = None,
                 intercept_hosts: Optional[set[str]] = None) -> None:
        self.ca = ca
        self.on_message = on_message
        self.on_event = on_event or (lambda name, info: None)
        self.watch_path = watch_path
        self.upstream_ctx = upstream_context or ssl.create_default_context()
        self.connect_timeout = connect_timeout
        self.upstream_proxy = upstream_proxy
        self.intercept_hosts = intercept_hosts
        self.port = 0
        self._server: Optional[_Server] = None
        self._thread: Optional[threading.Thread] = None
        self._socks: set = set()
        self._lock = threading.Lock()
        self._conn_seq = 0

    # lifecycle
    def start(self) -> int:
        proxy = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self) -> None:
                proxy._handle(self.request)

        self._server = _Server(("127.0.0.1", 0), Handler)
        self._server.proxy = self
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, kwargs={"poll_interval": 0.2},
                                        name="crd-proxy", daemon=True)
        self._thread.start()
        return self.port

    def stop(self) -> None:
        """Stop accepting, then close every relay socket so the handler threads end by themselves."""
        server, self._server = self._server, None
        if server is not None:
            if self._thread is not None and self._thread.is_alive():
                server.shutdown()  # returns once serve_forever() has noticed (poll_interval)
            server.server_close()
        with self._lock:
            socks = list(self._socks)
            self._socks.clear()
        for s in socks:
            _close(s)

    def env(self) -> Tuple[Dict[str, str], List[str]]:
        """(variables to set, variables to remove) for a Codex process that should use this proxy."""
        url = f"http://127.0.0.1:{self.port}"
        # Only HTTPS is proxied (plain http:// would get 405 here), and only Codex's own CA
        # variable is set: SSL_CERT_FILE would break every other TLS client in that console.
        add = {"HTTPS_PROXY": url, "https_proxy": url, "CODEX_CA_CERTIFICATE": str(self.ca.cert_path)}
        return add, ["NO_PROXY", "no_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"]

    # connections
    def _track(self, *socks: socket.socket) -> None:
        with self._lock:
            self._socks.update(socks)

    def _untrack(self, *socks: socket.socket) -> None:
        with self._lock:
            self._socks.difference_update(socks)

    def _handle(self, client: socket.socket) -> None:
        upstream_raw = client_tls = upstream = None
        self._track(client)
        try:
            client.settimeout(30)  # only the CONNECT line and the TLS handshake are time-limited
            head, rest = read_head(client)
            line, _ = parse_head(head)
            m = CONNECT_RE.match(line)
            if not m:
                self._forward_http(client, head, rest, line)
                return
            host, port = m.group(1).strip("[]"), int(m.group(2))
            try:
                upstream_raw = self._connect_upstream(host, port)
            except OSError as e:
                self.on_event("error", {"host": host, "error": f"connect failed: {e}"})
                client.sendall(b"HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
                return
            self._track(upstream_raw)
            intercept = self.intercept_hosts is None or any(
                host.lower() == allowed or host.lower().endswith("." + allowed)
                for allowed in self.intercept_hosts)
            if not intercept:
                client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                if rest:
                    upstream_raw.sendall(rest)
                client.settimeout(None)
                upstream_raw.settimeout(None)
                self._pump_both(client, upstream_raw, None, None, 0, b"")
                return
            if rest:  # bytes sent before our 200 cannot be handed to the TLS layer; say so instead of hiding it
                self.on_event("error", {"host": host, "error": f"{len(rest)} bytes sent before the CONNECT reply were dropped"})
            client.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            try:
                client_tls = self.ca.context_for(host).wrap_socket(client, server_side=True)
            except (ssl.SSLError, OSError) as e:
                self.on_event("error", {"host": host, "error": f"client TLS handshake failed: {e}"})
                return
            try:
                upstream = self.upstream_ctx.wrap_socket(upstream_raw, server_hostname=host)
            except (ssl.SSLError, OSError) as e:
                self.on_event("error", {"host": host, "error": f"upstream TLS handshake failed: {e}"})
                return
            self._track(client_tls, upstream)
            client_tls.settimeout(None)  # a pooled tunnel may sit idle for minutes before its first request
            self.on_event("connect", {"host": host, "port": port})
            self._intercept(client_tls, upstream, host)
        except socket.timeout:
            pass  # nothing arrived on a fresh tunnel: not worth a notice
        except (OSError, ValueError, ConnectionError) as e:
            self.on_event("error", {"error": f"{type(e).__name__}: {e}"})
        finally:
            for s in (client_tls, upstream, upstream_raw, client):
                _close(s)
            self._untrack(*[s for s in (client_tls, upstream, upstream_raw, client) if s is not None])

    def _forward_http(self, client: socket.socket, head: bytes, rest: bytes, line: str) -> None:
        """Pass plain HTTP through for other Windows apps using the system proxy."""
        parts = line.split(" ", 2)
        if len(parts) != 3 or not parts[1].startswith("http://"):
            client.sendall(b"HTTP/1.1 405 Method Not Allowed\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            return
        target = urlsplit(parts[1])
        if not target.hostname:
            return
        upstream = socket.create_connection(self.upstream_proxy or (target.hostname, target.port or 80),
                                            timeout=self.connect_timeout)
        self._track(upstream)
        try:
            if self.upstream_proxy is None:
                path = target.path or "/"
                if target.query:
                    path += "?" + target.query
                head = f"{parts[0]} {path} {parts[2]}\r\n".encode("ascii") + head.split(b"\r\n", 1)[1]
            upstream.sendall(head + rest)
            client.settimeout(None)
            upstream.settimeout(None)
            self._pump_both(client, upstream, None, None, 0, b"")
        finally:
            _close(upstream)
            self._untrack(upstream)

    def _connect_upstream(self, host: str, port: int) -> socket.socket:
        if self.upstream_proxy is None:
            return socket.create_connection((host, port), timeout=self.connect_timeout)
        sock = socket.create_connection(self.upstream_proxy, timeout=self.connect_timeout)
        try:
            authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
            sock.sendall(f"CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n".encode("ascii"))
            head, rest = read_head(sock)
            status, _ = parse_head(head)
            if not STATUS_RE.match(status) or STATUS_RE.match(status).group(1) != "200" or rest:
                raise ConnectionError(f"upstream proxy rejected CONNECT for {host}")
            return sock
        except Exception:
            _close(sock)
            raise

    def _intercept(self, client: ssl.SSLSocket, upstream: ssl.SSLSocket, host: str) -> None:
        """One HTTP/1.1 request on the tunnel: read its head, forward it, then either decode a
        WebSocket or relay bytes blindly. Both sockets are closed by the pumps when done."""
        client.settimeout(None)
        upstream.settimeout(None)
        while True:
            try:
                head, rest = read_head(client)
            except ConnectionError:
                return  # the client opened the tunnel and closed it again without asking for anything
            req_line, req_headers = parse_head(head)
            upstream.sendall(head)
            if rest:
                upstream.sendall(rest)
            parts = req_line.split()
            path = parts[1] if len(parts) >= 2 else ""
            if "websocket" in req_headers.get("upgrade", "").lower():
                break
            # A plain request: relay its body and response, then look at the next request on the
            # same tunnel (a WebSocket upgrade may follow on a kept-alive connection).
            if not self._relay_one_exchange(client, upstream, req_headers, rest, path, host,
                                            parts[0] if parts else ""):
                return
        rhead, rrest = read_head(upstream)
        status_line, resp_headers = parse_head(rhead)
        client.sendall(rhead)
        m = STATUS_RE.match(status_line)
        if not m or m.group(1) != "101":
            if rrest:
                client.sendall(rrest)
            self._pump_both(client, upstream, None, None, 0, b"")
            return
        watched = path.startswith(self.watch_path)
        on, c_reset, s_reset = deflate_params(resp_headers.get("sec-websocket-extensions", ""))
        with self._lock:
            self._conn_seq += 1
            conn = self._conn_seq
        hint = req_headers.get("x-codex-routing-hint", "")
        self.on_event("ws_open", {"conn": conn, "host": host, "path": path, "watched": watched, "deflate": on,
                                  "routing_hint": hint})
        c2s = WsParser(on, c_reset) if watched else None
        s2c = WsParser(on, s_reset) if watched else None
        if rrest and s2c is not None:
            self._deliver(s2c, rrest, "s2c", conn)
        if rrest:
            client.sendall(rrest)
        self._pump_both(client, upstream, c2s, s2c, conn, rest)

    def _relay_one_exchange(self, client: socket.socket, upstream: socket.socket, req_headers: Dict[str, str],
                            body_start: bytes, path: str, host: str, method: str) -> bool:
        """Forward one plain HTTP/1.1 request body and its response. Returns True if the tunnel
        stays open for another request, False if either side closed or framing is unknown."""
        watched = method.upper() == "POST" and path.startswith(self.watch_path)
        if req_headers.get("transfer-encoding") or (not watched and
                                                    req_headers.get("connection", "").lower() == "close"):
            self._pump_both(client, upstream, None, None, 0, b"")
            return False
        request_body = bytearray(body_start[:8 * 1024 * 1024]) if watched else bytearray()
        try:
            remaining = int(req_headers.get("content-length", "0")) - len(body_start)
        except ValueError:
            self._pump_both(client, upstream, None, None, 0, b"")
            return False
        while remaining > 0:
            chunk = client.recv(min(65536, remaining))
            if not chunk:
                return False
            upstream.sendall(chunk)
            if watched and len(request_body) < 8 * 1024 * 1024:
                request_body.extend(chunk[:8 * 1024 * 1024 - len(request_body)])
            remaining -= len(chunk)
        rhead, rrest = read_head(upstream)
        _status, rh = parse_head(rhead)
        client.sendall(rhead)
        if rrest:
            client.sendall(rrest)
        if watched and "text/event-stream" in rh.get("content-type", "").lower():
            with self._lock:
                self._conn_seq += 1
                conn = self._conn_seq
            self.on_event("http_open", {"conn": conn, "host": host, "path": path,
                                        "routing_hint": req_headers.get("x-codex-routing-hint", "")})
            try:
                obj = json.loads(request_body)
                if isinstance(obj, dict):
                    summary = {"type": "response.create", "model": obj.get("model")}
                    inputs = obj.get("input")
                    if isinstance(inputs, list):
                        summary["input"] = ([{"role": "user"}] if any(
                            isinstance(item, dict) and str(item.get("role", "")).lower() == "user"
                            for item in inputs) else [])
                    self.on_message(WsMessage("c2s", json.dumps(summary), time.time(), conn))
            except ValueError:
                self.on_event("parse_lost", {"conn": conn, "direction": "c2s", "error": "HTTP request body unavailable"})
            finally:
                request_body.clear()
            parser = SseParser(lambda body: self.on_message(WsMessage("s2c", body, time.time(), conn)),
                               "chunked" in rh.get("transfer-encoding", "").lower())
            try:
                if rrest:
                    parser.feed(rrest)
                remaining_body = int(rh["content-length"]) - len(rrest) if "content-length" in rh else None
                while not parser.done and (remaining_body is None or remaining_body > 0):
                    chunk = upstream.recv(min(65536, remaining_body) if remaining_body is not None else 65536)
                    if not chunk:
                        break
                    client.sendall(chunk)
                    parser.feed(chunk)
                    if remaining_body is not None:
                        remaining_body -= len(chunk)
            except ValueError as e:
                self.on_event("parse_lost", {"conn": conn, "direction": "s2c", "error": str(e)})
                self._pump_both(client, upstream, None, None, 0, b"")
            self.on_event("ws_close", {"conn": conn})
            return False
        if rh.get("transfer-encoding") or rh.get("connection", "").lower() == "close" or "content-length" not in rh:
            self._pump_both(client, upstream, None, None, 0, b"")  # cannot frame the rest: blind relay
            return False
        try:
            remaining = int(rh["content-length"]) - len(rrest)
        except ValueError:
            self._pump_both(client, upstream, None, None, 0, b"")
            return False
        while remaining > 0:
            chunk = upstream.recv(min(65536, remaining))
            if not chunk:
                return False
            client.sendall(chunk)
            remaining -= len(chunk)
        return True

    def _deliver(self, parser: WsParser, data: bytes, direction: str, conn: int) -> bool:
        """Feed bytes to a parser and hand out complete messages. False once decoding is lost."""
        try:
            for op, payload in parser.feed(data):
                if op in (1, 2):
                    self.on_message(WsMessage(direction, payload.decode("utf-8", "replace"), time.time(), conn))
            return True
        except WsError as e:
            self.on_event("parse_lost", {"conn": conn, "direction": direction, "error": str(e)})
            return False

    def _pump_both(self, client: socket.socket, upstream: socket.socket, c2s: Optional[WsParser],
                   s2c: Optional[WsParser], conn: int, client_early: bytes) -> None:
        if c2s is not None and client_early:
            c2s_ok = self._deliver(c2s, client_early, "c2s", conn)
        else:
            c2s_ok = c2s is not None
        t = threading.Thread(target=self._pump, args=(upstream, client, s2c, "s2c", conn, s2c is not None),
                             name=f"crd-pump-s2c-{conn}", daemon=True)
        t.start()
        self._pump(client, upstream, c2s, "c2s", conn, c2s_ok)
        t.join()
        if conn:
            self.on_event("ws_close", {"conn": conn})

    def _pump(self, src: socket.socket, dst: socket.socket, parser: Optional[WsParser], direction: str,
              conn: int, parsing: bool) -> None:
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                dst.sendall(data)
                if parsing and parser is not None:
                    parsing = self._deliver(parser, data, direction, conn)
        except (OSError, ValueError):
            pass
        finally:
            for s in (src, dst):
                try:
                    s.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
