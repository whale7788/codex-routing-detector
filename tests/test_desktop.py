"""Desktop transport and settings tests. None changes the machine's real proxy or CA store."""
import json
import os
import pathlib
import queue
import socket
import ssl
import tempfile
import threading
import time
import unittest
from types import SimpleNamespace
from unittest import mock

import codex_routing_live as live
import codex_routing_proxy as proxy
import codex_routing_windows as windows


class SseCapture(unittest.TestCase):
    def test_fragmented_chunked_events_reach_existing_verdict_logic(self):
        agg = live.LiveAggregator()
        conn = 42
        agg.feed(proxy.WsMessage("c2s", json.dumps({"type": "response.create", "model": "gpt-6-astra",
                                                     "input": [{"role": "user", "content": "hi"}]}), time.time(), conn))
        def on_event(body):
            agg.feed(proxy.WsMessage("s2c", body, time.time(), conn))
        parser = proxy.SseParser(on_event, chunked=True)
        payload = (b'event: response.created\r\ndata: {"response":{"id":"resp_1","model":"gpt-5.6-luna","status":"in_progress"}}\r\n\r\n'
                   b'event: response.completed\r\ndata: {"response":{"id":"resp_1","model":"gpt-5.6-luna","status":"completed"}}\r\n\r\n')
        wire = f"{len(payload):X}\r\n".encode() + payload + b"\r\n0\r\n\r\n"
        for byte in wire:
            parser.feed(bytes([byte]))
        self.assertTrue(parser.done)
        self.assertEqual(len(agg.rows), 1)
        self.assertEqual(agg.rows[0].requested, "gpt-6-astra")
        self.assertEqual(agg.rows[0].served, "gpt-5.6-luna")
        self.assertEqual(agg.rows[0].verdict(), "REROUTED")

    def test_proxy_address_selects_https_hop(self):
        self.assertEqual(windows._proxy_address("http=127.0.0.1:10809;https=127.0.0.1:10808"),
                         ("127.0.0.1", 10808))
        self.assertEqual(windows._proxy_address("http://127.0.0.1:10808"), ("127.0.0.1", 10808))
        self.assertIsNone(windows._proxy_address("socks=127.0.0.1:10808"))


@unittest.skipUnless(proxy.have_crypto(), "cryptography not installed")
class HttpProxyCapture(unittest.TestCase):
    def test_plain_http_from_other_app_is_forwarded(self):
        origin = socket.socket()
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        seen = []
        def serve():
            peer, _ = origin.accept()
            with peer:
                head, _ = proxy.read_head(peer)
                seen.append(head.split(b"\r\n", 1)[0])
                peer.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nhi")
        threading.Thread(target=serve, daemon=True).start()
        ca = proxy.CertAuthority()
        monitor = proxy.InterceptProxy(ca, lambda _: None, intercept_hosts={"chatgpt.com"})
        monitor.start()
        try:
            with socket.create_connection(("127.0.0.1", monitor.port), timeout=5) as client:
                client.sendall(f"GET http://127.0.0.1:{origin.getsockname()[1]}/x?y=1 HTTP/1.1\r\n"
                               f"Host: 127.0.0.1:{origin.getsockname()[1]}\r\n\r\n".encode())
                self.assertIn(b"\r\n\r\nhi", client.recv(4096))
            self.assertEqual(seen, [b"GET /x?y=1 HTTP/1.1"])
        finally:
            monitor.stop()
            ca.close()
            origin.close()

    def test_other_hosts_pass_unchanged_through_existing_http_proxy(self):
        origin = socket.socket()
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        upstream = socket.socket()
        upstream.bind(("127.0.0.1", 0))
        upstream.listen(1)
        seen = []
        def serve_origin():
            peer, _ = origin.accept()
            with peer:
                self.assertEqual(peer.recv(4), b"ping")
                peer.sendall(b"pong")
        def serve_upstream():
            peer, _ = upstream.accept()
            with peer:
                head, _ = proxy.read_head(peer)
                seen.append(head.split(b"\r\n", 1)[0])
                target = socket.create_connection(("127.0.0.1", origin.getsockname()[1]))
                with target:
                    peer.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    target.sendall(peer.recv(4))
                    peer.sendall(target.recv(4))
        threading.Thread(target=serve_origin, daemon=True).start()
        threading.Thread(target=serve_upstream, daemon=True).start()
        ca = proxy.CertAuthority()
        monitor = proxy.InterceptProxy(ca, lambda _: None,
                                       upstream_proxy=("127.0.0.1", upstream.getsockname()[1]),
                                       intercept_hosts={"chatgpt.com"})
        monitor.start()
        try:
            with socket.create_connection(("127.0.0.1", monitor.port), timeout=5) as client:
                client.sendall(f"CONNECT 127.0.0.1:{origin.getsockname()[1]} HTTP/1.1\r\n\r\n".encode())
                self.assertTrue(proxy.read_head(client)[0].startswith(b"HTTP/1.1 200"))
                client.sendall(b"ping")
                self.assertEqual(client.recv(4), b"pong")
            self.assertEqual(seen, [f"CONNECT 127.0.0.1:{origin.getsockname()[1]} HTTP/1.1".encode()])
        finally:
            monitor.stop()
            ca.close()
            upstream.close()
            origin.close()

    def test_post_sse_is_forwarded_and_labeled(self):
        server_ca = proxy.CertAuthority()
        monitor_ca = proxy.CertAuthority()
        origin = socket.socket()
        origin.bind(("127.0.0.1", 0))
        origin.listen(1)
        messages = queue.Queue()
        upstream_ctx = ssl.create_default_context(cafile=str(server_ca.cert_path))
        monitor = proxy.InterceptProxy(monitor_ca, messages.put, upstream_context=upstream_ctx,
                                       intercept_hosts={"localhost"})
        monitor.start()
        def serve():
            raw, _ = origin.accept()
            with server_ca.context_for("localhost").wrap_socket(raw, server_side=True) as tls:
                head, body = proxy.read_head(tls)
                _, headers = proxy.parse_head(head)
                while len(body) < int(headers["content-length"]):
                    body += tls.recv(4096)
                event = (b'event: response.completed\n'
                         b'data: {"response":{"id":"resp_2","model":"gpt-5.6-luna","status":"completed"}}\n\n')
                tls.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n"
                            b"Transfer-Encoding: chunked\r\n\r\n")
                tls.sendall(f"{len(event):x}\r\n".encode() + event + b"\r\n0\r\n\r\n")
        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            with socket.create_connection(("127.0.0.1", monitor.port), timeout=5) as raw:
                raw.sendall(f"CONNECT localhost:{origin.getsockname()[1]} HTTP/1.1\r\n\r\n".encode())
                self.assertTrue(proxy.read_head(raw)[0].startswith(b"HTTP/1.1 200"))
                client_ctx = ssl.create_default_context(cafile=str(monitor_ca.cert_path))
                with client_ctx.wrap_socket(raw, server_hostname="localhost") as tls:
                    body = b'{"model":"gpt-6-astra","input":[{"role":"user","content":"hi"}]}'
                    tls.sendall(b"POST /backend-api/codex/responses HTTP/1.1\r\nHost: localhost\r\n"
                                + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
                    response = bytearray()
                    while True:
                        part = tls.recv(4096)
                        if not part:
                            break
                        response.extend(part)
                    self.assertIn(b"response.completed", response)
            got = [messages.get(timeout=2), messages.get(timeout=2)]
            agg = live.LiveAggregator()
            for message in got:
                agg.feed(message)
            self.assertEqual(agg.rows[0].requested, "gpt-6-astra")
            self.assertEqual(agg.rows[0].served, "gpt-5.6-luna")
            self.assertEqual(agg.rows[0].verdict(), "REROUTED")
        finally:
            monitor.stop()
            origin.close()
            monitor_ca.close()
            server_ca.close()


@unittest.skipUnless(os.name == "nt", "Windows Desktop only")
class WindowsSession(unittest.TestCase):
    def test_desktop_process_check_includes_app_server_after_window_closes(self):
        completed = lambda output: SimpleNamespace(returncode=0, stdout=output, stderr="")
        with mock.patch.object(windows.subprocess, "run",
                               side_effect=[completed("INFO: No tasks are running\n"),
                                            completed("40160\n")]) as run:
            self.assertTrue(windows.desktop_running())
        self.assertIn("app-server", run.call_args.args[0][-1])

    def test_desktop_launcher_activates_packaged_app(self):
        monitor = live.DesktopMonitor()
        monitor._active = True
        monitor.proxy = SimpleNamespace(port=11692)
        monitor.ca = SimpleNamespace(cert_path=pathlib.Path("C:/temp/ca.pem"))
        with mock.patch.object(windows, "activate_desktop",
                               return_value="OpenAI.Codex_2p2nqsd0c76g0!App") as activate, \
             mock.patch.object(windows, "desktop_running", return_value=False), \
             mock.patch.object(live.subprocess, "Popen") as popen:
            monitor.launch_desktop()
        activate.assert_called_once_with()
        popen.assert_not_called()
        self.assertEqual(monitor.events.get_nowait()[0], "notice")

    def test_package_activation_uses_shell_app_id(self):
        with mock.patch.object(windows, "desktop_app_id",
                               return_value="OpenAI.Codex_2p2nqsd0c76g0!App"), \
             mock.patch.object(windows.os, "startfile") as startfile:
            self.assertEqual(windows.activate_desktop(), "OpenAI.Codex_2p2nqsd0c76g0!App")
        startfile.assert_called_once_with("shell:AppsFolder\\OpenAI.Codex_2p2nqsd0c76g0!App")

    def test_user_environment_is_restored_without_changing_system_proxy(self):
        original = {"WS_PROXY": ["http://127.0.0.1:10808", 1],
                    "WSS_PROXY": ["http://127.0.0.1:10808", 1],
                    "ws_proxy": None, "wss_proxy": None, "CODEX_CA_CERTIFICATE": None}
        writes = []
        with tempfile.TemporaryDirectory() as folder:
            cert = pathlib.Path(folder) / "ca.pem"
            dotenv = pathlib.Path(folder) / ".env"
            proxy_keys = ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "WS_PROXY", "WSS_PROXY",
                          "http_proxy", "https_proxy", "all_proxy", "ws_proxy", "wss_proxy")
            initial = (b"".join(f"{key}=http://127.0.0.1:10808\n".encode() for key in proxy_keys)
                       + b"no_proxy=localhost,127.0.0.1\nOTHER_SETTING=keep\n")
            dotenv.write_bytes(initial)
            session = windows.WindowsDesktopSession(14334, cert)
            session.path = pathlib.Path(folder) / "desktop-session.json"
            with mock.patch.object(windows, "_read_values", return_value=original), \
                 mock.patch.object(windows, "_dotenv_path", return_value=dotenv), \
                 mock.patch.object(windows, "_write_values",
                                   side_effect=lambda key, values: writes.append((key, values))), \
                 mock.patch.object(windows, "_broadcast_environment"), \
                 mock.patch.object(windows.subprocess, "Popen"):
                session.start()
                self.assertTrue(session.active)
                self.assertEqual(writes[0][0], windows.ENVIRONMENT)
                self.assertEqual(writes[0][1]["WS_PROXY"][0], "http://127.0.0.1:14334")
                self.assertEqual(writes[0][1]["CODEX_CA_CERTIFICATE"][0], str(cert))
                for key in proxy_keys:
                    self.assertIn(f"{key}=http://127.0.0.1:14334\n".encode(), dotenv.read_bytes())
                self.assertIn(b"no_proxy=localhost,127.0.0.1\n", dotenv.read_bytes())
                with dotenv.open("ab") as file:
                    file.write(b"ADDED_WHILE_MONITORING=keep\n")
                session.stop()
            self.assertFalse(session.path.exists())
            self.assertEqual(dotenv.read_bytes(), initial + b"ADDED_WHILE_MONITORING=keep\n")
            self.assertEqual(writes[-1], (windows.ENVIRONMENT, original))
            self.assertTrue(all(key != windows.INTERNET for key, _ in writes))

    def test_dotenv_rejects_duplicate_proxy_keys_before_editing(self):
        with tempfile.TemporaryDirectory() as folder:
            dotenv = pathlib.Path(folder) / ".env"
            content = b"HTTP_PROXY=http://127.0.0.1:10808\nHTTP_PROXY=http://127.0.0.1:10808\n"
            dotenv.write_bytes(content)
            with self.assertRaisesRegex(RuntimeError, "duplicate HTTP_PROXY"):
                windows._plan_dotenv(dotenv, "http://127.0.0.1:14334")
            self.assertEqual(dotenv.read_bytes(), content)

    def test_stop_keeps_proxy_and_ca_while_desktop_is_running(self):
        monitor = live.DesktopMonitor()
        monitor._active = True
        monitor.proxy = mock.Mock()
        monitor.ca = mock.Mock()
        with mock.patch.object(windows, "desktop_running", side_effect=[True, False]):
            with self.assertRaisesRegex(RuntimeError, "quit Codex Desktop"):
                monitor.stop()
            self.assertTrue(monitor.codex_running())
            monitor.proxy.stop.assert_not_called()
            monitor.ca.close.assert_not_called()
            monitor.stop()
        self.assertFalse(monitor.codex_running())
        self.assertIsNone(monitor.proxy)
        self.assertIsNone(monitor.ca)

    def test_desktop_monitor_keeps_existing_upstream(self):
        with mock.patch.object(windows, "previous_proxy", return_value=("127.0.0.1", 10808)), \
             mock.patch.object(windows, "WindowsDesktopSession") as session:
            monitor = live.DesktopMonitor()
            monitor.start()
        try:
            self.assertEqual(monitor.proxy.upstream_proxy, ("127.0.0.1", 10808))
            self.assertGreater(monitor.ca.cert_path.read_text(encoding="ascii").count("BEGIN CERTIFICATE"), 1)
        finally:
            with mock.patch.object(windows, "desktop_running", return_value=False):
                monitor.stop()


if __name__ == "__main__":
    unittest.main()
