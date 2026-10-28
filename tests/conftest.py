"""Loopback-only integration harness; no Tor daemon or external onion traffic."""
import base64
import hashlib
import http.client
import os
from pathlib import Path
import queue
import signal
import socket
import socketserver
import ssl
from datetime import datetime, timedelta, timezone
import ipaddress

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import subprocess
import sys
import threading
import time

import pytest

ROOT = Path(__file__).resolve().parents[1]
KEY = bytes(range(32))
VERSION = b'\x03'
CHECKSUM = hashlib.sha3_256(b'.onion checksum' + KEY + VERSION).digest()[:2]
ONION = base64.b32encode(KEY + CHECKSUM + VERSION).decode().lower() + '.onion'


def receive_exact(sock, count):
    data = b''
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise EOFError('socket closed during read')
        data += part
    return data


class SocksHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.connection.settimeout(5)
        if receive_exact(self.connection, 3) != b'\x05\x01\x00':
            raise ValueError('unexpected SOCKS greeting')
        self.connection.sendall(b'\x05\x00')
        prefix = receive_exact(self.connection, 5)
        assert prefix[:4] == b'\x05\x01\x00\x03'
        target = receive_exact(self.connection, prefix[4]).decode()
        port = int.from_bytes(receive_exact(self.connection, 2), 'big')
        self.connection.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
        # HTTPConnectionPool can reuse an upstream SOCKS connection.
        while True:
            line = self.rfile.readline()
            if not line:
                return
            method, path, _ = line.decode().strip().split(' ', 2)
            headers = {}
            while (line := self.rfile.readline()) != b'\r\n':
                name, value = line.decode().split(':', 1)
                headers[name.lower()] = value.strip()
            body = self.rfile.read(int(headers.get('content-length', '0')))
            self.server.requests.put((target, port, method, path, headers, body))
            if path == '/slow':
                time.sleep(2)
            status = b'200 OK'
            extra = b''
            if path == '/binary':
                content = bytes(range(256))
                mime = b'application/octet-stream'
            elif path == '/echo':
                content, mime = body, b'application/octet-stream'
            elif path == '/redirect':
                status = b'302 Found'
                content, mime = b'', b'text/plain'
                extra = b'Location: http://' + ONION.encode() + b'/short\r\n'
            else:
                content = b'<html><body><a href="http://' + ONION.encode() + b'/next">link</a></body></html>'
                mime = b'text/html'
                extra = b'Set-Cookie: session=abc; Domain=' + ONION.encode() + b'; Path=/\r\n'
            self.connection.sendall(
                b'HTTP/1.1 ' + status + b'\r\nContent-Type: ' + mime + b'\r\n'
                + b'Content-Length: ' + str(len(content)).encode() + b'\r\n' + extra + b'\r\n' + content
            )


@pytest.fixture
def gateway(tmp_path, request):
    options = getattr(request, "param", {})
    transport = options.get("transport", "HTTP")
    bind = options.get("bind", "127.0.0.1")
    test_python = os.environ.get('TOR2WEBZ_TEST_PYTHON', sys.executable)
    installed = 'TOR2WEBZ_TEST_PYTHON' in os.environ
    assets_setting = '' if installed else f'sysdatadir = {ROOT / "data"}'
    server = socketserver.ThreadingTCPServer(('127.0.0.1', 0), SocksHandler)
    server.daemon_threads = True
    server.requests = queue.Queue()
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    # Reserve an available loopback port, then release immediately before spawn.
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        port = reservation.getsockname()[1]
    for directory in ('certs', 'logs', 'lists'):
        (tmp_path / directory).mkdir()
    with socket.socket() as reservation:
        reservation.bind(('127.0.0.1', 0))
        https_port = reservation.getsockname()[1]
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'gateway.test')])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
            .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([
                x509.DNSName('gateway.test'), x509.DNSName('*.gateway.test'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
            ]), critical=False)
            .sign(key, hashes.SHA256()))
    (tmp_path / 'certs/tor2web-key.pem').write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption()))
    certpath = tmp_path / 'certs/tor2web-cert.pem'
    certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    config = tmp_path / 'tor2web.conf'
    config.write_text(f'''[main]
transport = {transport}
listen_ipv4 = {bind if ':' not in bind else 'None'}
listen_ipv6 = {bind if ':' in bind else 'None'}
listen_port_http = {port}
listen_port_https = {https_port}
basehost = gateway.test
datadir = {tmp_path}
{assets_setting}
processes = 1
disable_disclaimer = True
disable_banner = {options.get('disable_banner', True)}
source_url = {options.get('source_url', 'None')}
debugmode = True
debugtostdout = True
disable_tor_redirection = True
exit_node_list_refresh = 0
socksport = {server.server_address[1]}
max_request_body_bytes = 1024
max_concurrent_requests = {options.get('max_concurrent_requests', 16)}
request_timeout = {options.get('request_timeout', 60)}
''')
    logfile = tmp_path / 'process.log'
    with logfile.open('wb') as log:
        process = subprocess.Popen(
            [test_python, '-m', 'tor2web.t2w', '-c', str(config), '-n',
             '-d', str(tmp_path), '-p', str(tmp_path / 'pid')],
            cwd=tmp_path if installed else ROOT, stdout=log, stderr=log, start_new_session=True,
        )
        class Gateway:
            host = ONION[:-6] + '.gateway.test'
            requests = server.requests

            def request(self, path='/', method='GET', body=None, headers=None):
                if transport == 'HTTPS':
                    context = ssl.create_default_context(cafile=str(certpath))
                    connection = http.client.HTTPSConnection(bind, https_port, timeout=5, context=context)
                else:
                    connection = http.client.HTTPConnection(bind, port, timeout=5)
                request_headers = {'Host': self.host, **(headers or {})}
                connection.request(method, path, body=body, headers=request_headers)
                response = connection.getresponse()
                result = response.status, dict(response.getheaders()), response.read()
                connection.close()
                return result

            def logs(self):
                return logfile.read_text()

        instance = Gateway()
        instance.port = https_port if transport == "HTTPS" else port
        instance.https_port = https_port
        instance.certpath = certpath
        instance.config = config
        deadline = time.monotonic() + 10
        try:
            while True:
                try:
                    status, _, _ = instance.request('/checktor', headers={'Host': 'gateway.test'})
                    if status == 200 or (transport == "BOTH" and status == 302):
                        break
                except (OSError, http.client.HTTPException):
                    pass
                if process.poll() is not None or time.monotonic() > deadline:
                    pytest.fail('gateway did not start:\n' + instance.logs())
                time.sleep(0.05)
            yield instance
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
            server.shutdown()
            server.server_close()
