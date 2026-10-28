"""Bounded, loopback-only contact delivery for the public gateway."""
from collections import deque
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import urlsplit
import json
import os
import re
import smtplib
import ssl
import time

ORIGIN = 'https://onion.https.cl'
DESTINATIONS = {'contact': 'contacto@https.cl', 'abuse': 'abuse@https.cl'}
EMAIL = re.compile(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?\.[A-Za-z]{2,63}\Z")


def smtp_connect(config):
    context = ssl.create_default_context()
    if config['port'] == 465:
        connection = smtplib.SMTP_SSL(config['host'], config['port'], timeout=8, context=context)
    else:
        connection = smtplib.SMTP(config['host'], config['port'], timeout=8)
        try:
            connection.ehlo()
            connection.starttls(context=context)
            connection.ehlo()
        except Exception:
            connection.close()
            raise
    try:
        password = Path(config['password_file']).read_text().rstrip('\r\n')
        if not password:
            raise ValueError('empty SMTP credential')
        connection.login(config['username'], password)
    except Exception:
        connection.close()
        raise
    return connection


def deliver(config, kind, email, message, url=""):
    mail = EmailMessage()
    mail['From'] = config['username']
    mail['To'] = DESTINATIONS[kind]
    mail['Reply-To'] = email
    mail['Subject'] = '[TOR2WEBZ] ' + ('Reporte de abuso' if kind == 'abuse' else 'Contacto')
    mail['Date'] = formatdate(localtime=False)
    mail['Message-ID'] = make_msgid(domain='https.cl')
    mail.set_content('Mensaje recibido desde el formulario de TOR2WEBZ.\n\n'
                     + ('URL denunciada: ' + url + '\n\n' if kind == 'abuse' else '') + message)
    with smtp_connect(config) as connection:
        refused = connection.send_message(mail, from_addr=config['username'], to_addrs=[DESTINATIONS[kind]])
        if refused:
            raise smtplib.SMTPException('recipient refused')


def valid_report_url(value):
    if not isinstance(value, str) or not 1 <= len(value) <= 2048:
        return False
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        return False
    try:
        parsed = urlsplit(value)
        port = parsed.port  # Reject malformed or out-of-range ports.
        return (parsed.scheme in ('http', 'https') and bool(parsed.hostname)
                and parsed.username is None and parsed.password is None
                and '\\' not in value)
    except ValueError:
        return False


class ContactServer(HTTPServer):
    def __init__(self, address, config, sender=deliver):
        self.config = config
        self.sender = sender
        self.attempts = deque()
        super().__init__(address, ContactHandler)


class ContactHandler(BaseHTTPRequestHandler):
    server_version = 'TOR2WEBZ'
    sys_version = ''

    def setup(self):
        super().setup()
        self.connection.settimeout(10)

    def log_message(self, *args):
        pass  # Neither sender addresses nor message contents belong in access logs.

    def respond(self, status, value):
        data = json.dumps(value, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.end_headers()
        self.wfile.write(data)

    def ready(self):
        path = Path(self.server.config['password_file'])
        enabled = self.server.config.get('enabled_file')
        return (path.is_file() and path.stat().st_size > 0
                and (not enabled or (Path(enabled).is_file() and Path(enabled).read_text().strip() == 'enabled')))

    def do_GET(self):
        if self.path != '/__tor2webz/contact':
            return self.respond(404, {'ready': False})
        self.respond(200, {'ready': self.ready()})

    def do_POST(self):
        if self.path != '/__tor2webz/contact':
            return self.respond(404, {'sent': False})
        if self.headers.get('Origin') != ORIGIN:
            return self.respond(403, {'sent': False})
        if self.headers.get('Transfer-Encoding') or self.headers.get_content_type() != 'application/json':
            return self.respond(400, {'sent': False})
        try:
            length = int(self.headers.get('Content-Length', '0'))
            if not 0 < length <= 8192:
                return self.respond(413, {'sent': False})
            raw = self.rfile.read(length)
            if len(raw) != length:
                return self.respond(400, {'sent': False})
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError()
            kind = data.get('kind')
            email = data.get('email')
            message = data.get('message')
            url = data.get('url', '')
            if kind == 'abuse' and not valid_report_url(url):
                raise ValueError()
            if (kind not in DESTINATIONS or not isinstance(email, str) or len(email) > 254
                    or not EMAIL.fullmatch(email) or not isinstance(message, str)
                    or not 10 <= len(message.strip()) <= 4000 or '\x00' in message
                    or data.get('website')):
                raise ValueError()
        except (ValueError, UnicodeError, TypeError):
            return self.respond(400, {'sent': False})
        if not self.ready():
            return self.respond(503, {'sent': False})
        now = time.monotonic()
        while self.server.attempts and self.server.attempts[0] < now - 60:
            self.server.attempts.popleft()
        if len(self.server.attempts) >= 5:
            return self.respond(429, {'sent': False})
        self.server.attempts.append(now)
        try:
            self.server.sender(self.server.config, kind, email, message.strip(), url if kind == 'abuse' else '')
        except Exception:
            return self.respond(503, {'sent': False})
        self.respond(200, {'sent': True})


def main():
    config = json.loads(Path(os.environ.get('TOR2WEBZ_CONTACT_CONFIG', '/etc/tor2webz-contact/smtp.json')).read_text())
    ContactServer(('127.0.0.1', 9084), config).serve_forever()


if __name__ == '__main__':
    main()
