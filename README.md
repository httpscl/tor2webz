```
████████╗ ██████╗ ██████╗ ██████╗ ██╗    ██╗███████╗██████╗ ███████╗
╚══██╔══╝██╔═══██╗██╔══██╗╚════██╗██║    ██║██╔════╝██╔══██╗╚══███╔╝
   ██║   ██║   ██║██████╔╝ █████╔╝██║ █╗ ██║█████╗  ██████╔╝  ███╔╝ 
   ██║   ██║   ██║██╔══██╗██╔═══╝ ██║███╗██║██╔══╝  ██╔══██╗ ███╔╝  
   ██║   ╚██████╔╝██║  ██║███████╗╚███╔███╔╝███████╗██████╔╝███████╗
   ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝
```                                                                    
Tor2webz is an independent modernization of [Tor2web](https://github.com/tor2web/Tor2web),
the HTTP gateway originally developed by Aaron Swartz and Virgil Griffith and
subsequently maintained by the GlobaLeaks/Hermes community. Original attribution
and the AGPLv3 license are preserved. This work is not an official upstream release.

**Version 3.3.0.dev0.** The gateway is deployed on a small public Debian host,
with Nginx on the edge and a loopback-only Tor client and application backend.
The test suite uses a loopback SOCKS5 server; a live Tor Project onion has also
been checked through the public gateway. Compatibility with arbitrary onion
sites and public traffic capacity remain unproven. The hardening update is deployed
with the HTTPS.CL operator interface. Source
publication to the public repository is scheduled after the owner accepts the
finished production deployment. Internal development remains private.

## Modernization

- Python 3.13 packaging, import-safe startup, and virtual-environment entry points.
- Current cryptography/pyOpenSSL and supported Twisted TLS APIs; TLS 1.2 minimum.
- V3 onion validation checks the base32 alphabet, version, and SHA3 checksum.
- SOCKS5 waits for successful negotiation and handles fragmented IPv4, IPv6,
  domain-name replies, cancellation, and refused connections.
- Requests use Twisted's standard HTTP parser and body spooling rather than a
  copied implementation of its private request lifecycle.
- Correct byte/text boundaries, regex backreferences, short-page rewriting,
  redirects, gzip, and host-only response cookies. Automatic clearnet redirects
  and upstream Refresh headers are blocked.
- Client forwarding and hop-by-hop headers are removed before upstream requests.
  Outbound destinations, including redirects, must be valid v3 onions.
- Defaults bound request bodies to 8 MiB, upstream and decoded responses to
  16 MiB, active requests to 16 per worker, and each response to 60 seconds.
  Oversized request bodies are discarded after the threshold;
  the 413 response is sent once request reception completes. These limits do
  not replace an ingress connection/rate limiter. The production worker uses
  a lower concurrency limit of four.
- Built-in SMTP notifications are disabled and rejected by configuration. Forwarded client
  IP headers are not trusted; use the direct peer address. `/checktor` reports
  only Tor status, without disclosing the visitor IP, and usage statistics are
  not published by default.

## Development

```sh
python3.13 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install --no-deps -e .
.venv/bin/python -m pip install 'pytest>=9,<10' build pip-audit
.venv/bin/python -m pytest -q
.venv/bin/python -m build
.venv/bin/python -m pip_audit -r requirements.txt --no-deps --disable-pip
```

`requirements.txt` points to the tested runtime lock. The Bionic/Buster requirement
files, Debian packaging, legacy installation scripts and Travis configuration are
historical upstream material, not supported installation paths for this version.

**Dependency caveat:** Twisted is pinned to the official `26.10.0rc2` release
candidate, published October 26, 2026. The stable `26.4.0` release has known
advisories fixed in the October candidates. Track the
[upstream release](https://github.com/twisted/twisted/releases/tag/twisted-26.10.0rc2)
and promote to a reviewed stable release when available. Do not silently downgrade
to the older stable version. A clean dependency audit is not a security audit of
this application.

## Operator interface

The operator interface makes no third-party resource requests.
Source links are controlled by `source_url` and are disabled in deployment.
Original attribution remains in the privacy notice and license.

The separate loopback contact service in `tor2web/contact.py` delivers only to
`contacto@https.cl` or `abuse@https.cl`, through a configured authenticated SMTP
relay with verified TLS. It rejects cross-origin requests, bounds payloads and
rate-limits delivery. SMTP credentials are runtime files and never source files.

## Local configuration

Copy `examples/development.conf` to an untracked config file and adjust the runtime
paths. Create separate `certs`, `logs` and `lists` directories below `datadir` and
create `rundir` before startup. Use an unprivileged account.

```sh
.venv/bin/tor2webz -n -c /absolute/path/tor2web.conf \
  -d /absolute/path/runtime -p /absolute/path/runtime/tor2web.pid
```

The development example listens only on loopback, expects an independently managed
Tor SOCKS endpoint on loopback, and does not install or start Tor. Do not expose
its plain HTTP listener publicly. For native public TLS use `transport = BOTH`
or `HTTPS`, a matching key and complete certificate chain. Configure an explicit
`basehost` and keep administrative/runtime interfaces private. A general gateway
uses one `<56-character-onion-id>.<basehost>` hostname per onion; it requires
wildcard DNS and a matching wildcard certificate.

## Before public operation

A Tor2web gateway sees client IPs and decrypted HTTP content. It does not provide
Tor Browser anonymity or isolation. Rewriting is best effort: modern JavaScript,
WebSockets, CSP, authentication, third-party links, or anti-gateway measures may
not work. Keep each onion on its own subdomain; cookies are made host-only.

Public deployments require real-Tor tests, a focused security review,
connection/rate and transfer limits, resource measurements, TLS/DNS configuration,
monitoring, and a rollback plan. Run the gateway without host administration
privileges and isolate it from management networks. The response timer includes
long downloads: streams that exceed the deadline are terminated. A malicious
onion page can still link or script navigation to clearnet sites; visitors must
not assume the gateway prevents browser traffic to other origins.

The modified application remains AGPLv3. Public network users must receive a
prominent offer to obtain the corresponding source for the running version.
Make the exact running source available and configure `source_url` before
public deployment. The default banner displays this link; if the banner is
disabled, provide an equivalent prominent source link in the public interface.
Never publish runtime configuration, credentials, private keys, logs or databases.

## License

[GNU AGPLv3](LICENSE). Original copyright: 2011–2022,
[Hermes Center for Transparency and Digital Human Rights](https://www.hermescenter.org).
