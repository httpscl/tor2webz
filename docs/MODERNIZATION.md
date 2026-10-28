# Modernization record

Base: upstream `tor2web/Tor2web`, branch `main`, commit
`734416e960e4e0fb2bdb5ba3fa22fd80ee2982a6` (2022-07-15).

The first development update preserves the upstream history and architecture
(parent daemon, per-worker HTTP proxy, Unix-socket RPC, Tor SOCKS endpoint).
Its target is Python 3.13 on Linux. No host deployment is part of this update.

The original already supported onion v3. This update strengthens its validation;
it does not claim to introduce v3 support.

Compatibility changes include replacing removed `cgi` parsing, private regex
expansion, direct pyOpenSSL internals and manual HTTP lifecycle management.
Request bodies now finish reception before forwarding and are spooled by Twisted;
the configured body limit prevents unlimited accepted upload storage. This changes
the old optimistic streaming behavior. SOCKS negotiation also finishes before the
HTTP request is emitted.

Gateway cookies are host-only, forwarding client identity headers are stripped,
and clearnet redirect destinations are rejected. Default email recipients and
demo credentials are removed; built-in SMTP notifications are disabled.
Persistent access logging is off by default; debug logging is opt-in.

## Verification boundary

The tests use actual loopback TCP connections, child worker processes and a fake
SOCKS5 server. They cover v3 format/checksum/version validation, fragmented SOCKS
responses and failure/cancellation, request forwarding, binary and gzip content,
HTML/redirect/cookie handling, upload limits, keep-alive, native TLS, HTTP-to-HTTPS,
IPv6, concurrency limits, timeouts and chunked uploads. They do not connect to the
Tor network or prove compatibility with arbitrary live sites. CI is prepared but
cannot be called verified until it runs in the eventual public repository.

Runtime dependencies are locked in `requirements/runtime.txt`. As of 2026-10-28,
the official Twisted release candidate `26.10.0rc2` is used for its advisory fixes;
its prerelease status is an explicit pre-deployment consideration.

Legacy Debian installers and old requirement sets remain for historical context.
They have not been ported or tested; use the documented virtualenv installation.
Before deployment, use a focused security review and a real Tor client, measure
resources under bounded load, and verify isolation and the served source offer.

## Local result: 2026-10-28

- Python 3.13.5; Twisted 26.10.0rc2; pyOpenSSL 26.4.0; cryptography 50.0.2.
- 41 tests passed. All 17 gateway integration cases also ran against the built
  wheel installed into a clean virtual environment, outside the source checkout,
  exercising installed asset discovery and worker startup.
- Source distribution and wheel built successfully; `pip check` passed in the
  clean installation. Source archives include the runtime lock, test harness,
  development example and this modernization record.
- `pip-audit` reported no known vulnerabilities for the pinned runtime set.
- Tests emit upstream pyOpenSSL X509/PKey deprecation warnings through Twisted's
  certificate helpers; the explicit TLS 1.1 rejection test also emits the expected
  stdlib protocol deprecation warnings. These are warnings, not test failures.
- Changed/new text files passed a credential/private-topology pattern scan and
  manual diff review. Generated certificates, environments, runtime state and
  build outputs are excluded from Git.

## Deployed production-hardening update

The deployed update bounds raw, decoded and forwarded onion responses to 16 MiB,
including gzip expansion. It rejects automatic browser redirects outside valid
v3 onion destinations and this gateway, and strips upstream Refresh, Link,
Alt-Svc and browser reporting headers. CSP reporting directives are removed
while other upstream CSP directives remain. Valid onion origins in CSP source
expressions are translated to gateway origins, including `form-action` and
`connect-src`; nonce/hash values and unrelated allowlists remain intact. `/checktor` no longer returns a
visitor IP or permissive CORS headers. Usage statistics are disabled unless
explicitly enabled; the default listener is loopback HTTPS.

The production Nginx edge has separately gained a 64-connection global limit,
shorter body/header timeouts, a no-referrer policy, and filtering for upstream
headers that can initiate browser requests. These changes were verified on the
live edge while the application stayed on the prior published commit.

The application update is deployed from the internal source snapshot. The owner
controls the final public GitHub publication after production acceptance. The
HTTPS.CL operator UI uses local assets and does not load remote fonts or scripts.
A separate bounded contact service supports authenticated SMTP delivery; runtime
credentials are excluded from source.

Compatibility regressions cover unknown-length/chunked responses and HTTPS
301/302 redirects after POST, using browser-style conversion to GET. Streaming
limits continue to apply when Content-Length is unknown. Upstream error logs
record exception classes without URLs or query values.

After the one-hop internal HTTPS upgrade budget, remaining redirects are
validated and forwarded to the browser rather than converted into a 502. An
upstream service's Tor/bot refusal remains an upstream refusal.
