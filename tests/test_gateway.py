import gzip
import http.client
import ssl

import pytest

from conftest import ONION
from tor2web.t2w import safe_browser_redirect, rewrite_csp


@pytest.mark.parametrize(('location', 'allowed'), [
    (b'/inside', True),
    (b'next?x=1', True),
    (b'http://' + ONION.encode() + b'/next', True),
    (b'https://' + ONION[:-6].encode() + b'.gateway.test/next', True),
    (b'https://example.com/', False),
    (b'//example.com/', False),
    (b'\\\\example.com\\next', False),
    (b'javascript:alert(1)', False),
    (b'http://' + ONION.encode() + b':8080/', False),
    (b'http://user@' + ONION.encode() + b'/', False),
])
def test_browser_redirect_stays_on_gateway(location, allowed):
    assert safe_browser_redirect(location, 'gateway.test') is allowed


def test_short_html_and_cookie_rewriting(gateway):
    status, headers, body = gateway.request('/short')
    assert status == 200, gateway.logs()
    assert (f'http://{gateway.host}:{gateway.port}/next').encode() in body
    assert ONION.encode() not in body
    assert headers['Set-Cookie'] == 'session=abc; Path=/'
    target, port, method, path, _, _ = gateway.requests.get(timeout=2)
    assert (target, port, method, path) == (ONION, 80, 'GET', '/short')


def test_binary_passthrough(gateway):
    status, _, body = gateway.request('/binary')
    assert status == 200, gateway.logs()
    assert body == bytes(range(256))


def test_post_and_privacy_headers(gateway):
    status, _, body = gateway.request('/echo', 'POST', b'hello=world', {
        'X-Forwarded-For': '192.0.2.10', 'Forwarded': 'for=192.0.2.10',
        'X-Real-IP': '192.0.2.10', 'Proxy-Authorization': 'Basic not-a-secret',
        'Connection': 'keep-alive, X-Hop', 'X-Hop': 'remove-me',
        'Content-Type': 'application/x-www-form-urlencoded',
    })
    assert status == 200, gateway.logs()
    assert body == b'hello=world'
    _, _, _, _, headers, upstream_body = gateway.requests.get(timeout=2)
    assert headers['host'] == ONION
    assert upstream_body == body
    assert not {'x-forwarded-for', 'forwarded', 'x-real-ip', 'proxy-authorization', 'x-hop'} & headers.keys()


def test_response_gzip(gateway):
    status, headers, body = gateway.request('/short', headers={'Accept-Encoding': 'gzip'})
    assert status == 200, gateway.logs()
    assert headers['Content-Encoding'] == 'gzip'
    assert gateway.host.encode() in gzip.decompress(body)


def test_redirect_rewriting(gateway):
    status, headers, _ = gateway.request('/redirect')
    assert status == 302, gateway.logs()
    assert headers['Location'] == f'http://{gateway.host}:{gateway.port}/short'


@pytest.mark.parametrize('path', ['/external-http', '/external-https', '/external-relative'])
def test_clearnet_redirect_is_blocked(gateway, path):
    status, headers, body = gateway.request(path)
    assert status == 502, gateway.logs()
    assert 'Location' not in headers


def test_upstream_refresh_is_stripped(gateway):
    status, headers, body = gateway.request('/refresh')
    assert status == 200
    assert body == b'ok'
    assert 'Refresh' not in headers


def test_upstream_browser_request_hints_are_stripped(gateway):
    status, headers, body = gateway.request('/response-hints')
    assert status == 200
    assert body == b'ok'
    assert not {'Link', 'Content-Security-Policy-Report-Only', 'Reporting-Endpoints'} & headers.keys()
    assert "default-src 'self'" in headers['Content-Security-Policy']
    assert 'report-uri' not in headers['Content-Security-Policy']


def test_reject_unrelated_host(gateway):
    status, _, _ = gateway.request('/short', headers={'Host': ONION[:-6] + '.attacker.test'})
    assert status == 406
    assert gateway.requests.empty()


def test_reject_absolute_request_target(gateway):
    status, _, _ = gateway.request('http://example.com/')
    assert status == 400
    assert gateway.requests.empty()


def test_reject_invalid_onion_checksum(gateway):
    status, _, _ = gateway.request('/short', headers={'Host': 'a' * 56 + '.gateway.test'})
    assert status == 406
    assert gateway.requests.empty()


def test_body_limit(gateway):
    status, _, _ = gateway.request('/echo', 'POST', b'x' * 1025)
    assert status == 413
    assert gateway.requests.empty()


def test_checktor_does_not_reveal_client_ip(gateway):
    status, headers, body = gateway.request('/checktor', headers={'Host': 'gateway.test'})
    assert status == 200
    assert body == b'{"IsTor":false}'
    assert 'Access-Control-Allow-Origin' not in headers
    assert b'127.0.0.1' not in body


def test_usage_stats_are_private(gateway):
    assert gateway.request('/static/stats/yesterday')[0] == 404


@pytest.mark.parametrize('gateway', [{'max_response_bytes': 1024}], indirect=True)
def test_upstream_response_limit(gateway):
    assert gateway.request('/oversized')[0] == 502


@pytest.mark.parametrize('gateway', [{'max_response_bytes': 1024}], indirect=True)
def test_gzip_expansion_limit(gateway):
    assert gateway.request('/bomb')[0] == 502


def test_keepalive_lifecycle(gateway):
    connection = http.client.HTTPConnection('127.0.0.1', gateway.port, timeout=5)
    try:
        for path in ['/binary', '/short', '/binary']:
            connection.request('GET', path, headers={'Host': gateway.host})
            response = connection.getresponse()
            assert response.status == 200, gateway.logs()
            assert response.read()
    finally:
        connection.close()


@pytest.mark.parametrize('gateway', [{'transport': 'HTTPS'}], indirect=True)
def test_native_tls_and_https_rewrite(gateway):
    status, headers, body = gateway.request('/short')
    assert status == 200, gateway.logs()
    assert f'https://{gateway.host}:{gateway.port}/next'.encode() in body
    assert 'Strict-Transport-Security' in headers


@pytest.mark.parametrize('gateway', [{'transport': 'BOTH'}], indirect=True)
def test_http_redirects_to_https(gateway):
    status, headers, _ = gateway.request('/short')
    assert status == 302, gateway.logs()
    assert headers['Location'] == f'https://{gateway.host}:{gateway.https_port}/short'
    assert gateway.requests.empty()


@pytest.mark.parametrize('gateway', [{'bind': '::1'}], indirect=True)
def test_ipv6_inherited_socket(gateway):
    status, _, body = gateway.request('/binary')
    assert status == 200, gateway.logs()
    assert body == bytes(range(256))


@pytest.mark.parametrize('gateway', [{'request_timeout': 1}], indirect=True)
def test_upstream_timeout(gateway):
    status, _, _ = gateway.request('/slow')
    assert status == 504, gateway.logs()


@pytest.mark.parametrize('gateway', [{'max_concurrent_requests': 1}], indirect=True)
def test_concurrency_budget(gateway):
    from concurrent.futures import ThreadPoolExecutor
    with ThreadPoolExecutor(max_workers=1) as executor:
        pending = executor.submit(gateway.request, '/slow')
        gateway.requests.get(timeout=3)
        status, _, _ = gateway.request('/binary')
        assert status == 503, gateway.logs()
        assert pending.result(timeout=5)[0] == 200
    # Capacity is released when the earlier request finishes.
    assert gateway.request('/binary')[0] == 200


def test_chunked_post(gateway):
    connection = http.client.HTTPConnection('127.0.0.1', gateway.port, timeout=5)
    try:
        connection.request('POST', '/echo', body=iter([b'hello', b'world']),
                           headers={'Host': gateway.host}, encode_chunked=True)
        response = connection.getresponse()
        assert response.status == 200, gateway.logs()
        assert response.read() == b'helloworld'
    finally:
        connection.close()


@pytest.mark.parametrize('gateway', [{'disable_banner': False, 'source_url': 'https://example.com/source'}], indirect=True)
def test_banner_offers_modified_source(gateway):
    status, _, body = gateway.request('/short')
    assert status == 200, gateway.logs()
    assert b'href="https://example.com/source"' in body
    assert b'Source code (AGPLv3)' in body


@pytest.mark.parametrize('prefix', ['/static/', '/antanistaticmap/'])
def test_static_operator_font_has_a_font_mime_type(gateway, prefix):
    status, headers, body = gateway.request(prefix + 'jetbrains-mono-latin.woff2')
    assert status == 200
    assert headers['Content-Type'] == 'font/woff2'
    assert body[:4] == b'wOF2'


@pytest.mark.parametrize('gateway', [{'disable_banner': False}], indirect=True)
@pytest.mark.parametrize('path', ['/uppercase', '/uppercase-long', '/multiline-body'])
def test_banner_handles_html_body_case_and_multiline_attributes(gateway, path):
    status, _, body = gateway.request(path)
    assert status == 200, gateway.logs()
    assert body.count(b'id="t2wz-banner"') == 1
    assert b'id="t2wz-toggle"' in body


@pytest.mark.parametrize('source', [
    b'https://' + ONION.encode() + b'/search',
    b'http://' + ONION.encode() + b':80/search',
    ONION.encode() + b'/search',
    b'https://' + ONION.upper().encode() + b':443/search',
])
def test_csp_maps_onion_sources_to_gateway_origin(source):
    policy = b"default-src 'none'; form-action " + source + b"; script-src 'nonce-AbC' https://example.com; report-uri https://tracker.invalid/report"
    result = rewrite_csp(policy, 'gateway.test', b'https://', '')
    assert b'form-action https://' + ONION[:-6].encode() + b'.gateway.test/search' in result
    assert b"default-src 'none'" in result
    assert b"script-src 'nonce-AbC' https://example.com" in result
    assert b'report-uri' not in result


@pytest.mark.parametrize('source', [
    b'https://' + b'a'*56 + b'.onion/',
    b'https://' + ONION.encode() + b':8443/',
    b'https://' + ONION.encode() + b'.attacker.invalid/',
    b"'sha256-AbCdEf'", b"'self'", b"'none'",
])
def test_csp_does_not_broaden_other_sources(source):
    policy = b'form-action ' + source
    assert rewrite_csp(policy, 'gateway.test', b'https://', '') == policy


def test_upstream_csp_form_action_is_rewritten_without_dropping_restrictions(gateway):
    status, headers, _ = gateway.request('/response-hints')
    assert status == 200
    policy = headers['Content-Security-Policy']
    assert f'form-action http://{gateway.host}:{gateway.port}/search' in policy
    assert f'connect-src http://{gateway.host}:{gateway.port}' in policy
    assert "script-src 'nonce-AbC' https://example.com" in policy
    assert "object-src 'none'" in policy
    assert ONION + '/' not in policy
    assert 'report-uri' not in policy


@pytest.mark.parametrize(('path','expected'), [
    ('/chunked-response', b'chunked payload'),
    ('/close-delimited-response', b'close-delimited payload'),
])
def test_upstream_unknown_length_response_is_streamed(gateway, path, expected):
    status, _, body = gateway.request(path)
    assert status == 200, gateway.logs()
    assert body == expected


@pytest.mark.parametrize('gateway', [{'max_response_bytes':1024}], indirect=True)
def test_unknown_length_response_still_has_a_byte_limit(gateway):
    assert gateway.request('/chunked-oversized')[0] == 502


def test_upstream_static_directory_is_not_swallowed(gateway):
    status, _, _ = gateway.request('/static/upstream-only.css')
    assert status == 200, gateway.logs()
    _, _, _, path, _, _ = gateway.requests.get(timeout=2)
    assert path == '/static/upstream-only.css'
