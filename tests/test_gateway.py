import gzip
import http.client
import ssl

import pytest

from conftest import ONION


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
