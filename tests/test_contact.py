import http.client
import json
import threading

import pytest
from tor2web.contact import ContactServer, ORIGIN


@pytest.fixture
def contact(tmp_path):
    password = tmp_path/'password'
    password.write_text('test-only')
    sent = []
    config = {'password_file': str(password)}
    server = ContactServer(('127.0.0.1', 0), config, sender=lambda *args: sent.append(args))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    def request(data, origin=ORIGIN, headers=None):
        client = http.client.HTTPConnection(*server.server_address)
        payload = json.dumps(data)
        client.request('POST', '/__tor2webz/contact', payload,
                       {'Content-Type': 'application/json', 'Origin': origin, **(headers or {})})
        response = client.getresponse()
        result = response.status, json.loads(response.read())
        client.close()
        return result
    yield request, sent, password
    server.shutdown()
    server.server_close()
    thread.join()


@pytest.mark.parametrize('kind', ['contact', 'abuse'])
def test_contact_routes_only_known_categories(contact, kind):
    request, sent, _ = contact
    assert request({'kind':kind, 'email':'sender@example.invalid', 'message':'A legitimate test message.', 'url':'https://example.onion/path?q=1'}) == (200, {'sent':True})
    assert len(sent) == 1 and sent[0][1] == kind


@pytest.mark.parametrize('change', [
    {'kind':'attacker@example.invalid'}, {'email':'a@example.invalid\r\nBcc: x@example.invalid'},
    {'email':'invalid'}, {'message':'x'*4001}, {'website':'spam'}, {'message':'short'},
])
def test_invalid_messages_never_reach_smtp(contact, change):
    request,sent,_ = contact
    data={'kind':'contact','email':'sender@example.invalid','message':'A legitimate test message.',**change}
    assert request(data)[0] == 400
    assert not sent


def test_cross_origin_never_reaches_smtp(contact):
    request,sent,_=contact
    assert request({'kind':'contact','email':'sender@example.invalid','message':'A legitimate test message.'},origin='https://malicious.onion.https.cl')[0] == 403
    assert not sent


def test_missing_credentials_does_not_claim_delivery(contact):
    request,sent,password=contact
    password.write_text('')
    assert request({'kind':'contact','email':'sender@example.invalid','message':'A legitimate test message.'}) == (503,{'sent':False})
    assert not sent


def test_global_delivery_limit(contact):
    request,sent,_=contact
    message={'kind':'contact','email':'sender@example.invalid','message':'A legitimate test message.'}
    assert [request(message)[0] for _ in range(6)] == [200]*5+[429]
    assert len(sent)==5


@pytest.mark.parametrize('url', [None, '', 'example.onion', 'javascript:alert(1)',
    'https://', 'https://user:password@example.onion/', 'https://example.onion/\r\nInjected',
    'https://example.onion:99999/', 'https://[broken/', 'https://example.onion/' + 'a'*2048])
def test_abuse_requires_valid_url_before_smtp(contact, url):
    request, sent, _ = contact
    assert request({'kind':'abuse', 'email':'sender@example.invalid',
                    'message':'A legitimate abuse report.', 'url':url})[0] == 400
    assert not sent


def test_abuse_url_reaches_mail_sender(contact):
    request, sent, _ = contact
    url='https://example.onion/reported/path?item=1'
    assert request({'kind':'abuse', 'email':'sender@example.invalid',
                    'message':'A legitimate abuse report.', 'url':url})[0] == 200
    assert sent[0][4] == url


def test_abuse_mail_contains_reported_url(monkeypatch):
    from tor2web import contact as module
    from contextlib import contextmanager
    sent=[]
    class Connection:
        def send_message(self, mail, **kwargs):
            sent.append(mail)
            return {}
    @contextmanager
    def connect(config):
        yield Connection()
    monkeypatch.setattr(module, 'smtp_connect', connect)
    module.deliver({'username':'no-reply@https.cl'}, 'abuse', 'sender@example.invalid',
                   'Report description.', 'https://example.onion/report')
    assert 'URL denunciada: https://example.onion/report' in sent[0].get_content()
    assert sent[0]['To'] == 'abuse@https.cl'
