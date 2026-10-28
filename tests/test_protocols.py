import base64
import hashlib
import re

import pytest
from twisted.internet import defer, protocol
from twisted.internet.error import ConnectionLost
from twisted.internet.testing import StringTransport
from twisted.python.failure import Failure

from conftest import ONION
from tor2web.utils.misc import is_onion, re_sub
from tor2web.utils.socks import SOCKS5ClientFactory, SOCKSError
from tor2web.utils.lists import List, TorExitNodeList


def test_valid_onion_and_checksum():
    assert is_onion(ONION)
    assert is_onion(ONION.upper())
    assert not is_onion(('b' if ONION[0] == 'a' else 'a') + ONION[1:])


@pytest.mark.parametrize('host', [None, b'onion', 'a' * 16 + '.onion', 'a' * 56 + '.onion',
                                  'a' * 56 + 'Xonion', 'x.' + ONION, ONION + '\n',
                                  '0' * 56 + '.onion', ONION + '.example'])
def test_invalid_onions(host):
    assert not is_onion(host)


def test_onion_version():
    key = bytes(range(32))
    version = b'\x04'
    checksum = hashlib.sha3_256(b'.onion checksum' + key + version).digest()[:2]
    invalid = base64.b32encode(key + checksum + version).decode().lower() + '.onion'
    assert not is_onion(invalid)


def test_regex_optional_groups():
    pattern = re.compile(rb'(https?:)?//([a-z]+)')
    assert re_sub(pattern, br'\1-\2', b'//host') == b'-host'
    assert re_sub(pattern, br'\1-\2', b'http://host') == b'http:-host'


class RecordingProtocol(protocol.Protocol):
    def __init__(self):
        self.received = b''
        self.connected_count = 0

    def connectionMade(self):
        self.connected_count += 1

    def dataReceived(self, data):
        self.received += data


@pytest.fixture
def socks():
    inner = RecordingProtocol()
    factory = protocol.Factory.forProtocol(lambda: inner)
    wrapper = SOCKS5ClientFactory(ONION.encode(), 80, factory)
    failures = []
    wrapper.deferred.addErrback(failures.append)
    connection = wrapper.buildProtocol(None)
    transport = StringTransport()
    connection.makeConnection(transport)
    return wrapper, connection, transport, inner, failures


@pytest.mark.parametrize('reply', [
    b'\x05\x00\x00\x01' + bytes(6),
    b'\x05\x00\x00\x04' + bytes(18),
    b'\x05\x00\x00\x03\x04host\x00\x50',
])
def test_socks_fragmentation_and_no_early_http(socks, reply):
    wrapper, connection, transport, inner, failures = socks
    assert transport.value() == b'\x05\x01\x00'
    assert inner.connected_count == 0
    connection.dataReceived(b'\x05')
    assert inner.connected_count == 0
    connection.dataReceived(b'\x00')
    assert ONION.encode() in transport.value()
    for byte in reply[:-1]:
        connection.dataReceived(bytes([byte]))
        assert inner.connected_count == 0
    connection.dataReceived(reply[-1:] + b'HTTP/1.1')
    assert inner.connected_count == 1
    assert inner.received == b'HTTP/1.1'
    connection.dataReceived(b' 200 OK')
    assert inner.received == b'HTTP/1.1 200 OK'
    assert wrapper.deferred.called
    assert not failures


def test_socks_refused(socks):
    _, connection, transport, inner, failures = socks
    connection.dataReceived(b'\x05\x00\x05\x05\x00\x01')
    assert failures[0].check(SOCKSError)
    assert failures[0].value.code == 5
    assert not inner.connected_count
    assert transport.disconnecting


def test_socks_disconnected_during_handshake(socks):
    _, connection, _, inner, failures = socks
    connection.connectionLost(Failure(ConnectionLost()))
    assert failures[0].check(ConnectionLost)
    assert not inner.connected_count


def test_socks_cancellation(socks):
    wrapper, _, transport, _, failures = socks
    wrapper.deferred.cancel()
    assert failures[0].check(defer.CancelledError)
    assert transport.disconnecting


def test_remote_lists_decode_and_persist(tmp_path):
    entries = List(str(tmp_path / 'list.txt'))
    entries.processData(b'first\nsecond\n')
    assert entries == {'first', 'second'}
    assert List(str(tmp_path / 'list.txt')) == entries
    exits = TorExitNodeList(str(tmp_path / 'exits.txt'), mode='REPLACE')
    exits.processData(b'ExitAddress 192.0.2.1 2026-01-01 12:00:00\n')
    assert exits == {'192.0.2.1'}
    assert TorExitNodeList(str(tmp_path / 'exits.txt')) == exits


def test_socks_agent_refuses_clearnet_redirect_destinations():
    from twisted.web.error import SchemeNotSupported
    from tor2web.t2w import SOCKS5Agent
    from twisted.internet.task import Clock
    agent = SOCKS5Agent(Clock())
    with pytest.raises(SchemeNotSupported):
        agent._getEndpoint(b'https', b'example.com', 443)
