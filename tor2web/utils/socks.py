# -*- coding: utf-8 -*-
# Minimal SOCKS5 implementation
# The implementation supports:
# - Plaintexts connections
# - HTTPS connections
# - Waits for CONNECT success before forwarding application data
# - No authentication is implented as it is not required
#   in the context of GlobaLeaks
#
# code concept from https://github.com/habnabit/txsocksx

import struct

from twisted.internet import defer, interfaces
from twisted.internet.protocol import Protocol
from twisted.protocols import tls
from twisted.protocols.policies import ProtocolWrapper, WrappingFactory
from zope.interface import implementer, directlyProvides, providedBy


class SOCKSError(Exception):
    def __init__(self, value):
        Exception.__init__(self)
        self.code = value


class SOCKS5ClientProtocol(ProtocolWrapper):
    """SOCKS5 CONNECT with fragmented IPv4, IPv6 and domain replies."""

    def __init__(self, factory, wrappedProtocol, connectedDeferred, host, port):
        super().__init__(factory, wrappedProtocol)
        self._connectedDeferred = connectedDeferred
        self._host = host.encode("ascii") if isinstance(host, str) else host
        self._port = port
        self._buf = b""
        self.state = "greeting"

    def makeConnection(self, transport):
        directlyProvides(self, providedBy(transport))
        Protocol.makeConnection(self, transport)
        self.factory.registerProtocol(self)
        self.transport.write(b"\x05\x01\x00")

    def error(self, code=1):
        self.state = "failed"
        if not self._connectedDeferred.called:
            self._connectedDeferred.errback(SOCKSError(code))
        self.transport.abortConnection()

    def dataReceived(self, data):
        if self.state == "ready":
            self.wrappedProtocol.dataReceived(data)
            return
        if self.state == "failed":
            return
        self._buf += data
        if self.state == "greeting":
            if len(self._buf) < 2:
                return
            if self._buf[:2] != b"\x05\x00":
                self.error()
                return
            self._buf = self._buf[2:]
            self.state = "connect"
            self.transport.write(
                struct.pack("!BBBBB", 5, 1, 0, 3, len(self._host))
                + self._host + struct.pack("!H", self._port)
            )
        if len(self._buf) < 4:
            return
        if self._buf[0] != 5 or self._buf[2] != 0:
            self.error()
            return
        if self._buf[1] != 0:
            self.error(self._buf[1])
            return
        atyp = self._buf[3]
        if atyp == 1:
            reply_size = 10
        elif atyp == 4:
            reply_size = 22
        elif atyp == 3:
            if len(self._buf) < 5:
                return
            reply_size = 7 + self._buf[4]
        else:
            self.error(8)
            return
        if len(self._buf) < reply_size:
            return
        payload, self._buf = self._buf[reply_size:], b""
        self.state = "ready"
        self.wrappedProtocol.makeConnection(self)
        if not self._connectedDeferred.called:
            self._connectedDeferred.callback(self.wrappedProtocol)
        if payload:
            self.wrappedProtocol.dataReceived(payload)

    def connectionLost(self, reason):
        self.factory.unregisterProtocol(self)
        if self.state == "ready":
            self.wrappedProtocol.connectionLost(reason)
        elif not self._connectedDeferred.called:
            self._connectedDeferred.errback(reason)
        self.state = "failed"


class SOCKS5ClientFactory(WrappingFactory):
    protocol = SOCKS5ClientProtocol

    def __init__(self, host, port, wrappedFactory):
        self.host = host
        self.port = port
        self.socks_protocol = None
        self.deferred = defer.Deferred(self._cancel)
        super().__init__(wrappedFactory)

    def buildProtocol(self, addr):
        try:
            wrapped = self.wrappedFactory.buildProtocol(addr)
            if wrapped is None:
                raise SOCKSError(1)
            self.socks_protocol = self.protocol(self, wrapped, self.deferred, self.host, self.port)
            return self.socks_protocol
        except Exception:
            if not self.deferred.called:
                self.deferred.errback()
            return None

    def clientConnectionFailed(self, connector, reason):
        if not self.deferred.called:
            self.deferred.errback(reason)

    def _cancel(self, d):
        if self.socks_protocol is not None and self.socks_protocol.transport is not None:
            self.socks_protocol.transport.abortConnection()


@implementer(interfaces.IStreamClientEndpoint)
class SOCKS5ClientEndpoint(object):
    def __init__(self, host, port, proxyEndpoint):
        self.host = host
        self.port = port
        self.proxyEndpoint = proxyEndpoint

    def connect(self, protocolFactory):
        proxyFac = SOCKS5ClientFactory(self.host, self.port, protocolFactory)
        return self.proxyEndpoint.connect(proxyFac).addCallback(lambda proto: proxyFac.deferred)


@implementer(interfaces.IStreamClientEndpoint)
class TLSWrapClientEndpoint(object):
    _wrapper = tls.TLSMemoryBIOFactory

    def __init__(self, contextFactory, wrappedEndpoint):
        self.contextFactory = contextFactory
        self.wrappedEndpoint = wrappedEndpoint

    def connect(self, fac):
        fac = self._wrapper(self.contextFactory, True, fac)
        return self.wrappedEndpoint.connect(fac).addCallback(self._unwrapProtocol)

    def _unwrapProtocol(self, proto):
        return proto.wrappedProtocol
