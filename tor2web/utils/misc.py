"""

:mod:`Tor2Web`
=====================================================

.. automodule:: Tor2Web
   :synopsis: [GLOBALEAKS_MODULE_DESCRIPTION]

.. moduleauthor:: Arturo Filasto' <art@globaleaks.org>
.. moduleauthor:: Giovanni Pellerano <evilaliv3@globaleaks.org>

"""

# -*- coding: utf-8 -*-

import base64
import hashlib
import hmac
import re
import socket

from twisted.protocols import tls


def listenTCPonExistingFD(reactor, fd, factory):
    with socket.fromfd(fd, socket.AF_INET, socket.SOCK_STREAM) as inherited:
        family = socket.AF_INET6 if len(inherited.getsockname()) == 4 else socket.AF_INET
    return reactor.adoptStreamPort(fd, family, factory)


def listenSSLonExistingFD(reactor, fd, factory, contextFactory):

    tlsFactory = tls.TLSMemoryBIOFactory(contextFactory, False, factory)
    port = listenTCPonExistingFD(reactor, fd, tlsFactory)
    port._type = 'TLS'
    return port


def re_sub(pattern, replacement, string):
    # Python 3 replaces unmatched groups with an empty string itself.
    return re.sub(pattern, replacement, string)


def is_onion(hostname):
    """Validate a v3 onion's alphabet, version and SHA3 checksum."""
    if not isinstance(hostname, str):
        return False
    hostname = hostname.lower()
    if re.fullmatch(r'[a-z2-7]{56}\.onion', hostname) is None:
        return False
    decoded = base64.b32decode(hostname[:-6].upper())
    public_key, checksum, version = decoded[:32], decoded[32:34], decoded[34:]
    expected = hashlib.sha3_256(b'.onion checksum' + public_key + version).digest()[:2]
    return version == b'\x03' and hmac.compare_digest(checksum, expected)
