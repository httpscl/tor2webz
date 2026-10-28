"""Perform real TLS handshakes through memory BIOs, including chain validation."""
from datetime import datetime, timedelta, timezone
import ssl

import pytest
from OpenSSL import SSL
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from tor2web.utils.tls import T2WSSLContextFactory


@pytest.fixture
def identity(tmp_path):
    def key():
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def name(value):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, value)])

    def certificate(subject, issuer, pubkey, signing_key, ca, alt=False):
        builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer)
                   .public_key(pubkey).serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.now(timezone.utc) - timedelta(minutes=1))
                   .not_valid_after(datetime.now(timezone.utc) + timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
                   .add_extension(x509.SubjectKeyIdentifier.from_public_key(pubkey), critical=False)
                   .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False)
                   .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                               key_encipherment=not ca, data_encipherment=False,
                                               key_agreement=False, key_cert_sign=ca, crl_sign=ca,
                                               encipher_only=None, decipher_only=None), critical=True))
        if alt:
            builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName('gateway.test')]), critical=False)
        return builder.sign(signing_key, hashes.SHA256())

    rootkey, interkey, leafkey = key(), key(), key()
    root = certificate(name('Root'), name('Root'), rootkey.public_key(), rootkey, True)
    intermediate = certificate(name('Intermediate'), name('Root'), interkey.public_key(), rootkey, True)
    leaf = certificate(name('gateway.test'), name('Intermediate'), leafkey.public_key(), interkey, False, True)
    keypath, certpath, chainpath = (tmp_path / p for p in ('key.pem', 'leaf.pem', 'chain.pem'))
    keypath.write_bytes(leafkey.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                            serialization.NoEncryption()))
    certpath.write_bytes(leaf.public_bytes(serialization.Encoding.PEM))
    chainpath.write_bytes(intermediate.public_bytes(serialization.Encoding.PEM))
    factory = T2WSSLContextFactory(str(keypath), str(certpath), str(chainpath), 'ECDHE+AESGCM:ECDHE+CHACHA20')
    return factory, root.public_bytes(serialization.Encoding.PEM).decode()


def handshake(factory, root_pem, hostname='gateway.test', version=None):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.create_default_context(cadata=root_pem)
    if version is not None:
        context.minimum_version = context.maximum_version = version
        if version < ssl.TLSVersion.TLSv1_2:
            context.set_ciphers('ALL:@SECLEVEL=0')
    client = context.wrap_bio(incoming, outgoing, server_side=False, server_hostname=hostname)
    server = SSL.Connection(factory.getContext(), None)
    server.set_accept_state()
    client_done = server_done = False
    for _ in range(20):
        try:
            client.do_handshake()
            client_done = True
        except ssl.SSLWantReadError:
            pass
        data = outgoing.read()
        if data:
            server.bio_write(data)
        try:
            server.do_handshake()
            server_done = True
        except SSL.WantReadError:
            pass
        try:
            data = server.bio_read(65536)
        except SSL.WantReadError:
            data = b''
        if data:
            incoming.write(data)
        if client_done and server_done:
            return client.version()
    raise AssertionError('TLS handshake did not finish')


@pytest.mark.parametrize('version', [ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3])
def test_certificate_chain_and_modern_tls(identity, version):
    factory, root_pem = identity
    assert handshake(factory, root_pem, version=version) == ('TLSv1.2' if version == ssl.TLSVersion.TLSv1_2 else 'TLSv1.3')


def test_hostname_verification(identity):
    factory, root_pem = identity
    with pytest.raises(ssl.SSLCertVerificationError):
        handshake(factory, root_pem, hostname='wrong.test')


def test_legacy_tls_rejected(identity):
    factory, root_pem = identity
    with pytest.raises((SSL.Error, ssl.SSLError)):
        handshake(factory, root_pem, version=ssl.TLSVersion.TLSv1_1)
