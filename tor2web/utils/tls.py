"""TLS contexts built with supported Twisted APIs."""

import re
from pathlib import Path

from twisted.internet import ssl


class T2WSSLContextFactory:
    """Serve a matching key and complete certificate chain with TLS >= 1.2."""

    def __init__(self, privateKeyFilePath, certificateFilePath, intermediateFilePath, cipherList):
        cert_path = Path(certificateFilePath)
        if not cert_path.is_file():
            cert_path = Path(intermediateFilePath)
        blocks = re.findall(
            rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
            cert_path.read_bytes(), re.DOTALL,
        )
        if not blocks:
            raise ValueError("No PEM certificate in certificate file")
        if intermediateFilePath and Path(intermediateFilePath).is_file():
            for block in re.findall(
                rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                Path(intermediateFilePath).read_bytes(), re.DOTALL,
            ):
                if block not in blocks:
                    blocks.append(block)
        identity = ssl.PrivateCertificate.loadPEM(
            blocks[0] + b"\n" + Path(privateKeyFilePath).read_bytes()
        )
        options = dict(
            privateKey=identity.privateKey.original,
            certificate=identity.original,
            extraCertChain=[ssl.Certificate.loadPEM(block).original for block in blocks[1:]],
            raiseMinimumTo=ssl.TLSVersion.TLSv1_2,
        )
        if cipherList:
            options["acceptableCiphers"] = ssl.AcceptableCiphers.fromOpenSSLCipherString(cipherList)
        self._options = ssl.CertificateOptions(**options)
        self._context = self._options.getContext()

    def getContext(self):
        return self._context
