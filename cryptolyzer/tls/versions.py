#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

from cryptoparser.common.exception import NetworkError, NetworkErrorType

from cryptoparser.tls.client import TlsHandshakeClientHelloAnyAlgorithm, TlsAlert, SslHandshakeClientHelloAnyAlgorithm, SslError
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription, SslMessageType, SslErrorType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslVersion
from cryptoparser.tls.version import TlsProtocolVersionDraft
from cryptoparser.tls.extension import TlsExtensionType, TlsExtensionSupportedVersions, TlsExtensionKeyShare, TlsKeyShareEntry, TlsExtensionKeyShareReserved, TlsNamedCurve

from cryptolyzer.common.analyzer import AnalyzerBase, AnalyzerResultBase


class AnalyzerResultVersions(AnalyzerResultBase):
    def __init__(self, versions):
        self.versions = versions

    def as_json(self):
        return json.dumps([str(version) for version in self.versions])


class AnalyzerVersions(AnalyzerBase):
    @classmethod
    def get_name(cls):
        return 'versions'

    @classmethod
    def get_help(cls):
        return 'Check which protocol versions supported by the server(s)'

    def analyze(self, l7_client):
        supported_protocols = []

        try:
            client_hello = SslHandshakeClientHelloAnyAlgorithm()
            server_messages = l7_client.do_ssl_handshake(client_hello)
        except SslError as e:
            if e.error != SslErrorType.NO_CIPHER_ERROR:
                raise e
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e
        else:
            if server_messages[SslMessageType.SERVER_HELLO].cipher_kinds:
                supported_protocols.append(SslVersion.SSL2)

        client_hello = TlsHandshakeClientHelloAnyAlgorithm(l7_client.host)
        for tls_version in TlsVersion:
            try:
                protocol_version = TlsProtocolVersionFinal(tls_version)
                client_hello.protocol_version = protocol_version
                server_messages = l7_client.do_tls_handshake(client_hello, protocol_version)
            except TlsAlert as e:
                if e.description not in [TlsAlertDescription.PROTOCOL_VERSION, TlsAlertDescription.HANDSHAKE_FAILURE]:
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            else:
                if server_messages[TlsHandshakeType.SERVER_HELLO].protocol_version == protocol_version:
                    supported_protocols.append(protocol_version.minor)

        """
        from cryptography.hazmat.backends import default_backend
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        # Generate a private key for use in the exchange.
        private_key = X25519PrivateKey.generate()
        # In a real handshake the peer_public_key will be received from the
        # other party. For this example we'll generate another private key and
        # get a public key from that. Note that in a DH handshake both peers
        # must agree on a common set of parameters.
        peer_public_key = X25519PrivateKey.generate().public_key()
        shared_key = private_key.exchange(peer_public_key)
        # Perform key derivation.
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data',
            backend=default_backend()
        ).derive(shared_key)
        """

        client_hello = TlsHandshakeClientHelloAnyAlgorithm(l7_client.host)

        derived_key = map(int, b'"\x91\xdf\xe2\xd9y\xef]\xa3>K\xf6\x14h\xf1"\xc481\xed\xf47\x1e7\x9ee\xf2\xc3\x85\xb8\xfe\x84')
        key_share_entry = TlsKeyShareEntry(TlsNamedCurve.X25519, map(int, derived_key))
        client_hello.extensions.append(TlsExtensionKeyShareReserved([key_share_entry, ]))
        client_hello.extensions.append(TlsExtensionKeyShare([key_share_entry, ]))
        for draft_version in range(28, 17, -1):
            client_hello.extensions.append(TlsExtensionSupportedVersions([TlsProtocolVersionDraft(draft_version), ]))

            try:
                protocol_version = TlsProtocolVersionFinal(TlsVersion.TLS1_3)
                client_hello.protocol_version = protocol_version
                server_messages = l7_client.do_tls_handshake(client_hello, TlsProtocolVersionFinal(TlsVersion.TLS1_2), TlsHandshakeType.SERVER_HELLO)
            except TlsAlert as e:
                if e.description not in [TlsAlertDescription.PROTOCOL_VERSION]:
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            else:
                for extension in server_messages[TlsHandshakeType.SERVER_HELLO].extensions:
                    if extension.extension_type == TlsExtensionType.SUPPORTED_VERSIONS:
                        supported_protocols.append(extension.supported_versions[0])
                        break
                else:
                    server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
                    if server_hello.protocol_version > TlsProtocolVersionFinal(TlsVersion.TLS1_2):
                        supported_protocols.append(server_hello.protocol_version)
            finally:
                del client_hello.extensions[-1]

        return AnalyzerResultVersions(supported_protocols)
