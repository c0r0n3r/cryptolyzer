#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.subprotocol import SslMessageType, SslErrorType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, TlsProtocolVersionDraft, SslProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloAnyAlgorithm, TlsAlert
from cryptolyzer.tls.client import SslHandshakeClientHelloAnyAlgorithm, SslError
from cryptoparser.tls.extension import TlsExtensionType, TlsExtensionSupportedVersions, TlsNamedCurve


class AnalyzerResultVersions(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, versions):
        super(AnalyzerResultVersions, self).__init__()

        self.versions = versions

    def as_json(self):
        return json.dumps({'versions': [repr(version) for version in self.versions]})


class AnalyzerVersions(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'versions'

    @classmethod
    def get_help(cls):
        return 'Check which protocol versions supported by the server(s)'

    def analyze(self, l7_client, protocol_version):
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
                supported_protocols.append(SslProtocolVersion())

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
                server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
                if server_hello.protocol_version == protocol_version:
                    supported_protocols.append(server_hello.protocol_version)

        supported_protocols.extend(self._analyze_tls1_3_versions(l7_client))

        return AnalyzerResultVersions(supported_protocols)

    def _analyze_tls1_3_versions(self, l7_client):
        supported_protocols = []
        checkable_protocols = [TlsProtocolVersionFinal(TlsVersion.TLS1_3), ]
        checkable_protocols.extend([TlsProtocolVersionDraft(draft_version) for draft_version in range(28, 0, -1)])
        while checkable_protocols:
            client_hello = TlsHandshakeClientHelloAnyAlgorithm(l7_client.host, checkable_protocols)

            try:
                server_messages = l7_client.do_tls_handshake(client_hello, TlsProtocolVersionFinal(TlsVersion.TLS1_2), TlsHandshakeType.SERVER_HELLO)
            except TlsAlert as e:
                if e.description != TlsAlertDescription.PROTOCOL_VERSION:
                    raise e

                break
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e

                break
            else:
                for extension in server_messages[TlsHandshakeType.SERVER_HELLO].extensions:
                    if extension.extension_type == TlsExtensionType.SUPPORTED_VERSIONS:
                        supported_protocols.append(extension.supported_versions[0])
                        while checkable_protocols and checkable_protocols[0] >= extension.supported_versions[0]: 
                            del checkable_protocols[0]
                        break
                else:
                    server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
                    if server_hello.protocol_version > TlsProtocolVersionFinal(TlsVersion.TLS1_2):
                        supported_protocols.append(server_hello.protocol_version)

            del client_hello.extensions[-1]

        return reversed(supported_protocols)
