#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.subprotocol import SslMessageType, SslErrorType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloAnyAlgorithm, TlsAlert
from cryptolyzer.tls.client import SslHandshakeClientHelloAnyAlgorithm, SslError


class AnalyzerResultVersions(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, target, versions):
        super(AnalyzerResultVersions, self).__init__(target)

        self.versions = versions


class AnalyzerVersions(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'versions'

    @classmethod
    def get_help(cls):
        return 'Check which protocol versions supported by the server(s)'

    @staticmethod
    def _is_ssl2_supported(l7_client):
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
                return True

        return False

    @staticmethod
    def _get_supported_tls_versions(l7_client):
        supported_protocols = []
        for tls_version in (TlsVersion.SSL3, TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2):
            try:
                protocol_version = TlsProtocolVersionFinal(tls_version)
                client_hello = TlsHandshakeClientHelloAnyAlgorithm(l7_client.address)
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

        return supported_protocols

    def analyze(self, l7_client, protocol_version):
        supported_protocols = []

        if self._is_ssl2_supported(l7_client):
            supported_protocols.append(SslProtocolVersion())

        supported_protocols.extend(self._get_supported_tls_versions(l7_client))

        return AnalyzerResultVersions(
            AnalyzerTargetTls.from_l7_client(l7_client, protocol_version),
            supported_protocols
        )
