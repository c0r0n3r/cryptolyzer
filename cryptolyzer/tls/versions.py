#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.common.exception import NetworkError, NetworkErrorType

from cryptoparser.tls.client import TlsHandshakeClientHelloAnyAlgorithm, TlsAlert
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.common.analyzer import AnalyzerBase, AnalyzerResultBase


class AnalyzerResultVersions(AnalyzerResultBase):
    def __init__(self, versions):
        self.versions = versions

    def as_json(self):
        return json.dumps([version.name for version in self.versions])


class AnalyzerVersions(AnalyzerBase):
    @classmethod
    def get_name(cls):
        return 'versions'

    @classmethod
    def get_help(cls):
        return 'Check which protocol versions supported by the server(s)'

    def analyze(self, l7_client):
        supported_protocols = []

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
                    supported_protocols.append(protocol_version)

        return AnalyzerResultVersions(supported_protocols)
