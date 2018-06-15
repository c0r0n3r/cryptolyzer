#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

from cryptoparser.common.exception import NetworkError, NetworkErrorType

from cryptoparser.tls.client import TlsHandshakeClientHelloMandatoryCiphers, TlsAlert
from cryptoparser.tls.client import SslHandshakeClientHelloAnyAlgorithm, SslError
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.subprotocol import SslMessageType, SslErrorType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerTls, AnalyzerResultTls


class AnalyzerResultVersions(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, versions):
        super(AnalyzerResultVersions, self).__init__()

        self.versions = versions

    def as_json(self):
        return json.dumps([version.name for version in self.versions])


class AnalyzerVersions(AnalyzerTls):
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

        client_hello = TlsHandshakeClientHelloMandatoryCiphers()
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

        return AnalyzerResultVersions(supported_protocols)
