#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.subprotocol import SslMessageType, SslErrorType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloMandatoryCiphers, TlsAlert
from cryptolyzer.tls.client import TlsHandshakeClientHelloAnyAlgorithm
from cryptolyzer.tls.client import TlsHandshakeClientHelloAuthenticationRSA
from cryptolyzer.tls.client import TlsHandshakeClientHelloAuthenticationECDSA
from cryptolyzer.tls.client import TlsHandshakeClientHelloAuthenticationDeprecated
from cryptolyzer.tls.client import SslHandshakeClientHelloAnyAlgorithm, SslError


class AnalyzerResultVersions(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, versions, alerts_unsupported_tls_version):
        super(AnalyzerResultVersions, self).__init__()

        self.versions = versions
        self.alerts_unsupported_tls_version = alerts_unsupported_tls_version


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

        alerts_unsupported_tls_version = None
        for tls_version in (TlsVersion.SSL3, TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2):
            protocol_version = TlsProtocolVersionFinal(tls_version)

            client_hello_messsages_in_order_of_probability = (
                TlsHandshakeClientHelloAuthenticationRSA(l7_client.host),
                TlsHandshakeClientHelloAuthenticationECDSA(l7_client.host),
                TlsHandshakeClientHelloAuthenticationDeprecated(l7_client.host),
            )
            for client_hello in client_hello_messsages_in_order_of_probability:
                client_hello.protocol_version = protocol_version
                try:
                    server_messages = l7_client.do_tls_handshake(client_hello, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0))
                except TlsAlert as e:
                    if e.description not in [
                        TlsAlertDescription.PROTOCOL_VERSION,
                        TlsAlertDescription.HANDSHAKE_FAILURE
                    ]:
                        raise e

                    if e.description == TlsAlertDescription.PROTOCOL_VERSION:
                        alerts_unsupported_tls_version = True
                        break
                    elif tls_version == TlsVersion.SSL3:
                        break
                except NetworkError as e:
                    if e.error != NetworkErrorType.NO_RESPONSE:
                        raise e
                    if tls_version == TlsVersion.SSL3:
                        break
                else:
                    supported_protocols.append(server_messages[TlsHandshakeType.SERVER_HELLO].protocol_version)
                    break
            else:
                alerts_unsupported_tls_version = False

        return AnalyzerResultVersions(supported_protocols, alerts_unsupported_tls_version)
