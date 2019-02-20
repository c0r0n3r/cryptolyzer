#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.common.algorithm import Authentication
from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsHandshakeType, TlsAlertDescription, SslMessageType
from cryptoparser.tls.version import SslProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloAnyAlgorithm, TlsAlert, SslHandshakeClientHelloAnyAlgorithm


class AnalyzerResultCipherSuites(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, protocol_version, cipher_suites, cipher_suite_preference, cipher_suite_length_intolerance):
        super(AnalyzerResultCipherSuites, self).__init__()

        self.protocol_version = protocol_version
        self.cipher_suites = cipher_suites
        self.cipher_suite_preference = cipher_suite_preference
        self.cipher_suite_length_intolerance = cipher_suite_length_intolerance


class AnalyzerCipherSuites(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'ciphers'

    @classmethod
    def get_help(cls):
        return 'Check which cipher suites supported by the server(s)'

    @staticmethod
    def _get_accepted_cipher_suites(l7_client, protocol_version, checkable_cipher_suites):
        accepted_cipher_suites = []
        remaining_cipher_suites = list(checkable_cipher_suites)

        while True:
            try:
                if isinstance(protocol_version, SslProtocolVersion):
                    client_hello = SslHandshakeClientHelloAnyAlgorithm()
                    client_hello.cipher_suites = TlsCipherSuiteVector(remaining_cipher_suites)
                    server_messages = l7_client.do_ssl_handshake(client_hello)

                    accepted_cipher_suites = server_messages[SslMessageType.SERVER_HELLO].cipher_kinds
                    break
                else:
                    client_hello = TlsHandshakeClientHelloAnyAlgorithm(l7_client.host)
                    client_hello.cipher_suites = TlsCipherSuiteVector(remaining_cipher_suites)
                    client_hello.protocol_version = protocol_version

                    server_messages = l7_client.do_tls_handshake(client_hello, client_hello.protocol_version)
                    server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
                    for index, cipher_suite in enumerate(remaining_cipher_suites):
                        if cipher_suite == server_hello.cipher_suite:
                            del remaining_cipher_suites[index]
                            accepted_cipher_suites.append(cipher_suite)
                            break
            except TlsAlert as e:
                if (len(checkable_cipher_suites) == len(remaining_cipher_suites) and
                        e.description == TlsAlertDescription.PROTOCOL_VERSION):
                    return []
                if e.description == TlsAlertDescription.HANDSHAKE_FAILURE:
                    break
                else:
                    raise e
            except NetworkError as e:
                if e.error == NetworkErrorType.NO_RESPONSE:
                    break
                else:
                    raise e

            if not remaining_cipher_suites:
                break

        return accepted_cipher_suites

    def analyze(self, l7_client, protocol_version):
        if isinstance(protocol_version, SslProtocolVersion):
            checkable_cipher_suites = list(SslCipherKind)
        else:
            checkable_cipher_suites = list(TlsCipherSuite)

            rarely_used_cipher_suites = [
                cipher_suite
                for cipher_suite in checkable_cipher_suites
                if (cipher_suite.value.authentication and
                    cipher_suite.value.authentication not in [Authentication.RSA, Authentication.ECDSA])
            ]
            if not self._get_accepted_cipher_suites(l7_client, protocol_version, checkable_cipher_suites):
                rarely_used_cipher_suites = set(rarely_used_cipher_suites)
                checkable_cipher_suites = [
                    cipher_suite
                    for cipher_suite in checkable_cipher_suites
                    if cipher_suite not in rarely_used_cipher_suites
                ]

        accepted_cipher_suites = self._get_accepted_cipher_suites(l7_client, protocol_version, checkable_cipher_suites)
        if len(accepted_cipher_suites) > 1:
            checkable_cipher_suites = [accepted_cipher_suites[-1], accepted_cipher_suites[0]]
            cipher_suite_preference = self._get_accepted_cipher_suites(
                l7_client,
                protocol_version,
                checkable_cipher_suites
            ) != checkable_cipher_suites
        else:
            cipher_suite_preference = None

       
        cipher_suite_length_intolerance = None
        if not isinstance(protocol_version, SslProtocolVersion):
            cipher_suite_length_intolerance = accepted_cipher_suites and \
                not self._get_accepted_cipher_suites(l7_client, protocol_version, list(TlsCipherSuite))

        return AnalyzerResultCipherSuites(protocol_version, accepted_cipher_suites, cipher_suite_preference, cipher_suite_length_intolerance)
