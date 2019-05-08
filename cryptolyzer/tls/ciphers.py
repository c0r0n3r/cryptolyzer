#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsHandshakeType, TlsAlertDescription, SslMessageType
from cryptoparser.tls.version import SslProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import (
    SslHandshakeClientHelloAnyAlgorithm,
    TlsAlert,
    TlsHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloAuthenticationECDSA,
    TlsHandshakeClientHelloAuthenticationRSA,
    TlsHandshakeClientHelloAuthenticationRarelyUsed,
)


class AnalyzerResultCipherSuites(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, target, cipher_suites, cipher_suite_preference, long_cipher_suite_list_intolerance):
        super(AnalyzerResultCipherSuites, self).__init__(target)

        self.cipher_suites = cipher_suites
        self.cipher_suite_preference = cipher_suite_preference
        self.long_cipher_suite_list_intolerance = long_cipher_suite_list_intolerance


class AnalyzerCipherSuites(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'ciphers'

    @classmethod
    def get_help(cls):
        return 'Check which cipher suites supported by the server(s)'

    @staticmethod
    def _next_accepted_cipher_suites(l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites):
        if isinstance(protocol_version, SslProtocolVersion):
            client_hello = SslHandshakeClientHelloAnyAlgorithm()
            client_hello.cipher_suites = TlsCipherSuiteVector(remaining_cipher_suites)
            server_messages = l7_client.do_ssl_handshake(client_hello)

            accepted_cipher_suites.extend(server_messages[SslMessageType.SERVER_HELLO].cipher_kinds)
            raise StopIteration

        client_hello = TlsHandshakeClientHelloAnyAlgorithm(l7_client.address)
        client_hello.cipher_suites = TlsCipherSuiteVector(remaining_cipher_suites)
        client_hello.protocol_version = protocol_version

        server_messages = l7_client.do_tls_handshake(client_hello)
        server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
        for index, cipher_suite in enumerate(remaining_cipher_suites):
            if cipher_suite == server_hello.cipher_suite:
                del remaining_cipher_suites[index]
                accepted_cipher_suites.append(cipher_suite)
                break

        if not remaining_cipher_suites:
            raise StopIteration

    @staticmethod
    def _get_accepted_cipher_suites(l7_client, protocol_version, checkable_cipher_suites):
        accepted_cipher_suites = []
        remaining_cipher_suites = checkable_cipher_suites

        while True:
            try:
                AnalyzerCipherSuites._next_accepted_cipher_suites(
                    l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites
                )
            except StopIteration:
                break
            except TlsAlert as e:
                if (len(checkable_cipher_suites) == len(remaining_cipher_suites) and
                        e.description == TlsAlertDescription.PROTOCOL_VERSION):
                    return [], remaining_cipher_suites
                if e.description == TlsAlertDescription.HANDSHAKE_FAILURE:
                    break
                else:
                    raise e
            except NetworkError as e:
                if e.error == NetworkErrorType.NO_RESPONSE:
                    break
                else:
                    raise e

        return accepted_cipher_suites, remaining_cipher_suites

    @staticmethod
    def _get_accepted_cipher_suites_fallback(l7_client, protocol_version):
        accepted_cipher_suites = []
        client_hello_messsages_in_order_of_probability = (
            TlsHandshakeClientHelloAuthenticationRSA(l7_client.address),
            TlsHandshakeClientHelloAuthenticationECDSA(l7_client.address),
            TlsHandshakeClientHelloAuthenticationRarelyUsed(l7_client.address),
        )
        for client_hello in client_hello_messsages_in_order_of_probability:
            accepted_cipher_suites.extend(
                AnalyzerCipherSuites._get_accepted_cipher_suites(
                    l7_client, protocol_version, client_hello.cipher_suites
                )[0]
            )
        if accepted_cipher_suites:
            accepted_cipher_suites, _ = AnalyzerCipherSuites._get_accepted_cipher_suites(
                l7_client, protocol_version, accepted_cipher_suites
            )

        return accepted_cipher_suites

    def analyze(self, l7_client, protocol_version):
        if isinstance(protocol_version, SslProtocolVersion):
            checkable_cipher_suites = list(SslCipherKind)
        else:
            checkable_cipher_suites = list(TlsCipherSuite)

        long_cipher_suite_list_intolerance = False
        accepted_cipher_suites, remaining_cipher_suites = self._get_accepted_cipher_suites(
            l7_client, protocol_version, checkable_cipher_suites
        )
        if len(checkable_cipher_suites) == len(remaining_cipher_suites):
            accepted_cipher_suites = self._get_accepted_cipher_suites_fallback(l7_client, protocol_version)
            long_cipher_suite_list_intolerance = bool(accepted_cipher_suites)
        if len(accepted_cipher_suites) > 1:
            checkable_cipher_suites = [accepted_cipher_suites[-1], accepted_cipher_suites[0]]
            cipher_suite_preference = self._get_accepted_cipher_suites(
                l7_client,
                protocol_version,
                checkable_cipher_suites
            ) != checkable_cipher_suites
        else:
            cipher_suite_preference = None

        return AnalyzerResultCipherSuites(
            AnalyzerTargetTls.from_l7_client(l7_client, protocol_version),
            accepted_cipher_suites,
            cipher_suite_preference,
            long_cipher_suite_list_intolerance
        )
