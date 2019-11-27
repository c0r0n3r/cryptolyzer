# -*- coding: utf-8 -*-

import copy
import time

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsHandshakeType, TlsAlertDescription, SslMessageType
from cryptoparser.tls.version import SslProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, ResponseError
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

        client_hello = TlsHandshakeClientHelloAnyAlgorithm(protocol_version, l7_client.address)
        client_hello.cipher_suites = TlsCipherSuiteVector(remaining_cipher_suites)

        server_messages = l7_client.do_tls_handshake(client_hello)
        server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
        for index, cipher_suite in enumerate(remaining_cipher_suites):
            if cipher_suite == server_hello.cipher_suite:
                del remaining_cipher_suites[index]
                accepted_cipher_suites.append(cipher_suite)
                break

    @staticmethod
    def _get_accepted_cipher_suites(l7_client, protocol_version, checkable_cipher_suites):
        retried_internal_error = False
        accepted_cipher_suites = []
        remaining_cipher_suites = copy.copy(checkable_cipher_suites)

        while remaining_cipher_suites:
            try:
                if retried_internal_error:
                    time.sleep(1)

                AnalyzerCipherSuites._next_accepted_cipher_suites(
                    l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites
                )
            except StopIteration:
                break
            except TlsAlert as e:
                if (len(checkable_cipher_suites) == len(remaining_cipher_suites) and
                        e.description in [TlsAlertDescription.PROTOCOL_VERSION, TlsAlertDescription.UNRECOGNIZED_NAME]):
                    return [], remaining_cipher_suites
                if e.description == TlsAlertDescription.INTERNAL_ERROR:  # maybe too many handshake request
                    if retried_internal_error:
                        raise e

                    retried_internal_error = True
                    time.sleep(5)
                    continue

                if e.description in [
                        TlsAlertDescription.HANDSHAKE_FAILURE,  # no match in remaining cipher suites
                        TlsAlertDescription.INSUFFICIENT_SECURITY,  # not enough secure cipher suites remained
                        TlsAlertDescription.ILLEGAL_PARAMETER  # unimplemented cipher suites remained
                ]:
                    break

                raise e
            except NetworkError as e:
                if e.error == NetworkErrorType.NO_RESPONSE:
                    break

                raise e
            except ResponseError:
                if accepted_cipher_suites:
                    break

                return [], remaining_cipher_suites

        return accepted_cipher_suites, remaining_cipher_suites

    @staticmethod
    def _get_accepted_cipher_suites_all(l7_client, protocol_version, checkable_cipher_suites):
        return AnalyzerCipherSuites._get_accepted_cipher_suites(
            l7_client, protocol_version, checkable_cipher_suites
        )

    @staticmethod
    def _get_accepted_cipher_suites_fallback(l7_client, protocol_version):
        accepted_cipher_suites = []
        client_hello_messsages_in_order_of_probability = (
            TlsHandshakeClientHelloAuthenticationRSA(protocol_version, l7_client.address),
            TlsHandshakeClientHelloAuthenticationECDSA(protocol_version, l7_client.address),
            TlsHandshakeClientHelloAuthenticationRarelyUsed(protocol_version, l7_client.address),
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
        accepted_cipher_suites, remaining_cipher_suites = self._get_accepted_cipher_suites_all(
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
            )[0] != checkable_cipher_suites
        else:
            cipher_suite_preference = None

        return AnalyzerResultCipherSuites(
            AnalyzerTargetTls.from_l7_client(l7_client, protocol_version),
            accepted_cipher_suites,
            cipher_suite_preference,
            long_cipher_suite_list_intolerance
        )
