# -*- coding: utf-8 -*-

import copy
import time
import six

import attr

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsHandshakeType, TlsAlertDescription, SslMessageType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.tls.client import (
    SslHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloSpecalization,
    TlsHandshakeClientHelloAuthenticationECDSA,
    TlsHandshakeClientHelloAuthenticationGOST,
    TlsHandshakeClientHelloAuthenticationRSA,
    TlsHandshakeClientHelloAuthenticationDeprecated,
)
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultCipherSuites(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to the negotiable cipher suites.

    :param cipher_suites: the supported cipher suites.
    :param extension_supported: whether named group extension is supported.
    """

    cipher_suites = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of((TlsCipherSuite, SslCipherKind)))
    )
    cipher_suite_preference = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(bool)))
    long_cipher_suite_list_intolerance = attr.ib(validator=attr.validators.instance_of(bool))


class AnalyzerCipherSuites(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'ciphers'

    @classmethod
    def get_help(cls):
        return 'Check which cipher suites supported by the server(s)'

    @staticmethod
    def _handle_tls_alert(alert, retried_internal_error, checkable_cipher_suites, remaining_cipher_suites):
        if len(checkable_cipher_suites) == len(remaining_cipher_suites):
            if alert.description in [TlsAlertDescription.PROTOCOL_VERSION, TlsAlertDescription.UNRECOGNIZED_NAME]:
                return [], []
            if alert.description in (TlsAlertDescription.DECODE_ERROR, TlsAlertDescription.INTERNAL_ERROR):
                return [], remaining_cipher_suites
        if alert.description == TlsAlertDescription.INTERNAL_ERROR:  # maybe too many handshake request
            if retried_internal_error:
                return [], []

            time.sleep(5)
            raise OverflowError

        if alert.description in AnalyzerCipherSuites._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS:
            raise StopIteration

        raise alert

    @classmethod
    def _next_accepted_cipher_suites(cls, l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites):
        if protocol_version.version == TlsVersion.SSL2:
            client_hello = SslHandshakeClientHelloAnyAlgorithm()
            client_hello.cipher_suites = TlsCipherSuiteVector(remaining_cipher_suites)
            server_messages = l7_client.do_ssl_handshake(client_hello)

            accepted_cipher_suites.extend(server_messages[SslMessageType.SERVER_HELLO].cipher_kinds)
            del remaining_cipher_suites[:]
            raise StopIteration

        client_hello = TlsHandshakeClientHelloSpecalization(
            l7_client.address,
            [protocol_version, ],
            remaining_cipher_suites,
            named_curves=None,
            signature_algorithms=None,
            extensions=[]
        )
        server_messages = l7_client.do_tls_handshake(
            client_hello,
            record_version=TlsProtocolVersion(TlsVersion.TLS1_2)
        )
        server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
        for index, cipher_suite in enumerate(remaining_cipher_suites):
            if cipher_suite == server_hello.cipher_suite:
                del remaining_cipher_suites[index]
                accepted_cipher_suites.append(cipher_suite)
                break

    @classmethod
    def _get_accepted_cipher_suites(cls, l7_client, protocol_version, checkable_cipher_suites):
        retried_internal_error = False
        accepted_cipher_suites = []
        remaining_cipher_suites = copy.copy(checkable_cipher_suites)

        while remaining_cipher_suites:
            try:
                if retried_internal_error:
                    time.sleep(1)

                cls._next_accepted_cipher_suites(
                    l7_client, protocol_version, remaining_cipher_suites, accepted_cipher_suites
                )
                LogSingleton().log(level=60, msg=six.u('Server offers cipher suite %s (%s)') % (
                    accepted_cipher_suites[-1].name, protocol_version,
                ))
            except StopIteration:
                break
            except TlsAlert as e:
                try:
                    return cls._handle_tls_alert(
                        e, retried_internal_error, checkable_cipher_suites, remaining_cipher_suites
                    )
                except StopIteration:
                    break
                except OverflowError:
                    retried_internal_error = True
                    continue
            except NetworkError as e:
                if e.error == NetworkErrorType.NO_RESPONSE:
                    break

                raise e
            except SecurityError:
                if accepted_cipher_suites:
                    break

                return [], remaining_cipher_suites

        return accepted_cipher_suites, remaining_cipher_suites

    @classmethod
    def _get_accepted_cipher_suites_all(cls, l7_client, protocol_version, checkable_cipher_suites):
        return cls._get_accepted_cipher_suites(
            l7_client, protocol_version, checkable_cipher_suites
        )

    @classmethod
    def _get_accepted_cipher_suites_fallback(cls, l7_client, protocol_version):
        accepted_cipher_suites = []
        client_hello_messsages_in_order_of_probability = [
            TlsHandshakeClientHelloAuthenticationRSA(protocol_version, l7_client.address),
            TlsHandshakeClientHelloAuthenticationECDSA(protocol_version, l7_client.address),
        ]
        if protocol_version <= TlsProtocolVersion(TlsVersion.TLS1_2):
            client_hello_messsages_in_order_of_probability.append(
                TlsHandshakeClientHelloAuthenticationDeprecated(protocol_version, l7_client.address)
            )
        client_hello_messsages_in_order_of_probability.append(
            TlsHandshakeClientHelloAuthenticationGOST(protocol_version, l7_client.address)
        )
        for client_hello in client_hello_messsages_in_order_of_probability:
            accepted_cipher_suites.extend(
                cls._get_accepted_cipher_suites(
                    l7_client, protocol_version, list(client_hello.cipher_suites)
                )[0]
            )

        return accepted_cipher_suites

    @classmethod
    def _get_checkable_cipher_suites(cls, protocol_version):
        if protocol_version.version == TlsVersion.SSL2:
            checkable_cipher_suites = list(SslCipherKind)
        else:
            if protocol_version <= TlsProtocolVersion(TlsVersion.TLS1_2):
                min_version = protocol_version
                checkable_cipher_suites = [
                    cipher_suite
                    for cipher_suite in TlsCipherSuite
                    if TlsProtocolVersion(cipher_suite.value.initial_version) <= min_version
                ]
            else:
                min_version = TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_0)
                checkable_cipher_suites = [
                    cipher_suite
                    for cipher_suite in TlsCipherSuite
                    if TlsProtocolVersion(cipher_suite.value.initial_version) >= min_version
                ]

        return checkable_cipher_suites

    def analyze(self, analyzable, protocol_version):
        checkable_cipher_suites = self._get_checkable_cipher_suites(protocol_version)
        long_cipher_suite_list_intolerance = False
        accepted_cipher_suites, remaining_cipher_suites = self._get_accepted_cipher_suites_all(
            analyzable, protocol_version, checkable_cipher_suites
        )
        if len(checkable_cipher_suites) == len(remaining_cipher_suites):
            accepted_cipher_suites = self._get_accepted_cipher_suites_fallback(analyzable, protocol_version)
            long_cipher_suite_list_intolerance = bool(accepted_cipher_suites)
        if len(accepted_cipher_suites) > 1:
            LogSingleton().disabled = True
            checkable_cipher_suites = [accepted_cipher_suites[-1], accepted_cipher_suites[0]]
            cipher_suite_preference = self._get_accepted_cipher_suites(
                analyzable,
                protocol_version,
                checkable_cipher_suites
            )[0] != checkable_cipher_suites
            LogSingleton().disabled = False
        else:
            cipher_suite_preference = None

        return AnalyzerResultCipherSuites(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            accepted_cipher_suites,
            cipher_suite_preference,
            long_cipher_suite_list_intolerance
        )
