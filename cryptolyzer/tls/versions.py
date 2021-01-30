# -*- coding: utf-8 -*-

import attr

from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.subprotocol import SslMessageType, SslErrorType
from cryptoparser.tls.version import (
    SslProtocolVersion,
    TlsProtocolVersionBase,
    TlsProtocolVersionFinal,
    TlsVersion,
)

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import (
    SslError,
    SslHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloAuthenticationECDSA,
    TlsHandshakeClientHelloAuthenticationRSA,
    TlsHandshakeClientHelloAuthenticationRarelyUsed,
)
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultVersions(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    versions = attr.ib(
        validator=attr.validators.deep_iterable(
            attr.validators.instance_of((SslProtocolVersion, TlsProtocolVersionBase))
        ),
        metadata={'human_readable_name': 'Protocol Versions'},
    )
    alerts_unsupported_tls_version = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(bool)),
        metadata={'human_readable_name': 'Alerts Unsupported TLS Version'},
    )


class AnalyzerVersions(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'versions'

    @classmethod
    def get_help(cls):
        return 'Check which protocol versions supported by the server(s)'

    @staticmethod
    def _is_ssl2_supported(analyzable):
        try:
            client_hello = SslHandshakeClientHelloAnyAlgorithm()
            server_messages = analyzable.do_ssl_handshake(client_hello)
        except SslError as e:
            if e.error != SslErrorType.NO_CIPHER_ERROR:
                raise e
        except NetworkError:
            pass
        except SecurityError:
            pass
        else:
            if server_messages[SslMessageType.SERVER_HELLO].cipher_kinds:
                return True

        return False

    @staticmethod
    def _analyze_supported_tls_versions(analyzable):
        alerts_unsupported_tls_version = None
        supported_protocols = []
        for tls_version in (TlsVersion.SSL3, TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2):
            protocol_version = TlsProtocolVersionFinal(tls_version)
            client_hello_messsages_in_order_of_probability = (
                TlsHandshakeClientHelloAuthenticationRSA(protocol_version, analyzable.address),
                TlsHandshakeClientHelloAuthenticationECDSA(protocol_version, analyzable.address),
                TlsHandshakeClientHelloAuthenticationRarelyUsed(protocol_version, analyzable.address),
            )
            for client_hello in client_hello_messsages_in_order_of_probability:
                try:
                    server_messages = analyzable.do_tls_handshake(
                        hello_message=client_hello,
                    )
                    server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
                    supported_protocols.append(server_hello.protocol_version)
                    break
                except TlsAlert as e:
                    if e.description == TlsAlertDescription.UNRECOGNIZED_NAME:
                        return [], alerts_unsupported_tls_version
                    if e.description == TlsAlertDescription.PROTOCOL_VERSION:
                        alerts_unsupported_tls_version = True
                        break
                    if e.description in AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS + [
                            TlsAlertDescription.INTERNAL_ERROR
                    ]:
                        alerts_unsupported_tls_version = False
                        continue
                    if tls_version == TlsVersion.SSL3:
                        break

                    raise e
                except NetworkError as e:
                    if e.error != NetworkErrorType.NO_RESPONSE:
                        raise e
                    if tls_version == TlsVersion.SSL3:
                        break
                except SecurityError:
                    break

        if (alerts_unsupported_tls_version is None and
                supported_protocols and TlsProtocolVersionFinal(TlsVersion.TLS1_0) < supported_protocols[0]):
            alerts_unsupported_tls_version = False

        return supported_protocols, alerts_unsupported_tls_version

    def analyze(self, analyzable, protocol_version):
        supported_protocols = []

        if self._is_ssl2_supported(analyzable):
            supported_protocols.append(SslProtocolVersion())

        supported_tls_protocols, alerts_unsupported_tls_version = self._analyze_supported_tls_versions(analyzable)
        supported_protocols.extend(supported_tls_protocols)

        return AnalyzerResultVersions(
            AnalyzerTargetTls.from_l7_client(analyzable, None),
            supported_protocols,
            alerts_unsupported_tls_version
        )
