# -*- coding: utf-8 -*-

import six

import attr

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.extension import TlsExtensionType, TlsExtensionKeyShareClient
from cryptoparser.tls.subprotocol import TlsExtensionsClient, TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.subprotocol import SslMessageType, SslErrorType
from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.tls.client import (
    SslError,
    SslHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloSpecalization,
    TlsHandshakeClientHelloAuthenticationECDSA,
    TlsHandshakeClientHelloAuthenticationRSA,
    TlsHandshakeClientHelloAuthenticationRarelyUsed,
)
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultVersions(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    versions = attr.ib(
        validator=attr.validators.deep_iterable(
            attr.validators.instance_of(TlsProtocolVersion)
        ),
        metadata={'human_readable_name': 'Protocol Versions'},
    )
    alerts_unsupported_tls_version = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(bool)),
        metadata={'human_readable_name': 'Alerts Unsupported TLS Version'},
    )


class AnalyzerVersions(AnalyzerTlsBase):
    _DRAFT_VERSIONS_IN_REVERSE_ORDER = tuple(reversed([
        tls_protocol_version
        for tls_protocol_version in [TlsProtocolVersion(tls_version) for tls_version in TlsVersion]
        if tls_protocol_version.is_draft
    ]))

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
                LogSingleton().log(
                    level=60,
                    msg=six.u('Server offers protocol version %s') % (TlsProtocolVersion(TlsVersion.SSL2), )
                )
                return True

        return False

    @staticmethod
    def _handle_tls_early_versions_alerts(alert_description, tls_version):
        if alert_description == TlsAlertDescription.UNRECOGNIZED_NAME:
            raise StopIteration(None)
        acceptable_alerts = AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS + [
                TlsAlertDescription.DECODE_ERROR,
                TlsAlertDescription.INTERNAL_ERROR,
        ]
        if alert_description in acceptable_alerts:
            raise StopIteration(False)
        if alert_description == TlsAlertDescription.PROTOCOL_VERSION:
            raise StopIteration(True)
        if tls_version == TlsVersion.SSL3:
            raise StopIteration(None)

    @staticmethod
    def _analyze_supported_tls_early_versions(analyzable):
        alerts_unsupported_tls_version = None
        supported_protocols = []
        for tls_version in (TlsVersion.SSL3, TlsVersion.TLS1, TlsVersion.TLS1_1, TlsVersion.TLS1_2):
            protocol_version = TlsProtocolVersion(tls_version)
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
                except TlsAlert as e:
                    try:
                        AnalyzerVersions._handle_tls_early_versions_alerts(
                            e.description, tls_version
                        )
                    except StopIteration as exc:
                        alerts_unsupported_tls_version = exc.args[0]
                        continue

                    raise e
                except NetworkError as e:
                    alerts_unsupported_tls_version = False

                    if e.error != NetworkErrorType.NO_RESPONSE:
                        raise e
                    if tls_version == TlsVersion.SSL3:
                        break
                except SecurityError:
                    break
                else:
                    if protocol_version == server_hello.protocol_version:
                        LogSingleton().log(level=60, msg=six.u('Server offers protocol version %s') % (
                            server_hello.protocol_version,
                        ))
                        supported_protocols.append(server_hello.protocol_version)

                    break

        return supported_protocols, alerts_unsupported_tls_version

    @staticmethod
    def _handle_tls_1_3_alerts(alert_description, checkable_protocols):
        AnalyzerVersions._handle_tls_early_versions_alerts(alert_description, checkable_protocols[0])

    @staticmethod
    def _update_tls_1_3_protocol_lists(server_messages, checkable_protocols, supported_protocols):
        selected_version = server_messages[TlsHandshakeType.SERVER_HELLO].extensions.get_item_by_type(
            TlsExtensionType.SUPPORTED_VERSIONS
        ).selected_version
        supported_protocols.append(selected_version)
        LogSingleton().log(level=60, msg=six.u('Server offers protocol version %s supported') % (selected_version, ))
        while checkable_protocols and checkable_protocols[0] >= selected_version:
            del checkable_protocols[0]

    @staticmethod
    def _analyze_supported_tls_1_3_versions(analyzable):
        alerts_unsupported_tls_version = None
        supported_protocols = []
        checkable_protocols = [TlsProtocolVersion(TlsVersion.TLS1_3), ]
        checkable_protocols.extend(AnalyzerVersions._DRAFT_VERSIONS_IN_REVERSE_ORDER)
        while checkable_protocols:
            client_hello = TlsHandshakeClientHelloSpecalization(
                analyzable.address,
                checkable_protocols,
                TlsCipherSuite,
                named_curves=None,
                signature_algorithms=None,
                extensions=[],
            )
            extensions = [
                extension
                for extension in client_hello.extensions
                if extension.extension_type != TlsExtensionType.KEY_SHARE
            ]
            client_hello.extensions = TlsExtensionsClient(extensions + [TlsExtensionKeyShareClient([])])

            try:
                server_messages = analyzable.do_tls_handshake(
                    hello_message=client_hello,
                )
            except TlsAlert as e:
                try:
                    AnalyzerVersions._handle_tls_1_3_alerts(e.description, checkable_protocols)
                except StopIteration as exc:
                    alerts_unsupported_tls_version = exc.args[0]
                    break
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    #  handled in case of early TLS versions
                    pass  # pragma: no cover

                break
            except SecurityError:
                break
            else:
                AnalyzerVersions._update_tls_1_3_protocol_lists(
                    server_messages,
                    checkable_protocols,
                    supported_protocols,
                )

            del client_hello.extensions[-1]

        return reversed(supported_protocols), alerts_unsupported_tls_version

    def analyze(self, analyzable, protocol_version):
        supported_protocols = []

        if self._is_ssl2_supported(analyzable):
            supported_protocols.append(TlsProtocolVersion(TlsVersion.SSL2))

        supported_tls_protocols, alerts_unsupported_tls_version = \
            self._analyze_supported_tls_early_versions(analyzable)
        supported_protocols.extend(supported_tls_protocols)

        supported_tls_protocols, alerts_unsupported_tls_1_3_version = \
            self._analyze_supported_tls_1_3_versions(analyzable)
        supported_protocols.extend(supported_tls_protocols)

        return AnalyzerResultVersions(
            AnalyzerTargetTls.from_l7_client(analyzable, None),
            supported_protocols,
            alerts_unsupported_tls_version and alerts_unsupported_tls_1_3_version,
        )
