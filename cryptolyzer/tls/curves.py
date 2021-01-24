# -*- coding: utf-8 -*-

from collections import OrderedDict

import attr

from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsHandshakeType
from cryptoparser.tls.extension import (
    TlsEllipticCurveVector,
    TlsExtensionEllipticCurves,
    TlsExtensionType,
    TlsNamedCurve,
)

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.dhparam import parse_ecdh_params
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloKeyExchangeECDHx
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultCurves(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    curves = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.in_(TlsNamedCurve)),
        metadata={'human_readable_name': 'Named Curves'},
    )
    extension_supported = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(bool)),
        metadata={'human_readable_name': 'Named Curve Extension Supported'},
    )


class AnalyzerCurves(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'curves'

    @classmethod
    def get_help(cls):
        return 'Check which elliptic curves supported by the server(s)'

    @staticmethod
    def _get_key_exchange_message(l7_client, client_hello, curves):
        try:
            client_hello.extensions.append(TlsExtensionEllipticCurves(TlsEllipticCurveVector(curves)))
            server_messages = l7_client.do_tls_handshake(
                hello_message=client_hello,
                last_handshake_message_type=TlsHandshakeType.SERVER_KEY_EXCHANGE
            )
            return server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE]
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e

        return None

    @staticmethod
    def _get_supported_curve(server_key_exchange):
        try:
            supported_curve, _ = parse_ecdh_params(server_key_exchange.param_bytes)
        except NotImplementedError as e:
            if isinstance(e.args[0], TlsNamedCurve):
                supported_curve = TlsNamedCurve(e.args[0])
            else:
                raise e

        return supported_curve

    @staticmethod
    def _get_client_hello(l7_client, protocol_version):
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(protocol_version, l7_client.address)
        for index, extension in enumerate(client_hello.extensions):
            if extension.get_extension_type() == TlsExtensionType.SUPPORTED_GROUPS:
                del client_hello.extensions[index]
                break
        return client_hello

    def analyze(self, analyzable, protocol_version):
        client_hello = self._get_client_hello(analyzable, protocol_version)
        supported_curves = OrderedDict()
        extension_supported = True
        checkable_curves = list(TlsNamedCurve)
        while checkable_curves:
            try:
                server_key_exchange = self._get_key_exchange_message(analyzable, client_hello, checkable_curves)
            except TlsAlert as e:
                if len(TlsNamedCurve) == len(checkable_curves):
                    acceptable_alerts = AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS + [
                        TlsAlertDescription.PROTOCOL_VERSION,
                        TlsAlertDescription.UNRECOGNIZED_NAME,
                    ]
                    if e.description in acceptable_alerts:
                        extension_supported = None
                        break

                if e.description in AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS:
                    break

                raise e
            except SecurityError:
                if len(TlsNamedCurve) == len(checkable_curves):
                    extension_supported = None

                break
            finally:
                del client_hello.extensions[-1]

            if server_key_exchange is None:
                break

            supported_curve = self._get_supported_curve(server_key_exchange)

            try:
                checkable_curves.remove(supported_curve)
            except ValueError:
                # choosen curve is an already checked one
                extension_supported = False
                break

            supported_curves.update([(supported_curve.name, supported_curve), ])

        return AnalyzerResultCurves(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            list(supported_curves.values()),
            extension_supported
        )
