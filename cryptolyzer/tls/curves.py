# -*- coding: utf-8 -*-

from collections import OrderedDict

from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsHandshakeType, TlsECCurveType
from cryptoparser.tls.extension import TlsExtensionType, TlsNamedCurve, TlsExtensionEllipticCurves

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.dhparam import parse_ecdh_params
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, ResponseError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloKeyExchangeECDHx, TlsAlert


class AnalyzerResultCurves(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, target, curves, extension_supported):
        super(AnalyzerResultCurves, self).__init__(target)

        self.curves = curves
        self.extension_supported = extension_supported


class AnalyzerCurves(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'curves'

    @classmethod
    def get_help(cls):
        return 'Check which curve suites supported by the server(s)'

    @staticmethod
    def _get_key_exchange_message(l7_client, client_hello, curve):
        try:
            client_hello.extensions.append(TlsExtensionEllipticCurves([curve, ]))
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
            if isinstance(e.args[0], TlsECCurveType):
                supported_curve = None
            elif isinstance(e.args[0], TlsNamedCurve):
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

    def analyze(self, l7_client, protocol_version):
        client_hello = self._get_client_hello(l7_client, protocol_version)
        supported_curves = OrderedDict()
        extension_supported = True
        for curve in TlsNamedCurve:
            try:
                server_key_exchange = self._get_key_exchange_message(l7_client, client_hello, curve)
            except TlsAlert as e:
                if curve == next(iter(TlsNamedCurve)):
                    acceptable_alerts = [
                        TlsAlertDescription.PROTOCOL_VERSION,
                        TlsAlertDescription.UNRECOGNIZED_NAME,
                        TlsAlertDescription.INSUFFICIENT_SECURITY,
                    ]
                    if e.description in acceptable_alerts:
                        extension_supported = None
                        break

                if (e.description not in [
                        TlsAlertDescription.HANDSHAKE_FAILURE,
                        TlsAlertDescription.INTERNAL_ERROR,
                        TlsAlertDescription.INSUFFICIENT_SECURITY]):
                    raise e

                continue
            except ResponseError:
                if curve == next(iter(TlsNamedCurve)):
                    extension_supported = None
                    break

                continue
            finally:
                del client_hello.extensions[-1]

            if server_key_exchange is not None:
                supported_curve = self._get_supported_curve(server_key_exchange)
                if supported_curve is not None:
                    supported_curves.update([(supported_curve.name, supported_curve), ])
                    if supported_curve != curve:
                        extension_supported = False
                        break

        return AnalyzerResultCurves(
            AnalyzerTargetTls.from_l7_client(l7_client, protocol_version),
            list(supported_curves.values()),
            extension_supported
        )
