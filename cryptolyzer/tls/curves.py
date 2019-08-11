#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import OrderedDict

from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsHandshakeType, TlsECCurveType
from cryptoparser.tls.extension import TlsExtensionType, TlsNamedCurve, TlsExtensionEllipticCurves

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.dhparam import parse_ecdh_params
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
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
                record_version=client_hello.protocol_version,
                last_handshake_message_type=TlsHandshakeType.SERVER_KEY_EXCHANGE
            )
            return server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE]
        except TlsAlert as e:
            if e.description != TlsAlertDescription.HANDSHAKE_FAILURE:
                raise e
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e

        return None

    def analyze(self, l7_client, protocol_version):
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(l7_client.address)
        client_hello.protocol_version = protocol_version
        for index, extension in enumerate(client_hello.extensions):
            if extension.get_extension_type() == TlsExtensionType.SUPPORTED_GROUPS:
                del client_hello.extensions[index]
                break

        supported_curves = OrderedDict()
        extension_supported = True
        for curve in TlsNamedCurve:
            server_key_exchange = self._get_key_exchange_message(l7_client, client_hello, curve)
            if server_key_exchange is not None:
                try:
                    supported_curve, _ = parse_ecdh_params(server_key_exchange.param_bytes)
                except NotImplementedError as e:
                    if isinstance(e.args[0], TlsECCurveType):
                        break
                    elif isinstance(e.args[0], TlsNamedCurve):
                        named_curve = TlsNamedCurve(e.args[0])
                        supported_curves.update([(named_curve.name, named_curve), ])
                else:
                    supported_curves.update([(supported_curve.name, supported_curve), ])
                    if supported_curve != curve:
                        extension_supported = False
                        break

            del client_hello.extensions[-1]

        return AnalyzerResultCurves(
            AnalyzerTargetTls.from_l7_client(l7_client, protocol_version),
            list(supported_curves.values()),
            extension_supported
        )
