#!/usr/bin/env python
# -*- coding: utf-8 -*-

from collections import OrderedDict

from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsHandshakeType, TlsECCurveType
from cryptoparser.tls.extension import TlsExtensionType, TlsNamedCurve, TlsExtensionEllipticCurves

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.dhparam import parse_ecdh_params
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloKeyExchangeECDHx, TlsAlert


class AnalyzerResultCurves(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    def __init__(self, curves, extension_supported):
        self.curves = curves
        self.extension_supported = extension_supported


class AnalyzerCurves(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'curves'

    @classmethod
    def get_help(cls):
        return 'Check which curve suites supported by the server(s)'

    def analyze(self, l7_client, protocol_version):
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(l7_client.host)
        for index, extension in enumerate(client_hello.extensions):
            if extension.get_extension_type() == TlsExtensionType.SUPPORTED_GROUPS:
                del client_hello.extensions[index]
                break

        supported_curves = OrderedDict()
        extension_supported = True
        for curve in TlsNamedCurve:
            try:
                client_hello.extensions.append(TlsExtensionEllipticCurves([curve, ]))
                server_messages = l7_client.do_tls_handshake(
                    hello_message=client_hello,
                    protocol_version=client_hello.protocol_version,
                    last_handshake_message_type=TlsHandshakeType.SERVER_KEY_EXCHANGE
                )
            except TlsAlert as e:
                if e.description != TlsAlertDescription.HANDSHAKE_FAILURE:
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            else:
                server_key_exchange = server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE]
                try:
                    parse_ecdh_params(server_key_exchange.param_bytes).curve.name
                except NotImplementedError as e:
                    if isinstance(e.args[0], TlsECCurveType):
                        named_curve = None
                    elif isinstance(e.args[0], TlsNamedCurve):
                        named_curve = e.args[0]

                extension_supported = (named_curve == curve)
                if extension_supported:
                    supported_curves.update([(curve.name, curve), ])
                else:
                    if named_curve is not None:
                        supported_curves.update([(named_curve.name, named_curve), ])
                    break

            del client_hello.extensions[-1]

        return AnalyzerResultCurves(list(supported_curves.values()), extension_supported)
