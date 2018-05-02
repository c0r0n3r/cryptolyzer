#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.common.exception import NetworkError, NetworkErrorType

from cryptoparser.tls.client import TlsHandshakeClientHelloKeyExchangeECDHx, TlsAlert
from cryptoparser.tls.subprotocol import TlsAlertDescription
from cryptoparser.tls.extension import TlsExtensionType, TlsNamedCurve, TlsExtensionEllipticCurves

from cryptolyzer.common.analyzer import AnalyzerBase, AnalyzerResultBase


class AnalyzerResultCurves(AnalyzerResultBase):
    def __init__(self, curves):
        self.curves = [curve.name for curve in curves]


class AnalyzerCurves(AnalyzerBase):
    @classmethod
    def get_name(cls):
        return 'curves'

    @classmethod
    def get_help(cls):
        return 'Check which curve suites supported by the server(s)'

    def analyze(self, l7_client):
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(l7_client.host)
        for index, extension in enumerate(client_hello.extensions):
            if extension.get_extension_type() == TlsExtensionType.SUPPORTED_GROUPS:
                del client_hello.extensions[index]
                break

        supported_curves = []
        for curve in TlsNamedCurve:
            try:
                client_hello.extensions.append(TlsExtensionEllipticCurves([curve, ]))
                l7_client.do_tls_handshake(client_hello, client_hello.protocol_version)
            except TlsAlert as e:
                if e.description != TlsAlertDescription.HANDSHAKE_FAILURE:
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            else:
                supported_curves.append(curve)
            finally:
                del client_hello.extensions[-1]

        return AnalyzerResultCurves(supported_curves)
