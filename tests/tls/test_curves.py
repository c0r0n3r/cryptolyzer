#!/usr/bin/env python
# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

import six

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.subprotocol import (
    TlsAlertDescription,
    TlsContentType,
    TlsECCurveType,
    TlsHandshakeServerHelloDone,
)
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal
from cryptoparser.tls.extension import TlsNamedCurve

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, ResponseError, ResponseErrorType
from cryptolyzer.tls.client import L7ClientTlsBase, TlsAlert
from cryptolyzer.tls.curves import AnalyzerCurves

from .classes import TestTlsCases


ORIGINAL_GET_KEY_EXCHANGE_MESSAGE = AnalyzerCurves._get_key_exchange_message  # pylint: disable=protected-access


def _wrapped_get_key_exchange_message(l7_client, client_hello, curve):
    if curve == TlsNamedCurve.X25519:
        raise ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE)
    return ORIGINAL_GET_KEY_EXCHANGE_MESSAGE(l7_client, client_hello, curve)


class TestTlsCurves(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0), timeout=None):
        analyzer = AnalyzerCurves()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=len(TlsNamedCurve) * [NetworkError(NetworkErrorType.NO_RESPONSE)]
    )
    def test_error_response_error_no_response(self, _):
        result = self.get_result('ecc256.badssl.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        self.assertEqual(len(result.curves), 0)

    @mock.patch(
        'cryptolyzer.tls.curves.parse_ecdh_params',
        side_effect=NotImplementedError(TlsECCurveType.EXPLICIT_PRIME)
    )
    def test_error_not_implemented_curve_type(self, _):
        result = self.get_result('ecc256.badssl.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        self.assertEqual(result.curves, [])

    @mock.patch(
        'cryptolyzer.tls.curves.parse_ecdh_params',
        side_effect=NotImplementedError(TlsNamedCurve.X25519)
    )
    def test_error_not_implemented_named_curve(self, _):
        result = self.get_result('ecc256.badssl.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        self.assertEqual(result.curves, [TlsNamedCurve.X25519])

    @mock.patch(
        'cryptolyzer.tls.curves.parse_ecdh_params',
        side_effect=NotImplementedError('cryptolyzer.tls.curves.parse_ecdh_params')
    )
    def test_error_not_implemented_other(self, _):
        with six.assertRaisesRegex(self, NotImplementedError, 'cryptolyzer.tls.curves.parse_ecdh_params'):
            self.get_result('ecc256.badssl.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_2))

    @mock.patch.object(
        AnalyzerCurves, '_get_key_exchange_message',
        side_effect=TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)
    )
    def test_error_tls_alert_for_first_time(self, _):
        result = self.get_result('ecc256.badssl.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        self.assertEqual(result.curves, [])

    @mock.patch.object(
        AnalyzerCurves, '_get_key_exchange_message',
        wraps=_wrapped_get_key_exchange_message
    )
    def test_error_response_error_for_last_time(self, _):
        result = self.get_result('www.cloudflare.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        self.assertEqual(
            result.curves,
            [TlsNamedCurve.SECP256R1, TlsNamedCurve.SECP384R1, TlsNamedCurve.SECP521R1]
        )

    def test_curves(self):
        result = self.get_result('ecc256.badssl.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        self.assertEqual(result.curves, [TlsNamedCurve.SECP256R1, ])
        self.assertTrue(result.extension_supported)

        result = self.get_result('neptun.uni-obuda.hu', 443)
        self.assertEqual(result.curves, [TlsNamedCurve.SECP256R1, ])
        self.assertFalse(result.extension_supported)

    def test_no_ec_support(self):
        result = self.get_result('static-rsa.badssl.com', 443)
        self.assertEqual(len(result.curves), 0)

    def test_plain_text_response(self):
        self.assertEqual(self.get_result('ptt.cc', 443).curves, [])
        self.assertEqual(self.get_result('cplusplus.com', 443).curves, [])

    @mock.patch.object(
        TlsRecord, 'messages', mock.PropertyMock(return_value=2 * [TlsHandshakeServerHelloDone()])
    )
    @mock.patch.object(
        TlsRecord, 'content_type', mock.PropertyMock(return_value=TlsContentType.HANDSHAKE)
    )
    def test_error_repeated_message_in_server_reply(self):
        with self.assertRaises(TlsAlert) as context_manager:
            self.get_result('badssl.com', 443)
        self.assertEqual(context_manager.exception.description, TlsAlertDescription.UNEXPECTED_MESSAGE)

    @mock.patch.object(L7ClientTlsBase, 'receive', side_effect=NotEnoughData)
    @mock.patch.object(L7ClientTlsBase, 'buffer', mock.PropertyMock(side_effect=[b'', b'some content', ]))
    def test_error_connection_closed_during_the_handshake(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('badssl.com', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)
