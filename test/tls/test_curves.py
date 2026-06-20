# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from unittest import mock

import socket

from test.common.classes import TestMainBase
from test.common.markers import live_server

from cryptoparser.tls.subprotocol import TlsAlertDescription
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion
from cryptoparser.tls.extension import TlsNamedCurve

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4ClientTCP, L4TransferSocketParams
from cryptolyzer.tls.client import L7ClientTlsBase, TlsHandshakeClientHelloAnyAlgorithm
from cryptolyzer.tls.curves import AnalyzerCurves
from cryptolyzer.tls.exception import TlsAlert, UnexpectedAlertError

from cryptolyzer.__main__ import main

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse, L7ServerTlsAlert, TlsServerAlert


class TestTlsCurves(TestTlsCases.TestTlsBase, TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return main

    @staticmethod
    def get_result(
            host,
            port,
            protocol_version=TlsProtocolVersion(TlsVersion.TLS1),
            l4_socket_params=L4TransferSocketParams(),
            ip=None,
            scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerCurves()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=len(TlsNamedCurve) * [NetworkError(NetworkErrorType.NO_RESPONSE)]
    )
    def test_error_response_error_no_response(self, _):
        result = self.get_result(
            'localhost', 0, TlsProtocolVersion(TlsVersion.TLS1_2),
        )
        self.assertEqual(len(result.curves), 0)

    @live_server
    @mock.patch(
        'cryptolyzer.tls.curves.parse_ecdh_params',
        side_effect=NotImplementedError(TlsNamedCurve.X25519)
    )
    def test_error_not_implemented_named_curve(self, _):
        result = self.get_result(
            'ecc256.badssl.com', 443, TlsProtocolVersion(TlsVersion.TLS1_2),
            l4_socket_params=L4TransferSocketParams(timeout=10)
        )
        self.assertEqual(result.curves, [TlsNamedCurve.X25519])

    @live_server
    @mock.patch(
        'cryptolyzer.tls.curves.parse_ecdh_params',
        side_effect=NotImplementedError('cryptolyzer.tls.curves.parse_ecdh_params')
    )
    def test_error_not_implemented_other(self, _):
        with self.assertRaisesRegex(NotImplementedError, 'cryptolyzer.tls.curves.parse_ecdh_params'):
            self.get_result(
                'ecc256.badssl.com', 443, TlsProtocolVersion(TlsVersion.TLS1_2),
                l4_socket_params=L4TransferSocketParams(timeout=10)
            )

    @mock.patch.object(
        AnalyzerCurves, '_get_response_message',
        side_effect=TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)
    )
    def test_error_tls_alert_for_first_time(self, _):
        result = self.get_result(
            'localhost', 0, TlsProtocolVersion(TlsVersion.TLS1_2),
        )
        self.assertEqual(result.curves, [])

    @mock.patch.object(
        TlsServerAlert, '_get_alert_message', return_value=TlsHandshakeClientHelloAnyAlgorithm(
            [TlsProtocolVersion(TlsVersion.TLS1_2), ], 'localhost'
        )
    )
    def test_error_repeated_message_in_server_reply(self, _):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsAlert('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.wait_for_server_listen()

        with self.assertRaises(UnexpectedAlertError) as context_manager:
            self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(str(context_manager.exception), 'alert message received (unexpected_message)')

    @live_server
    def test_curves(self):
        result = self.get_result(
            'ecc256.badssl.com', 443, TlsProtocolVersion(TlsVersion.TLS1_2),
            l4_socket_params=L4TransferSocketParams(timeout=10)
        )
        self.assertEqual(result.curves, [TlsNamedCurve.SECP256R1, ])
        self.assertTrue(result.extension_supported)
        self.assertEqual(
            self.pop_log_lines(), [
                'Server offers elliptic-curve PRIME256V1',
            ]
        )

        result = self.get_result('www.cloudflare.com', 443, TlsProtocolVersion(TlsVersion.TLS1_3))
        curves = result.curves
        # different instances run with different configuration, the following is the common subset
        self.assertIn(TlsNamedCurve.X25519_KYBER_768_R3, curves)
        self.assertIn(TlsNamedCurve.X25519, curves)
        self.assertIn(TlsNamedCurve.SECP256R1, curves)

        self.assertTrue(result.extension_supported)

        curve_log_lines = self.pop_log_lines()
        self.assertIn('Server offers elliptic-curve X25519_KYBER_768_R3', curve_log_lines)
        self.assertIn('Server offers elliptic-curve CURVE25519', curve_log_lines)
        self.assertIn('Server offers elliptic-curve PRIME256V1', curve_log_lines)

    def test_no_ec_support(self):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.curves), 0)
        self.assertFalse(self.log_stream.getvalue(), '')

    @live_server
    def test_tls_1_3(self):
        curves = self.get_result('www.cloudflare.com', 443, TlsProtocolVersion(TlsVersion.TLS1_3)).curves
        # different instances run with different configuration, the following is the common subset
        self.assertIn(TlsNamedCurve.X25519_KYBER_768_R3, curves)
        self.assertIn(TlsNamedCurve.X25519, curves)
        self.assertIn(TlsNamedCurve.SECP256R1, curves)

        curve_log_lines = self.pop_log_lines()
        self.assertIn('Server offers elliptic-curve X25519_KYBER_768_R3', curve_log_lines)
        self.assertIn('Server offers elliptic-curve CURVE25519', curve_log_lines)
        self.assertIn('Server offers elliptic-curve PRIME256V1', curve_log_lines)

    @live_server
    def test_pqc(self):
        curves = self.get_result('pq.cloudflareresearch.com', 443, TlsProtocolVersion(TlsVersion.TLS1_3)).curves

        # different instances run with different configuration, the following is the common subset
        self.assertIn(TlsNamedCurve.X25519_KYBER_768_R3, curves)
        self.assertIn(TlsNamedCurve.X25519, curves)
        self.assertIn(TlsNamedCurve.SECP256R1, curves)

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()
        self.assertEqual(self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port).curves, [])

    @mock.patch.object(L4ClientTCP, 'send', side_effect=socket.timeout)
    def test_error_connection_closed_during_the_handshake(self, _):
        threaded_server = self.create_server()
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_json(self):
        threaded_server = self.create_server()
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result)

    @live_server
    def test_output(self):
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1_2), 'curves', 'ecc256.badssl.com', 443, timeout=10, scheme='tls'
        )
        result = self.get_result(**func_arguments)
        self.assertEqual(self._get_test_analyzer_result_json(**cli_arguments), result.as_json() + '\n')
        self.assertEqual(self._get_test_analyzer_result_markdown(**cli_arguments), result.as_markdown() + '\n')
