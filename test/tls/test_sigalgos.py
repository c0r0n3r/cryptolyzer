# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from unittest import mock

from test.common.classes import TestMainBase
from test.common.markers import live_dns, live_server

from cryptodatahub.tls.algorithm import TlsSignatureAndHashAlgorithm
from cryptoparser.tls.subprotocol import TlsAlertDescription
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.exception import SecurityError, SecurityErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos

from cryptolyzer.__main__ import main

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


class TestTlsSigAlgos(TestTlsCases.TestTlsBase, TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return main

    @staticmethod
    def get_result(
            host, port, protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2),
            l4_socket_params=L4TransferSocketParams(), ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerSigAlgos()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @live_dns
    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)
    )
    def test_error_tls_alert_protocol_version(self, _):
        result = self.get_result('ecc256.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertEqual(result.sig_algos, [])

    @live_dns
    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=[
            mock.DEFAULT,
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
        ]
    )
    def test_error_response_error_no_response(self, _):
        result = self.get_result('ecc256.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertEqual(result.sig_algos, [
            TlsSignatureAndHashAlgorithm.RSA_NONE,
        ])

    @live_server
    def test_sigalgos(self):
        result = self.get_result('badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertEqual(result.sig_algos, [
            TlsSignatureAndHashAlgorithm.RSA_SHA1,
            TlsSignatureAndHashAlgorithm.RSA_SHA224,
            TlsSignatureAndHashAlgorithm.RSA_SHA256,
            TlsSignatureAndHashAlgorithm.RSA_SHA384,
            TlsSignatureAndHashAlgorithm.RSA_SHA512,
        ])
        log_lines = self.get_log_lines()
        for idx, signature_algorithm in enumerate(result.sig_algos):
            self.assertEqual(f'Server offers signature algorithm {signature_algorithm.name}', log_lines[idx])

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.start()
        protocol_version = TlsProtocolVersion(TlsVersion.TLS1_2)
        self.assertEqual(
            self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port, protocol_version).sig_algos,
            []
        )

    @live_server
    def test_json(self):
        result = self.get_result('ecc256.badssl.com', 443, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertTrue(result)

    @live_server
    def test_output(self):
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1_2), 'sigalgos', 'ecc256.badssl.com', 443, timeout=10, scheme='tls'
        )
        result = self.get_result(**func_arguments)
        self.assertEqual(self._get_test_analyzer_result_json(**cli_arguments), result.as_json() + '\n')
        self.assertEqual(self._get_test_analyzer_result_markdown(**cli_arguments), result.as_markdown() + '\n')
