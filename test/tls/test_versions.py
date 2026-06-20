# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from unittest import mock

from test.common.classes import TestMainBase
from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.subprotocol import TlsAlertDescription, SslErrorType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.exception import SecurityError, SecurityErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.tls.client import L7ClientTlsBase, SslError
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration
from cryptolyzer.tls.versions import AnalyzerVersions

from cryptolyzer.__main__ import main

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


class TestSslVersions(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(
            host, port, protocol_version=None, l4_socket_params=L4TransferSocketParams(), ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        result = analyzer.analyze(l7_client, None)
        return result

    @mock.patch.object(
        L7ClientTlsBase, 'do_ssl_handshake',
        side_effect=SslError(SslErrorType.NO_CERTIFICATE_ERROR)
    )
    def test_error_ssl_error(self, _):
        with self.assertRaises(SslError) as context_manager:
            self.get_result('localhost', 0)
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CERTIFICATE_ERROR)

    @mock.patch.object(
        L7ClientTlsBase, 'do_ssl_handshake',
        side_effect=SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE)
    )
    def test_error_security_error(self, _):
        threaded_server = self.create_server(TlsServerConfiguration(
            protocol_versions=[
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        ))
        self.assertEqual(
            self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port).versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        )

    def test_ssl_2(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            protocol_versions=[TlsProtocolVersion(TlsVersion.SSL3), ],
            fallback_to_ssl=True
        ))
        self.assertEqual(
            self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port).versions,
            [TlsProtocolVersion(TlsVersion.SSL2), TlsProtocolVersion(TlsVersion.SSL3), ]
        )

    def test_versions(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTls('localhost', 0, L4TransferSocketParams(timeout=0.5)),
        )
        threaded_server.start()

        server_port = threaded_server.l7_server.l4_transfer.bind_port

        self.assertEqual(
            self.get_result('localhost', server_port).versions,
            [
                TlsProtocolVersion(TlsVersion.SSL3),
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        )

    def test_tls_alert_response_to_ssl_handshake(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            protocol_versions=[
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
                TlsProtocolVersion(TlsVersion.TLS1_3),
            ],
            cipher_suites=[
                TlsCipherSuite.TLS_RSA_WITH_RC2_CBC_MD5,
                TlsCipherSuite.TLS_AES_128_GCM_SHA256,
            ],
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(version)
                for version in [TlsVersion.TLS1, TlsVersion.TLS1_1, TlsVersion.TLS1_2, TlsVersion.TLS1_3, ]
            ]
        )


class TestTlsVersions(TestTlsCases.TestTlsBase, TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return main

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNRECOGNIZED_NAME),
    )
    def test_error_tls_alert_unrecognized_name(self, _):
        threaded_server = self.create_server()
        self.assertEqual(
            self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port).versions,
            []
        )

    @staticmethod
    def get_result(
            host, port, protocol_version=None, l4_socket_params=L4TransferSocketParams(), ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, l4_socket_params, ip)
        analyzer_result = analyzer.analyze(l7_client, protocol_version)

        return analyzer_result

    def _check_log(self, result):
        for version in result.versions:
            self.assertIn(f'Server offers protocol version {str(version)}', self.log_stream.getvalue())

    def test_missing_fallback_scsv_support(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            protocol_versions=[TlsProtocolVersion(TlsVersion.TLS1_1), TlsProtocolVersion(TlsVersion.TLS1_2)],
            fallback_to_ssl=False
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.inappropriate_version_fallback.value)

        threaded_server = self.create_server(TlsServerConfiguration(
            protocol_versions=[TlsProtocolVersion(TlsVersion.TLS1_1), TlsProtocolVersion(TlsVersion.TLS1_2)],
            fallback_to_ssl=False,
            close_on_error=True,
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.inappropriate_version_fallback.value)

    def test_undecidable_fallback_scsv_support(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            protocol_versions=[TlsProtocolVersion(TlsVersion.TLS1_2)],
            fallback_to_ssl=False
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.inappropriate_version_fallback, None)

    def test_tls_1_2_3(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            protocol_versions=[
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(version) for version in [TlsVersion.TLS1, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )
        self._check_log(result)

    def test_ecdsa_only(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            protocol_versions=[
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(version) for version in [TlsVersion.TLS1, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )
        self._check_log(result)

    def test_with_client_auth(self):
        threaded_server = self.create_server(TlsServerConfiguration(
            protocol_versions=[
                TlsProtocolVersion(TlsVersion.TLS1),
                TlsProtocolVersion(TlsVersion.TLS1_1),
                TlsProtocolVersion(TlsVersion.TLS1_2),
            ]
        ))
        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(version) for version in [TlsVersion.TLS1, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )
        self._check_log(result)

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, L4TransferSocketParams(timeout=0.2)),
        )
        threaded_server.start()
        self.assertEqual(self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port).versions, [])

    def test_output(self):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            '127.0.0.1', 0,
            L4TransferSocketParams(timeout=5.0),
            configuration=TlsServerConfiguration(
                protocol_versions=[TlsProtocolVersion(TlsVersion.TLS1)]
            )
        ))
        threaded_server.wait_for_server_listen()
        func_arguments, cli_arguments = self._get_arguments(
            'tls', 'versions', '127.0.0.1',
            threaded_server.l7_server.l4_transfer.bind_port, scheme='tls'
        )
        result = self.get_result(**func_arguments)
        self.assertEqual(self._get_test_analyzer_result_json(**cli_arguments), result.as_json() + '\n')
        self.assertEqual(self._get_test_analyzer_result_markdown(**cli_arguments), result.as_markdown() + '\n')
