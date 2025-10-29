# -*- coding: utf-8 -*-

from unittest import mock

from cryptoparser.tls.subprotocol import TlsAlertDescription, SslErrorType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.exception import SecurityError, SecurityErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.tls.client import L7ClientTlsBase, SslError
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration
from cryptolyzer.tls.versions import AnalyzerVersions

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
            self.get_result('badssl.com', 443)
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CERTIFICATE_ERROR)

    @mock.patch.object(
        L7ClientTlsBase, 'do_ssl_handshake',
        side_effect=SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE)
    )
    def test_error_security_error(self, _):
        self.assertEqual(
            self.get_result('badssl.com', 443).versions,
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
        result = self.get_result('www.google.com', 443)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(version)
                for version in [TlsVersion.TLS1, TlsVersion.TLS1_1, TlsVersion.TLS1_2, TlsVersion.TLS1_3, ]
            ]
        )


class TestTlsVersions(TestTlsCases.TestTlsBase):
    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNRECOGNIZED_NAME),
    )
    def test_error_tls_alert_unrecognized_name(self, _):
        self.assertEqual(self.get_result('badssl.com', 443).versions, [])

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

    def test_tls_1_0_only(self):
        result = self.get_result('tls-v1-0.badssl.com', 1010)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(TlsVersion.TLS1)]
        )
        self._check_log(result)

    def test_tls_1_1_only(self):
        result = self.get_result('tls-v1-1.badssl.com', 1011)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(TlsVersion.TLS1_1)]
        )
        self._check_log(result)

    def test_tls_1_2_only(self):
        result = self.get_result('tls-v1-2.badssl.com', 1012)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(TlsVersion.TLS1_2)]
        )
        self._check_log(result)

    def test_tls_1_2_3(self):
        result = self.get_result('badssl.com', 443)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(version) for version in [TlsVersion.TLS1, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )
        self._check_log(result)

    def test_tls_1_3(self):
        result = self.get_result('www.busanbank.co.kr', 443)
        self.assertEqual(
            result.versions,
            [
                TlsProtocolVersion(TlsVersion.TLS1_2),
                TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_26),
                TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_27),
                TlsProtocolVersion(TlsVersion.TLS1_3_DRAFT_28),
                TlsProtocolVersion(TlsVersion.TLS1_3),
            ]
        )
        self._check_log(result)

    def test_ecdsa_only(self):
        result = self.get_result('ecc256.badssl.com', 443)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersion(version) for version in [TlsVersion.TLS1, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )
        self._check_log(result)

    def test_with_client_auth(self):
        result = self.get_result('client.badssl.com', 443)
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
