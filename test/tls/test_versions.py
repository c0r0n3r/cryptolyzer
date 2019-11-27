# -*- coding: utf-8 -*-

import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.tls.subprotocol import TlsAlertDescription, SslErrorType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslProtocolVersion

from cryptolyzer.tls.client import L7ClientTlsBase, TlsAlert, SslError
from cryptolyzer.tls.versions import AnalyzerVersions

from .classes import TestTlsCases


class TestSslVersions(unittest.TestCase):
    @staticmethod
    def get_result(host, port):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, SslProtocolVersion())
        return result

    @mock.patch.object(
        L7ClientTlsBase, 'do_ssl_handshake',
        side_effect=SslError(SslErrorType.NO_CERTIFICATE_ERROR)
    )
    def test_error_ssl_error(self, _):
        with self.assertRaises(SslError) as context_manager:
            self.get_result('badssl.com', 443)
        self.assertEqual(context_manager.exception.error, SslErrorType.NO_CERTIFICATE_ERROR)

    def test_versions(self):
        result = self.get_result('164.100.148.73', 443)
        self.assertEqual(result.versions, [
            SslProtocolVersion(),
            TlsProtocolVersionFinal(TlsVersion.SSL3),
            TlsProtocolVersionFinal(TlsVersion.TLS1_0),
        ])

    def test_tls_alert_response_to_ssl_handshake(self):
        result = self.get_result('www.google.com', 443)
        self.assertEqual(
            result.versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )


class TestTlsVersions(TestTlsCases.TestTlsBase):
    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNRECOGNIZED_NAME),
    )
    def test_error_tls_alert_unrecognized_name(self, _):
        self.assertEqual(self.get_result('badssl.com', 443).versions, [])

    @staticmethod
    def get_result(host, port, protocol_version=None, timeout=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        analyzer_result = analyzer.analyze(l7_client, protocol_version)

        return analyzer_result

    def test_tls_1_0_only(self):
        self.assertEqual(
            self.get_result('tls-v1-0.badssl.com', 1010).versions,
            [TlsProtocolVersionFinal(TlsVersion.TLS1_0)]
        )

    def test_tls_1_1_only(self):
        self.assertEqual(
            self.get_result('tls-v1-1.badssl.com', 1011).versions,
            [TlsProtocolVersionFinal(TlsVersion.TLS1_1)]
        )

    def test_tls_1_2_only(self):
        self.assertEqual(
            self.get_result('tls-v1-2.badssl.com', 1012).versions,
            [TlsProtocolVersionFinal(TlsVersion.TLS1_2)]
        )

    def test_tls_1_2_3(self):
        self.assertEqual(
            self.get_result('badssl.com', 443).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_with_client_auth(self):
        self.assertEqual(
            self.get_result('client.badssl.com', 443).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_long_cipher_suite_list_intolerance(self):
        self.assertEqual(
            self.get_result('secure.simplepay.hu', 443).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )
        self.assertEqual(
            self.get_result('www.aegon.hu', 443).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_2]]
        )
        self.assertEqual(
            self.get_result('direkt.nn.hu', 443).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_plain_text_response(self):
        self.assertEqual(
            self.get_result('ptt.cc', 443).versions,
            [TlsProtocolVersionFinal(version) for version in []]
        )
        self.assertEqual(
            self.get_result('cplusplus.com', 443).versions,
            [TlsProtocolVersionFinal(version) for version in []]
        )
