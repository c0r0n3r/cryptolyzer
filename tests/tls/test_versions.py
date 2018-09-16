#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.client import L7Client
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.versions import AnalyzerVersions


class TestTlsVersions(unittest.TestCase):
    @staticmethod
    def _get_result(host, port):
        analyzer = AnalyzerVersions()
        l7_client = L7Client.from_scheme('tls', host, port)
        analyzer_result = analyzer.analyze(l7_client, None)

        return analyzer_result

    def test_tls_1_0_only(self):
        self.assertEqual(
            self._get_result('tls-v1-0.badssl.com', 1010).versions,
            [TlsProtocolVersionFinal(TlsVersion.TLS1_0)]
        )

    def test_tls_1_1_only(self):
        self.assertEqual(
            self._get_result('tls-v1-1.badssl.com', 1011).versions,
            [TlsProtocolVersionFinal(TlsVersion.TLS1_1)]
        )

    def test_tls_1_2_only(self):
        self.assertEqual(
            self._get_result('tls-v1-2.badssl.com', 1012).versions,
            [TlsProtocolVersionFinal(TlsVersion.TLS1_2)]
        )

    def test_tls_1_2_3(self):
        self.assertEqual(
            self._get_result('badssl.com', 443).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )

    def test_json(self):
        self.assertEqual(
            self._get_result('client.badssl.com', 443).as_json(),
            '{"versions": ["tls1", "tls1_1", "tls1_2"]}'
        )

    def test_with_client_auth(self):
        self.assertEqual(
            self._get_result('client.badssl.com', 443).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )
