#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.versions import AnalyzerVersions


class TestL7Client(unittest.TestCase):
    @staticmethod
    def get_result(proto, host, port):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme(proto, host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    def test_tls_client(self):
        self.assertEqual(
            self.get_result('tls', 'badssl.com', 443).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )

    def test_https_client(self):
        self.assertEqual(
            self.get_result('https', 'badssl.com', None).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )

    def test_pop3_client(self):
        self.assertEqual(
            self.get_result('pop', 'pop3.comcast.net', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )
        # self.assertEqual(self.get_result('pop', 'pop3.citromail.hu', None).versions, [])

    def test_imap_client(self):
        self.assertEqual(
            self.get_result('imap', 'imap.comcast.net', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_smtp_client(self):
        self.assertEqual(
            self.get_result('smtp', 'smtp.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )
