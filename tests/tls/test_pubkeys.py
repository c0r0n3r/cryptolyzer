#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7Client
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys


class TestTlsPubKeys(unittest.TestCase):
    @staticmethod
    def get_result(host, port):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7Client.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    def test_subject_match(self):
        result = self.get_result('badssl.com', 443)
        self.assertTrue(result.pubkeys[0].subject_matches)

        result = self.get_result('wrong.host.badssl.com', 443)
        self.assertFalse(result.pubkeys[0].subject_matches)

    def test_fallback_certificate(self):
        result = self.get_result('cloudflare.com', 443)
        self.assertEqual(len(result.pubkeys), 3)
