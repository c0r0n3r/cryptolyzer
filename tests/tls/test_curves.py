#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.client import L7Client
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslProtocolVersion

from cryptolyzer.tls.curves import AnalyzerCurves


class TestTlsCurves(unittest.TestCase):
    def _get_result(self, host, port):
        analyzer = AnalyzerCurves()
        l7_client = L7Client.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    def test_curves(self):
        result = self._get_result('ecc256.badssl.com', 443)
        self.assertEqual(result.curves, ['SECP256R1', ])
