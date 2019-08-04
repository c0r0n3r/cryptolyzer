#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal
from cryptoparser.tls.extension import TlsNamedCurve

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.curves import AnalyzerCurves


class TestTlsCurves(unittest.TestCase):
    @staticmethod
    def get_result(host, port):
        analyzer = AnalyzerCurves()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    def test_curves(self):
        result = self.get_result('ecc256.badssl.com', 443)
        self.assertEqual(result.curves, [TlsNamedCurve.SECP256R1, ])
