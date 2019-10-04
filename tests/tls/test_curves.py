#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal
from cryptoparser.tls.extension import TlsNamedCurve

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.curves import AnalyzerCurves

from .classes import TestTlsCases


class TestTlsCurves(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0), timeout=None):
        analyzer = AnalyzerCurves()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    def test_curves(self):
        result = self.get_result('ecc256.badssl.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        self.assertEqual(result.curves, [TlsNamedCurve.SECP256R1, ])
        self.assertTrue(result.extension_supported)

        result = self.get_result('neptun.uni-obuda.hu', 443)
        self.assertEqual(result.curves, [TlsNamedCurve.SECP256R1, ])
        self.assertFalse(result.extension_supported)

    def test_plain_text_response(self):
        self.assertEqual(self.get_result('ptt.cc', 443).curves, [])
        self.assertEqual(self.get_result('cplusplus.com', 443).curves, [])
