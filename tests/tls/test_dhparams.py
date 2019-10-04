#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.dhparams import AnalyzerDHParams

from .classes import TestTlsCases


class TestTlsDHParams(TestTlsCases.TestTlsBase):
    @classmethod
    def get_result(cls, host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2), timeout=None):
        analyzer = AnalyzerDHParams()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    def test_size(self):
        result = self.get_result('dh480.badssl.com', 443)
        self.assertEqual(len(result.dhparams), 1)
        self.assertEqual(result.dhparams[0].key_size, 480)
        self.assertEqual(result.dhparams[0].prime, True)
        self.assertEqual(result.dhparams[0].safe_prime, True)

    def test_prime(self):
        result = self.get_result('dh-composite.badssl.com', 443)
        self.assertEqual(len(result.dhparams), 1)
        self.assertEqual(result.dhparams[0].key_size, 2047)
        self.assertEqual(result.dhparams[0].prime, False)
        self.assertEqual(result.dhparams[0].safe_prime, False)

    def test_safe_prime(self):
        result = self.get_result('dh-small-subgroup.badssl.com', 443)
        self.assertEqual(len(result.dhparams), 1)
        self.assertEqual(result.dhparams[0].key_size, 2048)
        self.assertEqual(result.dhparams[0].prime, True)
        self.assertEqual(result.dhparams[0].safe_prime, False)

    def test_plain_text_response(self):
        self.assertEqual(self.get_result('ptt.cc', 443).dhparams, [])
        self.assertEqual(self.get_result('cplusplus.com', 443).dhparams, [])
