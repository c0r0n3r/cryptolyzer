#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7Client
from cryptolyzer.tls.dhparams import AnalyzerDHParams


class TestTlsDHParams(unittest.TestCase):
    @staticmethod
    def _get_result(host, port):
        analyzer = AnalyzerDHParams()
        l7_client = L7Client.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    def test_size(self):
        result = self._get_result('dh480.badssl.com', 443)
        self.assertEqual(len(result.dhparams), 1)
        self.assertEqual(result.dhparams[0].key_size, 480)
        self.assertEqual(result.dhparams[0].prime, True)
        self.assertEqual(result.dhparams[0].safe_prime, True)

    def test_prime(self):
        result = self._get_result('dh-composite.badssl.com', 443)
        self.assertEqual(len(result.dhparams), 1)
        self.assertEqual(result.dhparams[0].key_size, 2047)
        self.assertEqual(result.dhparams[0].prime, False)
        self.assertEqual(result.dhparams[0].safe_prime, False)

    def test_safe_prime(self):
        result = self._get_result('dh-small-subgroup.badssl.com', 443)
        self.assertEqual(len(result.dhparams), 1)
        self.assertEqual(result.dhparams[0].key_size, 2048)
        self.assertEqual(result.dhparams[0].prime, True)
        self.assertEqual(result.dhparams[0].safe_prime, False)
