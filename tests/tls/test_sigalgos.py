#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.client import L7Client
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos


class TestTlsSigAlgos(unittest.TestCase):
    @staticmethod
    def _get_result(host, port):
        analyzer = AnalyzerSigAlgos()
        l7_client = L7Client.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    def test_sigalgos(self):
        result = self._get_result('ecc256.badssl.com', 443)
        self.assertEqual(result.sig_algos, [
            'ECDSA_SHA1',
            'ECDSA_SHA224',
            'ECDSA_SHA256',
            'ECDSA_SHA384',
            'ECDSA_SHA512'
        ])