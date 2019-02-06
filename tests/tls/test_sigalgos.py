#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal
from cryptoparser.tls.extension import TlsSignatureAndHashAlgorithm

from cryptolyzer.tls.client import L7Client
from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos


class TestTlsSigAlgos(unittest.TestCase):
    @staticmethod
    def get_result(host, port):
        analyzer = AnalyzerSigAlgos()
        l7_client = L7Client.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    def test_sigalgos(self):
        result = self.get_result('ecc256.badssl.com', 443)
        self.assertEqual(result.sig_algos, [
            TlsSignatureAndHashAlgorithm.ECDSA_SHA1,
            TlsSignatureAndHashAlgorithm.ECDSA_SHA224,
            TlsSignatureAndHashAlgorithm.ECDSA_SHA256,
            TlsSignatureAndHashAlgorithm.ECDSA_SHA384,
            TlsSignatureAndHashAlgorithm.ECDSA_SHA512,
        ])
