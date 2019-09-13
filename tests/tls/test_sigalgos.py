#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal
from cryptoparser.tls.extension import TlsSignatureAndHashAlgorithm

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.sigalgos import AnalyzerSigAlgos


class TestTlsSigAlgos(unittest.TestCase):
    @staticmethod
    def get_result(host, port, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_2)):
        analyzer = AnalyzerSigAlgos()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, protocol_version)
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

    def test_plain_text_response(self):
        protocol_version = TlsProtocolVersionFinal(TlsVersion.TLS1_0)
        self.assertEqual(self.get_result('ptt.cc', 443, protocol_version).sig_algos, [])
        self.assertEqual(self.get_result('cplusplus.com', 443, protocol_version).sig_algos, [])
