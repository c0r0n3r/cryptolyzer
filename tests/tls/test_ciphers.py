#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.common.algorithm import Authentication, BlockCipher

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.client import L7Client
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.ciphers import AnalyzerCipherSuites


class TestTlsCiphers(unittest.TestCase):
    @staticmethod
    def _get_result(host, port):
        analyzer = AnalyzerCipherSuites()
        l7_client = L7Client.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_0))
        return result

    def test_cbc(self):
        result = self._get_result('cbc.badssl.com', 443)

        self.assertEqual(result.cipher_suite_preference, True)
        self.assertEqual(
            result.cipher_suites,
            [
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_256_CBC_SHA,
                TlsCipherSuite.TLS_RSA_WITH_AES_256_CBC_SHA,
                TlsCipherSuite.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
                TlsCipherSuite.TLS_DHE_RSA_WITH_AES_128_CBC_SHA,
                TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA,
            ]
        )

    def test_rc4(self):
        result = self._get_result('rc4.badssl.com', 443)

        rc4_block_ciphers = [
            BlockCipher.RC4_40,
            BlockCipher.RC4_128,
            BlockCipher.RC4_128_EXPORT40,
        ]

        self.assertTrue(all([
            cipher_suite.value.block_cipher in rc4_block_ciphers
            for cipher_suite in result.cipher_suites
        ]))

    def test_rc4_md5(self):
        result = self._get_result('rc4-md5.badssl.com', 443)

        self.assertEqual(result.cipher_suite_preference, None)
        self.assertEqual(result.cipher_suites, [TlsCipherSuite.TLS_RSA_WITH_RC4_128_MD5, ])

    def test_triple_des(self):
        result = self._get_result('3des.badssl.com', 443)

        triple_des_block_ciphers = [
            BlockCipher.TRIPLE_DES,
            BlockCipher.TRIPLE_DES_EDE,
        ]

        self.assertTrue(all([
            cipher_suite.value.block_cipher in triple_des_block_ciphers
            for cipher_suite in result.cipher_suites
        ]))

    def test_anon(self):
        result = self._get_result('null.badssl.com', 443)

        self.assertTrue(all([
            'NULL' in cipher_suite.name or 'anon' in cipher_suite.name
            for cipher_suite in result.cipher_suites
        ]))

    def test_rsa(self):
        result = self._get_result('static-rsa.badssl.com', 443)

        self.assertTrue(all([
            cipher_suite.value.authentication == Authentication.RSA
            for cipher_suite in result.cipher_suites
        ]))