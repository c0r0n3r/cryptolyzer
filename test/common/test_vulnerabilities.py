# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.common.algorithm import BlockCipher, KeyExchange

from cryptolyzer.common.vulnerability import (
    AnalyzerResultVulnerabilityCiphersBase,
    AnalyzerResultVulnerabilityDHParamsBase,
)


class TestVulnerabilities(unittest.TestCase):
    def test_ciphers(self):
        result = AnalyzerResultVulnerabilityCiphersBase.from_algorithms(
            key_exchange_algorithms=[KeyExchange.ADH],
            bulk_cipher_algorithms=[],
        )
        self.assertTrue(result.anonymous_dh.value)
        self.assertFalse(result.sweet32.value)
        self.assertFalse(result.rc4.value)
        self.assertFalse(result.non_forward_secret.value)

        result = AnalyzerResultVulnerabilityCiphersBase.from_algorithms(
            key_exchange_algorithms=[KeyExchange.RSA],
            bulk_cipher_algorithms=[],
        )
        self.assertFalse(result.anonymous_dh.value)
        self.assertFalse(result.sweet32.value)
        self.assertFalse(result.rc4.value)
        self.assertTrue(result.non_forward_secret.value)

        result = AnalyzerResultVulnerabilityCiphersBase.from_algorithms(
            key_exchange_algorithms=[],
            bulk_cipher_algorithms=[BlockCipher.RC4_40],
        )
        self.assertFalse(result.anonymous_dh.value)
        self.assertFalse(result.sweet32.value)
        self.assertTrue(result.rc4.value)
        self.assertFalse(result.non_forward_secret.value)

        result = AnalyzerResultVulnerabilityCiphersBase.from_algorithms(
            key_exchange_algorithms=[],
            bulk_cipher_algorithms=[BlockCipher.DES],
        )
        self.assertFalse(result.anonymous_dh.value)
        self.assertTrue(result.sweet32.value)
        self.assertFalse(result.rc4.value)
        self.assertFalse(result.non_forward_secret.value)

    def test_dhparams(self):
        result = AnalyzerResultVulnerabilityDHParamsBase.from_key_sizes([1024])
        self.assertTrue(result.weak_dh.value)
        self.assertFalse(result.dheat.value)

        result = AnalyzerResultVulnerabilityDHParamsBase.from_key_sizes([2048])
        self.assertFalse(result.weak_dh.value)
        self.assertFalse(result.dheat.value)

        result = AnalyzerResultVulnerabilityDHParamsBase.from_key_sizes([8192])
        self.assertFalse(result.weak_dh.value)
        self.assertTrue(result.dheat.value)
