#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import datetime

from collections import OrderedDict

from cryptoparser.common.algorithm import MAC
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7Client
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys


class TestTlsPubKeys(unittest.TestCase):
    @staticmethod
    def _get_result(host, port):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7Client.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    def test_common_name(self):
        result = self._get_result('no-common-name.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)
        self.assertEqual(len(result.pubkeys[0].certificate_chain), 3)
        self.assertNotEqual(result.pubkeys[0].certificate_chain[0].subject, [])
        self.assertFalse('commonName' in result.pubkeys[0].certificate_chain[0].subject)

        result = self._get_result('long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].common_names, ['*.badssl.com', ])
        self.assertEqual(
            result.pubkeys[0].certificate_chain[0].subject_alternative_names,
            ['*.badssl.com', 'badssl.com']
        )

    def test_no_subject(self):
        result = self._get_result('no-subject.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].subject, [])

    def test_validity(self):
        result = self._get_result('expired.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].certificate_chain[0].valid_not_before,
            datetime.datetime(2015, 4, 9, 0, 0)
        )
        self.assertEqual(
            result.pubkeys[0].certificate_chain[0].valid_not_after,
            datetime.datetime(2015, 4, 12, 23, 59, 59)
        )
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].validity_period,
            datetime.timedelta(days=4, seconds=-1)
        )
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].validity_remaining_time,
            None
        )
        #self.assertEqual(
        #    result.pubkeys[0].certificate_chain.items[0].fingerprints,
        #    None
        #)

    def test_extended_validation(self):
        result = self._get_result('extended-validation.badssl.com', 443)
        self.assertTrue(result.pubkeys[0].certificate_chain[0].extended_validation)

        result = self._get_result('badssl.com', 443)
        self.assertFalse(result.pubkeys[0].certificate_chain[0].extended_validation)

    def test_key_type_and_size(self):
        result = self._get_result('ecc256.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].key_type, 'EllipticCurve')
        self.assertEqual(result.pubkeys[0].certificate_chain[0].key_size, 256)
        result = self._get_result('ecc384.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].key_type, 'EllipticCurve')
        self.assertEqual(result.pubkeys[0].certificate_chain[0].key_size, 384)

        result = self._get_result('rsa2048.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].key_type, 'RSA')
        self.assertEqual(result.pubkeys[0].certificate_chain[0].key_size, 2048)
        result = self._get_result('rsa4096.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].key_type, 'RSA')
        self.assertEqual(result.pubkeys[0].certificate_chain[0].key_size, 4096)
        result = self._get_result('rsa8192.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].key_type, 'RSA')
        self.assertEqual(result.pubkeys[0].certificate_chain[0].key_size, 8192)

    def test_signature_algorithm(self):
        result = self._get_result('sha1-intermediate.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].signature_hash_algorithm, MAC.SHA256)

        result = self._get_result('sha256.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].signature_hash_algorithm, MAC.SHA256)
        result = self._get_result('sha384.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].signature_hash_algorithm, MAC.SHA384)
        result = self._get_result('sha512.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].certificate_chain[0].signature_hash_algorithm, MAC.SHA512)

    def test_fallback_certificate(self):
        result = self._get_result('cloudflare.com', 443)
        self.assertEqual(len(result.pubkeys), 2)
