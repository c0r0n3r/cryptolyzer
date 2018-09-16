#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from collections import OrderedDict

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7Client
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys


class TestTlsPubKeys(unittest.TestCase):
    def _get_result(self, host, port):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7Client.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    def test_common_name(self):
        result = self._get_result('no-common-name.badssl.com', 443)
        self.assertEqual(len(result.certificate_chains), 1)
        self.assertNotEqual(result.certificate_chains[0][0]['subject'], OrderedDict([]))
        self.assertFalse('commonName' in result.certificate_chains[0][0]['subject'])

        result = self._get_result('long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com', 443)
        self.assertEqual(result.certificate_chains[0][0]['subject']['commonName'], '*.badssl.com')
        self.assertEqual(
            result.certificate_chains[0][0]['subject_alternative_names'],
            ['*.badssl.com', 'badssl.com']
        )

    def test_no_subject(self):
        result = self._get_result('no-subject.badssl.com', 443)
        self.assertEqual(len(result.certificate_chains), 1)
        self.assertEqual(result.certificate_chains[0][0]['subject'], OrderedDict([]))

    def test_subject_match(self):
        result = self._get_result('badssl.com', 443)
        self.assertTrue(result.certificate_chains[0][0]['subject_matches'])

        result = self._get_result('wrong.host.badssl.com', 443)
        self.assertFalse(result.certificate_chains[0][0]['subject_matches'])

    def test_validity(self):
        result = self._get_result('expired.badssl.com', 443)
        self.assertEqual(
            result.certificate_chains[0][0]['validity']['not_before'],
            '2015-04-09 00:00:00'
        )
        self.assertEqual(
            result.certificate_chains[0][0]['validity']['not_after'],
            '2015-04-12 23:59:59'
        )

    def test_extended_validation(self):
        result = self._get_result('extended-validation.badssl.com', 443)
        self.assertTrue(result.certificate_chains[0][0]['extended_validation'])

        result = self._get_result('badssl.com', 443)
        self.assertFalse(result.certificate_chains[0][0]['extended_validation'])

    def test_key_type_and_size(self):
        result = self._get_result('ecc256.badssl.com', 443)
        self.assertEqual(result.certificate_chains[0][0]['key_type'], 'EllipticCurve')
        self.assertEqual(result.certificate_chains[0][0]['key_size'], 256)
        result = self._get_result('ecc384.badssl.com', 443)
        self.assertEqual(result.certificate_chains[0][0]['key_type'], 'EllipticCurve')
        self.assertEqual(result.certificate_chains[0][0]['key_size'], 384)

        result = self._get_result('rsa2048.badssl.com', 443)
        self.assertEqual(result.certificate_chains[0][0]['key_type'], 'RSA')
        self.assertEqual(result.certificate_chains[0][0]['key_size'], 2048)
        result = self._get_result('rsa4096.badssl.com', 443)
        self.assertEqual(result.certificate_chains[0][0]['key_type'], 'RSA')
        self.assertEqual(result.certificate_chains[0][0]['key_size'], 4096)
        result = self._get_result('rsa8192.badssl.com', 443)
        self.assertEqual(result.certificate_chains[0][0]['key_type'], 'RSA')
        self.assertEqual(result.certificate_chains[0][0]['key_size'], 8192)

    def test_signature_algorithm(self):
        result = self._get_result('sha1-intermediate.badssl.com', 443)
        self.assertEqual(result.certificate_chains[0][0]['signature_algorithm'], 'sha256WithRSAEncryption')

        result = self._get_result('sha256.badssl.com', 443)
        self.assertEqual(result.certificate_chains[0][0]['signature_algorithm'], 'sha256WithRSAEncryption')
        result = self._get_result('sha384.badssl.com', 443)
        self.assertEqual(result.certificate_chains[0][0]['signature_algorithm'], 'sha384WithRSAEncryption')
        result = self._get_result('sha512.badssl.com', 443)
        self.assertEqual(result.certificate_chains[0][0]['signature_algorithm'], 'sha512WithRSAEncryption')

    def test_fallback_certificate(self):
        result = self._get_result('cloudflare.com', 443)
        self.assertEqual(len(result.certificate_chains), 3)

        result = self._get_result('www.cloudflare.com', 443)
        self.assertEqual(len(result.certificate_chains), 3)
