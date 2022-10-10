# -*- coding: utf-8 -*-

import os

import datetime

from collections import OrderedDict

try:
    from unittest import mock
except ImportError:
    import mock

from test.common.classes import TestLoggerBase

import asn1crypto.pem
import asn1crypto.x509

from cryptoparser.common.algorithm import Authentication, Hash, Signature
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.common.x509 import PublicKeyX509
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys


class TestPublicKeyX509(TestLoggerBase):
    @staticmethod
    def _get_result(host, port):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    @staticmethod
    def _get_public_key_x509(relative_file_path):
        test_dir = os.path.dirname(__file__)
        with open(os.path.join(test_dir, relative_file_path), 'rb') as pem_file:
            _, _, der_bytes = asn1crypto.pem.unarmor(pem_file.read())
            return PublicKeyX509(asn1crypto.x509.Certificate.load(der_bytes))

    def test_common_name(self):
        result = self._get_result('no-common-name.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)
        self.assertEqual(len(result.pubkeys[0].tls_certificate_chain.items), 3)
        self.assertNotEqual(result.pubkeys[0].tls_certificate_chain.items[0].subject, OrderedDict([]))
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].subject_alternative_names,
            ['no-common-name.badssl.com', ]
        )
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].valid_domains,
            ['no-common-name.badssl.com', ]
        )

        result = self._get_result('long-extended-subdomain-name-containing-many-letters-and-dashes.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].valid_domains, ['*.badssl.com', 'badssl.com'])

    def test_subject_alternative_names(self):
        result = self._get_result('no-subject.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].subject, OrderedDict([]))
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].subject_alternative_names,
            ['no-subject.badssl.com']
        )
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].valid_domains,
            ['no-subject.badssl.com']
        )

        result = self._get_result('badssl.com', 443)
        self.assertNotEqual(result.pubkeys[0].tls_certificate_chain.items[0].subject, OrderedDict([]))
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].subject_alternative_names,
            ['*.badssl.com', 'badssl.com']
        )
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].valid_domains,
            ['*.badssl.com', 'badssl.com']
        )

    def test_no_subject(self):
        result = self._get_result('no-subject.badssl.com', 443)
        self.assertEqual(len(result.pubkeys), 1)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].subject, OrderedDict([]))
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].subject_alternative_names,
            ['no-subject.badssl.com', ]
        )
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].valid_domains,
            ['no-subject.badssl.com', ]
        )

    def test_issuer(self):
        result = self._get_result('expired.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].issuer,
            OrderedDict([
                ('country_name', 'GB'),
                ('state_or_province_name', 'Greater Manchester'),
                ('locality_name', 'Salford'),
                ('organization_name', 'COMODO CA Limited'),
                ('common_name', 'COMODO RSA Domain Validation Secure Server CA')
            ])
        )

    def test_crl_distribution_points(self):
        result = self._get_result('expired.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].crl_distribution_points,
            ['http://crl.comodoca.com/COMODORSADomainValidationSecureServerCA.crl']
        )

        result = self._get_result('letsencrypt.org', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].crl_distribution_points,
            []
        )

    def test_crl_distribution_points_relative_name(self):
        result = self._get_result('expired.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].crl_distribution_points,
            ['http://crl.comodoca.com/COMODORSADomainValidationSecureServerCA.crl', ]
        )

    def test_ocsp_responders(self):
        result = self._get_result('expired.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[1].ocsp_responders,
            ['http://ocsp.comodoca.com']
        )

    @mock.patch.object(
        asn1crypto.x509.Certificate, 'authority_information_access_value',
        return_value=None
    )
    def test_ocsp_responders_no_extension(self, _):
        result = self._get_result('expired.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[1].ocsp_responders,
            []
        )

    def test_is_ca(self):
        result = self._get_result('badssl.com', 443)
        self.assertFalse(result.pubkeys[0].tls_certificate_chain.items[0].is_ca)
        self.assertTrue(result.pubkeys[0].tls_certificate_chain.items[1].is_ca)

    def test_validity(self):
        result = self._get_result('expired.badssl.com', 443)
        self.assertTrue(result.pubkeys[0].tls_certificate_chain.items[0].expired)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].valid_not_before,
            datetime.datetime(2015, 4, 9, 0, 0, tzinfo=asn1crypto.util.timezone.utc)
        )
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].valid_not_after,
            datetime.datetime(2015, 4, 12, 23, 59, 59, tzinfo=asn1crypto.util.timezone.utc)
        )
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].validity_period,
            datetime.timedelta(days=4, seconds=-1)
        )
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].validity_remaining_time,
            None
        )

        result = self._get_result('badssl.com', 443)
        self.assertFalse(result.pubkeys[0].tls_certificate_chain.items[0].expired)

    def test_fingerprints(self):
        result = self._get_result('expired.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].fingerprints,
            {
                Hash.MD5:
                    '67:34:4E:61:C0:43:1C:F1:F7:25:7C:1D:6D:E7:A7:85',
                Hash.SHA1:
                    '40:4B:BD:2F:1F:4C:C2:FD:EE:F1:3A:AB:DD:52:3E:F6:1F:1C:71:F3',
                Hash.SHA2_256:
                    'BA:10:5C:E0:2B:AC:76:88:8E:CE:E4:7C:D4:EB:79:41:' +
                    '65:3E:9A:C9:93:B6:1B:2E:B3:DC:C8:20:14:D2:1B:4F',
            }
        )

    def test_public_key_pin(self):
        result = self._get_result('expired.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].public_key_pin,
            '9SLklscvzMYj8f+52lp5ze/hY0CFHyLSPQzSpYYIBm8='
        )

    def test_extended_validation(self):
        result = self._get_result('extended-validation.badssl.com', 443)
        self.assertTrue(result.pubkeys[0].tls_certificate_chain.items[0].extended_validation)

        result = self._get_result('badssl.com', 443)
        self.assertFalse(result.pubkeys[0].tls_certificate_chain.items[0].extended_validation)

    def test_key_type_and_size(self):
        result = self._get_result('ecc256.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].key_type, Authentication.ECDSA)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].key_size, 256)
        result = self._get_result('ecc384.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].key_type, Authentication.ECDSA)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].key_size, 384)

        result = self._get_result('rsa2048.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].key_type, Authentication.RSA)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].key_size, 2048)
        result = self._get_result('rsa4096.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].key_type, Authentication.RSA)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].key_size, 4096)
        result = self._get_result('rsa8192.badssl.com', 443)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].key_type, Authentication.RSA)
        self.assertEqual(result.pubkeys[0].tls_certificate_chain.items[0].key_size, 8192)

        public_key_x509 = self._get_public_key_x509('certs/gost_2001_cert.pem')
        self.assertEqual(public_key_x509.key_size, 256)
        public_key_x509 = self._get_public_key_x509('certs/gost_2012_256_cert.pem')
        self.assertEqual(public_key_x509.key_size, 256)
        public_key_x509 = self._get_public_key_x509('certs/gost_2012_512_cert.pem')
        self.assertEqual(public_key_x509.key_size, 512)

    def test_signature_algorithm_unknown(self):
        result = self._get_result('sha1-intermediate.badssl.com', 443)
        with mock.patch('asn1crypto.algos.SignedDigestAlgorithmId.dotted', new_callable=mock.PropertyMock) as prop_mock:
            prop_mock.side_effect = KeyError('1.2.840.113549.1.1.2')
            self.assertEqual(
                result.pubkeys[0].tls_certificate_chain.items[1].signature_hash_algorithm,
                Signature.RSA_WITH_MD2
            )

    def test_signature_algorithm(self):
        result = self._get_result('sha1-intermediate.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[1].signature_hash_algorithm,
            Signature.RSA_WITH_SHA1
        )

        result = self._get_result('sha256.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].signature_hash_algorithm,
            Signature.RSA_WITH_SHA2_256
        )
        result = self._get_result('sha384.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].signature_hash_algorithm,
            Signature.RSA_WITH_SHA2_384
        )
        result = self._get_result('sha512.badssl.com', 443)
        self.assertEqual(
            result.pubkeys[0].tls_certificate_chain.items[0].signature_hash_algorithm,
            Signature.RSA_WITH_SHA2_512
        )
