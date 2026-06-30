# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import datetime
import pathlib

from collections import OrderedDict
from unittest import mock

from test.common.classes import OFFLINE_L4_SOCKET_PARAMS, TestKeyBase, TestLoggerBase
from test.tls.classes import L7ServerTlsTest

import asn1crypto.crl
import asn1crypto.pem
import asn1crypto.x509
import certvalidator.crl_client
import oscrypto.trust_list

from cryptodatahub.common.algorithm import Authentication, Hash, Signature

from cryptoparser.common.x509 import PublicKeyX509

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.common.x509 import CertificateChainX509Validator
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys
from cryptolyzer.tls.server import L7ServerTls, TlsServerConfiguration


class TestPublicKeyX509(TestLoggerBase):
    _CERTS_DIR = pathlib.Path(__file__).parent / 'certs'
    EXPIRED_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'expired_certificate.crt').read_text(encoding='ascii')
    ).der
    SNAKEOIL_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'snakeoil_cert.pem').read_text(encoding='ascii')
    ).der
    SNAKEOIL_CA_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'snakeoil_ca_cert.pem').read_text(encoding='ascii')
    ).der
    NO_COMMON_NAME_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'no_common_name_certificate.crt').read_text(encoding='ascii')
    ).der
    LONG_COMMON_NAME_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'long_common_name_certificate.crt').read_text(encoding='ascii')
    ).der
    CRL_DISTRIBUTION_POINT_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'crl_distribution_point_certificate.crt').read_text(encoding='ascii')
    ).der
    NO_SUBJECT_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'no_subject_certificate.crt').read_text(encoding='ascii')
    ).der
    ECDSA_P256_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'ecdsa_p256_certificate.crt').read_text(encoding='ascii')
    ).der
    ECDSA_P384_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'ecdsa_p384_certificate.crt').read_text(encoding='ascii')
    ).der
    RSA_2048_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'rsa_2048_certificate.crt').read_text(encoding='ascii')
    ).der
    RSA_4096_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'rsa_4096_certificate.crt').read_text(encoding='ascii')
    ).der
    RSA_8192_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'rsa_8192_certificate.crt').read_text(encoding='ascii')
    ).der
    SIGNATURE_SHA1_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'signature_sha1_certificate.crt').read_text(encoding='ascii')
    ).der
    SIGNATURE_SHA1_CA_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'signature_sha1_ca_certificate.crt').read_text(encoding='ascii')
    ).der
    SIGNATURE_SHA256_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'signature_sha256_certificate.crt').read_text(encoding='ascii')
    ).der
    SIGNATURE_SHA384_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'signature_sha384_certificate.crt').read_text(encoding='ascii')
    ).der
    SIGNATURE_SHA512_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'signature_sha512_certificate.crt').read_text(encoding='ascii')
    ).der
    OCSP_RESPONDER_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'ocsp_responder_certificate.crt').read_text(encoding='ascii')
    ).der
    EXTENDED_VALIDATION_CERT_DER = PublicKeyX509.from_pem(
        (_CERTS_DIR / 'extended_validation_certificate.crt').read_text(encoding='ascii')
    ).der

    @classmethod
    def _get_cert(cls, filename):
        return PublicKeyX509.from_pem((cls._CERTS_DIR / filename).read_text(encoding='ascii'))

    @staticmethod
    def _create_server(cert_ders):
        threaded_server = L7ServerTlsTest(L7ServerTls(
            'localhost', 0, OFFLINE_L4_SOCKET_PARAMS,
            configuration=TlsServerConfiguration(certificates=cert_ders)
        ))
        threaded_server.wait_for_server_listen()
        return threaded_server

    @staticmethod
    def _get_result(host, port, l4_socket_params=L4TransferSocketParams()):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7ClientTlsBase.from_scheme('tls', host, port, l4_socket_params)
        result = analyzer.analyze(l7_client, TlsProtocolVersion(TlsVersion.TLS1_2))
        return result

    def test_common_name(self):
        threaded_server = self._create_server([self.NO_COMMON_NAME_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.pubkeys), 1)
        self.assertNotEqual(result.pubkeys[0].certificate_chain.items[0].subject, OrderedDict([]))
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].subject_alternative_names,
            ['no-common-name.example.com', ]
        )
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].valid_domains,
            ['no-common-name.example.com', ]
        )

        threaded_server = self._create_server([self.LONG_COMMON_NAME_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].valid_domains,
            ['*.example.com', 'example.com']
        )

    def test_subject_alternative_names(self):
        threaded_server = self._create_server([self.NO_SUBJECT_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.pubkeys[0].certificate_chain.items[0].subject, OrderedDict([]))
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].subject_alternative_names,
            ['no-subject.example.com']
        )
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].valid_domains,
            ['no-subject.example.com']
        )

        threaded_server = self._create_server([self.LONG_COMMON_NAME_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertNotEqual(result.pubkeys[0].certificate_chain.items[0].subject, OrderedDict([]))
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].subject_alternative_names,
            ['*.example.com', 'example.com']
        )
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].valid_domains,
            ['*.example.com', 'example.com']
        )

    def test_no_subject(self):
        threaded_server = self._create_server([self.NO_SUBJECT_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(len(result.pubkeys), 1)
        self.assertEqual(result.pubkeys[0].certificate_chain.items[0].subject, OrderedDict([]))
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].subject_alternative_names,
            ['no-subject.example.com', ]
        )
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].valid_domains,
            ['no-subject.example.com', ]
        )

    def test_issuer(self):
        threaded_server = self._create_server([self.EXPIRED_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].issuer,
            OrderedDict([
                ('country_name', 'XX'),
                ('state_or_province_name', 'Default Province'),
                ('locality_name', 'Default City'),
                ('organization_name', 'Default Company Ltd'),
                ('common_name', 'expired.example.com')
            ])
        )

    def test_crl_distribution_points(self):
        threaded_server = self._create_server([self.CRL_DISTRIBUTION_POINT_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].crl_distribution_points,
            ['http://crl.example.com/default_company.crl']
        )

        threaded_server = self._create_server([self.SNAKEOIL_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].crl_distribution_points,
            []
        )

    def test_crl_distribution_points_relative_name(self):
        threaded_server = self._create_server([self.CRL_DISTRIBUTION_POINT_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].crl_distribution_points,
            ['http://crl.example.com/default_company.crl', ]
        )

    def test_ocsp_responders(self):
        threaded_server = self._create_server([self.OCSP_RESPONDER_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].ocsp_responders,
            ['http://ocsp.example.com']
        )

    @mock.patch.object(
        asn1crypto.x509.Certificate, 'authority_information_access_value',
        return_value=None
    )
    def test_ocsp_responders_no_extension(self, _):
        threaded_server = self._create_server([self.SNAKEOIL_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].ocsp_responders,
            []
        )

    def test_is_ca(self):
        threaded_server = self._create_server([self.SNAKEOIL_CERT_DER, self.SNAKEOIL_CA_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.pubkeys[0].certificate_chain.items[0].is_ca)
        self.assertTrue(result.pubkeys[0].certificate_chain.items[1].is_ca)

    def test_validity(self):
        threaded_server = self._create_server([self.EXPIRED_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.pubkeys[0].certificate_chain.items[0].expired)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].valid_not_before,
            datetime.datetime(2020, 1, 1, 0, 0, tzinfo=asn1crypto.util.timezone.utc)
        )
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].valid_not_after,
            datetime.datetime(2020, 1, 5, 0, 0, tzinfo=asn1crypto.util.timezone.utc)
        )
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].validity_period,
            datetime.timedelta(days=4)
        )
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].validity_remaining_time,
            None
        )

        threaded_server = self._create_server([self.SNAKEOIL_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.pubkeys[0].certificate_chain.items[0].expired)

    def test_fingerprints(self):
        threaded_server = self._create_server([self.EXPIRED_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].fingerprints,
            {
                Hash.MD5:
                    'D4:78:97:6A:89:3A:BF:E0:BA:0A:D6:E8:90:9A:DE:6B',
                Hash.SHA1:
                    '6B:1C:F0:50:A4:6B:BE:03:CC:55:98:B5:51:1E:FF:F1:5F:95:29:98',
                Hash.SHA2_256:
                    'FA:95:33:E0:29:83:90:A5:72:A7:8F:10:76:41:5A:02:' +
                    '5D:1E:D5:C0:B7:4A:66:E8:F4:51:51:E1:3A:6F:FE:55',
            }
        )

    def test_public_key_pin(self):
        threaded_server = self._create_server([self.EXPIRED_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].public_key_pin,
            '8EUycVnDfcqgrruGXTHzw9R5xSussL0EndupW7IqdDI='
        )

    def test_extended_validation(self):
        threaded_server = self._create_server([self.EXTENDED_VALIDATION_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertTrue(result.pubkeys[0].certificate_chain.items[0].extended_validation)

        threaded_server = self._create_server([self.SNAKEOIL_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertFalse(result.pubkeys[0].certificate_chain.items[0].extended_validation)

    def test_key_type_and_size(self):
        for cert_der, key_type, key_size in (
                (self.ECDSA_P256_CERT_DER, Authentication.ECDSA, 256),
                (self.ECDSA_P384_CERT_DER, Authentication.ECDSA, 384),
                (self.RSA_2048_CERT_DER, Authentication.RSA, 2048),
                (self.RSA_4096_CERT_DER, Authentication.RSA, 4096),
                (self.RSA_8192_CERT_DER, Authentication.RSA, 8192),
        ):
            threaded_server = self._create_server([cert_der])
            result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
            self.assertEqual(result.pubkeys[0].certificate_chain.items[0].key_type, key_type)
            self.assertEqual(result.pubkeys[0].certificate_chain.items[0].key_size, key_size)

    def test_signature_algorithm_unknown(self):
        threaded_server = self._create_server([self.SNAKEOIL_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        with mock.patch('asn1crypto.algos.SignedDigestAlgorithmId.dotted', new_callable=mock.PropertyMock) as prop_mock:
            prop_mock.side_effect = KeyError('1.2.840.113549.1.1.2')
            self.assertEqual(
                result.pubkeys[0].certificate_chain.items[0].signature_hash_algorithm,
                Signature.RSA_WITH_MD2
            )

    def test_signature_algorithm(self):
        threaded_server = self._create_server([self.SIGNATURE_SHA1_CERT_DER, self.SIGNATURE_SHA1_CA_CERT_DER])
        result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(
            result.pubkeys[0].certificate_chain.items[0].signature_hash_algorithm,
            Signature.RSA_WITH_SHA1
        )

        for cert_der, signature in (
                (self.SIGNATURE_SHA256_CERT_DER, Signature.RSA_WITH_SHA2_256),
                (self.SIGNATURE_SHA384_CERT_DER, Signature.RSA_WITH_SHA2_384),
                (self.SIGNATURE_SHA512_CERT_DER, Signature.RSA_WITH_SHA2_512),
        ):
            threaded_server = self._create_server([cert_der])
            result = self._get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
            self.assertEqual(
                result.pubkeys[0].certificate_chain.items[0].signature_hash_algorithm,
                signature
            )


class TestX509CertificateChain(TestKeyBase):  # pylint: disable=too-many-instance-attributes
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        oscrypto.trust_list.get_list()

    def setUp(self):
        super().setUp()

        self.trusted_root_ca = self._get_public_key_x509('rsa8192.badssl.com_root_ca.crt')
        self.trusted_intermediate_ca = self._get_public_key_x509('rsa8192.badssl.com_intermediate_ca.crt')
        self.trusted_certificate = self._get_public_key_x509('rsa8192.badssl.com_certificate.crt')

        self.untrudted_root_ca = self._get_public_key_x509('default_company_rsa_root_ca.crt')
        self.untrudted_intermediate_ca = self._get_public_key_x509('default_company_rsa_intermediate_ca.crt')
        self.untrudted_intermediate_ca_crl_pem = self._get_pem_str('default_company_rsa_intermediate_ca.crl')
        self.untrudted_certificate = self._get_public_key_x509('default_company_rsa_certificate.crt')
        self.untrudted_certificate_revoked = self._get_public_key_x509('default_company_rsa_certificate_revoked.crt')

    @mock.patch.object(
        certvalidator.CertificateValidator, 'validate_usage', side_effect=certvalidator.errors.PathValidationError
    )
    def test_error_path_validation(self, _):
        certificate_chain = CertificateChainX509Validator()([
            self.trusted_certificate,
            self.trusted_intermediate_ca,
            self.trusted_root_ca,
        ])

        self.assertEqual(certificate_chain.ordered, None)
        self.assertEqual(certificate_chain.contains_anchor, None)
        self.assertEqual(
            list(certificate_chain.trust_roots.values()),
            [False, False, False, False, False, False, False],
        )
        self.assertEqual(certificate_chain.revoked, None)

    @mock.patch.object(CertificateChainX509Validator, 'validate')
    @mock.patch('cryptolyzer.common.x509.certvalidator.context.ValidationContext')
    @mock.patch('cryptolyzer.common.x509.certvalidator.CertificateValidator')
    def test_ocsp_revoked(self, mock_cert_validator_class, _, __):
        mock_instance = mock.MagicMock()
        mock_cert_validator_class.return_value = mock_instance
        mock_instance.validate_usage.side_effect = [
            certvalidator.errors.PathValidationError,
            certvalidator.errors.RevokedError,
        ]
        certificate_chain = CertificateChainX509Validator()(
            [self.trusted_certificate, self.trusted_intermediate_ca, self.trusted_root_ca],
            certificate_status_list=[mock.MagicMock()],
        )
        self.assertTrue(certificate_chain.revoked)

    @mock.patch.object(CertificateChainX509Validator, 'validate')
    @mock.patch('cryptolyzer.common.x509.certvalidator.context.ValidationContext')
    @mock.patch('cryptolyzer.common.x509.certvalidator.CertificateValidator')
    def test_ocsp_path_validation_error(self, mock_cert_validator_class, _, __):
        mock_instance = mock.MagicMock()
        mock_cert_validator_class.return_value = mock_instance
        mock_instance.validate_usage.side_effect = [
            certvalidator.errors.PathValidationError,
            certvalidator.errors.PathValidationError,
            certvalidator.errors.PathValidationError,
        ]
        certificate_chain = CertificateChainX509Validator()(
            [self.trusted_certificate, self.trusted_intermediate_ca, self.trusted_root_ca],
            certificate_status_list=[mock.MagicMock()],
        )
        self.assertIsNone(certificate_chain.revoked)

    @mock.patch.object(CertificateChainX509Validator, 'validate')
    @mock.patch('cryptolyzer.common.x509.certvalidator.context.ValidationContext')
    @mock.patch('cryptolyzer.common.x509.certvalidator.CertificateValidator')
    def test_ocsp_not_revoked(self, mock_cert_validator_class, _, __):
        mock_instance = mock.MagicMock()
        mock_cert_validator_class.return_value = mock_instance
        mock_instance.validate_usage.side_effect = [
            certvalidator.errors.PathValidationError,
            None,
        ]
        certificate_chain = CertificateChainX509Validator()(
            [self.trusted_certificate, self.trusted_intermediate_ca, self.trusted_root_ca],
            certificate_status_list=[mock.MagicMock()],
        )
        self.assertFalse(certificate_chain.revoked)

    def test_trusted_contains_anchor(self):
        certificate_chain = CertificateChainX509Validator()([
            self.trusted_certificate,
            self.trusted_intermediate_ca,
            self.trusted_root_ca,
        ])

        self.assertTrue(certificate_chain.ordered)
        self.assertTrue(certificate_chain.contains_anchor)
        self.assertEqual(list(certificate_chain.trust_roots.values()), [True, True, True, True, True, True, True])
        self.assertFalse(certificate_chain.revoked)

    def test_trusted_no_anchor(self):
        certificate_chain = CertificateChainX509Validator()([
            self.trusted_certificate,
            self.trusted_intermediate_ca,
        ])

        self.assertTrue(certificate_chain.ordered)
        self.assertFalse(certificate_chain.contains_anchor)
        self.assertEqual(list(certificate_chain.trust_roots.values()), [True, True, True, True, True, True, True])
        self.assertFalse(certificate_chain.revoked)

    def test_trusted_unordered(self):
        certificate_chain = CertificateChainX509Validator()([
            self.trusted_intermediate_ca,
            self.trusted_certificate,
        ])

        self.assertFalse(certificate_chain.ordered)
        self.assertFalse(certificate_chain.contains_anchor)
        self.assertEqual(list(certificate_chain.trust_roots.values()), [True, True, True, True, True, True, True])
        self.assertFalse(certificate_chain.revoked)

    def test_untrusted_incomplete(self):
        certificate_chain = CertificateChainX509Validator()([
            self.untrudted_certificate,
            self.untrudted_intermediate_ca,
        ])

        self.assertEqual(certificate_chain.ordered, None)
        self.assertEqual(certificate_chain.contains_anchor, None)
        self.assertEqual(
            list(certificate_chain.trust_roots.values()),
            [False, False, False, False, False, False, False],
        )
        self.assertFalse(certificate_chain.revoked)

    def test_untrusted_ordered(self):
        certificate_chain = CertificateChainX509Validator()([
            self.untrudted_certificate,
            self.untrudted_intermediate_ca,
            self.untrudted_root_ca,
        ])

        self.assertTrue(certificate_chain.ordered)
        self.assertTrue(certificate_chain.contains_anchor)
        self.assertEqual(
            list(certificate_chain.trust_roots.values()),
            [False, False, False, False, False, False, False],
        )
        self.assertFalse(certificate_chain.revoked)

    def test_untrusted_unordered(self):
        certificate_chain = CertificateChainX509Validator()([
            self.untrudted_root_ca,
            self.untrudted_intermediate_ca,
            self.untrudted_certificate,
        ])

        self.assertFalse(certificate_chain.ordered)
        self.assertTrue(certificate_chain.contains_anchor)
        self.assertEqual(
            list(certificate_chain.trust_roots.values()),
            [False, False, False, False, False, False, False],
        )
        self.assertFalse(certificate_chain.revoked)

    def test_untrusted_revoked(self):
        crl = asn1crypto.crl.CertificateList.load(asn1crypto.pem.unarmor(
            self.untrudted_intermediate_ca_crl_pem.encode('ascii')
        )[2])
        with mock.patch.object(certvalidator.crl_client, '_grab_crl', return_value=crl):
            certificate_chain = CertificateChainX509Validator()([
                self.untrudted_certificate_revoked,
                self.untrudted_intermediate_ca,
                self.untrudted_root_ca,
            ])

            self.assertTrue(certificate_chain.ordered)
            self.assertTrue(certificate_chain.contains_anchor)
            self.assertEqual(
                list(certificate_chain.trust_roots.values()),
                [False, False, False, False, False, False, False],
            )
            self.assertTrue(certificate_chain.revoked)

    def test_empty_chain(self):
        certificate_chain = CertificateChainX509Validator()([])
        self.assertIsNone(certificate_chain.ordered)

    @mock.patch('cryptolyzer.common.x509.certvalidator.context.ValidationContext')
    @mock.patch('cryptolyzer.common.x509.certvalidator.CertificateValidator')
    def test_ca_only_chain(self, _, __):
        certificate_chain = CertificateChainX509Validator()([self.trusted_root_ca])
        self.assertIsNotNone(certificate_chain)
