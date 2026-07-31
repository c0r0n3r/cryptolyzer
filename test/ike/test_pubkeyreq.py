# SPDX-License-Identifier: MPL-2.0

import collections
import unittest
from unittest import mock

import asn1crypto.x509

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode
from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1CertificateType,
    Ikev1DiffieHellmanGroup,
    Ikev1Doi,
    Ikev1EncryptionAlgorithm,
    Ikev1ExchangeType,
    Ikev1HashAlgorithm,
    Ikev1ProtocolId,
    Ikev1TransformId,
    Ikev2CertificateType,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2IntegrityAlgorithm,
    Ikev2PseudorandomFunction,
)
from cryptodatahub.ike.version import IkeVersion

from cryptoparser.ike.isakmp import IsakmpFlags, IsakmpMessage
from cryptoparser.ike.version import IsakmpProtocolVersion
from cryptoparser.ike.ikev1 import (
    Ikev1AttributeAuthenticationMethod,
    Ikev1PayloadCertificateRequest,
    Ikev1PayloadProposal,
    Ikev1PayloadSecurityAssociation,
    Ikev1PayloadTransform,
    Ikev1Situation,
)
from cryptoparser.ike.ikev2 import Ikev2PayloadCertificateRequest, Ikev2PayloadNonce

from cryptolyzer.common.result import AnalyzerTargetIke
from cryptolyzer.ike.analyzer import ProtocolHandlerIKEv1, ProtocolHandlerIKEv2
from cryptolyzer.ike.crypto import (
    AeadBulkCipherDescriptor,
    _NegotiatedIkev1Transforms,
    _NegotiatedIkev2Transforms,
)
from cryptolyzer.ike.pubkeyreq import (
    AnalyzerPublicKeyRequest,
    AnalyzerResultIkev1PublicKeyRequest,
    AnalyzerResultIkev2PublicKeyRequest,
)


class _PubkeyReqFixtures:
    _TEST_TARGET = AnalyzerTargetIke(
        scheme='ipsec', address='127.0.0.1', ip='127.0.0.1', port=500,
    )


class _Ikev1PubkeyReqFixtures(_PubkeyReqFixtures):
    _TEST_CA_DN_NATIVE = collections.OrderedDict([
        ('country_name', 'CH'),
        ('organization_name', 'strongSwan'),
        ('common_name', 'strongSwan pubkeys test CA'),
    ])
    _TEST_CA_DN_DER = asn1crypto.x509.Name.build(_TEST_CA_DN_NATIVE).dump()

    @staticmethod
    def _make_ikev1_aggressive_response(payloads):
        return IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=0xdeadbeefcafebabe,
            responder_spi=0xfeedface12345678,
            exchange_type=Ikev1ExchangeType.AGGRESSIVE,
            flags=[IsakmpFlags.RESPONSE],
            message_id=0,
            payloads=payloads,
        )

    @staticmethod
    def _make_ikev1_sa_response(auth_method):
        return Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation=[Ikev1Situation.SIT_IDENTITY_ONLY],
            proposals=[Ikev1PayloadProposal(
                protocol_id=Ikev1ProtocolId.ISAKMP,
                transforms=[Ikev1PayloadTransform(
                    transform_id=Ikev1TransformId.KEY_IKE,
                    attributes=[Ikev1AttributeAuthenticationMethod(auth_method)],
                )],
            )],
        )


class _Ikev2PubkeyReqFixtures(_PubkeyReqFixtures):
    _TEST_SPKI_HASH_A = bytes(range(20))
    _TEST_SPKI_HASH_B = bytes(range(20, 40))
    _TEST_SPKI_HASH_C = bytes(range(40, 60))


class TestCollectIkev1CertreqData(_Ikev1PubkeyReqFixtures, unittest.TestCase):
    def test_empty_message(self):
        response = self._make_ikev1_aggressive_response([])
        # pylint: disable-next=protected-access
        certificate_types, distinguished_names = AnalyzerPublicKeyRequest._get_ikev1_certreq_data(response)
        self.assertEqual(certificate_types, [])
        self.assertEqual(distinguished_names, [])

    def test_single_certreq_with_valid_dn(self):
        response = self._make_ikev1_aggressive_response([
            Ikev1PayloadCertificateRequest(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                certification_authority=self._TEST_CA_DN_DER,
            ),
        ])
        # pylint: disable-next=protected-access
        certificate_types, distinguished_names = AnalyzerPublicKeyRequest._get_ikev1_certreq_data(response)
        self.assertEqual(certificate_types, [Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE])
        self.assertEqual(distinguished_names, [self._TEST_CA_DN_NATIVE])

    def test_multiple_certreqs_dedup_cert_type(self):
        response = self._make_ikev1_aggressive_response([
            Ikev1PayloadCertificateRequest(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                certification_authority=self._TEST_CA_DN_DER,
            ),
            Ikev1PayloadCertificateRequest(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                certification_authority=self._TEST_CA_DN_DER,
            ),
        ])
        # pylint: disable-next=protected-access
        certificate_types, distinguished_names = AnalyzerPublicKeyRequest._get_ikev1_certreq_data(response)
        self.assertEqual(certificate_types, [Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE])
        self.assertEqual(distinguished_names, [self._TEST_CA_DN_NATIVE])

    def test_non_x509_encoding_contributes_type_but_no_dn(self):
        response = self._make_ikev1_aggressive_response([
            Ikev1PayloadCertificateRequest(
                cert_encoding=Ikev1CertificateType.PKCS7_WRAPPED_X509_CERTIFICATE,
                certification_authority=b'\xaa\xbb\xcc',
            ),
        ])
        # pylint: disable-next=protected-access
        certificate_types, distinguished_names = AnalyzerPublicKeyRequest._get_ikev1_certreq_data(response)
        self.assertEqual(
            certificate_types,
            [Ikev1CertificateType.PKCS7_WRAPPED_X509_CERTIFICATE],
        )
        self.assertEqual(distinguished_names, [])

    def test_unparseable_dn_dropped_but_cert_type_recorded(self):
        response = self._make_ikev1_aggressive_response([
            Ikev1PayloadCertificateRequest(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                certification_authority=b'\xff\xff not-asn1',
            ),
        ])
        # pylint: disable-next=protected-access
        certificate_types, distinguished_names = AnalyzerPublicKeyRequest._get_ikev1_certreq_data(response)
        self.assertEqual(certificate_types, [Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE])
        self.assertEqual(distinguished_names, [])

    def test_non_certreq_payloads_ignored(self):
        response = self._make_ikev1_aggressive_response([
            self._make_ikev1_sa_response(auth_method=Ikev1AuthenticationMethod.RSA_SIGNATURES),
        ])
        # pylint: disable-next=protected-access
        certificate_types, distinguished_names = AnalyzerPublicKeyRequest._get_ikev1_certreq_data(response)
        self.assertEqual(certificate_types, [])
        self.assertEqual(distinguished_names, [])


class TestCollectIkev2CertreqData(_Ikev2PubkeyReqFixtures, unittest.TestCase):
    def test_empty_payloads(self):
        # pylint: disable-next=protected-access
        certificate_types, trusted_ca_hashes = AnalyzerPublicKeyRequest._get_ikev2_certreq_data([])
        self.assertEqual(certificate_types, [])
        self.assertEqual(trusted_ca_hashes, [])

    def test_single_certreq_multiple_hashes(self):
        payloads = [Ikev2PayloadCertificateRequest(
            flags=set(),
            cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
            certification_authority=self._TEST_SPKI_HASH_A + self._TEST_SPKI_HASH_B,
        )]
        # pylint: disable-next=protected-access
        certificate_types, trusted_ca_hashes = AnalyzerPublicKeyRequest._get_ikev2_certreq_data(payloads)
        self.assertEqual(certificate_types, [Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE])
        self.assertEqual(trusted_ca_hashes, [self._TEST_SPKI_HASH_A, self._TEST_SPKI_HASH_B])

    def test_multiple_certreqs_dedup_hashes(self):
        payloads = [
            Ikev2PayloadCertificateRequest(
                flags=set(),
                cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
                certification_authority=self._TEST_SPKI_HASH_A,
            ),
            Ikev2PayloadCertificateRequest(
                flags=set(),
                cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
                certification_authority=self._TEST_SPKI_HASH_A + self._TEST_SPKI_HASH_B,
            ),
        ]
        # pylint: disable-next=protected-access
        certificate_types, trusted_ca_hashes = AnalyzerPublicKeyRequest._get_ikev2_certreq_data(payloads)
        self.assertEqual(certificate_types, [Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE])
        self.assertEqual(trusted_ca_hashes, [self._TEST_SPKI_HASH_A, self._TEST_SPKI_HASH_B])

    def test_non_x509_encoding_no_hashes(self):
        payloads = [Ikev2PayloadCertificateRequest(
            flags=set(),
            cert_encoding=Ikev2CertificateType.RAW_PUBLIC_KEY,
            certification_authority=b'\xaa\xbb\xcc',
        )]
        # pylint: disable-next=protected-access
        certificate_types, trusted_ca_hashes = AnalyzerPublicKeyRequest._get_ikev2_certreq_data(payloads)
        self.assertEqual(certificate_types, [Ikev2CertificateType.RAW_PUBLIC_KEY])
        self.assertEqual(trusted_ca_hashes, [])

    def test_non_certreq_payloads_ignored(self):
        payloads = [Ikev2PayloadNonce(flags=set(), nonce_data=b'\xaa' * 32)]
        # pylint: disable-next=protected-access
        certificate_types, trusted_ca_hashes = AnalyzerPublicKeyRequest._get_ikev2_certreq_data(payloads)
        self.assertEqual(certificate_types, [])
        self.assertEqual(trusted_ca_hashes, [])

    def test_hash_and_url_of_x509_certificate_encoding_hashes_captured(self):
        # RFC 7296 §3.7: SHA-1(SPKI) hashes for X509_CERTIFICATE_SIGNATURE, HASH_AND_URL_OF_X509_CERTIFICATE, and
        # HASH_AND_URL_OF_X509_BUNDLE encodings.
        payloads = [Ikev2PayloadCertificateRequest(
            flags=set(),
            cert_encoding=Ikev2CertificateType.HASH_AND_URL_OF_X509_CERTIFICATE,
            certification_authority=self._TEST_SPKI_HASH_A + self._TEST_SPKI_HASH_B,
        )]
        # pylint: disable-next=protected-access
        certificate_types, trusted_ca_hashes = AnalyzerPublicKeyRequest._get_ikev2_certreq_data(payloads)
        self.assertEqual(
            certificate_types,
            [Ikev2CertificateType.HASH_AND_URL_OF_X509_CERTIFICATE],
        )
        self.assertEqual(trusted_ca_hashes, [self._TEST_SPKI_HASH_A, self._TEST_SPKI_HASH_B])

    def test_hash_and_url_of_x509_bundle_encoding_hashes_captured(self):
        # RFC 7296 §3.7 hash-bearing encoding HASH_AND_URL_OF_X509_BUNDLE.
        payloads = [Ikev2PayloadCertificateRequest(
            flags=set(),
            cert_encoding=Ikev2CertificateType.HASH_AND_URL_OF_X509_BUNDLE,
            certification_authority=self._TEST_SPKI_HASH_C,
        )]
        # pylint: disable-next=protected-access
        certificate_types, trusted_ca_hashes = AnalyzerPublicKeyRequest._get_ikev2_certreq_data(payloads)
        self.assertEqual(
            certificate_types,
            [Ikev2CertificateType.HASH_AND_URL_OF_X509_BUNDLE],
        )
        self.assertEqual(trusted_ca_hashes, [self._TEST_SPKI_HASH_C])


class TestAnalyzerResultIkev1PublicKeyRequestValidation(_PubkeyReqFixtures, unittest.TestCase):
    def test_accepts_none_fields(self):
        result = AnalyzerResultIkev1PublicKeyRequest(
            target=self._TEST_TARGET,
            certificate_types=None,
            distinguished_names=None,
        )
        self.assertIsNone(result.certificate_types)
        self.assertIsNone(result.distinguished_names)

    def test_rejects_wrong_certificate_type_enum(self):
        with self.assertRaises(ValueError):
            AnalyzerResultIkev1PublicKeyRequest(
                target=self._TEST_TARGET,
                certificate_types=[Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE],
                distinguished_names=None,
            )

    def test_rejects_non_orderedddict_distinguished_name(self):
        with self.assertRaises(TypeError):
            AnalyzerResultIkev1PublicKeyRequest(
                target=self._TEST_TARGET,
                certificate_types=None,
                distinguished_names=[{'country_name': 'CH'}],
            )


class TestAnalyzerResultIkev2PublicKeyRequestValidation(_PubkeyReqFixtures, unittest.TestCase):
    def test_accepts_none_fields(self):
        result = AnalyzerResultIkev2PublicKeyRequest(
            target=self._TEST_TARGET,
            certificate_types=None,
            trusted_ca_hashes=None,
        )
        self.assertIsNone(result.certificate_types)
        self.assertIsNone(result.trusted_ca_hashes)

    def test_rejects_wrong_certificate_type_enum(self):
        with self.assertRaises(ValueError):
            AnalyzerResultIkev2PublicKeyRequest(
                target=self._TEST_TARGET,
                certificate_types=[Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE],
                trusted_ca_hashes=None,
            )

    def test_rejects_non_bytes_hash(self):
        with self.assertRaises(TypeError):
            AnalyzerResultIkev2PublicKeyRequest(
                target=self._TEST_TARGET,
                certificate_types=None,
                trusted_ca_hashes=['not-bytes'],
            )


class TestAnalyzerMetadata(unittest.TestCase):
    def test_get_name(self):
        self.assertEqual(AnalyzerPublicKeyRequest.get_name(), 'pubkeyreq')

    def test_get_help_is_non_empty(self):
        self.assertTrue(AnalyzerPublicKeyRequest.get_help())


class TestAnalyzerIkev1Dispatch(_Ikev1PubkeyReqFixtures, unittest.TestCase):
    """Probe driver stubbed to exercise CERTREQ aggregation without a live IKE responder."""

    @staticmethod
    def _make_algorithm_set():
        return _NegotiatedIkev1Transforms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
            key_length=128,
            hash_algorithm=Ikev1HashAlgorithm.SHA2_256,
            authentication_method=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            dh_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
        )

    def _run_ikev1(self, aggressive_response):
        analyzable = mock.MagicMock()
        analyzable.address = '127.0.0.1'
        analyzable.port = 500
        with mock.patch(
                'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev1_dh_groups',
                return_value=([Ikev1DiffieHellmanGroup.MODP_2048_BIT], self._make_algorithm_set()),
        ), mock.patch(
                'cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev1_run_aggressive_probe',
                return_value=aggressive_response,
        ), mock.patch(
                'cryptolyzer.ike.pubkeyreq.AnalyzerTargetIke.from_l7_client',
                return_value=self._TEST_TARGET,
        ):
            return AnalyzerPublicKeyRequest()._analyze_ikev1(analyzable)  # pylint: disable=protected-access

    def test_discovery_finds_no_dh_group_raises(self):
        analyzable = mock.MagicMock()
        analyzable.address = '127.0.0.1'
        analyzable.port = 500
        with mock.patch(
                'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev1_dh_groups',
                return_value=([], None),
        ), mock.patch(
                'cryptolyzer.ike.pubkeyreq.AnalyzerTargetIke.from_l7_client',
                return_value=self._TEST_TARGET,
        ):
            with self.assertRaises(ValueError):
                # pylint: disable-next=protected-access
                AnalyzerPublicKeyRequest()._analyze_ikev1(analyzable)

    def test_responder_sends_certreqs_populates_row(self):
        aggressive_response = self._make_ikev1_aggressive_response([
            Ikev1PayloadCertificateRequest(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                certification_authority=self._TEST_CA_DN_DER,
            ),
        ])
        result = self._run_ikev1(aggressive_response)
        self.assertEqual(
            result.certificate_types,
            [Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE],
        )
        self.assertEqual(result.distinguished_names, [self._TEST_CA_DN_NATIVE])

    def test_responder_without_certreqs_returns_null_row(self):
        aggressive_response = self._make_ikev1_aggressive_response([
            self._make_ikev1_sa_response(auth_method=Ikev1AuthenticationMethod.RSA_SIGNATURES),
        ])
        result = self._run_ikev1(aggressive_response)
        # No CERTREQ in the response — certreq_seen stays False across the whole probe grid → certificate_types == None
        # (indistinguishable from probe silence), distinguished_names == None.
        self.assertIsNone(result.certificate_types)
        self.assertIsNone(result.distinguished_names)

    def test_probe_returns_none_treated_as_no_response(self):
        analyzable = mock.MagicMock()
        analyzable.address = '127.0.0.1'
        analyzable.port = 500
        with mock.patch(
                'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev1_dh_groups',
                return_value=([Ikev1DiffieHellmanGroup.MODP_2048_BIT], self._make_algorithm_set()),
        ), mock.patch(
                'cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev1_run_aggressive_probe',
                return_value=None,
        ), mock.patch(
                'cryptolyzer.ike.pubkeyreq.AnalyzerTargetIke.from_l7_client',
                return_value=self._TEST_TARGET,
        ):
            result = AnalyzerPublicKeyRequest()._analyze_ikev1(analyzable)  # pylint: disable=protected-access
        self.assertIsNone(result.certificate_types)
        self.assertIsNone(result.distinguished_names)

    def test_response_with_wrong_exchange_type_skipped(self):
        """A probe response whose ``exchange_type`` isn't AGGRESSIVE (e.g. a stray IDENTITY_PROTECTION message) is not
        walked for CERTREQ payloads — matches the guard in ``_analyze_ikev1``. The response still carries a CERTREQ
        payload so the test would fail if the exchange_type guard were removed."""
        wrong_exchange_response = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=0xdeadbeefcafebabe,
            responder_spi=0xfeedface12345678,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.RESPONSE],
            message_id=0,
            payloads=[
                Ikev1PayloadCertificateRequest(
                    cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                    certification_authority=self._TEST_CA_DN_DER,
                ),
            ],
        )
        result = self._run_ikev1(wrong_exchange_response)
        self.assertIsNone(result.certificate_types)
        self.assertIsNone(result.distinguished_names)


class TestAnalyzerIkev2Dispatch(_Ikev2PubkeyReqFixtures, unittest.TestCase):
    """Analyzer-level tests for the IKEv2 branch."""

    @staticmethod
    def _make_algorithm_set():
        return _NegotiatedIkev2Transforms(
            encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
            encryption_key_length_bits=128,
            encryption_descriptor=AeadBulkCipherDescriptor(
                bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
            ),
            integrity_algorithm=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
            prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            dh_group=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        )

    def _run_ikev2(self, probe_return):
        analyzable = mock.MagicMock()
        analyzable.address = '127.0.0.1'
        analyzable.port = 500
        with mock.patch(
                'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev2_dh_groups',
                return_value=(
                    [Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT],
                    self._make_algorithm_set(),
                ),
        ), mock.patch(
                'cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_run_eap_probe',
                return_value=probe_return,
        ), mock.patch(
                'cryptolyzer.ike.pubkeyreq.AnalyzerTargetIke.from_l7_client',
                return_value=self._TEST_TARGET,
        ):
            return AnalyzerPublicKeyRequest()._analyze_ikev2(analyzable)  # pylint: disable=protected-access

    def test_discovery_no_algorithm_set_raises(self):
        analyzable = mock.MagicMock()
        analyzable.address = '127.0.0.1'
        analyzable.port = 500
        with mock.patch(
                'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev2_dh_groups',
                return_value=([], None),
        ), mock.patch(
                'cryptolyzer.ike.pubkeyreq.AnalyzerTargetIke.from_l7_client',
                return_value=self._TEST_TARGET,
        ):
            with self.assertRaises(ValueError):
                # pylint: disable-next=protected-access
                AnalyzerPublicKeyRequest()._analyze_ikev2(analyzable)

    def test_ike_sa_init_response_certreqs_captured(self):
        init_payloads = [Ikev2PayloadCertificateRequest(
            flags=set(),
            cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
            certification_authority=self._TEST_SPKI_HASH_A + self._TEST_SPKI_HASH_B,
        )]
        result = self._run_ikev2((init_payloads, []))
        self.assertEqual(
            result.certificate_types,
            [Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE],
        )
        self.assertEqual(result.trusted_ca_hashes, [self._TEST_SPKI_HASH_A, self._TEST_SPKI_HASH_B])

    def test_ike_auth_inner_payload_certreqs_captured(self):
        inner_payloads = [Ikev2PayloadCertificateRequest(
            flags=set(),
            cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
            certification_authority=self._TEST_SPKI_HASH_C,
        )]
        result = self._run_ikev2(([], inner_payloads))
        self.assertEqual(result.trusted_ca_hashes, [self._TEST_SPKI_HASH_C])

    def test_probe_returns_none_returns_null_row(self):
        result = self._run_ikev2(None)
        self.assertIsNone(result.certificate_types)
        self.assertIsNone(result.trusted_ca_hashes)


class TestAnalyzerDispatch(unittest.TestCase):

    def test_dispatch_ikev1(self):
        analyzable = mock.MagicMock()
        with mock.patch.object(
                AnalyzerPublicKeyRequest, '_analyze_ikev1',
                return_value='ikev1-result',
        ) as ikev1_call:
            result = AnalyzerPublicKeyRequest().analyze(analyzable, IkeVersion.V1)
        self.assertEqual(result, 'ikev1-result')
        ikev1_call.assert_called_once_with(analyzable)

    def test_dispatch_ikev2(self):
        analyzable = mock.MagicMock()
        with mock.patch.object(
                AnalyzerPublicKeyRequest, '_analyze_ikev2',
                return_value='ikev2-result',
        ) as ikev2_call:
            result = AnalyzerPublicKeyRequest().analyze(analyzable, IkeVersion.V2)
        self.assertEqual(result, 'ikev2-result')
        ikev2_call.assert_called_once_with(analyzable)


class TestAnalyzerRegistration(unittest.TestCase):

    def test_registered_on_ikev1_handler(self):
        self.assertIn(AnalyzerPublicKeyRequest, ProtocolHandlerIKEv1.get_analyzers())

    def test_registered_on_ikev2_handler(self):
        self.assertIn(AnalyzerPublicKeyRequest, ProtocolHandlerIKEv2.get_analyzers())


if __name__ == '__main__':
    unittest.main()
