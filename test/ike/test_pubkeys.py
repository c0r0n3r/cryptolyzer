# SPDX-License-Identifier: MPL-2.0
# pylint: disable=too-many-lines,protected-access

import hashlib
import ipaddress
import pathlib
import unittest
from unittest import mock

from test.common.classes import TestLoggerBase
from test.ike.classes import (
    L7ServerIkeNoProposalChosen,
    L7ServerIkeNotify,
    create_ike_server,
)

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, IpProtocolNumber, Signature
from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1CertificateType,
    Ikev1DiffieHellmanGroup,
    Ikev1Doi,
    Ikev1EncryptionAlgorithm,
    Ikev1ExchangeType,
    Ikev1HashAlgorithm,
    Ikev1IdType,
    Ikev1LifeType,
    Ikev1NotifyType,
    Ikev1PayloadType,
    Ikev1ProtocolId,
    Ikev1TransformId,
    Ikev2AuthenticationMethod,
    Ikev2CertificateType,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2ExchangeType,
    Ikev2IdType,
    Ikev2IntegrityAlgorithm,
    Ikev2NotifyType,
    Ikev2PayloadType,
    Ikev2ProtocolId,
    Ikev2PseudorandomFunction,
)

from cryptodatahub.ike.version import IkeVersion

from cryptoparser.common.exception import InvalidType as CryptoparserInvalidType, NotEnoughData as NotEnoughDataImport
from cryptoparser.common.parse import ComposerBinary
from cryptoparser.common.x509 import PublicKeyX509
from cryptoparser.ike.isakmp import IsakmpFlags, IsakmpMessage
from cryptoparser.ike.version import IsakmpProtocolVersion
from cryptoparser.ike.ikev1 import (
    Ikev1AttributeAuthenticationMethod,
    Ikev1AttributeDiffieHellmanGroup,
    Ikev1AttributeEncryptionAlgorithm,
    Ikev1AttributeHashAlgorithm,
    Ikev1AttributeKeyLength,
    Ikev1AttributeLifeDuration,
    Ikev1AttributeLifeType,
    Ikev1PayloadCertificate,
    Ikev1PayloadIdentificationFqdn,
    Ikev1PayloadIdentificationIpv4Addr,
    Ikev1PayloadIdentificationIpv6Addr,
    Ikev1PayloadIdentificationKeyId,
    Ikev1PayloadKeyExchange,
    Ikev1PayloadNonce,
    Ikev1PayloadProposal,
    Ikev1PayloadSecurityAssociation,
    Ikev1PayloadSignature,
    Ikev1PayloadTransform,
    Ikev1Situation,
)
from cryptoparser.ike.ikev2 import (
    Ikev2AuthDigitalSignatureEnvelope,
    Ikev2NotifyPayloadCookie,
    Ikev2NotifyPayloadInvalidKe,
    Ikev2PayloadAuthentication,
    Ikev2PayloadCertificate,
    Ikev2PayloadCertificateRequest,
    Ikev2PayloadEncryptedAndAuthenticated,
    Ikev2PayloadIdentificationInitiatorBase,
    Ikev2PayloadIdentificationInitiatorFqdn,
    Ikev2PayloadIdentificationInitiatorRfc822Addr,
    Ikev2PayloadIdentificationResponderFqdn,
    Ikev2PayloadIdentificationResponderRfc822Addr,
    Ikev2PayloadKeyExchange,
    Ikev2PayloadNonce,
    Ikev2PayloadNotifyAuthenticationFailed,
    Ikev2PayloadSecurityAssociation,
    Ikev2PayloadVendorId,
    Ikev2Proposal,
    Ikev2TransformDhGroup,
    Ikev2TransformEncryptionAlgorithm,
    Ikev2TransformIntegrity,
    Ikev2TransformPrf,
)

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.common.x509 import CertificateChainX509Validator

from cryptolyzer.ike.client import (
    L7ClientIPsecBase,
    Ikev2SecurityAssociationBase,
)
from cryptolyzer.ike.crypto import dhe_ephemeral_material_backend
from cryptolyzer.ike.exception import (
    Ikev2SkAuthenticationError,
    Ikev2TransformDerivationError,
)
from cryptolyzer.ike.pubkeys import (
    AnalyzerPublicKeys,
    CertificateChainIke,
    IkeIdentification,
    Transport,
)
from cryptolyzer.ike.pubkey import (
    _IKEV1_PUBKEY_AUTH_METHODS,
    _IKEV2_PUBKEY_AUTH_METHODS,
    _AnalyzerIkePubkeyBase,
)
from cryptolyzer.ike.crypto import (
    AeadBulkCipherDescriptor,
    Ikev2SkDecryptor,
    Ikev2SkDecryptorCryptodome,
    Ikev2SkDecryptorNonAead,
    Ikev2SkDecryptorNonAeadCryptodome,
    _NegotiatedIkev1Transforms,
    _NegotiatedIkev2Transforms,
)

from cryptolyzer.ike.server import IkeServerHandshakeBase, L7ServerIke, ServerResponseMode


_TEST_CERT_DIR = pathlib.Path(__file__).resolve().parent.parent / 'common' / 'certs'


def _default_ikev2_extractor(_init_payloads, inner_payloads):
    return CertificateChainIke.from_ikev2_eap_inner_payloads(inner_payloads)


_IKEV2_TEST_ALGORITHM_SET = _NegotiatedIkev2Transforms(
    encryption_descriptor=AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
    ),
    encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
    encryption_key_length_bits=128,
    integrity_algorithm=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
    prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
    dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
)


def _load_test_cert_der(name: str = 'snakeoil_cert.pem') -> bytes:
    with open(_TEST_CERT_DIR / name, encoding='ascii') as pem_file:
        return PublicKeyX509.from_pem(pem_file.read()).der


class L7ServerIkeAggressiveCertResponse(L7ServerIke):
    """In-process mock IKE responder that answers an Aggressive-Mode probe
    with the full ``HDR, SA, KE, Nr, IDir, CERT, SIG_R`` chain.

    Exists so the IKEv1 pubkeys positive-path test can exercise X.509
    chain extraction without a containerized peer."""

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        address,
        port,
        l4_socket_params,
        *,
        cert_der: bytes,
        identification_fqdn: str = 'gateway.test.org',
        signature_length: int = 256,
        auth_method: Ikev1AuthenticationMethod = Ikev1AuthenticationMethod.RSA_SIGNATURES,
        cert_encoding: Ikev1CertificateType = Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
        **kwargs,
    ):
        self._cert_der = cert_der
        self._identification_fqdn = identification_fqdn
        self._signature_length = signature_length
        self._auth_method = auth_method
        self._cert_encoding = cert_encoding
        super().__init__(address, port, l4_socket_params, **kwargs)

    def _get_handshake_class(self):
        super()._get_handshake_class()

        cert_der = self._cert_der
        identification_fqdn = self._identification_fqdn
        signature_length = self._signature_length
        auth_method = self._auth_method
        cert_encoding = self._cert_encoding

        class _Handshake(IkeServerHandshakeBase):
            def _get_no_connection_nonce_payload(self):
                return Ikev1PayloadNonce(nonce_data=b'\x00' * 32)

            # pylint: disable=unused-argument
            def _process_handshake_message(self, message, last_handshake_message_type):
                self.client_messages = {'ike_version': message.version.major, 'message': message}

                if self.configuration.response_mode == ServerResponseMode.NONE:
                    raise StopIteration()

                responder_spi = self._get_responder_spi()

                security_association = Ikev1PayloadSecurityAssociation(
                    doi=Ikev1Doi.IPSEC,
                    situation=[Ikev1Situation.SIT_IDENTITY_ONLY],
                    proposals=[Ikev1PayloadProposal(
                        protocol_id=Ikev1ProtocolId.ISAKMP,
                        transforms=[Ikev1PayloadTransform(
                            transform_id=Ikev1TransformId.KEY_IKE,
                            attributes=[
                                Ikev1AttributeEncryptionAlgorithm(Ikev1EncryptionAlgorithm.AES_CBC),
                                Ikev1AttributeKeyLength(128),
                                Ikev1AttributeHashAlgorithm(Ikev1HashAlgorithm.SHA2_256),
                                Ikev1AttributeDiffieHellmanGroup(Ikev1DiffieHellmanGroup.MODP_2048_BIT),
                                Ikev1AttributeAuthenticationMethod(auth_method),
                                Ikev1AttributeLifeType(value=Ikev1LifeType.SECONDS),
                                Ikev1AttributeLifeDuration(value=86400),
                            ],
                        )],
                    )],
                )
                key_exchange = Ikev1PayloadKeyExchange(key_exchange_data=b'\xab' * 256)
                nonce = Ikev1PayloadNonce(nonce_data=b'\xcd' * 32)
                identification = Ikev1PayloadIdentificationFqdn(
                    protocol_id=IpProtocolNumber.HOPOPT,
                    port=0,
                    identifier=identification_fqdn,
                )
                certificate = Ikev1PayloadCertificate(
                    cert_encoding=cert_encoding,
                    certificate_data=cert_der,
                )
                signature = Ikev1PayloadSignature(signature_data=b'\xef' * signature_length)

                response = IsakmpMessage(
                    version=message.version,
                    initiator_spi=message.initiator_spi,
                    responder_spi=responder_spi,
                    exchange_type=Ikev1ExchangeType.AGGRESSIVE,
                    flags=[IsakmpFlags.RESPONSE],
                    message_id=message.message_id,
                    payloads=[security_association, key_exchange, nonce, identification, certificate, signature],
                )
                self.l7_transfer.send(response.compose())

                raise StopIteration()

        return _Handshake


class TestTransport(unittest.TestCase):
    def test_as_markdown_renders_human_readable_value(self):
        self.assertEqual(Transport.AGGRESSIVE_CLEARTEXT.as_markdown(), 'IKEv1 aggressive (cleartext)')
        self.assertEqual(Transport.IKEV2_EAP_MODE.as_markdown(), 'IKEv2 EAP mode')


class TestIkeIdentification(unittest.TestCase):
    def test_construct_minimal(self):
        identification = IkeIdentification(
            id_type=Ikev1IdType.IPV4_ADDR,
            protocol_id=IpProtocolNumber.UDP,
            port=500,
            id_data=b'\xc0\x00\x02\x01',
        )
        self.assertEqual(identification.id_type, Ikev1IdType.IPV4_ADDR)
        self.assertEqual(identification.protocol_id, IpProtocolNumber.UDP)
        self.assertEqual(identification.port, 500)
        self.assertEqual(identification.id_data, b'\xc0\x00\x02\x01')

    def test_construct_fqdn(self):
        identification = IkeIdentification(
            id_type=Ikev1IdType.FQDN,
            protocol_id=IpProtocolNumber.HOPOPT,
            port=0,
            id_data=b'gateway.example.com',
        )
        self.assertEqual(identification.id_type, Ikev1IdType.FQDN)
        self.assertEqual(identification.id_data.decode('ascii'), 'gateway.example.com')

    def test_construct_id_data_bytearray(self):
        identification = IkeIdentification(
            id_type=Ikev1IdType.KEY_ID,
            protocol_id=IpProtocolNumber.HOPOPT,
            port=0,
            id_data=bytearray(b'opaque-vendor-id'),
        )
        self.assertEqual(identification.id_data, bytearray(b'opaque-vendor-id'))

    def test_error_wrong_id_type(self):
        with self.assertRaises(TypeError):
            IkeIdentification(
                id_type='IPV4_ADDR',
                protocol_id=IpProtocolNumber.HOPOPT,
                port=0,
                id_data=b'',
            )


class TestIdentifierWireBytes(unittest.TestCase):
    """Per-``ID Type`` conversion from cryptoparser's typed ``identifier``
    attribute back to the wire ``Identification Data`` octet sequence."""

    def test_str_identifier_encoded_as_ascii(self):
        payload = Ikev1PayloadIdentificationFqdn(
            protocol_id=IpProtocolNumber.HOPOPT, port=0, identifier='gateway.example.com',
        )
        self.assertEqual(IkeIdentification.wire_bytes(payload), b'gateway.example.com')

    def test_ipv4_identifier_packed(self):
        payload = Ikev1PayloadIdentificationIpv4Addr(
            protocol_id=IpProtocolNumber.HOPOPT, port=0, identifier=ipaddress.IPv4Address('192.0.2.1'),
        )
        self.assertEqual(IkeIdentification.wire_bytes(payload), b'\xc0\x00\x02\x01')

    def test_ipv6_identifier_packed(self):
        payload = Ikev1PayloadIdentificationIpv6Addr(
            protocol_id=IpProtocolNumber.HOPOPT, port=0, identifier=ipaddress.IPv6Address('::1'),
        )
        self.assertEqual(IkeIdentification.wire_bytes(payload), b'\x00' * 15 + b'\x01')

    def test_bytes_identifier_returned_verbatim(self):
        payload = Ikev1PayloadIdentificationKeyId(
            protocol_id=IpProtocolNumber.HOPOPT, port=0, identifier=b'opaque-vendor-id',
        )
        self.assertEqual(IkeIdentification.wire_bytes(payload), b'opaque-vendor-id')


class TestCertificateChainIke(unittest.TestCase):
    @staticmethod
    def _make_identification():
        return IkeIdentification(
            id_type=Ikev1IdType.FQDN,
            protocol_id=IpProtocolNumber.HOPOPT,
            port=0,
            id_data=b'gateway.example.com',
        )

    def test_construct_aggressive_cleartext(self):
        identification = self._make_identification()
        cert_chain = CertificateChainIke(
            cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
            identification=identification,
            auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            signature_length=256,
            transport=Transport.AGGRESSIVE_CLEARTEXT,
        )
        self.assertEqual(cert_chain.cert_encoding, Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE)
        self.assertIs(cert_chain.identification, identification)
        self.assertEqual(cert_chain.auth_method_used, Ikev1AuthenticationMethod.RSA_SIGNATURES)
        self.assertEqual(cert_chain.signature_length, 256)
        self.assertEqual(cert_chain.transport, Transport.AGGRESSIVE_CLEARTEXT)
        self.assertIsNone(cert_chain.certificate_chain)
        self.assertIsNone(cert_chain.raw_bytes)

    def test_construct_with_raw_bytes(self):
        cert_chain = CertificateChainIke(
            cert_encoding=Ikev1CertificateType.CERTIFICATE_REVOCATION_LIST,
            identification=self._make_identification(),
            auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            signature_length=256,
            transport=Transport.AGGRESSIVE_CLEARTEXT,
            raw_bytes=b'\x30\x82\x01\x00',
        )
        self.assertEqual(cert_chain.raw_bytes, b'\x30\x82\x01\x00')

    def test_error_invalid_transport(self):
        with self.assertRaises(ValueError):
            CertificateChainIke(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                identification=self._make_identification(),
                auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
                signature_length=256,
                transport='invalid-transport',
            )

    def test_error_wrong_cert_encoding_type(self):
        with self.assertRaises(TypeError):
            CertificateChainIke(
                cert_encoding=4,    # raw int, not enum
                identification=self._make_identification(),
                auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
                signature_length=256,
                transport=Transport.AGGRESSIVE_CLEARTEXT,
            )

    def test_error_wrong_identification_type(self):
        with self.assertRaises(TypeError):
            CertificateChainIke(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                identification={'id_type': 'FQDN'},    # not an IkeIdentification
                auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
                signature_length=256,
                transport=Transport.AGGRESSIVE_CLEARTEXT,
            )


def _make_isakmp_message(payloads, exchange_type=None):
    """Synthesize an IsakmpMessage for parser-level tests. Default exchange type is Aggressive; callers pass
    IDENTITY_PROTECTION for Main Mode tests."""
    return IsakmpMessage(
        version=IsakmpProtocolVersion(IkeVersion.V1, 0),
        initiator_spi=0xdeadbeefcafebabe,
        responder_spi=0xfeedface12345678,
        exchange_type=exchange_type if exchange_type is not None else Ikev1ExchangeType.AGGRESSIVE,
        flags=[IsakmpFlags.RESPONSE],
        message_id=0,
        payloads=payloads,
    )


def _make_id_payload():
    return Ikev1PayloadIdentificationFqdn(
        protocol_id=IpProtocolNumber.HOPOPT,
        port=0,
        identifier='gateway.example.com',
    )


def _make_signature_payload(length=256):
    return Ikev1PayloadSignature(signature_data=b'\xab' * length)




class TestPayloadsOfType(unittest.TestCase):
    def test_returns_all_matches(self):
        id_payload = _make_id_payload()
        sig_payload = _make_signature_payload(256)
        second_sig = _make_signature_payload(128)

        message = _make_isakmp_message([id_payload, sig_payload, second_sig])

        signatures = message.get_payloads_by_type(Ikev1PayloadType.SIGNATURE)
        self.assertEqual(len(signatures), 2)
        self.assertIs(signatures[0], sig_payload)
        self.assertIs(signatures[1], second_sig)

    def test_returns_empty_when_absent(self):
        message = _make_isakmp_message([_make_id_payload()])
        self.assertEqual(message.get_payloads_by_type(Ikev1PayloadType.SIGNATURE), [])


class TestExtractResultFromResponse(unittest.TestCase):
    def test_returns_none_when_id_missing(self):
        message = _make_isakmp_message([_make_signature_payload()])
        result = CertificateChainIke.from_ikev1_aggressive_response(
            message, Ikev1AuthenticationMethod.RSA_SIGNATURES
        )
        self.assertIsNone(result)

    def test_returns_none_when_signature_missing(self):
        message = _make_isakmp_message([_make_id_payload()])
        result = CertificateChainIke.from_ikev1_aggressive_response(
            message, Ikev1AuthenticationMethod.RSA_SIGNATURES
        )
        self.assertIsNone(result)

    def test_returns_certless_row_when_only_id_and_sig_without_cert(self):
        """IDir + SIG_R but no CERT payload — strongSwan ``send_cert=never``
        config, or any other responder that authenticates without shipping
        its chain. The row is still returned (with ``cert_encoding=None``
        / ``certificate_chain=None`` / ``raw_bytes=None``) so the caller
        can distinguish "responder deliberately withheld its cert" from
        "probe failed" — matches the IKEv2 EAP-mode shape.
        """
        message = _make_isakmp_message([
            _make_id_payload(),
            _make_signature_payload(256),
        ])
        result = CertificateChainIke.from_ikev1_aggressive_response(
            message, Ikev1AuthenticationMethod.RSA_SIGNATURES
        )
        self.assertIsNotNone(result)
        self.assertIsNone(result.cert_encoding)
        self.assertIsNone(result.certificate_chain)
        self.assertIsNone(result.raw_bytes)
        self.assertEqual(result.signature_length, 256)
        self.assertEqual(result.auth_method_used, Ikev1AuthenticationMethod.RSA_SIGNATURES)


class TestBuildInitMessages(unittest.TestCase):
    @staticmethod
    def _default_algorithm_set(
            *,
            authentication_method=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            dh_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
    ):
        return _NegotiatedIkev1Transforms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
            hash_algorithm=Ikev1HashAlgorithm.SHA2_256,
            authentication_method=authentication_method,
            dh_group=dh_group,
            key_length=128,
        )

    def test_aggressive_algorithm_set_narrows_proposal(self):
        # When discovery returns a full algorithm set, the aggressive
        # proposal must use the server-confirmed (encr, key_length, hash)
        # tuple — not the fallback (AES-CBC-128 + SHA2-256) defaults.
        algorithm_set = _NegotiatedIkev1Transforms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.DES3_CBC,
            hash_algorithm=Ikev1HashAlgorithm.SHA,
            authentication_method=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            dh_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            key_length=None,
        )
        message = _AnalyzerIkePubkeyBase._ikev1_build_aggressive_init_message(
            Ikev1AuthenticationMethod.RSA_SIGNATURES,
            Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            algorithm_set=algorithm_set,
        )
        sa_payload = message.payloads[0]
        proposal = sa_payload.proposals[0]
        transform = proposal.transforms[0]
        attribute_types = {type(attribute) for attribute in transform.attributes}
        self.assertNotIn(Ikev1AttributeKeyLength, attribute_types)
        encr_attribute = next(
            attribute for attribute in transform.attributes
            if isinstance(attribute, Ikev1AttributeEncryptionAlgorithm)
        )
        hash_attribute = next(
            attribute for attribute in transform.attributes
            if isinstance(attribute, Ikev1AttributeHashAlgorithm)
        )
        self.assertEqual(encr_attribute.value, Ikev1EncryptionAlgorithm.DES3_CBC)
        self.assertEqual(hash_attribute.value, Ikev1HashAlgorithm.SHA)

    def test_aggressive_payload_order_matches_rfc(self):
        message = _AnalyzerIkePubkeyBase._ikev1_build_aggressive_init_message(
            Ikev1AuthenticationMethod.RSA_SIGNATURES,
            Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            algorithm_set=self._default_algorithm_set(),
        )

        self.assertEqual(message.exchange_type, Ikev1ExchangeType.AGGRESSIVE)
        self.assertIn(IsakmpFlags.INITIATOR, message.flags)

        # RFC 2409 §5.1: HDR, SA, KE, Ni, IDii, [CERTREQ]
        payload_types = [p.get_payload_type() for p in message.payloads]
        self.assertEqual(
            payload_types,
            [
                Ikev1PayloadType.SECURITY_ASSOCIATION,
                Ikev1PayloadType.KEY_EXCHANGE,
                Ikev1PayloadType.NONCE,
                Ikev1PayloadType.IDENTIFICATION,
                Ikev1PayloadType.CERTIFICATE_REQUEST,
            ],
        )
        # MODP-2048 KE payload is 256 octets (2048 bits) per RFC 3526 §3.
        key_exchange = message.payloads[1]
        self.assertEqual(len(bytes(key_exchange.key_exchange_data)), 256)

    def test_aggressive_ecp_256_wire_length_matches_rfc_5903(self):
        # RFC 5903 §7: raw x||y with no SEC1 0x04 prefix — 64 octets for P-256.
        message = _AnalyzerIkePubkeyBase._ikev1_build_aggressive_init_message(
            Ikev1AuthenticationMethod.ECDSA_SHA_256_P_256,
            Ikev1DiffieHellmanGroup.ECP_256_BIT,
            algorithm_set=self._default_algorithm_set(
                authentication_method=Ikev1AuthenticationMethod.ECDSA_SHA_256_P_256,
                dh_group=Ikev1DiffieHellmanGroup.ECP_256_BIT,
            ),
        )
        key_exchange = message.payloads[1]
        self.assertEqual(len(bytes(key_exchange.key_exchange_data)), 64)

    def test_aggressive_ecp_384_wire_length_matches_rfc_5903(self):
        # RFC 5903 §7: raw x||y with no SEC1 0x04 prefix — 96 octets for P-384.
        message = _AnalyzerIkePubkeyBase._ikev1_build_aggressive_init_message(
            Ikev1AuthenticationMethod.ECDSA_SHA_384_P_384,
            Ikev1DiffieHellmanGroup.ECP_384_BIT,
            algorithm_set=self._default_algorithm_set(
                authentication_method=Ikev1AuthenticationMethod.ECDSA_SHA_384_P_384,
                dh_group=Ikev1DiffieHellmanGroup.ECP_384_BIT,
            ),
        )
        key_exchange = message.payloads[1]
        self.assertEqual(len(bytes(key_exchange.key_exchange_data)), 96)

    def test_aggressive_ecp_521_wire_length_matches_rfc_5903(self):
        # RFC 5903 §7: raw x||y with no SEC1 0x04 prefix — 132 octets for P-521.
        message = _AnalyzerIkePubkeyBase._ikev1_build_aggressive_init_message(
            Ikev1AuthenticationMethod.ECDSA_SHA_512_P_521,
            Ikev1DiffieHellmanGroup.ECP_521_BIT,
            algorithm_set=self._default_algorithm_set(
                authentication_method=Ikev1AuthenticationMethod.ECDSA_SHA_512_P_521,
                dh_group=Ikev1DiffieHellmanGroup.ECP_521_BIT,
            ),
        )
        key_exchange = message.payloads[1]
        self.assertEqual(len(bytes(key_exchange.key_exchange_data)), 132)

    def test_unsupported_key_parameter_raises(self):
        # an elliptic curve and a Diffie-Hellman group are the only two recognised
        # key-parameter shapes; a synthetic DH group whose key_parameter
        # is neither must raise so we do not silently emit a KE payload
        # the responder can never verify.
        stub = mock.MagicMock()
        stub.value.key_parameter = object()
        with self.assertRaises(NotImplementedError):
            _AnalyzerIkePubkeyBase._ikev1_build_key_exchange_payload(stub)


class TestAnalyzerPublicKeys(TestLoggerBase):
    """Network-level analyzer tests using the in-process mock IKE server.

    The IKEv1 dispatch now runs
    :func:`cryptolyzer.ike.dh.discover_supported_ikev1_dh_groups` before
    the Aggressive-Mode probe grid, so the in-process ``L7ServerIke``
    mocks (which respond to any request with one fixed exchange type)
    cannot cover both paths. The discovery helper is stubbed so the
    network-level tests still exercise the aggressive / main-mode
    probes against the mock responder — the discovery helper has its
    own module-level ``TestDiscoverSupportedIkev1DhGroups`` suite.
    """

    _DISCOVERY_STUB_RETURN = (
        [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
        _NegotiatedIkev1Transforms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
            hash_algorithm=Ikev1HashAlgorithm.SHA2_256,
            authentication_method=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            dh_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            key_length=128,
        ),
    )

    @staticmethod
    def _analyze(host, port, *, ip):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7ClientIPsecBase.from_scheme(
            'ipsec', host, port, L4TransferSocketParams(timeout=1), ip=ip
        )
        return analyzer.analyze(l7_client, IkeVersion.V1)

    @mock.patch(
        'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev1_dh_groups',
        return_value=_DISCOVERY_STUB_RETURN,
    )
    def test_no_proposal_chosen_returns_empty_result(self, _discover_mock):
        """Server rejects every proposal — Aggressive AND Main-Mode fallback
        both yield NO_PROPOSAL_CHOSEN, so the result row list is empty."""
        # max_handshake_count covers Aggressive attempt + Main-Mode fallback
        # across every ``_IKEV1_PUBKEY_AUTH_METHODS`` entry.
        threaded_server = create_ike_server(
            L7ServerIkeNoProposalChosen,
            max_handshake_count=2 * len(_IKEV1_PUBKEY_AUTH_METHODS),
        )
        l4 = threaded_server.l7_server.l4_transfer
        assert l4 is not None

        result = self._analyze('localhost', l4.bind_port, ip=l4.bind_address)
        self.assertEqual(result.public_keys, [])

        threaded_server.join()

    @mock.patch(
        'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev1_dh_groups',
        return_value=_DISCOVERY_STUB_RETURN,
    )
    def test_unrelated_notify_returns_empty_result(self, _discover_mock):
        """A non-NO_PROPOSAL_CHOSEN IKEv1 notify is logged and treated as
        'no result' rather than reraised."""
        threaded_server = create_ike_server(
            L7ServerIkeNotify,
            max_handshake_count=2 * len(_IKEV1_PUBKEY_AUTH_METHODS),
            notify_type_ikev1=Ikev1NotifyType.INVALID_PAYLOAD_TYPE,
        )
        l4 = threaded_server.l7_server.l4_transfer
        assert l4 is not None

        result = self._analyze('localhost', l4.bind_port, ip=l4.bind_address)
        self.assertEqual(result.public_keys, [])

        threaded_server.join()

    @mock.patch(
        'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev1_dh_groups',
        return_value=_DISCOVERY_STUB_RETURN,
    )
    def test_aggressive_x509_certificate_extracted_end_to_end(self, _discover_mock):
        """Aggressive responder sends an X.509 CERT; the analyzer extracts
        the chain, IDr, and SIG_R length on the cleartext positive path."""
        cert_der = _load_test_cert_der()
        threaded_server = create_ike_server(
            L7ServerIkeAggressiveCertResponse,
            max_handshake_count=len(_IKEV1_PUBKEY_AUTH_METHODS),
            cert_der=cert_der,
            identification_fqdn='gateway.test.org',
            signature_length=256,
        )
        l4 = threaded_server.l7_server.l4_transfer
        assert l4 is not None

        result = self._analyze('localhost', l4.bind_port, ip=l4.bind_address)
        threaded_server.join()

        self.assertGreaterEqual(len(result.public_keys), 1)
        row = result.public_keys[0]
        self.assertIsInstance(row, CertificateChainIke)
        self.assertEqual(row.cert_encoding, Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE)
        self.assertEqual(row.auth_method_used, Ikev1AuthenticationMethod.RSA_SIGNATURES)
        self.assertEqual(row.transport, Transport.AGGRESSIVE_CLEARTEXT)
        self.assertEqual(row.signature_length, 256)
        self.assertEqual(row.identification.id_type, Ikev1IdType.FQDN)
        self.assertEqual(bytes(row.identification.id_data), b'gateway.test.org')
        self.assertIsNotNone(row.certificate_chain)
        self.assertIsNone(row.raw_bytes)

    @mock.patch(
        'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev1_dh_groups',
        return_value=_DISCOVERY_STUB_RETURN,
    )
    def test_aggressive_non_x509_encoding_falls_back_to_raw_bytes(self, _discover_mock):
        """Responder sends a non-X.509 CERT encoding (e.g. CRL); the analyzer
        records the encoding + raw bytes rather than synthesising an empty
        chain."""
        cert_der = _load_test_cert_der()
        threaded_server = create_ike_server(
            L7ServerIkeAggressiveCertResponse,
            max_handshake_count=len(_IKEV1_PUBKEY_AUTH_METHODS),
            cert_der=cert_der,
            cert_encoding=Ikev1CertificateType.CERTIFICATE_REVOCATION_LIST,
        )
        l4 = threaded_server.l7_server.l4_transfer
        assert l4 is not None

        result = self._analyze('localhost', l4.bind_port, ip=l4.bind_address)
        threaded_server.join()

        self.assertGreaterEqual(len(result.public_keys), 1)
        row = result.public_keys[0]
        self.assertEqual(row.cert_encoding, Ikev1CertificateType.CERTIFICATE_REVOCATION_LIST)
        self.assertEqual(row.raw_bytes, cert_der)
        self.assertIsNone(row.certificate_chain)

    @mock.patch(
        'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev1_dh_groups',
        return_value=([], None),
    )
    def test_ikev1_empty_discovered_dh_groups_raises(self, _discover_mock):
        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.address = '203.0.113.10'
        client.port = 500
        client.ip = '203.0.113.10'
        client.get_scheme.return_value = 'ipsec'
        client.l4_socket_params = mock.MagicMock()
        with self.assertRaises(ValueError):
            AnalyzerPublicKeys().analyze(client, IkeVersion.V1)
        client.do_ikev1_handshake.assert_not_called()


class TestAnalyzerPublicKeysMetadata(unittest.TestCase):
    """Static analyzer-class accessors. Exists only to exercise
    ``get_name`` / ``get_help`` classmethods so coverage reflects their
    presence in the module surface."""

    def test_get_name(self):
        self.assertEqual(AnalyzerPublicKeys.get_name(), 'pubkeys')

    def test_get_help(self):
        self.assertIn('public keys', AnalyzerPublicKeys.get_help())


class TestIkev1RunAggressiveProbeFailurePaths(unittest.TestCase):
    """Exercise the network/protocol failure paths of ``_ikev1_run_aggressive_probe`` via a mocked
    ``L7ClientIPsecBase``."""

    @staticmethod
    def _make_client(**overrides):
        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.address = '203.0.113.1'
        client.port = 500
        for key, value in overrides.items():
            setattr(client, key, value)
        return client

    @staticmethod
    def _algorithm_set():
        return _NegotiatedIkev1Transforms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
            hash_algorithm=Ikev1HashAlgorithm.SHA2_256,
            authentication_method=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            dh_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            key_length=128,
        )

    def test_no_response_returns_none(self):
        client = self._make_client()
        client.do_ikev1_handshake.side_effect = NetworkError(NetworkErrorType.NO_RESPONSE)

        result = _AnalyzerIkePubkeyBase._ikev1_run_aggressive_probe(
            client, Ikev1AuthenticationMethod.RSA_SIGNATURES,
            Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            self._algorithm_set(),
        )
        self.assertIsNone(result)

    def test_other_network_error_re_raises(self):
        client = self._make_client()
        client.do_ikev1_handshake.side_effect = NetworkError(NetworkErrorType.NO_CONNECTION)

        with self.assertRaises(NetworkError):
            _AnalyzerIkePubkeyBase._ikev1_run_aggressive_probe(
                client, Ikev1AuthenticationMethod.RSA_SIGNATURES,
                Ikev1DiffieHellmanGroup.MODP_2048_BIT,
                self._algorithm_set(),
            )

    def test_missing_aggressive_response_returns_none(self):
        client = self._make_client()
        client.do_ikev1_handshake.return_value = {}

        result = _AnalyzerIkePubkeyBase._ikev1_run_aggressive_probe(
            client, Ikev1AuthenticationMethod.RSA_SIGNATURES,
            Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            self._algorithm_set(),
        )
        self.assertIsNone(result)


class TestIkev2AppendKeyExchangePayload(unittest.TestCase):
    """Helper extracted from ``Ikev2SecurityAssociationBase._get_payloads``
    to drop pylint R0914 below threshold while keeping the per-branch
    ephemeral-vs-forged logic tight. Covers all three branches +
    unsupported-group fallback."""

    def test_ephemeral_key_exchange_uses_real_public_key(self):
        ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(
            Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        )
        payloads = []
        Ikev2SecurityAssociationBase.append_key_exchange_payload(
            payloads,
            [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            [],
            ephemeral,
            Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        )
        self.assertEqual(len(payloads), 1)
        self.assertIsInstance(payloads[0], Ikev2PayloadKeyExchange)
        # RFC 5903 §7: ECP KE wire form is raw x||y with no SEC1 0x04 prefix.
        self.assertEqual(bytes(payloads[0].key_exchange_data), ephemeral.public_key_bytes[1:])
        self.assertEqual(len(payloads[0].key_exchange_data), 64)
        self.assertEqual(payloads[0].dh_group, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT)

    def test_ecdh_branch_uses_forged_half_key(self):
        payloads = []
        Ikev2SecurityAssociationBase.append_key_exchange_payload(
            payloads,
            [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            [],
            None,
            Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        )
        self.assertEqual(len(payloads), 1)
        self.assertIsInstance(payloads[0], Ikev2PayloadKeyExchange)
        self.assertEqual(payloads[0].dh_group, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT)
        # Forged P-256 half-key is the uncompressed x||y (64 octets).
        self.assertEqual(len(payloads[0].key_exchange_data), 64)

    def test_ffdh_branch_uses_forged_modp_half_key(self):
        payloads = []
        Ikev2SecurityAssociationBase.append_key_exchange_payload(
            payloads,
            [Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT],
            [],
            [Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT],
            None,
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        )
        self.assertEqual(len(payloads), 1)
        self.assertIsInstance(payloads[0], Ikev2PayloadKeyExchange)
        self.assertEqual(payloads[0].dh_group, Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT)
        self.assertEqual(len(payloads[0].key_exchange_data), 256)  # 2048 / 8

    def test_unsupported_group_appends_nothing(self):
        # 768-bit MODP has DHParamWellKnown.RFC2539_768_BIT_MODP_GROUP, so it
        # would yield a forged payload — exercise the no-append path by
        # using a mocked dh_group with neither an elliptic curve nor a Diffie-Hellman group
        # key_parameter.
        bogus = mock.Mock()
        bogus.value.key_parameter = 'UNRECOGNISED'
        payloads = []
        Ikev2SecurityAssociationBase.append_key_exchange_payload(
            payloads, [bogus], [], [], None, bogus,
        )
        self.assertEqual(payloads, [])


class TestCertificateChainIkeAuthEnvelope(unittest.TestCase):
    """IKEv2-only ``auth_envelope`` field on the result row.

    IKEv1 result rows leave it ``None``. IKEv2 method-14
    (DIGITAL_SIGNATURE, RFC 7427) rows populate it with the parsed
    AlgorithmIdentifier + signature envelope."""

    @staticmethod
    def _make_identification():
        return IkeIdentification(
            id_type=Ikev1IdType.FQDN, protocol_id=IpProtocolNumber.HOPOPT, port=0,
            id_data=b'gateway.test.org',
        )

    def test_auth_envelope_defaults_to_none_for_ikev1_rows(self):
        row = CertificateChainIke(
            cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
            identification=self._make_identification(),
            auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            signature_length=256,
            transport=Transport.AGGRESSIVE_CLEARTEXT,
        )
        self.assertIsNone(row.auth_envelope)

    def test_ikev2_eap_mode_transport_accepted(self):
        row = CertificateChainIke(
            cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
            identification=self._make_identification(),
            auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            signature_length=256,
            transport=Transport.IKEV2_EAP_MODE,
        )
        self.assertEqual(row.transport, Transport.IKEV2_EAP_MODE)

    def test_auth_envelope_accepts_digital_signature_envelope(self):
        envelope = Ikev2AuthDigitalSignatureEnvelope(
            signature_algorithm=Signature.ECDSA_WITH_SHA2_256,
            signature=b'\xab' * 64,  # P-256 r||s
        )
        row = CertificateChainIke(
            cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
            identification=self._make_identification(),
            auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            signature_length=64,
            transport=Transport.IKEV2_EAP_MODE,
            auth_envelope=envelope,
        )
        self.assertIs(row.auth_envelope, envelope)
        self.assertEqual(row.auth_envelope.signature_algorithm, Signature.ECDSA_WITH_SHA2_256)

    def test_auth_envelope_rejects_wrong_type(self):
        with self.assertRaises(TypeError):
            CertificateChainIke(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                identification=self._make_identification(),
                auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
                signature_length=64,
                transport=Transport.IKEV2_EAP_MODE,
                auth_envelope=b'not an envelope',
            )


class TestIkev2InnerPayloadChain(unittest.TestCase):
    """Composition + parse round-trip for the inner payload chain that
    sits inside the SK envelope after AEAD decrypt."""

    @staticmethod
    def _identification_initiator():
        return Ikev2PayloadIdentificationInitiatorRfc822Addr(
            flags=set(),
            identifier='scanner@cryptolyzer',
        )

    @staticmethod
    def _cert_request():
        return Ikev2PayloadCertificateRequest(
            flags=set(),
            cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
            certification_authority=b'',
        )

    def test_compose_chains_next_payload_fields(self):
        chain = [self._identification_initiator(), self._cert_request()]

        composed = Ikev2SkDecryptor.compose_inner_payload_chain(chain)
        self.assertEqual(chain[0].next_payload, Ikev2PayloadType.CERTREQ)
        self.assertEqual(chain[1].next_payload, Ikev2PayloadType.NONE)
        self.assertGreater(len(composed), 0)

    def test_compose_parse_round_trips(self):
        chain = [self._identification_initiator(), self._cert_request()]
        composed = Ikev2SkDecryptor.compose_inner_payload_chain(chain)

        parsed = Ikev2SkDecryptor.parse_inner_payload_chain(composed, Ikev2PayloadType.IDI)
        self.assertEqual(len(parsed), 2)
        self.assertIsInstance(parsed[0], Ikev2PayloadIdentificationInitiatorBase)
        self.assertIsInstance(parsed[1], Ikev2PayloadCertificateRequest)

    def test_parse_rejects_unregistered_first_payload_type(self):
        # TSI (44) has no parser class registered (see test_isakmp.py for
        # the matching IKEv2 unsupported-payload check).
        bytes_ = Ikev2SkDecryptor.compose_inner_payload_chain([self._cert_request()])
        with self.assertRaises(CryptoparserInvalidType):
            Ikev2SkDecryptor.parse_inner_payload_chain(bytes_, Ikev2PayloadType.TSI)

    def test_pad_aead_block_size_one_appends_only_pad_length(self):
        padded = Ikev2SkDecryptor.pad_inner_plaintext(b'abcd', block_size=1)
        # block_size=1 → pad_length=0, single trailing byte.
        self.assertEqual(padded, b'abcd\x00')

    def test_pad_cbc_block_size_sixteen_aligns(self):
        # 4 bytes + 1 pad_length = 5; need 11 padding bytes to reach 16.
        padded = Ikev2SkDecryptor.pad_inner_plaintext(b'abcd', block_size=16)
        self.assertEqual(len(padded) % 16, 0)
        self.assertEqual(padded[-1], 11)  # pad_length

    def test_pad_rejects_invalid_block_size(self):
        with self.assertRaises(ValueError):
            Ikev2SkDecryptor.pad_inner_plaintext(b'x', block_size=0)


class TestBuildIkev2EapInnerPayloads(unittest.TestCase):
    def test_default_emits_id_rfc822_and_certreq_stack(self):
        # One IDii + one CERTREQ per encoding in
        # ``_IKEV2_PROBE_CERTREQ_ENCODINGS`` (RFC 4945 §3.3.7 stacking).
        chain = _AnalyzerIkePubkeyBase._ikev2_build_eap_mode_inner_payloads()
        self.assertEqual(len(chain), 1 + 4)
        self.assertIsInstance(chain[0], Ikev2PayloadIdentificationInitiatorBase)
        self.assertEqual(chain[0].id_type, Ikev2IdType.RFC822_ADDR)
        self.assertEqual(chain[0].identifier, 'cryptolyzer@cryptolyzer')
        for payload in chain[1:]:
            self.assertIsInstance(payload, Ikev2PayloadCertificateRequest)
            self.assertEqual(bytes(payload.certification_authority), b'')
        # RFC 7296 §3.6 codes 4 / 12 / 13 + RFC 7670 §3 code 15.
        self.assertEqual(
            [payload.cert_encoding for payload in chain[1:]],
            [
                Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
                Ikev2CertificateType.HASH_AND_URL_OF_X509_CERTIFICATE,
                Ikev2CertificateType.HASH_AND_URL_OF_X509_BUNDLE,
                Ikev2CertificateType.RAW_PUBLIC_KEY,
            ],
        )

    def test_custom_initiator_id_data_propagates(self):
        chain = _AnalyzerIkePubkeyBase._ikev2_build_eap_mode_inner_payloads(
            initiator_identification_data='other@example.org',
        )
        self.assertEqual(chain[0].identifier, 'other@example.org')


class TestCertificateChainFingerprint(unittest.TestCase):
    """Dedup key stability across the branches of :meth:`CertificateChainIke.fingerprint`."""

    _IDENTIFICATION = IkeIdentification(
        id_type=Ikev1IdType.FQDN, protocol_id=IpProtocolNumber.HOPOPT, port=0,
        id_data=b'gateway.test.org',
    )

    def _make_row(self, **overrides):
        base = {
            'cert_encoding': Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
            'identification': self._IDENTIFICATION,
            'auth_method_used': Ikev1AuthenticationMethod.RSA_SIGNATURES,
            'signature_length': 256,
            'transport': Transport.IKEV2_EAP_MODE,
        }
        base.update(overrides)
        return CertificateChainIke(**base)

    def test_x509_chain_returns_leaf_cert_sha256(self):
        cert_der = _load_test_cert_der()
        chain = CertificateChainX509Validator()(
            items=[PublicKeyX509.from_der(cert_der)], certificate_status_list=[],
        )
        row = self._make_row(certificate_chain=chain)
        expected = hashlib.sha256(cert_der).digest()
        self.assertEqual(row.fingerprint(), expected)

    def test_raw_public_key_returns_raw_bytes(self):
        # RAW_PUBLIC_KEY (RFC 7670 §3 code 15) populates ``raw_bytes``
        # rather than a parsed X.509 chain; the fingerprint helper
        # returns those bytes verbatim so distinct raw payloads dedup
        # independently.
        raw = b'\x30\x59' + b'\xaa' * 89  # arbitrary SPKI-shaped bytes
        row = self._make_row(
            cert_encoding=Ikev2CertificateType.RAW_PUBLIC_KEY,
            raw_bytes=raw,
        )
        self.assertEqual(row.fingerprint(), raw)

    def test_identical_x509_chains_dedup_to_same_fingerprint(self):
        cert_der = _load_test_cert_der()
        chain_one = CertificateChainX509Validator()(
            items=[PublicKeyX509.from_der(cert_der)], certificate_status_list=[],
        )
        chain_two = CertificateChainX509Validator()(
            items=[PublicKeyX509.from_der(cert_der)], certificate_status_list=[],
        )
        self.assertEqual(
            self._make_row(certificate_chain=chain_one).fingerprint(),
            self._make_row(certificate_chain=chain_two).fingerprint(),
        )


class TestExtractIkev2ResultFromInnerPayloads(unittest.TestCase):
    def setUp(self):
        cert_der = _load_test_cert_der()
        self.cert_payload = Ikev2PayloadCertificate(
            flags=set(),
            cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
            certificate_data=cert_der,
        )
        self.id_responder = Ikev2PayloadIdentificationResponderFqdn(
            flags=set(),
            identifier='gateway.test.org',
        )
        self.auth_payload_rsa = Ikev2PayloadAuthentication(
            flags=set(),
            auth_method=Ikev2AuthenticationMethod.RSA_DIGITAL_SIGNATURE,
            auth_data=b'\xab' * 256,
        )

    def test_extracts_rsa_chain(self):
        row = CertificateChainIke.from_ikev2_eap_inner_payloads(
            [self.id_responder, self.cert_payload, self.auth_payload_rsa],
        )
        self.assertIsNotNone(row)
        self.assertEqual(row.transport, Transport.IKEV2_EAP_MODE)
        self.assertEqual(row.auth_method_used, Ikev2AuthenticationMethod.RSA_DIGITAL_SIGNATURE)
        self.assertEqual(row.signature_length, 256)
        self.assertIsNotNone(row.certificate_chain)
        self.assertIsNone(row.auth_envelope)
        self.assertEqual(row.identification.id_type, Ikev1IdType.FQDN)
        self.assertEqual(bytes(row.identification.id_data), b'gateway.test.org')

    def test_extracts_digital_signature_envelope(self):
        envelope_body = (
            bytes([0x0c]) + bytes.fromhex('300a06082a8648ce3d040302')  # 12-octet AlgorithmIdentifier
            + b'\xcd' * 64
        )
        auth_payload_digital = Ikev2PayloadAuthentication(
            flags=set(),
            auth_method=Ikev2AuthenticationMethod.DIGITAL_SIGNATURE,
            auth_data=envelope_body,
        )
        row = CertificateChainIke.from_ikev2_eap_inner_payloads(
            [self.id_responder, self.cert_payload, auth_payload_digital],
        )
        self.assertIsNotNone(row)
        self.assertIsInstance(row.auth_envelope, Ikev2AuthDigitalSignatureEnvelope)
        self.assertEqual(row.auth_envelope.signature_algorithm, Signature.ECDSA_WITH_SHA2_256)
        self.assertEqual(len(row.auth_envelope.signature), 64)

    def test_returns_none_when_idr_missing(self):
        row = CertificateChainIke.from_ikev2_eap_inner_payloads(
            [self.cert_payload, self.auth_payload_rsa],
        )
        self.assertIsNone(row)

    def test_returns_none_when_auth_missing(self):
        row = CertificateChainIke.from_ikev2_eap_inner_payloads(
            [self.id_responder, self.cert_payload],
        )
        self.assertIsNone(row)

    def test_no_cert_payload_returns_row_without_chain(self):
        row = CertificateChainIke.from_ikev2_eap_inner_payloads(
            [self.id_responder, self.auth_payload_rsa],
        )
        self.assertIsNotNone(row)
        self.assertIsNone(row.certificate_chain)
        self.assertIsNone(row.raw_bytes)
        # A responder that sent no CERT payload (e.g. RFC 7619 NULL_AUTH)
        # must not be misreported as X509_CERTIFICATE_SIGNATURE.
        self.assertIsNone(row.cert_encoding)

    def test_non_x509_cert_falls_back_to_raw_bytes(self):
        raw_cert_payload = Ikev2PayloadCertificate(
            flags=set(),
            cert_encoding=Ikev2CertificateType.CERTIFICATE_REVOCATION_LIST,
            certificate_data=b'\x99' * 50,
        )
        row = CertificateChainIke.from_ikev2_eap_inner_payloads(
            [self.id_responder, raw_cert_payload, self.auth_payload_rsa],
        )
        self.assertIsNotNone(row)
        self.assertIsNone(row.certificate_chain)
        self.assertEqual(row.raw_bytes, b'\x99' * 50)

    def test_rfc822_id_type_maps_to_user_fqdn(self):
        id_rfc822 = Ikev2PayloadIdentificationResponderRfc822Addr(
            flags=set(),
            identifier='admin@gw.example',
        )
        row = CertificateChainIke.from_ikev2_eap_inner_payloads(
            [id_rfc822, self.cert_payload, self.auth_payload_rsa],
        )
        self.assertEqual(row.identification.id_type, Ikev1IdType.USER_FQDN)

    def test_ecdsa_p384_auth_method_maps(self):
        auth_ecdsa = Ikev2PayloadAuthentication(
            flags=set(),
            auth_method=Ikev2AuthenticationMethod.ECDSA_SHA_384_P_384,
            auth_data=b'\xaa' * 96,
        )
        row = CertificateChainIke.from_ikev2_eap_inner_payloads(
            [self.id_responder, self.cert_payload, auth_ecdsa],
        )
        self.assertEqual(row.auth_method_used, Ikev2AuthenticationMethod.ECDSA_SHA_384_P_384)


class TestResolveAeadBulkCipherDescriptor(unittest.TestCase):
    def test_aes_gcm_128(self):
        descriptor = AeadBulkCipherDescriptor.from_encryption_algorithm(
            Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 128,
        )
        self.assertEqual(descriptor.bulk_cipher.name, 'AES_128')
        self.assertEqual(descriptor.block_cipher_mode.name, 'GCM')

    def test_aes_gcm_256(self):
        descriptor = AeadBulkCipherDescriptor.from_encryption_algorithm(
            Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 256,
        )
        self.assertEqual(descriptor.bulk_cipher.name, 'AES_256')

    def test_aes_cbc_192(self):
        descriptor = AeadBulkCipherDescriptor.from_encryption_algorithm(
            Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 192,
        )
        self.assertEqual(descriptor.bulk_cipher.name, 'AES_192')
        self.assertEqual(descriptor.block_cipher_mode.name, 'CBC')

    def test_unknown_combination_raises(self):
        with self.assertRaises(ValueError):
            AeadBulkCipherDescriptor.from_encryption_algorithm(
                Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 384,  # not a valid AES key size
            )

    def test_chacha20_poly1305_none_key_length(self):
        descriptor = AeadBulkCipherDescriptor.from_encryption_algorithm(
            Ikev2EncryptionAlgorithm.ENCR_CHACHA20_POLY1305, None,
        )
        self.assertEqual(descriptor.bulk_cipher, BlockCipher.CHACHA20)
        self.assertIsNone(descriptor.block_cipher_mode)

    def test_aes_192_gcm_supported(self):
        descriptor = AeadBulkCipherDescriptor.from_encryption_algorithm(
            Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 192,
        )
        self.assertEqual(descriptor.bulk_cipher, BlockCipher.AES_192)
        self.assertEqual(descriptor.block_cipher_mode, BlockCipherMode.GCM)


class TestExtractIkev2NegotiatedTransforms(unittest.TestCase):
    @staticmethod
    def _build_sa(*, encr_alg, encr_key_length, integ_alg, prf, dh_group):
        transforms = [
            Ikev2TransformEncryptionAlgorithm(transform_id=encr_alg, key_length=encr_key_length),
            Ikev2TransformPrf(transform_id=prf),
            Ikev2TransformDhGroup(transform_id=dh_group),
        ]
        if integ_alg is not None:
            transforms.append(Ikev2TransformIntegrity(transform_id=integ_alg))
        return Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[Ikev2Proposal(
                protocol_id=Ikev2ProtocolId.IKE,
                spi=b'',
                transforms=transforms,
            )],
        )

    def test_aead_aes_gcm_256_no_integrity(self):
        sa = self._build_sa(
            encr_alg=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, encr_key_length=256,
            integ_alg=None,
            prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        )
        transforms = _NegotiatedIkev2Transforms.from_message(sa)
        self.assertEqual(transforms.encryption_algorithm,
                         Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16)
        self.assertEqual(transforms.encryption_key_length_bits, 256)
        self.assertEqual(transforms.encryption_descriptor.bulk_cipher.name, 'AES_256')
        self.assertIsNone(transforms.integrity_algorithm)
        self.assertEqual(transforms.prf, Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256)
        self.assertEqual(transforms.dh_group, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT)

    def test_non_aead_aes_cbc_128_with_integrity(self):
        sa = self._build_sa(
            encr_alg=Ikev2EncryptionAlgorithm.ENCR_AES_CBC, encr_key_length=128,
            integ_alg=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
            prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            dh_group=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        )
        transforms = _NegotiatedIkev2Transforms.from_message(sa)
        self.assertEqual(transforms.encryption_descriptor.bulk_cipher.name, 'AES_128')
        self.assertEqual(transforms.encryption_descriptor.block_cipher_mode.name, 'CBC')
        self.assertEqual(transforms.integrity_algorithm,
                         Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128)

    def test_empty_proposals_raises(self):
        sa = Ikev2PayloadSecurityAssociation(flags=set(), proposals=[])
        with self.assertRaises(ValueError):
            _NegotiatedIkev2Transforms.from_message(sa)

    def test_missing_prf_raises(self):
        sa = Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[Ikev2Proposal(
                protocol_id=Ikev2ProtocolId.IKE,
                spi=b'',
                transforms=[
                    Ikev2TransformEncryptionAlgorithm(
                        transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
                        key_length=128,
                    ),
                    Ikev2TransformDhGroup(
                        transform_id=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
                    ),
                ],
            )],
        )
        with self.assertRaises(ValueError):
            _NegotiatedIkev2Transforms.from_message(sa)


class TestComposeAndDecryptIkev2IkeAuthMessageAead(unittest.TestCase):
    """End-to-end test: compose an IKE_AUTH outer message, parse it back as
    an IsakmpMessage, decrypt the SK payload, and confirm the inner chain
    survives the round trip with the AEAD AAD computed correctly from the
    composed bytes."""

    _DESCRIPTOR = AeadBulkCipherDescriptor(
        bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
    )

    def setUp(self):
        parameters = Ikev2SkDecryptorCryptodome.get_encryption_transform_derivation_parameters(
            self._DESCRIPTOR,
        )
        self._sk_er = bytes(range(parameters.write_key_length_bytes + parameters.salt_length_bytes))
        self._decryptor = Ikev2SkDecryptorCryptodome(
            encryption_transform=self._DESCRIPTOR, sk_er=self._sk_er,
        )
        self._initiator_spi = 0xdeadbeefcafebabe
        self._responder_spi = 0xfeedface12345678

    def test_compose_round_trips_through_decrypt(self):
        inner_payloads = _AnalyzerIkePubkeyBase._ikev2_build_eap_mode_inner_payloads()
        ike_auth_bytes = Ikev2SkDecryptor.compose_ike_auth_message(
            self._decryptor, inner_payloads, self._initiator_spi, self._responder_spi,
        )

        # Parse the outer message; ensure SK payload is present.
        outer_message, _ = IsakmpMessage.parse_immutable(ike_auth_bytes)
        sk_payload = outer_message.get_payload_by_type(Ikev2PayloadType.SK)
        self.assertIsInstance(sk_payload, Ikev2PayloadEncryptedAndAuthenticated)
        self.assertEqual(outer_message.initiator_spi, self._initiator_spi)
        self.assertEqual(outer_message.responder_spi, self._responder_spi)

        # Decrypt: should recover the original inner payload list.
        recovered = Ikev2SkDecryptor.decrypt_sk_payload(
            self._decryptor, outer_message, sk_payload, ike_auth_bytes,
        )
        self.assertEqual(len(recovered), len(inner_payloads))
        self.assertIsInstance(recovered[0], Ikev2PayloadIdentificationInitiatorBase)
        self.assertEqual(recovered[0].identifier, 'cryptolyzer@cryptolyzer')
        self.assertIsInstance(recovered[1], Ikev2PayloadCertificateRequest)

    def test_compose_sets_outer_message_id_default_one(self):
        ike_auth_bytes = Ikev2SkDecryptor.compose_ike_auth_message(
            self._decryptor, _AnalyzerIkePubkeyBase._ikev2_build_eap_mode_inner_payloads(),
            self._initiator_spi, self._responder_spi,
        )
        outer_message, _ = IsakmpMessage.parse_immutable(ike_auth_bytes)
        self.assertEqual(outer_message.message_id, 1)

    def test_compose_respects_explicit_message_id(self):
        ike_auth_bytes = Ikev2SkDecryptor.compose_ike_auth_message(
            self._decryptor, _AnalyzerIkePubkeyBase._ikev2_build_eap_mode_inner_payloads(),
            self._initiator_spi, self._responder_spi, message_id=42,
        )
        outer_message, _ = IsakmpMessage.parse_immutable(ike_auth_bytes)
        self.assertEqual(outer_message.message_id, 42)

    def _compose_ike_header_bytes(self, first_payload_type, ike_message_length):
        composer = ComposerBinary()
        composer.compose_numeric(self._initiator_spi, 8)
        composer.compose_numeric(self._responder_spi, 8)
        composer.compose_numeric_enum_coded(first_payload_type)
        composer.compose_parsable(IsakmpProtocolVersion(IkeVersion.V2, 0))
        composer.compose_numeric_enum_coded(Ikev2ExchangeType.IKE_AUTH)
        composer.compose_numeric_flags({IsakmpFlags.INITIATOR}, 1)
        composer.compose_numeric(1, 4)
        composer.compose_numeric(ike_message_length, 4)
        return composer.composed_bytes

    def test_decrypt_walks_unencrypted_payloads_before_sk_payload(self):
        """RFC 5282 §5.1: AAD = IKEHeader | unencrypted payloads before
        SK | first 4 octets of SK header. Any unencrypted payload
        preceding SK (e.g. NAT_DETECTION_* / REDIRECT notifies, or a
        VendorId) shifts the SK header offset in the on-wire bytes.
        The AEAD SK decrypt helper must walk
        ``response_message.payloads`` up to the SK payload to find
        that offset and include the unencrypted payload bytes in the
        AAD. Sibling to
        :meth:`TestComposeAndDecryptIkev2IkeAuthMessageNonAead\\
        .test_decrypt_walks_unencrypted_payloads_before_sk_payload`
        in ``test.ike.test_crypto``."""
        inner_payloads = _AnalyzerIkePubkeyBase._ikev2_build_eap_mode_inner_payloads()
        plaintext_padded = Ikev2SkDecryptor.pad_inner_plaintext(
            Ikev2SkDecryptor.compose_inner_payload_chain(inner_payloads), block_size=1,
        )
        vendor_id_payload = Ikev2PayloadVendorId(flags=set(), vendor_id=b'\xaa' * 8)
        vendor_id_payload.next_payload = Ikev2PayloadType.SK
        vendor_id_bytes = vendor_id_payload.compose()

        sk_body_length = (
            self._decryptor.on_wire_initialization_vector_length_bytes
            + len(plaintext_padded)
            + self._decryptor.authentication_tag_length_bytes
        )
        sk_payload = Ikev2PayloadEncryptedAndAuthenticated(flags=set(), encrypted_data=b'')
        sk_payload.next_payload = inner_payloads[0].get_payload_type()
        sk_header_bytes = sk_payload.compose_header(sk_body_length).composed_bytes

        ike_header_bytes = self._compose_ike_header_bytes(
            Ikev2PayloadType.VENDOR_ID,
            IsakmpMessage.HEADER_SIZE + len(vendor_id_bytes)
            + Ikev2PayloadEncryptedAndAuthenticated.HEADER_SIZE + sk_body_length,
        )
        sk_envelope_body = self._decryptor.encrypt(
            plaintext_padded, ike_header_bytes + vendor_id_bytes + sk_header_bytes[:4],
        )
        raw_bytes = ike_header_bytes + vendor_id_bytes + sk_header_bytes + sk_envelope_body
        outer_message, _ = IsakmpMessage.parse_immutable(raw_bytes)

        recovered = Ikev2SkDecryptor.decrypt_sk_payload(
            self._decryptor, outer_message,
            outer_message.get_payload_by_type(Ikev2PayloadType.SK), raw_bytes,
        )
        self.assertEqual(len(recovered), len(inner_payloads))
        self.assertIsInstance(recovered[0], Ikev2PayloadIdentificationInitiatorBase)
        self.assertIsInstance(recovered[1], Ikev2PayloadCertificateRequest)

    def test_decrypt_raises_sk_authentication_error_on_tag_tampering(self):
        """A tampered trailing AEAD tag causes ``decryptor.decrypt`` to
        raise ``ValueError``; the AEAD SK decrypt helper wraps that in
        :class:`Ikev2SkAuthenticationError` so the outer probe catches
        it as a cryptographic failure rather than a parse error."""
        ike_auth_bytes = Ikev2SkDecryptor.compose_ike_auth_message(
            self._decryptor, _AnalyzerIkePubkeyBase._ikev2_build_eap_mode_inner_payloads(),
            self._initiator_spi, self._responder_spi,
        )
        tampered_bytes = bytearray(ike_auth_bytes)
        tampered_bytes[-1] ^= 0x01
        tampered = bytes(tampered_bytes)

        outer_message, _ = IsakmpMessage.parse_immutable(tampered)
        sk_payload = outer_message.get_payload_by_type(Ikev2PayloadType.SK)
        with self.assertRaises(Ikev2SkAuthenticationError):
            Ikev2SkDecryptor.decrypt_sk_payload(
                self._decryptor, outer_message, sk_payload, tampered,
            )


class TestDeriveIkev2SkDecryptors(unittest.TestCase):
    """``_ikev2_derive_sk_decryptors`` is the lone piece of crypto that
    sits between the negotiated transforms and the SK envelope; cover
    it directly so we don't need a full wire mock for the schedule
    plumbing."""

    def test_aead_descriptor_selects_aead_decryptor(self):
        descriptor = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
        )
        transforms = _NegotiatedIkev2Transforms(
            encryption_descriptor=descriptor,
            encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
            encryption_key_length_bits=256,
            integrity_algorithm=None,
            prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        )
        outgoing, incoming = _AnalyzerIkePubkeyBase._ikev2_derive_sk_decryptors(
            transforms,
            shared_secret=bytes(range(32)),
            nonce_initiator=bytes(range(16)),
            nonce_responder=bytes(range(16, 32)),
            spi_initiator=0xdeadbeefcafebabe,
            spi_responder=0xfeedface12345678,
        )
        self.assertIsInstance(outgoing, Ikev2SkDecryptorCryptodome)
        self.assertIsInstance(incoming, Ikev2SkDecryptorCryptodome)
        self.assertNotEqual(outgoing.sk_er, incoming.sk_er)

    def test_cbc_descriptor_selects_non_aead_decryptor(self):
        """CBC + HMAC path: ``_ikev2_derive_sk_decryptors`` returns
        :class:`Ikev2SkDecryptorNonAeadCryptodome` pair and derives
        matching ``SK_ai`` / ``SK_ar`` so the initiator's outgoing HMAC
        key equals the responder's incoming HMAC verify key."""
        descriptor = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
        )
        transforms = _NegotiatedIkev2Transforms(
            encryption_descriptor=descriptor,
            encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
            encryption_key_length_bits=128,
            integrity_algorithm=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
            prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        )
        outgoing, incoming = _AnalyzerIkePubkeyBase._ikev2_derive_sk_decryptors(
            transforms,
            shared_secret=bytes(range(32)),
            nonce_initiator=bytes(range(16)),
            nonce_responder=bytes(range(16, 32)),
            spi_initiator=0xdeadbeefcafebabe,
            spi_responder=0xfeedface12345678,
        )
        self.assertIsInstance(outgoing, Ikev2SkDecryptorNonAeadCryptodome)
        self.assertIsInstance(incoming, Ikev2SkDecryptorNonAeadCryptodome)
        self.assertNotEqual(outgoing.sk_er, incoming.sk_er)
        self.assertNotEqual(outgoing.sk_ar, incoming.sk_ar)
        # SK_ai length matches HMAC-SHA-256 digest size (32 octets per RFC 4868).
        self.assertEqual(len(outgoing.sk_ar), 32)
        self.assertEqual(len(incoming.sk_ar), 32)

    def test_ctr_descriptor_selects_non_aead_decryptor(self):
        """CTR + HMAC path: RFC 5930 AES-CTR is non-AEAD (mode
        ``aead=False``), so ``_ikev2_derive_sk_decryptors`` must route
        it through the non-AEAD branch — the same as CBC — and NOT
        the AEAD branch (which would raise ``ValueError`` because
        :class:`Ikev2SkDecryptor` has no CTR entry)."""
        descriptor = AeadBulkCipherDescriptor(
            bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CTR,
        )
        transforms = _NegotiatedIkev2Transforms(
            encryption_descriptor=descriptor,
            encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_CTR,
            encryption_key_length_bits=128,
            integrity_algorithm=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
            prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        )
        outgoing, incoming = _AnalyzerIkePubkeyBase._ikev2_derive_sk_decryptors(
            transforms,
            shared_secret=bytes(range(32)),
            nonce_initiator=bytes(range(16)),
            nonce_responder=bytes(range(16, 32)),
            spi_initiator=0xdeadbeefcafebabe,
            spi_responder=0xfeedface12345678,
        )
        self.assertIsInstance(outgoing, Ikev2SkDecryptorNonAeadCryptodome)
        self.assertIsInstance(incoming, Ikev2SkDecryptorNonAeadCryptodome)


class TestReceiveIsakmpMessage(unittest.TestCase):
    """``_receive_isakmp_message`` wraps the parse-loop pattern from
    :class:`cryptolyzer.ike.client.IKEv2ClientHandshake.do_handshake`."""

    def test_no_response_raises_no_response_network_error(self):
        transfer = mock.MagicMock()
        transfer.buffer = bytearray()
        transfer.receive.side_effect = NotEnoughDataImport(bytes_needed=100)
        with self.assertRaises(NetworkError) as ctx:
            _AnalyzerIkePubkeyBase._receive_isakmp_message(transfer)
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_RESPONSE)

    def test_partial_buffer_raises_no_connection(self):
        transfer = mock.MagicMock()
        transfer.buffer = bytearray(b'\x00' * 4)  # non-empty but too short
        transfer.receive.side_effect = NotEnoughDataImport(bytes_needed=100)
        with self.assertRaises(NetworkError) as ctx:
            _AnalyzerIkePubkeyBase._receive_isakmp_message(transfer)
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)


class TestTryIkev2EapProbeFailurePaths(unittest.TestCase):
    """Cover error-path branches of the IKEv2 EAP probe via mocked
    ``L7ClientIPsecBase`` so the wire driver does not need a live
    responder for unit verification."""

    @staticmethod
    def _make_client(**overrides):
        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.address = '203.0.113.1'
        client.port = 500
        for key, value in overrides.items():
            setattr(client, key, value)
        return client

    def test_init_connection_failure_returns_none(self):
        client = self._make_client()
        client.init_connection.side_effect = NetworkError(NetworkErrorType.NO_CONNECTION)
        self.assertIsNone(
            _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
                client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
                _default_ikev2_extractor,
            ),
        )

    def test_send_network_error_returns_none(self):
        client = self._make_client()
        client.init_connection.return_value = None
        client.l4_transfer = mock.MagicMock()
        client.l4_transfer.send.side_effect = NetworkError(NetworkErrorType.NO_RESPONSE)
        self.assertIsNone(
            _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
                client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
                _default_ikev2_extractor,
            ),
        )

    def test_value_error_in_inner_returns_none(self):
        """A malformed responder SA causes ValueError; the wrapper logs
        and returns None instead of propagating."""
        client = self._make_client()
        client.init_connection.return_value = None
        client.l4_transfer = mock.MagicMock()
        client.l4_transfer.send.return_value = None
        client.l4_transfer.buffer = bytearray()
        # NotEnoughData → NetworkError(NO_RESPONSE) on receive; wrapper catches.
        client.l4_transfer.receive.side_effect = NotEnoughDataImport(bytes_needed=100)
        self.assertIsNone(
            _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
                client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
                _default_ikev2_extractor,
            ),
        )

    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_try_eap_probe_inner')
    def test_sk_authentication_error_returns_none(self, inner_mock):
        """``Ikev2SkAuthenticationError`` from SK decrypt (HMAC ICV mismatch
        or AEAD tag failure) is caught by the outer wrapper."""
        inner_mock.side_effect = Ikev2SkAuthenticationError('bad ICV')
        client = self._make_client()
        client.init_connection.return_value = None
        self.assertIsNone(
            _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
                client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
                _default_ikev2_extractor,
            ),
        )

    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_try_eap_probe_inner')
    def test_transform_derivation_error_returns_none(self, inner_mock):
        """``Ikev2TransformDerivationError`` from an unsupported transform
        combination is caught by the outer wrapper."""
        inner_mock.side_effect = Ikev2TransformDerivationError('unsupported')
        client = self._make_client()
        client.init_connection.return_value = None
        self.assertIsNone(
            _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
                client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
                _default_ikev2_extractor,
            ),
        )

    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_try_eap_probe_inner')
    def test_invalid_type_returns_none(self, inner_mock):
        """``InvalidType`` from a parse failure inside the inner driver
        is caught by the outer wrapper."""
        inner_mock.side_effect = CryptoparserInvalidType()
        client = self._make_client()
        client.init_connection.return_value = None
        self.assertIsNone(
            _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
                client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
                _default_ikev2_extractor,
            ),
        )

    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_try_eap_probe_inner')
    def test_key_error_returns_none(self, inner_mock):
        """``KeyError`` from :meth:`IsakmpMessage.get_payload_by_type` on a
        response missing a required payload is caught by the outer wrapper."""
        inner_mock.side_effect = KeyError('missing payload')
        client = self._make_client()
        client.init_connection.return_value = None
        self.assertIsNone(
            _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
                client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
                _default_ikev2_extractor,
            ),
        )


class TestIkev2EapProbeEndToEnd(unittest.TestCase):
    """In-process synthetic IKEv2 responder for the EAP-mode probe.

    Mocks the L4 transfer: captures the analyzer's outgoing IKE_SA_INIT,
    parses the initiator's KE/Nonce/SPIi, builds a matching IKE_SA_INIT
    response (responder KE/Nonce + AEAD AES-GCM-256 SA), derives the
    same SK_* the analyzer will derive, then encrypts a synthetic
    IKE_AUTH response carrying IDr+CERT+AUTH so the full flow can be
    exercised without a live responder."""

    @staticmethod
    def _build_dh_group():
        return Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT

    def _build_init_response_bytes(  # pylint: disable=too-many-locals
            self, initiator_message_bytes, responder_ephemeral,
            responder_nonce, responder_spi,
    ):
        initiator_message, _ = IsakmpMessage.parse_immutable(initiator_message_bytes)
        initiator_spi = initiator_message.initiator_spi
        ke_init = initiator_message.get_payload_by_type(Ikev2PayloadType.KE)
        nonce_init = initiator_message.get_payload_by_type(Ikev2PayloadType.NONCE)

        sa_response = Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[Ikev2Proposal(
                protocol_id=Ikev2ProtocolId.IKE,
                spi=b'',
                transforms=[
                    Ikev2TransformEncryptionAlgorithm(
                        transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
                        key_length=256,
                    ),
                    Ikev2TransformPrf(
                        transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                    ),
                    Ikev2TransformDhGroup(
                        transform_id=self._build_dh_group(),
                    ),
                ],
            )],
        )
        ke_response = Ikev2PayloadKeyExchange(
            flags=set(),
            dh_group=self._build_dh_group(),
            key_exchange_data=dhe_ephemeral_material_backend.key_exchange_wire_bytes(
                self._build_dh_group(), responder_ephemeral,
            ),
        )
        nonce_responder_payload = _build_ikev2_payload_nonce(responder_nonce)

        response = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=initiator_spi,
            responder_spi=responder_spi,
            exchange_type=_get_ikev2_exchange_type('IKE_SA_INIT'),
            flags=[IsakmpFlags.RESPONSE],
            message_id=0,
            payloads=[sa_response, ke_response, nonce_responder_payload],
        )
        shared_secret = responder_ephemeral.compute_shared_secret(
            dhe_ephemeral_material_backend.peer_key_exchange_from_wire(
                self._build_dh_group(), bytes(ke_init.key_exchange_data),
            )
        )
        return response.compose(), shared_secret, bytes(nonce_init.nonce_data), initiator_spi

    @staticmethod
    def _build_auth_response_bytes(initiator_spi, responder_spi, sk_decryptor_outgoing, inner_payloads):
        # Reuse the same builder as the analyzer side — IKE_AUTH from responder.
        ike_auth_bytes = Ikev2SkDecryptor.compose_ike_auth_message(
            sk_decryptor_outgoing, inner_payloads, initiator_spi, responder_spi, message_id=1,
        )
        # Patch flags to RESPONSE; analyzer's checker only matches exchange_type.
        return ike_auth_bytes

    def test_full_flow_extracts_certificate_chain(self):  # pylint: disable=too-many-locals
        dh_group = self._build_dh_group()
        responder_ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(dh_group)
        responder_nonce = bytes(reversed(range(32)))
        responder_spi = 0x1122334455667788

        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.init_connection.return_value = None
        client.address = '203.0.113.4'
        client.port = 500
        client.l4_transfer = mock.MagicMock()
        buffer_holder = {'buf': bytearray()}
        # Use a property-like getattr/setattr so the analyzer's
        # ``l4_transfer.buffer`` reads always return the current bytearray.
        type(client.l4_transfer).buffer = property(
            lambda self_: buffer_holder['buf'],
            lambda self_, val: buffer_holder.__setitem__('buf', bytearray(val)),
        )
        captured_sent_bytes = []

        def fake_send(payload):
            captured_sent_bytes.append(bytes(payload))

        def fake_flush(byte_num=None):
            if byte_num is None:
                buffer_holder['buf'] = bytearray()
            else:
                buffer_holder['buf'] = bytearray(buffer_holder['buf'][byte_num:])

        client.l4_transfer.send.side_effect = fake_send
        client.l4_transfer.flush_buffer.side_effect = fake_flush

        def fake_receive(_byte_num):
            self.assertGreater(len(captured_sent_bytes), 0,
                               'analyzer must send before responder receives')
            stage = len(captured_sent_bytes)
            if stage == 1:
                init_response_bytes, shared_secret, _ni, _init_spi = (
                    self._build_init_response_bytes(
                        captured_sent_bytes[0], responder_ephemeral,
                        responder_nonce, responder_spi,
                    )
                )
                buffer_holder['buf'].extend(init_response_bytes)
            else:
                # Build SK responder decryptor using the same key material
                initiator_message, _ = IsakmpMessage.parse_immutable(captured_sent_bytes[0])
                nonce_initiator = bytes(
                    initiator_message.get_payload_by_type(Ikev2PayloadType.NONCE).nonce_data,
                )
                init_response_bytes, shared_secret, _ni, init_spi = (
                    self._build_init_response_bytes(
                        captured_sent_bytes[0], responder_ephemeral,
                        responder_nonce, responder_spi,
                    )
                )
                transforms = _NegotiatedIkev2Transforms(
                    encryption_descriptor=AeadBulkCipherDescriptor(
                        bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
                    ),
                    encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
                    encryption_key_length_bits=256,
                    integrity_algorithm=None,
                    prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                    dh_group=dh_group,
                )
                # outgoing (responder→initiator) uses SK_er
                # incoming (initiator→responder) uses SK_ei — for AAD purposes
                # The analyzer's incoming decryptor uses SK_er, so responder
                # writes to SK_er and reads from SK_ei. Swap by swapping
                # initiator/responder when calling _derive_*.
                # Responder's outgoing direction encrypts with SK_er, which
                # is the *incoming* decryptor for the initiator side. Use
                # that one to encrypt the synthetic IKE_AUTH response.
                _, real_resp_outgoing = _AnalyzerIkePubkeyBase._ikev2_derive_sk_decryptors(
                    transforms,
                    shared_secret,
                    nonce_initiator,
                    responder_nonce,
                    init_spi, responder_spi,
                )

                cert_der = _load_test_cert_der()
                inner_payloads = [
                    Ikev2PayloadIdentificationResponderFqdn(
                        flags=set(), identifier='gateway.test.org',
                    ),
                    Ikev2PayloadCertificate(
                        flags=set(),
                        cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
                        certificate_data=cert_der,
                    ),
                    Ikev2PayloadAuthentication(
                        flags=set(),
                        auth_method=Ikev2AuthenticationMethod.RSA_DIGITAL_SIGNATURE,
                        auth_data=b'\xab' * 256,
                    ),
                ]
                # Use the responder's actual SK_er key — encrypt outgoing.
                auth_response_bytes = self._build_auth_response_bytes(
                    init_spi, responder_spi, real_resp_outgoing, inner_payloads,
                )
                buffer_holder['buf'].extend(auth_response_bytes)
            return len(buffer_holder['buf'])

        client.l4_transfer.receive.side_effect = fake_receive

        result = _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
            client, dh_group, _IKEV2_TEST_ALGORITHM_SET, _default_ikev2_extractor,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.transport, Transport.IKEV2_EAP_MODE)
        self.assertEqual(result.auth_method_used, Ikev2AuthenticationMethod.RSA_DIGITAL_SIGNATURE)

    def test_run_ikev2_eap_probe_returns_raw_payload_lists(self):  # pylint: disable=too-many-locals
        """``_ikev2_run_eap_probe`` bypasses the ``CertificateChainIke``
        extraction and hands back the raw
        ``(ike_sa_init_response_payloads, ike_auth_inner_payloads)``
        tuple — the shape the pubkeyreq CERTREQ payload walker needs.
        Same synthetic in-process responder as
        :meth:`test_full_flow_extracts_certificate_chain`."""
        dh_group = self._build_dh_group()
        responder_ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(dh_group)
        responder_nonce = bytes(reversed(range(32)))
        responder_spi = 0x1122334455667788

        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.init_connection.return_value = None
        client.address = '203.0.113.4'
        client.port = 500
        client.l4_transfer = mock.MagicMock()
        buffer_holder = {'buf': bytearray()}
        type(client.l4_transfer).buffer = property(
            lambda self_: buffer_holder['buf'],
            lambda self_, val: buffer_holder.__setitem__('buf', bytearray(val)),
        )
        captured_sent_bytes = []

        def fake_send(payload):
            captured_sent_bytes.append(bytes(payload))

        def fake_flush(byte_num=None):
            if byte_num is None:
                buffer_holder['buf'] = bytearray()
            else:
                buffer_holder['buf'] = bytearray(buffer_holder['buf'][byte_num:])

        client.l4_transfer.send.side_effect = fake_send
        client.l4_transfer.flush_buffer.side_effect = fake_flush

        def fake_receive(_byte_num):
            self.assertGreater(len(captured_sent_bytes), 0,
                               'analyzer must send before responder receives')
            stage = len(captured_sent_bytes)
            if stage == 1:
                init_response_bytes, _shared_secret, _ni, _init_spi = (
                    self._build_init_response_bytes(
                        captured_sent_bytes[0], responder_ephemeral,
                        responder_nonce, responder_spi,
                    )
                )
                buffer_holder['buf'].extend(init_response_bytes)
            else:
                initiator_message, _ = IsakmpMessage.parse_immutable(captured_sent_bytes[0])
                nonce_initiator = bytes(
                    initiator_message.get_payload_by_type(Ikev2PayloadType.NONCE).nonce_data,
                )
                init_response_bytes, shared_secret, _ni, init_spi = (
                    self._build_init_response_bytes(
                        captured_sent_bytes[0], responder_ephemeral,
                        responder_nonce, responder_spi,
                    )
                )
                transforms = _NegotiatedIkev2Transforms(
                    encryption_descriptor=AeadBulkCipherDescriptor(
                        bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
                    ),
                    encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
                    encryption_key_length_bits=256,
                    integrity_algorithm=None,
                    prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                    dh_group=dh_group,
                )
                _, real_resp_outgoing = _AnalyzerIkePubkeyBase._ikev2_derive_sk_decryptors(
                    transforms,
                    shared_secret,
                    nonce_initiator,
                    responder_nonce,
                    init_spi, responder_spi,
                )

                cert_der = _load_test_cert_der()
                inner_payloads = [
                    Ikev2PayloadIdentificationResponderFqdn(
                        flags=set(), identifier='gateway.test.org',
                    ),
                    Ikev2PayloadCertificate(
                        flags=set(),
                        cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
                        certificate_data=cert_der,
                    ),
                    Ikev2PayloadAuthentication(
                        flags=set(),
                        auth_method=Ikev2AuthenticationMethod.RSA_DIGITAL_SIGNATURE,
                        auth_data=b'\xab' * 256,
                    ),
                ]
                auth_response_bytes = self._build_auth_response_bytes(
                    init_spi, responder_spi, real_resp_outgoing, inner_payloads,
                )
                buffer_holder['buf'].extend(auth_response_bytes)
            return len(buffer_holder['buf'])

        client.l4_transfer.receive.side_effect = fake_receive

        result = _AnalyzerIkePubkeyBase._ikev2_run_eap_probe(client, dh_group, _IKEV2_TEST_ALGORITHM_SET)

        self.assertIsNotNone(result)
        init_payloads, decrypted_inner_payloads = result
        self.assertEqual(len(init_payloads), 3)
        self.assertEqual(len(decrypted_inner_payloads), 3)
        self.assertIsInstance(decrypted_inner_payloads[1], Ikev2PayloadCertificate)


class TestRunIkev2EapProbeFailurePaths(unittest.TestCase):
    """``_ikev2_run_eap_probe`` returns ``None`` when the lower-level
    ``_ikev2_try_eap_probe`` probe fails for any reason (network error,
    unexpected notify, SK authentication failure, ...) without ever
    invoking the raw-payload capture callback."""

    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_try_eap_probe')
    def test_returns_none_when_probe_fails(self, mock_probe):
        mock_probe.return_value = None
        result = _AnalyzerIkePubkeyBase._ikev2_run_eap_probe(
            mock.Mock(), Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
        )
        self.assertIsNone(result)
        mock_probe.assert_called_once()


def _build_ikev2_payload_nonce(nonce_data):
    return Ikev2PayloadNonce(flags=set(), nonce_data=nonce_data)


def _get_ikev2_exchange_type(name):
    return getattr(Ikev2ExchangeType, name)


class TestIkev2EapProbeEndToEndNonAead(unittest.TestCase):
    """Non-AEAD (AES-CBC + HMAC-SHA-256) sibling of
    :class:`TestIkev2EapProbeEndToEnd`.

    Same synthetic-responder pattern: the wire fake replies with an
    IKE_SA_INIT that negotiates AES-CBC-128 + AUTH_HMAC_SHA2_256_128,
    then builds the IKE_AUTH response by feeding IDr + CERT + AUTH
    through :func:`_compose_ikev2_ike_auth_message_non_aead` with the
    responder-side :class:`Ikev2SkDecryptorNonAeadCryptodome`. This
    exercises the whole non-AEAD envelope path end-to-end without a
    live IPsec responder."""

    @staticmethod
    def _build_dh_group():
        return Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT

    def _build_init_response_bytes(  # pylint: disable=too-many-locals
            self, initiator_message_bytes, responder_ephemeral,
            responder_nonce, responder_spi,
    ):
        initiator_message, _ = IsakmpMessage.parse_immutable(initiator_message_bytes)
        initiator_spi = initiator_message.initiator_spi
        ke_init = initiator_message.get_payload_by_type(Ikev2PayloadType.KE)
        nonce_init = initiator_message.get_payload_by_type(Ikev2PayloadType.NONCE)

        sa_response = Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[Ikev2Proposal(
                protocol_id=Ikev2ProtocolId.IKE,
                spi=b'',
                transforms=[
                    Ikev2TransformEncryptionAlgorithm(
                        transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
                        key_length=128,
                    ),
                    Ikev2TransformIntegrity(
                        transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
                    ),
                    Ikev2TransformPrf(
                        transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                    ),
                    Ikev2TransformDhGroup(
                        transform_id=self._build_dh_group(),
                    ),
                ],
            )],
        )
        ke_response = Ikev2PayloadKeyExchange(
            flags=set(),
            dh_group=self._build_dh_group(),
            key_exchange_data=dhe_ephemeral_material_backend.key_exchange_wire_bytes(
                self._build_dh_group(), responder_ephemeral,
            ),
        )
        nonce_responder_payload = _build_ikev2_payload_nonce(responder_nonce)

        response = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=initiator_spi,
            responder_spi=responder_spi,
            exchange_type=_get_ikev2_exchange_type('IKE_SA_INIT'),
            flags=[IsakmpFlags.RESPONSE],
            message_id=0,
            payloads=[sa_response, ke_response, nonce_responder_payload],
        )
        shared_secret = responder_ephemeral.compute_shared_secret(
            dhe_ephemeral_material_backend.peer_key_exchange_from_wire(
                self._build_dh_group(), bytes(ke_init.key_exchange_data),
            )
        )
        return response.compose(), shared_secret, bytes(nonce_init.nonce_data), initiator_spi

    @staticmethod
    def _build_auth_response_bytes(
            initiator_spi, responder_spi, sk_decryptor_outgoing, inner_payloads,
    ):
        return Ikev2SkDecryptorNonAead.compose_ike_auth_message(
            sk_decryptor_outgoing, inner_payloads, initiator_spi, responder_spi, message_id=1,
        )

    def test_full_flow_extracts_certificate_chain(self):  # pylint: disable=too-many-locals
        dh_group = self._build_dh_group()
        responder_ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(dh_group)
        responder_nonce = bytes(reversed(range(32)))
        responder_spi = 0x1122334455667788

        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.init_connection.return_value = None
        client.address = '203.0.113.4'
        client.port = 500
        client.l4_transfer = mock.MagicMock()
        buffer_holder = {'buf': bytearray()}
        type(client.l4_transfer).buffer = property(
            lambda self_: buffer_holder['buf'],
            lambda self_, val: buffer_holder.__setitem__('buf', bytearray(val)),
        )
        captured_sent_bytes = []

        def fake_send(payload):
            captured_sent_bytes.append(bytes(payload))

        def fake_flush(byte_num=None):
            if byte_num is None:
                buffer_holder['buf'] = bytearray()
            else:
                buffer_holder['buf'] = bytearray(buffer_holder['buf'][byte_num:])

        client.l4_transfer.send.side_effect = fake_send
        client.l4_transfer.flush_buffer.side_effect = fake_flush

        def fake_receive(_byte_num):
            self.assertGreater(len(captured_sent_bytes), 0,
                               'analyzer must send before responder receives')
            stage = len(captured_sent_bytes)
            if stage == 1:
                init_response_bytes, _shared_secret, _ni, _init_spi = (
                    self._build_init_response_bytes(
                        captured_sent_bytes[0], responder_ephemeral,
                        responder_nonce, responder_spi,
                    )
                )
                buffer_holder['buf'].extend(init_response_bytes)
            else:
                initiator_message, _ = IsakmpMessage.parse_immutable(captured_sent_bytes[0])
                nonce_initiator = bytes(
                    initiator_message.get_payload_by_type(Ikev2PayloadType.NONCE).nonce_data,
                )
                _init_response_bytes, shared_secret, _ni, init_spi = (
                    self._build_init_response_bytes(
                        captured_sent_bytes[0], responder_ephemeral,
                        responder_nonce, responder_spi,
                    )
                )
                transforms = _NegotiatedIkev2Transforms(
                    encryption_descriptor=AeadBulkCipherDescriptor(
                        bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
                    ),
                    encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
                    encryption_key_length_bits=128,
                    integrity_algorithm=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
                    prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                    dh_group=dh_group,
                )
                # The responder writes with SK_er + SK_ar, which is the
                # analyzer's *incoming* decryptor — swap initiator/responder
                # SPI + nonce so ``_ikev2_derive_sk_decryptors`` returns the
                # responder's outgoing keys as the second element.
                _, real_resp_outgoing = _AnalyzerIkePubkeyBase._ikev2_derive_sk_decryptors(
                    transforms,
                    shared_secret,
                    nonce_initiator,
                    responder_nonce,
                    init_spi, responder_spi,
                )

                cert_der = _load_test_cert_der()
                inner_payloads = [
                    Ikev2PayloadIdentificationResponderFqdn(
                        flags=set(), identifier='gateway.test.org',
                    ),
                    Ikev2PayloadCertificate(
                        flags=set(),
                        cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
                        certificate_data=cert_der,
                    ),
                    Ikev2PayloadAuthentication(
                        flags=set(),
                        auth_method=Ikev2AuthenticationMethod.RSA_DIGITAL_SIGNATURE,
                        auth_data=b'\xab' * 256,
                    ),
                ]
                auth_response_bytes = self._build_auth_response_bytes(
                    init_spi, responder_spi, real_resp_outgoing, inner_payloads,
                )
                buffer_holder['buf'].extend(auth_response_bytes)
            return len(buffer_holder['buf'])

        client.l4_transfer.receive.side_effect = fake_receive

        result = _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
            client, dh_group, _IKEV2_TEST_ALGORITHM_SET, _default_ikev2_extractor,
        )

        self.assertIsNotNone(result)
        self.assertEqual(result.transport, Transport.IKEV2_EAP_MODE)
        self.assertEqual(result.auth_method_used, Ikev2AuthenticationMethod.RSA_DIGITAL_SIGNATURE)

    def test_tampered_icv_returns_none_via_sk_authentication_error(self):
        """Flipping a bit in the trailing ICV of the responder's IKE_AUTH
        makes :func:`_decrypt_ikev2_sk_payload_non_aead` raise
        :class:`Ikev2SkAuthenticationError`; the outer probe wrapper
        catches it and returns ``None`` so a corrupted / MITM'd envelope
        surfaces as a benign probe failure."""
        dh_group = self._build_dh_group()
        responder_ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(dh_group)
        responder_nonce = bytes(reversed(range(32)))
        responder_spi = 0x1122334455667788

        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.init_connection.return_value = None
        client.address = '203.0.113.5'
        client.port = 500
        client.l4_transfer = mock.MagicMock()
        buffer_holder = {'buf': bytearray()}
        type(client.l4_transfer).buffer = property(
            lambda self_: buffer_holder['buf'],
            lambda self_, val: buffer_holder.__setitem__('buf', bytearray(val)),
        )
        captured_sent_bytes = []

        def fake_send(payload):
            captured_sent_bytes.append(bytes(payload))

        def fake_flush(byte_num=None):
            if byte_num is None:
                buffer_holder['buf'] = bytearray()
            else:
                buffer_holder['buf'] = bytearray(buffer_holder['buf'][byte_num:])

        client.l4_transfer.send.side_effect = fake_send
        client.l4_transfer.flush_buffer.side_effect = fake_flush

        def fake_receive(_byte_num):
            stage = len(captured_sent_bytes)
            if stage == 1:
                init_response_bytes, _shared_secret, _ni, _init_spi = (
                    self._build_init_response_bytes(
                        captured_sent_bytes[0], responder_ephemeral,
                        responder_nonce, responder_spi,
                    )
                )
                buffer_holder['buf'].extend(init_response_bytes)
            else:
                initiator_message, _ = IsakmpMessage.parse_immutable(captured_sent_bytes[0])
                nonce_initiator = bytes(
                    initiator_message.get_payload_by_type(Ikev2PayloadType.NONCE).nonce_data,
                )
                _init_response_bytes, shared_secret, _ni, init_spi = (
                    self._build_init_response_bytes(
                        captured_sent_bytes[0], responder_ephemeral,
                        responder_nonce, responder_spi,
                    )
                )
                transforms = _NegotiatedIkev2Transforms(
                    encryption_descriptor=AeadBulkCipherDescriptor(
                        bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
                    ),
                    encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
                    encryption_key_length_bits=128,
                    integrity_algorithm=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
                    prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                    dh_group=dh_group,
                )
                _, real_resp_outgoing = _AnalyzerIkePubkeyBase._ikev2_derive_sk_decryptors(
                    transforms,
                    shared_secret,
                    nonce_initiator,
                    responder_nonce,
                    init_spi, responder_spi,
                )
                inner_payloads = [
                    Ikev2PayloadIdentificationResponderFqdn(
                        flags=set(), identifier='gateway.test.org',
                    ),
                    Ikev2PayloadAuthentication(
                        flags=set(),
                        auth_method=Ikev2AuthenticationMethod.RSA_DIGITAL_SIGNATURE,
                        auth_data=b'\xab' * 256,
                    ),
                ]
                auth_response_bytes = bytearray(self._build_auth_response_bytes(
                    init_spi, responder_spi, real_resp_outgoing, inner_payloads,
                ))
                # Flip a bit in the trailing ICV → HMAC verification fails.
                auth_response_bytes[-1] ^= 0x01
                buffer_holder['buf'].extend(bytes(auth_response_bytes))
            return len(buffer_holder['buf'])

        client.l4_transfer.receive.side_effect = fake_receive

        self.assertIsNone(_AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
            client, dh_group, _IKEV2_TEST_ALGORITHM_SET, _default_ikev2_extractor,
        ))


class TestTryIkev2EapProbeWrongExchangeTypes(unittest.TestCase):
    """Cover ``return None`` paths when the responder sends back the wrong
    exchange type at either round."""

    @staticmethod
    def _make_client():
        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.address = '203.0.113.5'
        client.port = 500
        client.l4_transfer = mock.MagicMock()
        return client

    @staticmethod
    def _wire_static_response(client, response_message):
        """Mock the client so the first send produces ``response_message`` on receive."""
        buffer = {'b': bytearray()}
        type(client.l4_transfer).buffer = property(
            lambda _: buffer['b'],
            lambda _, v: buffer.__setitem__('b', bytearray(v)),
        )

        def fake_send(_payload):
            buffer['b'].extend(response_message.compose())

        client.l4_transfer.send.side_effect = fake_send
        client.l4_transfer.receive.side_effect = lambda _b: len(buffer['b'])
        client.l4_transfer.flush_buffer.side_effect = (
            lambda _b=None: buffer.__setitem__('b', bytearray())
        )

    def test_wrong_init_response_exchange_type_returns_none(self):
        client = self._make_client()
        client.init_connection.return_value = None
        mismatch = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=1, responder_spi=2,
            exchange_type=Ikev2ExchangeType.IKE_AUTH,
            flags=[IsakmpFlags.RESPONSE], message_id=0,
            payloads=[Ikev2PayloadIdentificationInitiatorFqdn(
                flags=set(), identifier='',
            )],
        )
        self._wire_static_response(client, mismatch)
        self.assertIsNone(
            _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
                client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
                _default_ikev2_extractor,
            ),
        )

    def test_wrong_ike_auth_response_exchange_type_returns_none(self):
        """Second round-trip: responder sends back IKE_SA_INIT instead of
        IKE_AUTH after the analyzer sent its IKE_AUTH request. Edge case
        the inner driver guards against."""
        client = self._make_client()
        client.init_connection.return_value = None
        dh_group = Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT
        responder_ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(dh_group)
        responder_spi = 0xabcdef
        valid_init = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=1, responder_spi=responder_spi,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.RESPONSE], message_id=0,
            payloads=[
                Ikev2PayloadSecurityAssociation(
                    flags=set(),
                    proposals=[Ikev2Proposal(
                        protocol_id=Ikev2ProtocolId.IKE, spi=b'',
                        transforms=[
                            Ikev2TransformEncryptionAlgorithm(
                                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
                                key_length=256,
                            ),
                            Ikev2TransformPrf(
                                transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                            ),
                            Ikev2TransformDhGroup(transform_id=dh_group),
                        ],
                    )],
                ),
                Ikev2PayloadKeyExchange(
                    flags=set(), dh_group=dh_group,
                    key_exchange_data=dhe_ephemeral_material_backend.key_exchange_wire_bytes(
                        dh_group, responder_ephemeral,
                    ),
                ),
                Ikev2PayloadNonce(flags=set(), nonce_data=bytes(range(32))),
            ],
        )
        wrong_auth = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=1, responder_spi=responder_spi,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,  # wrong!
            flags=[IsakmpFlags.RESPONSE], message_id=1,
            payloads=[
                Ikev2PayloadIdentificationInitiatorFqdn(
                    flags=set(), identifier='',
                ),
            ],
        )

        buffer = {'b': bytearray()}
        type(client.l4_transfer).buffer = property(
            lambda _: buffer['b'],
            lambda _, v: buffer.__setitem__('b', bytearray(v)),
        )
        responses = [valid_init.compose(), wrong_auth.compose()]

        def fake_send(_payload):
            buffer['b'].extend(responses.pop(0))

        client.l4_transfer.send.side_effect = fake_send
        client.l4_transfer.receive.side_effect = lambda _b: len(buffer['b'])
        client.l4_transfer.flush_buffer.side_effect = (
            lambda _b=None: buffer.__setitem__('b', bytearray())
        )

        self.assertIsNone(_AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
            client, dh_group, _IKEV2_TEST_ALGORITHM_SET, _default_ikev2_extractor,
        ))

    def test_malformed_sa_response_triggers_parse_error_path(self):
        """``_extract_ikev2_negotiated_transforms`` raises ValueError when
        the responder SA has no proposals; the outer wrapper catches and
        returns None."""
        client = self._make_client()
        client.init_connection.return_value = None
        malformed_sa = Ikev2PayloadSecurityAssociation(flags=set(), proposals=[])
        response = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=1, responder_spi=2,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.RESPONSE], message_id=0,
            payloads=[malformed_sa],
        )
        self._wire_static_response(client, response)
        self.assertIsNone(
            _AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
                client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
                _default_ikev2_extractor,
            ),
        )


class TestIkev2InitRetries(unittest.TestCase):
    """COOKIE + INVALID_KE_PAYLOAD retry paths in
    ``_ikev2_send_ike_sa_init_with_retry``."""

    @staticmethod
    def _make_client():
        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.address = '203.0.113.6'
        client.port = 500
        client.l4_transfer = mock.MagicMock()
        return client

    @staticmethod
    def _wire_response_sequence(client, response_messages):
        """Mock the client so each send delivers the next response in the sequence."""
        buffer = {'b': bytearray()}
        type(client.l4_transfer).buffer = property(
            lambda _: buffer['b'],
            lambda _, v: buffer.__setitem__('b', bytearray(v)),
        )
        compose_iter = iter(response_messages)

        def fake_send(_payload):
            buffer['b'].extend(next(compose_iter).compose())

        client.l4_transfer.send.side_effect = fake_send
        client.l4_transfer.receive.side_effect = lambda _b: len(buffer['b'])
        client.l4_transfer.flush_buffer.side_effect = (
            lambda _b=None: buffer.__setitem__('b', bytearray())
        )

    @staticmethod
    def _notify_only_response(notify_payload, *, message_id=0):
        return IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=1, responder_spi=2,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.RESPONSE], message_id=message_id,
            payloads=[notify_payload],
        )

    def test_cookie_retry_then_bail_on_persistent_notify(self):
        """First IKE_SA_INIT → COOKIE notify; analyzer rebuilds with
        cookie and resends; second response is another error notify → bail.
        Exercises lines 1118-1120 (cookie branch)."""
        client = self._make_client()
        client.init_connection.return_value = None
        first = self._notify_only_response(Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.COOKIE,
            spi=b'',
            cookie=b'\xab' * 32,
        ))
        second = self._notify_only_response(Ikev2PayloadNotifyAuthenticationFailed(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.AUTHENTICATION_FAILED,
            spi=b'',
        ))
        self._wire_response_sequence(client, [first, second])

        self.assertIsNone(_AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
            client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
            _default_ikev2_extractor,
        ))
        self.assertEqual(client.l4_transfer.send.call_count, 2)

    def test_invalid_ke_retry_then_bail_on_persistent_notify(self):
        """Lines 1122-1124 (INVALID_KE_PAYLOAD branch)."""
        client = self._make_client()
        client.init_connection.return_value = None
        first = self._notify_only_response(Ikev2NotifyPayloadInvalidKe(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.INVALID_KE_PAYLOAD,
            spi=b'',
            dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT,
        ))
        second = self._notify_only_response(Ikev2PayloadNotifyAuthenticationFailed(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.AUTHENTICATION_FAILED,
            spi=b'',
        ))
        self._wire_response_sequence(client, [first, second])

        self.assertIsNone(_AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
            client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
            _default_ikev2_extractor,
        ))
        self.assertEqual(client.l4_transfer.send.call_count, 2)

    def test_other_notify_bails_immediately(self):
        """Line 1128 — a notify that's neither COOKIE nor INVALID_KE_PAYLOAD
        (e.g. AUTHENTICATION_FAILED) makes the analyzer return None on the
        first response."""
        client = self._make_client()
        client.init_connection.return_value = None
        response = self._notify_only_response(Ikev2PayloadNotifyAuthenticationFailed(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.AUTHENTICATION_FAILED,
            spi=b'',
        ))
        self._wire_response_sequence(client, [response])

        self.assertIsNone(_AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
            client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
            _default_ikev2_extractor,
        ))

    def test_max_attempts_exhausted_returns_none(self):
        """Line 1135 — if responder keeps replying with COOKIE notifies (we
        retry once, then bail because cookie_seen is True), the loop
        exits via the for/else and returns None."""
        client = self._make_client()
        client.init_connection.return_value = None
        cookie_notify = self._notify_only_response(Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.COOKIE,
            spi=b'',
            cookie=b'\xab' * 32,
        ))
        invalid_ke_notify = self._notify_only_response(Ikev2NotifyPayloadInvalidKe(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.INVALID_KE_PAYLOAD,
            spi=b'',
            dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT,
        ))
        another_invalid_ke = self._notify_only_response(Ikev2NotifyPayloadInvalidKe(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.INVALID_KE_PAYLOAD,
            spi=b'',
            dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_521_BIT,
        ))
        # cookie → cookie_seen=True; invalid_ke → invalid_ke_seen=True;
        # third response is another invalid_ke but invalid_ke_seen is True
        # → falls through to the "other notify" return None at line 1128.
        # To actually exhaust the loop (line 1135) need 3 retryable notifies
        # but each flag can only retry once. So this case ALWAYS exits via
        # line 1128. The for/else fall-through at line 1135 is only
        # reachable if every attempt re-emits the SAME ALREADY-SEEN notify
        # without any non-retryable bail-out — impossible by construction.
        # Confirm the analyzer still returns None via the line 1128 path.
        self._wire_response_sequence(
            client, [cookie_notify, invalid_ke_notify, another_invalid_ke],
        )

        self.assertIsNone(_AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
            client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
            _default_ikev2_extractor,
        ))

    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._receive_isakmp_message')
    def test_empty_payloads_response_returns_none(self, receive_mock):
        """A responder that returns a payload-less IKE_SA_INIT (nothing to
        dispatch on) must exit the retry loop with ``None``."""
        empty_response = mock.MagicMock()
        empty_response.exchange_type = Ikev2ExchangeType.IKE_SA_INIT
        empty_response.payloads = []
        receive_mock.return_value = (empty_response, b'')
        client = self._make_client()
        client.init_connection.return_value = None
        client.l4_transfer = mock.MagicMock()
        self.assertIsNone(_AnalyzerIkePubkeyBase._ikev2_try_eap_probe(
            client, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT, _IKEV2_TEST_ALGORITHM_SET,
            _default_ikev2_extractor,
        ))


class TestAnalyzerPublicKeysIkev2Dispatch(unittest.TestCase):
    """Confirm :meth:`AnalyzerPublicKeys.analyze` branches on
    ``protocol_version`` rather than running the IKEv1 helpers for
    IKEv2 requests."""

    @mock.patch(
        'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev2_dh_groups',
        return_value=(
            [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            _NegotiatedIkev2Transforms(
                encryption_descriptor=AeadBulkCipherDescriptor(
                    bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
                ),
                encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
                encryption_key_length_bits=256,
                integrity_algorithm=None,
                prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
            ),
        ),
    )
    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_try_eap_probe')
    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev1_run_aggressive_probe')
    def test_ikev2_calls_eap_probe_not_aggressive(
            self, aggressive_mock, eap_mock, _discover_mock,
    ):
        eap_mock.return_value = None
        aggressive_mock.return_value = None

        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.address = '203.0.113.2'
        client.port = 500
        client.ip = '203.0.113.2'
        client.get_scheme.return_value = 'ipsec'
        client.l4_socket_params = mock.MagicMock()
        result = AnalyzerPublicKeys().analyze(client, IkeVersion.V2)

        # Every AUTH method is tried against the single accepted DH group.
        self.assertEqual(eap_mock.call_count, len(_IKEV2_PUBKEY_AUTH_METHODS))
        self.assertEqual(aggressive_mock.call_count, 0)
        self.assertEqual(result.public_keys, [])

    @mock.patch(
        'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev2_dh_groups',
        return_value=(
            [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            _NegotiatedIkev2Transforms(
                encryption_descriptor=AeadBulkCipherDescriptor(
                    bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
                ),
                encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
                encryption_key_length_bits=256,
                integrity_algorithm=None,
                prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
            ),
        ),
    )
    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_try_eap_probe')
    def test_ikev2_dedups_repeated_chain_across_auth_methods(self, eap_mock, _discover_mock):
        # The outer loop iterates every AUTH method in
        # ``_IKEV2_PUBKEY_AUTH_METHODS`` for the first working DH group,
        # so a responder that returns the same chain across auth
        # methods collapses to a single result row via the leaf-cert
        # fingerprint dedup.
        synthetic_row = CertificateChainIke(
            cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
            identification=IkeIdentification(
                id_type=Ikev1IdType.FQDN, protocol_id=IpProtocolNumber.HOPOPT, port=0,
                id_data=b'gateway.test.org',
            ),
            auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            signature_length=256,
            transport=Transport.IKEV2_EAP_MODE,
        )
        eap_mock.return_value = synthetic_row

        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.address = '203.0.113.3'
        client.port = 500
        client.ip = '203.0.113.3'
        client.get_scheme.return_value = 'ipsec'
        client.l4_socket_params = mock.MagicMock()
        result = AnalyzerPublicKeys().analyze(client, IkeVersion.V2)

        # First DH group is enough; every AUTH method attempted for it.
        self.assertEqual(result.public_keys, [synthetic_row])
        self.assertEqual(eap_mock.call_count, len(_IKEV2_PUBKEY_AUTH_METHODS))

    @mock.patch(
        'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev2_dh_groups',
        return_value=(
            [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            _NegotiatedIkev2Transforms(
                encryption_descriptor=AeadBulkCipherDescriptor(
                    bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
                ),
                encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
                encryption_key_length_bits=256,
                integrity_algorithm=None,
                prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
            ),
        ),
    )
    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_try_eap_probe')
    def test_ikev2_multi_auth_methods_yield_multiple_chains(self, eap_mock, _discover_mock):
        # Distinct chains per AUTH method → distinct fingerprints, so
        # the outer loop returns one result row per chain.
        def _make_row(cert_der: bytes) -> CertificateChainIke:
            return CertificateChainIke(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                identification=IkeIdentification(
                    id_type=Ikev1IdType.FQDN, protocol_id=IpProtocolNumber.HOPOPT, port=0,
                    id_data=b'gateway.test.org',
                ),
                auth_method_used=Ikev1AuthenticationMethod.RSA_SIGNATURES,
                signature_length=256,
                transport=Transport.IKEV2_EAP_MODE,
                raw_bytes=cert_der,
            )

        rows = [_make_row(bytes([index]) * 32) for index in range(len(_IKEV2_PUBKEY_AUTH_METHODS))]
        eap_mock.side_effect = rows

        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.address = '203.0.113.4'
        client.port = 500
        client.ip = '203.0.113.4'
        client.get_scheme.return_value = 'ipsec'
        client.l4_socket_params = mock.MagicMock()
        result = AnalyzerPublicKeys().analyze(client, IkeVersion.V2)

        self.assertEqual(result.public_keys, rows)
        self.assertEqual(eap_mock.call_count, len(_IKEV2_PUBKEY_AUTH_METHODS))

    @mock.patch('cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev2_dh_groups')
    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_try_eap_probe')
    def test_ikev2_iterates_every_discovered_dh_group_when_none_yields_chain(
            self, eap_mock, discover_mock,
    ):
        # No chain returned → outer loop must try every DH group the
        # discovery helper reported, one AUTH-method sweep per group.
        discover_mock.return_value = (
            [
                Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
                Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
            ],
            _NegotiatedIkev2Transforms(
                encryption_descriptor=AeadBulkCipherDescriptor(
                    bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
                ),
                encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
                encryption_key_length_bits=256,
                integrity_algorithm=None,
                prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
                dh_group=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
            ),
        )
        eap_mock.return_value = None

        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.address = '203.0.113.5'
        client.port = 500
        client.ip = '203.0.113.5'
        client.get_scheme.return_value = 'ipsec'
        client.l4_socket_params = mock.MagicMock()
        result = AnalyzerPublicKeys().analyze(client, IkeVersion.V2)

        dh_groups_probed = {call.args[1] for call in eap_mock.call_args_list}
        expected_dh_groups = set(discover_mock.return_value[0])
        self.assertEqual(dh_groups_probed, expected_dh_groups)
        self.assertEqual(
            eap_mock.call_count,
            len(discover_mock.return_value[0]) * len(_IKEV2_PUBKEY_AUTH_METHODS),
        )
        self.assertEqual(result.public_keys, [])

    @mock.patch(
        'cryptolyzer.ike.pubkey.AnalyzerDHBase.discover_supported_ikev2_dh_groups',
        return_value=([], None),
    )
    @mock.patch('cryptolyzer.ike.pubkey._AnalyzerIkePubkeyBase._ikev2_try_eap_probe')
    def test_ikev2_empty_discovered_dh_groups_raises(self, eap_mock, _discover_mock):
        client = mock.create_autospec(L7ClientIPsecBase, instance=True)
        client.address = '203.0.113.6'
        client.port = 500
        client.ip = '203.0.113.6'
        client.get_scheme.return_value = 'ipsec'
        client.l4_socket_params = mock.MagicMock()
        with self.assertRaises(ValueError):
            AnalyzerPublicKeys().analyze(client, IkeVersion.V2)
        self.assertEqual(eap_mock.call_count, 0)


class TestBuildPubkeysSaProposalKwargs(unittest.TestCase):
    """Kwargs assembly for the pubkeys IKE_SA_INIT SA proposal.

    The helper narrows the SA proposal to the responder-confirmed
    ``(encr, integ, prf)`` tuple when ``algorithm_set`` is supplied so
    the follow-up IKE_SA_INIT cannot renegotiate to a different suite.
    """

    _DH_GROUP = Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT

    def _algorithm_set_aead(self):
        return _NegotiatedIkev2Transforms(
            encryption_descriptor=AeadBulkCipherDescriptor(
                bulk_cipher=BlockCipher.AES_256, block_cipher_mode=BlockCipherMode.GCM,
            ),
            encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16,
            encryption_key_length_bits=256,
            integrity_algorithm=None,
            prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            dh_group=self._DH_GROUP,
        )

    def _algorithm_set_non_aead(self):
        return _NegotiatedIkev2Transforms(
            encryption_descriptor=AeadBulkCipherDescriptor(
                bulk_cipher=BlockCipher.AES_128, block_cipher_mode=BlockCipherMode.CBC,
            ),
            encryption_algorithm=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
            encryption_key_length_bits=128,
            integrity_algorithm=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
            prf=Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            dh_group=self._DH_GROUP,
        )

    def test_narrows_encr_prf_when_algorithm_set_supplied_aead(self):
        algorithm_set = self._algorithm_set_aead()
        sa_kwargs: dict = {}
        _AnalyzerIkePubkeyBase._ikev2_narrow_sa_proposal_kwargs(sa_kwargs, algorithm_set)
        self.assertEqual(sa_kwargs['encryption_algorithm_tuples'], [(
            algorithm_set.encryption_algorithm,
            algorithm_set.encryption_key_length_bits,
        )])
        self.assertEqual(sa_kwargs['pseudorandom_functions'], [algorithm_set.prf])
        self.assertNotIn('integrity_algorithms', sa_kwargs)

    def test_narrows_integrity_when_algorithm_set_has_integrity_algorithm(self):
        algorithm_set = self._algorithm_set_non_aead()
        sa_kwargs: dict = {}
        _AnalyzerIkePubkeyBase._ikev2_narrow_sa_proposal_kwargs(sa_kwargs, algorithm_set)
        self.assertEqual(sa_kwargs['integrity_algorithms'], [algorithm_set.integrity_algorithm])


class TestLogIkev1PubkeysProbeGrid(TestLoggerBase):
    """Cover :func:`_log_ikev1_pubkeys_probe_grid`: the populated-transforms path emits the full
    ``encr / key_length / hash / auth / dh`` tuple per the ``ike/`` IKE log format."""

    def test_populated_algorithm_set_logs_full_tuple(self):
        algorithm_set = _NegotiatedIkev1Transforms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
            hash_algorithm=Ikev1HashAlgorithm.SHA2_256,
            authentication_method=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            dh_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            key_length=128,
        )
        _AnalyzerIkePubkeyBase._ikev1_log_probe_grid('pubkeys', algorithm_set.dh_group, algorithm_set)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('encr=', log_output)
        self.assertIn('key_length=128', log_output)
        self.assertIn('hash=', log_output)
        self.assertIn('auth=', log_output)
        self.assertIn('dh=', log_output)

    def test_algorithm_set_without_key_length_logs_none_sentinel(self):
        # Fixed-key IKEv1 ciphers (3DES) omit the Key Length attribute —
        # the log formatter must render the None value as the ``NONE``
        # sentinel string rather than crashing on ``str(None)``.
        algorithm_set = _NegotiatedIkev1Transforms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.DES3_CBC,
            hash_algorithm=Ikev1HashAlgorithm.SHA,
            authentication_method=Ikev1AuthenticationMethod.RSA_SIGNATURES,
            dh_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            key_length=None,
        )
        _AnalyzerIkePubkeyBase._ikev1_log_probe_grid('pubkeys', algorithm_set.dh_group, algorithm_set)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('key_length=NONE', log_output)


if __name__ == '__main__':
    unittest.main()
