# -*- coding: utf-8 -*-

import collections
import unittest
import unittest.mock

from cryptodatahub.common.algorithm import BlockCipherMode
from cryptodatahub.ike.algorithm import (
    Ikev1AttributeType,
    Ikev1AuthenticationMethod,
    Ikev1DiffieHellmanGroup,
    Ikev1EncryptionAlgorithm,
    Ikev1ExchangeType,
    Ikev1HashAlgorithm,
    Ikev1NotifyType,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2ExchangeType,
    Ikev2IntegrityAlgorithm,
    Ikev2NotifyType,
    Ikev2ProtocolId,
    Ikev2PseudorandomFunction,
    Ikev2TransformType,
)
from cryptodatahub.ike.version import IkeVersion
from cryptoparser.ike.isakmp import IsakmpFlags, IsakmpMessage, IsakmpProtocolVersion
from cryptoparser.ike.ikev2 import (
    Ikev2NotifyPayloadInvalidKe,
    Ikev2PayloadFlags,
    Ikev2PayloadSecurityAssociation,
    Ikev2Proposal as Ikev2ProposalPayload,
    Ikev2TransformDhGroup,
    Ikev2TransformEncryptionAlgorithm,
    Ikev2TransformIntegrity,
    Ikev2TransformPrf,
)
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.ike.ciphers import (
    AnalyzerCiphers,
    Ikev1CipherSuite as Ikev1CipherSuiteCiphers,
    Ikev2CipherSuite as Ikev2CipherSuiteCiphers,
)
from cryptolyzer.ike.client import (
    Ikev1SecurityAssociationProposalAlgorithms,
    L7ClientIPsecBase,
)
from cryptolyzer.ike.common import Ikev1CipherSuite, Ikev2CipherSuite
from cryptolyzer.ike.exception import IsakmpNotify


def _make_mock_client():
    """Construct a real L7ClientIPsecBase without any network I/O.

    `from_scheme` is a pure constructor; the actual network call happens in
    `init_connection`, which we never trigger because do_ikev*_handshake is
    patched in each test.
    """
    return L7ClientIPsecBase.from_scheme(
        'ipsec',
        'localhost',
        500,
        L4TransferSocketParams(timeout=1.0),
        ip='127.0.0.1',
    )


def _raise_ikev1_notify(notify_type):
    """Return a side_effect callable that raises IsakmpNotify with empty server_messages.

    Mimics the real client.py:892 assignment so the analyzer's
    `e.server_messages` check in INVALID_KEY_INFORMATION handling sees an
    empty dict.
    """
    def _side_effect(*_args, **_kwargs):
        exception = IsakmpNotify(notify_type)
        exception.server_messages = {}
        raise exception
    return _side_effect


def _make_ikev1_sa_response_messages(encr, dh, hash_algo, auth, key_length):
    """Build a mock-based IKEv1 IDENTITY_PROTECTION server_messages dict.

    `_get_algorithm_from_server_messages_ikev1` only walks a small subset of
    the cryptoparser API (`get_payload_by_type`, `proposals[0].transforms[0]`,
    `transform.get_attribute_by_type(...).value`). Building real
    `Ikev1PayloadSecurityAssociation` instances would require constructing
    every wire-level attribute; mocks satisfy the access pattern with far
    less ceremony.
    """
    def _attribute(value):
        attribute = unittest.mock.MagicMock()
        attribute.value = value
        return attribute

    attributes = {
        Ikev1AttributeType.ENCRYPTION_ALGORITHM: _attribute(encr),
        Ikev1AttributeType.GROUP_DESCRIPTION: _attribute(dh),
        Ikev1AttributeType.HASH_ALGORITHM: _attribute(hash_algo),
        Ikev1AttributeType.AUTHENTICATION_METHOD: _attribute(auth),
    }
    if key_length is not None:
        attributes[Ikev1AttributeType.KEY_LENGTH] = _attribute(key_length)

    transform = unittest.mock.MagicMock()
    transform.get_attribute_by_type.side_effect = lambda t: attributes[t]

    sa_payload = unittest.mock.MagicMock()
    sa_payload.proposals = [unittest.mock.MagicMock()]
    sa_payload.proposals[0].transforms = [transform]

    response_message = unittest.mock.MagicMock()
    response_message.get_payload_by_type.return_value = sa_payload

    return {Ikev1ExchangeType.IDENTITY_PROTECTION: [response_message]}


def _make_ikev2_sa_response(transforms):
    """Build a real IKE_SA_INIT IsakmpMessage carrying a single proposal."""
    proposal = Ikev2ProposalPayload(
        protocol_id=Ikev2ProtocolId.IKE,
        transforms=transforms,
        spi=bytes(),
    )
    sa_payload = Ikev2PayloadSecurityAssociation(
        flags=set([Ikev2PayloadFlags.CRITICAL]),
        proposals=[proposal],
    )
    message = IsakmpMessage(
        version=IsakmpProtocolVersion(IkeVersion.V2, 0),
        initiator_spi=1,
        responder_spi=2,
        exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
        flags=[IsakmpFlags.RESPONSE],
        message_id=0,
        payloads=[sa_payload],
    )
    return {Ikev2ExchangeType.IKE_SA_INIT: message}


class TestCipherSuiteUnit(unittest.TestCase):
    def test_ikev1_cipher_suite_invalid_key_length(self):
        with self.assertRaises(ValueError):
            Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(
                Ikev1SecurityAssociationProposalAlgorithms(
                    encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
                    diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_1024_BIT,
                    hash_algorithm=Ikev1HashAlgorithm.SHA,
                    authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                    key_length=999,
                )
            )

    def test_ikev1_cipher_suite_ciphers_invalid_key_length(self):
        with self.assertRaises(ValueError):
            Ikev1CipherSuiteCiphers.from_ikev1_security_association_proposal_algorithms(
                Ikev1SecurityAssociationProposalAlgorithms(
                    encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
                    diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_1024_BIT,
                    hash_algorithm=Ikev1HashAlgorithm.SHA,
                    authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                    key_length=999,
                )
            )

    def test_ikev1_cipher_suite_ciphers_fixed_key(self):
        suite = Ikev1CipherSuiteCiphers.from_ikev1_security_association_proposal_algorithms(
            Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=Ikev1EncryptionAlgorithm.DES3_CBC,
                diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_1024_BIT,
                hash_algorithm=Ikev1HashAlgorithm.SHA,
                authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                key_length=None,
            )
        )
        self.assertEqual(suite.block_cipher_mode, BlockCipherMode.CBC)

    def test_ikev2_cipher_suite_invalid_key_length(self):
        with self.assertRaises(ValueError):
            Ikev2CipherSuite.from_transform_ids(
                encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
                integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
                pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
                diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT,
                key_length=999,
            )

    def test_ikev2_cipher_suite_ciphers_invalid_key_length(self):
        with self.assertRaises(ValueError):
            Ikev2CipherSuiteCiphers.from_transform_ids(
                encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
                integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
                pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
                diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT,
                key_length=999,
            )

    def test_ikev2_cipher_suite_ciphers_fixed_key(self):
        suite = Ikev2CipherSuiteCiphers.from_transform_ids(
            encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_CHACHA20_POLY1305,
            integrity_transform_id=Ikev2IntegrityAlgorithm.NONE,
            pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT,
            key_length=None,
        )
        self.assertIsNone(suite.integrity_algorithm)
        self.assertIsNone(suite.block_cipher_mode)


class TestAnalyzerCiphersUnit(unittest.TestCase):
    def test_get_name(self):
        self.assertEqual(AnalyzerCiphers.get_name(), 'ciphers')

    def test_get_help(self):
        self.assertIsInstance(AnalyzerCiphers.get_help(), str)

    def test_ikev2_invalid_ke_known_dh(self):
        dh_list = [
            Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT,
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        ]
        accepted = set()
        notify = unittest.mock.MagicMock()
        notify.dh_group = Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT
        result = AnalyzerCiphers._handle_invalid_ke_payload_ikev2(  # pylint: disable=protected-access
            notify, dh_list, accepted,
        )
        self.assertEqual(result, Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT)
        self.assertIn(Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT, accepted)

    def test_ikev2_invalid_ke_unknown_dh(self):
        dh_list = [Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT]
        accepted = set()
        notify = unittest.mock.MagicMock()
        notify.dh_group = Ikev2DiffieHellmanGroup.MODP_GROUP_8192_BIT
        result = AnalyzerCiphers._handle_invalid_ke_payload_ikev2(  # pylint: disable=protected-access
            notify, dh_list, accepted,
        )
        self.assertIsNone(result)
        self.assertEqual(accepted, set())

    def test_ikev1_extract_algorithm_multi_bulk(self):
        server_messages = _make_ikev1_sa_response_messages(
            encr=Ikev1EncryptionAlgorithm.AES_CBC,
            dh=Ikev1DiffieHellmanGroup.MODP_1024_BIT,
            hash_algo=Ikev1HashAlgorithm.SHA,
            auth=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
            key_length=128,
        )
        result = AnalyzerCiphers._get_algorithm_from_server_messages_ikev1(  # pylint: disable=protected-access
            server_messages,
        )
        self.assertEqual(result.encryption_algorithm, Ikev1EncryptionAlgorithm.AES_CBC)
        self.assertEqual(result.key_length, 128)
        self.assertEqual(result.diffie_hellman_group, Ikev1DiffieHellmanGroup.MODP_1024_BIT)
        self.assertEqual(result.hash_algorithm, Ikev1HashAlgorithm.SHA)
        self.assertEqual(result.authentication_method, Ikev1AuthenticationMethod.PRE_SHARED_KEY)

    def test_ikev1_extract_algorithm_single_bulk(self):
        server_messages = _make_ikev1_sa_response_messages(
            encr=Ikev1EncryptionAlgorithm.DES3_CBC,
            dh=Ikev1DiffieHellmanGroup.MODP_1024_BIT,
            hash_algo=Ikev1HashAlgorithm.SHA,
            auth=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
            key_length=None,
        )
        result = AnalyzerCiphers._get_algorithm_from_server_messages_ikev1(  # pylint: disable=protected-access
            server_messages,
        )
        self.assertEqual(result.encryption_algorithm, Ikev1EncryptionAlgorithm.DES3_CBC)
        self.assertIsNone(result.key_length)

    def test_ikev2_extract_cipher_suite_aead(self):
        sa_response = _make_ikev2_sa_response([
            Ikev2TransformEncryptionAlgorithm(
                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_GCM_128_16, key_length=128,
            ),
            Ikev2TransformPrf(transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1),
            Ikev2TransformDhGroup(transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT),
        ])
        suite = AnalyzerCiphers._get_cipher_suite_from_server_messages_ikev2(  # pylint: disable=protected-access
            sa_response,
        )
        self.assertEqual(suite.block_cipher_mode, BlockCipherMode.GCM_16)
        self.assertIsNone(suite.integrity_algorithm)

    def test_ikev2_response_key_encr(self):
        sa_payload = unittest.mock.MagicMock()
        transform = unittest.mock.MagicMock()
        transform.transform_id = Ikev2EncryptionAlgorithm.ENCR_AES_CBC
        transform.key_length = 128
        sa_payload.get_transform_by_type.return_value = transform
        result = AnalyzerCiphers._get_response_key_ikev2(  # pylint: disable=protected-access
            Ikev2TransformType.ENCR, sa_payload,
        )
        self.assertEqual(result, (Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128))

    def test_ikev2_response_key_non_encr(self):
        sa_payload = unittest.mock.MagicMock()
        transform = unittest.mock.MagicMock()
        transform.transform_id = Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT
        sa_payload.get_transform_by_type.return_value = transform
        result = AnalyzerCiphers._get_response_key_ikev2(  # pylint: disable=protected-access
            Ikev2TransformType.DH, sa_payload,
        )
        self.assertEqual(result, Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT)

    def test_ikev1_send_invalid_key_information_with_messages(self):
        l7_client = unittest.mock.MagicMock()

        def raise_invalid_key(*_args, **_kwargs):
            exception = IsakmpNotify(Ikev1NotifyType.INVALID_KEY_INFORMATION)
            exception.server_messages = _make_ikev1_sa_response_messages(
                encr=Ikev1EncryptionAlgorithm.AES_CBC,
                dh=Ikev1DiffieHellmanGroup.MODP_1024_BIT,
                hash_algo=Ikev1HashAlgorithm.SHA,
                auth=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                key_length=128,
            )
            raise exception

        l7_client.do_ikev1_handshake.side_effect = raise_invalid_key
        with self.assertRaises(StopIteration) as ctx:
            AnalyzerCiphers._send_ikev1_init_message(  # pylint: disable=protected-access
                l7_client,
                init_message=unittest.mock.MagicMock(),
                algorithms=[],
            )
        offered = ctx.exception.value
        self.assertEqual(offered.encryption_algorithm, Ikev1EncryptionAlgorithm.AES_CBC)

    def test_ikev1_send_network_error_no_connection_reraises(self):
        l7_client = unittest.mock.MagicMock()
        l7_client.do_ikev1_handshake.side_effect = NetworkError(NetworkErrorType.NO_CONNECTION)
        with self.assertRaises(NetworkError):
            AnalyzerCiphers._send_ikev1_init_message(  # pylint: disable=protected-access
                l7_client,
                init_message=unittest.mock.MagicMock(),
                algorithms=[],
            )

    def test_enumerate_branch_ikev2_invalid_ke_unknown_dh(self):
        analyzer = AnalyzerCiphers()
        analyzer._probe_attempt = 0  # pylint: disable=protected-access
        l7_client = _make_mock_client()

        def raise_unknown_dh(*_args, **_kwargs):
            payload = Ikev2NotifyPayloadInvalidKe(
                flags=set(),
                protocol_id=Ikev2ProtocolId.IKE,
                type=Ikev2NotifyType.INVALID_KE_PAYLOAD,
                spi=b'',
                dh_group=Ikev2DiffieHellmanGroup.MODP_GROUP_8192_BIT,
            )
            raise IsakmpNotify(Ikev2NotifyType.INVALID_KE_PAYLOAD, payload)

        accepted = set()
        with unittest.mock.patch.object(l7_client, 'do_ikev2_handshake', side_effect=raise_unknown_dh):
            result = analyzer._enumerate_branch_ikev2(  # pylint: disable=protected-access
                l7_client=l7_client,
                algorithms=collections.OrderedDict([
                    (Ikev2TransformType.ENCR, [(Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128)]),
                    (Ikev2TransformType.DH, [Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT]),
                    (Ikev2TransformType.PRF, [Ikev2PseudorandomFunction.PRF_HMAC_SHA1]),
                    (Ikev2TransformType.INTEG, [Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96]),
                ]),
                accepted_dh_groups=accepted,
            )
        self.assertEqual(result, [])
        self.assertEqual(accepted, set())

    def test_enumerate_branch_ikev2_response_missing_transform(self):
        analyzer = AnalyzerCiphers()
        analyzer._probe_attempt = 0  # pylint: disable=protected-access
        l7_client = _make_mock_client()
        sa_response = _make_ikev2_sa_response([
            Ikev2TransformEncryptionAlgorithm(
                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC, key_length=128,
            ),
            Ikev2TransformIntegrity(transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96),
            Ikev2TransformPrf(transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1),
            Ikev2TransformDhGroup(transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT),
        ])
        with unittest.mock.patch.object(l7_client, 'do_ikev2_handshake', return_value=sa_response), \
             unittest.mock.patch.object(AnalyzerCiphers, '_get_response_key_ikev2', side_effect=KeyError('test')):
            result = analyzer._enumerate_branch_ikev2(  # pylint: disable=protected-access
                l7_client=l7_client,
                algorithms=collections.OrderedDict([
                    (Ikev2TransformType.ENCR, [(Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128)]),
                    (Ikev2TransformType.DH, [Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT]),
                    (Ikev2TransformType.PRF, [Ikev2PseudorandomFunction.PRF_HMAC_SHA1]),
                    (Ikev2TransformType.INTEG, [Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96]),
                ]),
                accepted_dh_groups=set(),
            )
        self.assertEqual(len(result), 1)

    def test_enumerate_branch_ikev2_axis_exhausted(self):
        analyzer = AnalyzerCiphers()
        analyzer._probe_attempt = 0  # pylint: disable=protected-access
        l7_client = _make_mock_client()
        sa_response = _make_ikev2_sa_response([
            Ikev2TransformEncryptionAlgorithm(
                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC, key_length=128,
            ),
            Ikev2TransformIntegrity(transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96),
            Ikev2TransformPrf(transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1),
            Ikev2TransformDhGroup(transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT),
        ])
        with unittest.mock.patch.object(l7_client, 'do_ikev2_handshake', return_value=sa_response):
            result = analyzer._enumerate_branch_ikev2(  # pylint: disable=protected-access
                l7_client=l7_client,
                algorithms=collections.OrderedDict([
                    (Ikev2TransformType.ENCR, [(Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128)]),
                    (Ikev2TransformType.DH, [Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT]),
                    (Ikev2TransformType.PRF, [Ikev2PseudorandomFunction.PRF_HMAC_SHA1]),
                    (Ikev2TransformType.INTEG, [Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96]),
                ]),
                accepted_dh_groups=set(),
            )
        self.assertGreaterEqual(len(result), 1)

    def test_enumerate_branch_ikev2_preseed_keyerror_skipped(self):
        analyzer = AnalyzerCiphers()
        analyzer._probe_attempt = 0  # pylint: disable=protected-access
        l7_client = _make_mock_client()
        sa_response = _make_ikev2_sa_response([
            Ikev2TransformEncryptionAlgorithm(
                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC, key_length=128,
            ),
            Ikev2TransformIntegrity(transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96),
            Ikev2TransformPrf(transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1),
            Ikev2TransformDhGroup(transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT),
        ])

        def side_effect(transform_type, sa_payload):  # pylint: disable=unused-argument
            if transform_type == Ikev2TransformType.ENCR:
                return (Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128)
            raise KeyError(transform_type)

        with unittest.mock.patch.object(l7_client, 'do_ikev2_handshake', return_value=sa_response), \
             unittest.mock.patch.object(AnalyzerCiphers, '_get_response_key_ikev2', side_effect=side_effect):
            result = analyzer._enumerate_branch_ikev2(  # pylint: disable=protected-access
                l7_client=l7_client,
                algorithms=collections.OrderedDict([
                    (Ikev2TransformType.ENCR, [(Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128)]),
                    (Ikev2TransformType.DH, [Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT]),
                    (Ikev2TransformType.PRF, [Ikev2PseudorandomFunction.PRF_HMAC_SHA1]),
                    (Ikev2TransformType.INTEG, [Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96]),
                ]),
                accepted_dh_groups=set(),
            )
        self.assertGreaterEqual(len(result), 1)

    def test_enumerate_branch_ikev2_skips_empty_axis(self):
        analyzer = AnalyzerCiphers()
        analyzer._probe_attempt = 0  # pylint: disable=protected-access
        algorithms = collections.OrderedDict([
            (Ikev2TransformType.ENCR, []),
            (Ikev2TransformType.DH, []),
            (Ikev2TransformType.PRF, []),
            (Ikev2TransformType.INTEG, []),
        ])
        result = analyzer._enumerate_branch_ikev2(  # pylint: disable=protected-access
            l7_client=unittest.mock.MagicMock(),
            algorithms=algorithms,
            accepted_dh_groups=set(),
        )
        self.assertEqual(result, [])

    def test_enumerate_branch_ikev2_no_redundant_phase_probes(self):
        # With one value per axis the ENCR probe reveals all axis values via the
        # SA response; phase-transition pre-seeding must skip DH, PRF, and INTEG
        # phases entirely — exactly one handshake call, not four.
        analyzer = AnalyzerCiphers()
        analyzer._probe_attempt = 0  # pylint: disable=protected-access
        l7_client = _make_mock_client()
        sa_response = _make_ikev2_sa_response([
            Ikev2TransformEncryptionAlgorithm(
                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC, key_length=128,
            ),
            Ikev2TransformIntegrity(transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96),
            Ikev2TransformPrf(transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1),
            Ikev2TransformDhGroup(transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT),
        ])
        with unittest.mock.patch.object(
            l7_client, 'do_ikev2_handshake', return_value=sa_response,
        ) as mock_handshake:
            result = analyzer._enumerate_branch_ikev2(  # pylint: disable=protected-access
                l7_client=l7_client,
                algorithms=collections.OrderedDict([
                    (Ikev2TransformType.ENCR, [(Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128)]),
                    (Ikev2TransformType.DH, [Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT]),
                    (Ikev2TransformType.PRF, [Ikev2PseudorandomFunction.PRF_HMAC_SHA1]),
                    (Ikev2TransformType.INTEG, [Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96]),
                ]),
                accepted_dh_groups=set(),
            )
        mock_handshake.assert_called_once()
        self.assertEqual(len(result), 1)


class TestAnalyzerCiphers(unittest.TestCase):
    """Mock-based end-to-end tests for AnalyzerCiphers.

    Every test mocks `do_ikev1_handshake` / `do_ikev2_handshake` on the
    L7ClientIPsecBase instance — no real UDP traffic or threaded server.
    Per-test runtime drops from 6-90 s to well under 2 s.
    """

    # IKEv1 enumeration is a 4-axis cartesian (DH × auth × encr × hash) of ~250
    # algorithms by default. Each IKEv1 test patches these enums to single-item
    # lists in the ciphers module namespace so the analyzer issues 1-3 probes
    # instead of hundreds.
    _ikev1_enum_patches = [
        ('cryptolyzer.ike.ciphers.Ikev1DiffieHellmanGroup',
         [Ikev1DiffieHellmanGroup.MODP_1024_BIT]),
        ('cryptolyzer.ike.ciphers.Ikev1AuthenticationMethod',
         [Ikev1AuthenticationMethod.PRE_SHARED_KEY]),
        ('cryptolyzer.ike.ciphers.Ikev1EncryptionAlgorithm',
         [Ikev1EncryptionAlgorithm.AES_CBC]),
        ('cryptolyzer.ike.ciphers.Ikev1HashAlgorithm',
         [Ikev1HashAlgorithm.SHA]),
    ]

    def _patch_ikev1_enums(self):
        for target, replacement in self._ikev1_enum_patches:
            patcher = unittest.mock.patch(target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)

    # ---------- IKEv1 ----------
    def test_ikev1_no_proposal_chosen(self):
        self._patch_ikev1_enums()
        client = _make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake',
            side_effect=_raise_ikev1_notify(Ikev1NotifyType.NO_PROPOSAL_CHOSEN),
        ):
            result = AnalyzerCiphers().analyze(client, IkeVersion.V1)
        self.assertEqual(len(result.encryption_algorithms), 0)
        self.assertEqual(len(result.hash_algorithms), 0)
        self.assertEqual(len(result.diffie_hellman_groups), 0)

    def test_ikev1_unknown_notify_raises(self):
        # Unknown notify (not NO_PROPOSAL/INVALID_KEY) → analyzer re-raises.
        self._patch_ikev1_enums()
        client = _make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake',
            side_effect=_raise_ikev1_notify(Ikev1NotifyType.INVALID_HASH_INFORMATION),
        ):
            with self.assertRaises(IsakmpNotify) as ctx:
                AnalyzerCiphers().analyze(client, IkeVersion.V1)
        self.assertEqual(ctx.exception.notify, Ikev1NotifyType.INVALID_HASH_INFORMATION)

    def test_ikev1_auth_method_unsupported(self):
        self._patch_ikev1_enums()
        client = _make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake',
            side_effect=_raise_ikev1_notify(Ikev1NotifyType.INVALID_KEY_INFORMATION),
        ):
            result = AnalyzerCiphers().analyze(client, IkeVersion.V1)
        self.assertEqual(len(result.encryption_algorithms), 0)

    def test_ikev1_auth_method_skips_subsets(self):
        for target, replacement in [
            ('cryptolyzer.ike.ciphers.Ikev1DiffieHellmanGroup',
             [Ikev1DiffieHellmanGroup.MODP_1024_BIT]),
            ('cryptolyzer.ike.ciphers.Ikev1AuthenticationMethod',
             [Ikev1AuthenticationMethod.PRE_SHARED_KEY]),
            ('cryptolyzer.ike.ciphers.Ikev1EncryptionAlgorithm',
             [Ikev1EncryptionAlgorithm.DES3_CBC]),
            ('cryptolyzer.ike.ciphers.Ikev1HashAlgorithm',
             [Ikev1HashAlgorithm.SHA, Ikev1HashAlgorithm.MD5]),
        ]:
            patcher = unittest.mock.patch(target, replacement)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = unittest.mock.patch.object(AnalyzerCiphers, '_MAX_PROPOSALS_PER_INIT_MESSAGE', 1)
        patcher.start()
        self.addCleanup(patcher.stop)

        client = _make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake',
            side_effect=_raise_ikev1_notify(Ikev1NotifyType.INVALID_KEY_INFORMATION),
        ):
            result = AnalyzerCiphers().analyze(client, IkeVersion.V1)
        self.assertEqual(len(result.encryption_algorithms), 0)

    def test_ikev1_network_no_response(self):
        # NetworkError NO_RESPONSE → analyzer logs and skips probe; empty result.
        self._patch_ikev1_enums()
        client = _make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake',
            side_effect=NetworkError(NetworkErrorType.NO_RESPONSE),
        ):
            result = AnalyzerCiphers().analyze(client, IkeVersion.V1)
        self.assertEqual(len(result.encryption_algorithms), 0)

    def test_ikev1_fixed_key_encryption(self):
        # Patch Ikev1EncryptionAlgorithm to a single-bulk cipher (3DES) so
        # `_get_ikev1_algorithms_for_dh_group_and_auth` takes the
        # `key_lengths = [None]` branch (ciphers.py:300).
        self._patch_ikev1_enums()
        # Override the encryption enum patch with the fixed-key cipher.
        patcher = unittest.mock.patch(
            'cryptolyzer.ike.ciphers.Ikev1EncryptionAlgorithm',
            [Ikev1EncryptionAlgorithm.DES3_CBC],
        )
        patcher.start()
        self.addCleanup(patcher.stop)

        client = _make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake',
            side_effect=_raise_ikev1_notify(Ikev1NotifyType.NO_PROPOSAL_CHOSEN),
        ):
            result = AnalyzerCiphers().analyze(client, IkeVersion.V1)
        self.assertEqual(len(result.encryption_algorithms), 0)

    def test_ikev1_single_suite(self):
        # First probe returns one match (AES-128-CBC / SHA / MODP-1024 / PRE_SHARED_KEY).
        # All subsequent probes get NO_PROPOSAL_CHOSEN.
        self._patch_ikev1_enums()
        client = _make_mock_client()
        matching_algorithm = Ikev1SecurityAssociationProposalAlgorithms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
            diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_1024_BIT,
            hash_algorithm=Ikev1HashAlgorithm.SHA,
            authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
            key_length=128,
        )
        call_count = [0]

        def respond(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return {Ikev1ExchangeType.IDENTITY_PROTECTION: [object()]}
            exception = IsakmpNotify(Ikev1NotifyType.NO_PROPOSAL_CHOSEN)
            exception.server_messages = {}
            raise exception

        with unittest.mock.patch.object(client, 'do_ikev1_handshake', side_effect=respond), \
             unittest.mock.patch.object(
                 AnalyzerCiphers,
                 '_get_algorithm_from_server_messages_ikev1',
                 return_value=matching_algorithm,
             ):
            result = AnalyzerCiphers().analyze(client, IkeVersion.V1)

        self.assertEqual(len(result.encryption_algorithms), 1)
        self.assertEqual(result.encryption_algorithms[0].block_cipher_mode, BlockCipherMode.CBC)
        self.assertEqual(len(result.hash_algorithms), 1)
        self.assertEqual(len(result.diffie_hellman_groups), 1)

    # ---------- IKEv2 ----------
    def test_ikev2_no_proposal_chosen(self):
        client = _make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev2_handshake',
            side_effect=IsakmpNotify(Ikev2NotifyType.NO_PROPOSAL_CHOSEN),
        ):
            result = AnalyzerCiphers().analyze(client, IkeVersion.V2)
        self.assertEqual(len(result.encryption_algorithms), 0)
        self.assertEqual(len(result.pseudorandom_functions), 0)
        self.assertEqual(len(result.integrity_algorithms), 0)
        self.assertEqual(len(result.diffie_hellman_groups), 0)

    def test_ikev2_unknown_notify_raises(self):
        client = _make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev2_handshake',
            side_effect=IsakmpNotify(Ikev2NotifyType.INVALID_SYNTAX),
        ):
            with self.assertRaises(IsakmpNotify) as ctx:
                AnalyzerCiphers().analyze(client, IkeVersion.V2)
        self.assertEqual(ctx.exception.notify, Ikev2NotifyType.INVALID_SYNTAX)

    def test_ikev2_network_no_response(self):
        # NetworkError NO_RESPONSE → analyzer logs and returns empty result
        # (ciphers.py:388-391).
        client = _make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev2_handshake',
            side_effect=NetworkError(NetworkErrorType.NO_RESPONSE),
        ):
            result = AnalyzerCiphers().analyze(client, IkeVersion.V2)
        self.assertEqual(len(result.encryption_algorithms), 0)

    def test_ikev2_network_error_other_reraises(self):
        # NetworkError with non-NO_RESPONSE → analyzer re-raises (ciphers.py:393).
        client = _make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev2_handshake',
            side_effect=NetworkError(NetworkErrorType.NO_CONNECTION),
        ):
            with self.assertRaises(NetworkError):
                AnalyzerCiphers().analyze(client, IkeVersion.V2)

    def test_ikev2_invalid_ke_payload_retry(self):
        # First call: INVALID_KE_PAYLOAD suggesting MODP_2048 → analyzer records the
        # group in accepted_dh_groups, retries with key_exchange_dh=MODP_2048.
        # Second call: NO_PROPOSAL_CHOSEN → branch exits. The MODP_2048 group
        # surfaces in result.diffie_hellman_groups even though no cipher suite
        # was captured.
        client = _make_mock_client()
        call_count = [0]

        def respond(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                payload = Ikev2NotifyPayloadInvalidKe(
                    flags=set(),
                    protocol_id=Ikev2ProtocolId.IKE,
                    type=Ikev2NotifyType.INVALID_KE_PAYLOAD,
                    spi=b'',
                    dh_group=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
                )
                raise IsakmpNotify(Ikev2NotifyType.INVALID_KE_PAYLOAD, payload)
            raise IsakmpNotify(Ikev2NotifyType.NO_PROPOSAL_CHOSEN)

        with unittest.mock.patch.object(client, 'do_ikev2_handshake', side_effect=respond):
            result = AnalyzerCiphers().analyze(client, IkeVersion.V2)

        self.assertEqual(len(result.encryption_algorithms), 0)
        self.assertIn(
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT.value.key_parameter,
            result.diffie_hellman_groups,
        )

    def test_ikev2_single_suite(self):
        client = _make_mock_client()
        sa_response = _make_ikev2_sa_response([
            Ikev2TransformEncryptionAlgorithm(
                transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC, key_length=128,
            ),
            Ikev2TransformIntegrity(transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96),
            Ikev2TransformPrf(transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1),
            Ikev2TransformDhGroup(transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_1024_BIT),
        ])
        call_count = [0]

        def respond(*_args, **_kwargs):
            call_count[0] += 1
            if call_count[0] == 1:
                return sa_response
            raise IsakmpNotify(Ikev2NotifyType.NO_PROPOSAL_CHOSEN)

        with unittest.mock.patch.object(client, 'do_ikev2_handshake', side_effect=respond):
            result = AnalyzerCiphers().analyze(client, IkeVersion.V2)

        self.assertEqual(len(result.encryption_algorithms), 1)
        self.assertEqual(result.encryption_algorithms[0].block_cipher_mode, BlockCipherMode.CBC)
        self.assertEqual(len(result.pseudorandom_functions), 1)
        self.assertEqual(len(result.integrity_algorithms), 1)
        self.assertEqual(len(result.diffie_hellman_groups), 1)
