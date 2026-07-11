# SPDX-License-Identifier: MPL-2.0

import unittest

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, Hash
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.ike.algorithm import (
    Ikev1DiffieHellmanGroup,
    Ikev1Doi,
    Ikev1EncryptionAlgorithm,
    Ikev1ExchangeType,
    Ikev1HashAlgorithm,
    Ikev1NotifyType,
    Ikev1ProtocolId,
    Ikev1TransformId,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2ExchangeType,
    Ikev2IntegrityAlgorithm,
    Ikev2NotifyType,
    Ikev2ProtocolId,
    Ikev2PseudorandomFunction,
    MAC,
)

from cryptodatahub.ike.version import IkeVersion

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.ike.isakmp import IsakmpMessage, IsakmpFlags
from cryptoparser.ike.version import IsakmpProtocolVersion
from cryptoparser.ike.ikev1 import (
    Ikev1AttributeDiffieHellmanGroup,
    Ikev1AttributeEncryptionAlgorithm,
    Ikev1AttributeHashAlgorithm,
    Ikev1AttributeKeyLength,
    Ikev1PayloadKeyExchange,
    Ikev1PayloadProposal,
    Ikev1PayloadSecurityAssociation,
    Ikev1PayloadTransform,
    Ikev1Situation,
)
from cryptoparser.ike.ikev2 import (
    Ikev2NotifyPayloadCookie,
    Ikev2PayloadKeyExchange,
    Ikev2PayloadNonce,
    Ikev2PayloadNotifyUnparsed,
    Ikev2PayloadSecurityAssociation,
    Ikev2Proposal as Ikev2ProposalPayload,
    Ikev2TransformDhGroup,
    Ikev2TransformEncryptionAlgorithm,
    Ikev2TransformIntegrity,
    Ikev2TransformPrf,
)

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.ike.client import L7ClientIPsecBase
from cryptolyzer.ike.common import Ikev1CipherSuite, Ikev2CipherSuite
from cryptolyzer.ike.server import (
    IkeServerConfiguration,
    IkeServerHandshakeBase,
    Ikev1ServerHandshake,
    Ikev2ServerHandshake,
    L7ServerIke,
    ServerResponseMode,
)

from .classes import L4TransferCapture, L4TransferDummy, get_ecdh_only_server_configuration


class _TestIkeServerHandshakeHelpers:
    _TIMEOUT = 0.5

    @classmethod
    def _socket_params(cls):
        return L4TransferSocketParams(timeout=cls._TIMEOUT)

    @classmethod
    def _create_server(cls, configuration=None):
        if configuration is None:
            configuration = IkeServerConfiguration()

        return L7ServerIke(
            'localhost',
            0,
            cls._socket_params(),
            configuration=configuration,
            max_handshake_count=1,
        )


class TestIkeServerHandshakeBase(unittest.TestCase, _TestIkeServerHandshakeHelpers):
    @classmethod
    def _create_l4_transfer(cls, buffer_bytes=b''):
        l4_transfer = L4TransferDummy('localhost', 0, cls._socket_params())
        l4_transfer._buffer = bytearray(buffer_bytes)  # pylint: disable=protected-access
        return l4_transfer

    @staticmethod
    def _create_base_handshake(l7_server):
        return IkeServerHandshakeBase(l7_server, l7_server.configuration)

    def test_error_invalid_message(self):
        message = b'\x00\x01\x02\x03'
        l7_server = self._create_server()
        l4_transfer = self._create_l4_transfer(message)
        l7_server.l4_transfer = l4_transfer

        handshake = self._create_base_handshake(l7_server)
        with self.assertRaises(NotEnoughData) as ctx:
            handshake._parse_record()  # pylint: disable=protected-access
        self.assertEqual(ctx.exception.bytes_needed, IsakmpMessage.HEADER_SIZE - len(message))
        self.assertEqual(l4_transfer.buffer, message)

    def test_error_invalid_message_message(self):
        l7_server = self._create_server()
        handshake = self._create_base_handshake(l7_server)

        with self.assertRaises(StopIteration):
            handshake._process_invalid_message()  # pylint: disable=protected-access

    def test_error_not_enough_data(self):
        l7_server = self._create_server()
        handshake = self._create_base_handshake(l7_server)

        with self.assertRaises(StopIteration):
            handshake._process_not_enough_data()  # pylint: disable=protected-access


class TestIkeServerHandshakeIkev1(unittest.TestCase, _TestIkeServerHandshakeHelpers):
    @staticmethod
    def _create_message(payloads=None):
        if payloads is None:
            payloads = []
        return IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=1,
            responder_spi=0,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.INITIATOR],
            message_id=0,
            payloads=payloads,
        )

    def test_error_non_handshake_message(self):
        l7_server = self._create_server(IkeServerConfiguration(response_mode=ServerResponseMode.NONE))
        handshake = Ikev1ServerHandshake(l7_server, l7_server.configuration)
        message = self._create_message()

        with self.assertRaises(StopIteration):
            handshake._process_non_handshake_message(message)  # pylint: disable=protected-access

    def test_no_proposals_returns_none(self):
        l7_server = self._create_server()
        handshake = Ikev1ServerHandshake(l7_server, l7_server.configuration)
        sa_payload = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation=[Ikev1Situation.SIT_SECRECY],
            proposals=[],
        )
        result = handshake._select_sa_from_client(sa_payload)  # pylint: disable=protected-access
        self.assertIsNone(result)

    def test_no_proposal_chosen_notify(self):
        l7_server = self._create_server(IkeServerConfiguration(response_mode=ServerResponseMode.NOTIFY))
        l4_transfer = L4TransferCapture('localhost', 0, self._socket_params())
        l7_server.l4_transfer = l4_transfer

        handshake = Ikev1ServerHandshake(l7_server, l7_server.configuration)
        message = self._create_message(payloads=[])

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        self.assertIsNotNone(l4_transfer.last_sent)
        parsed, parsed_len = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertEqual(parsed_len, len(l4_transfer.last_sent))
        self.assertEqual(parsed.payloads[0].notify_type, Ikev1NotifyType.NO_PROPOSAL_CHOSEN)

    def test_response_mode_partial_sends_truncated(self):
        l7_server = self._create_server(IkeServerConfiguration(response_mode=ServerResponseMode.PARTIAL))
        l4_transfer = L4TransferCapture('localhost', 0, self._socket_params())
        l7_server.l4_transfer = l4_transfer

        handshake = Ikev1ServerHandshake(l7_server, l7_server.configuration)
        message = self._create_message(payloads=[])

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        self.assertIsNotNone(l4_transfer.last_sent)
        self.assertEqual(len(l4_transfer.last_sent), IsakmpMessage.HEADER_SIZE + 1)


class TestIkeServerHandshakeIkev2(unittest.TestCase, _TestIkeServerHandshakeHelpers):
    @staticmethod
    def _create_message(payloads=None):
        if payloads is None:
            payloads = []

        return IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=1,
            responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.INITIATOR],
            message_id=0,
            payloads=payloads,
        )

    def test_no_proposals_returns_none(self):
        l7_server = self._create_server()
        handshake = Ikev2ServerHandshake(l7_server, l7_server.configuration)
        sa_payload = Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[],
        )
        result = handshake._select_sa_from_client(sa_payload)  # pylint: disable=protected-access
        self.assertIsNone(result)

    def test_bad_cookie_resends_cookie(self):
        configuration = IkeServerConfiguration(cookie_challenge=True)
        l7_server = self._create_server(configuration)
        l4_transfer = L4TransferCapture('localhost', 0, self._socket_params())
        l7_server.l4_transfer = l4_transfer

        handshake = Ikev2ServerHandshake(l7_server, l7_server.configuration)
        handshake._expected_cookie = b'expected-cookie'  # pylint: disable=protected-access

        cookie_payload = Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.COOKIE,
            spi=b'',
            cookie=b'wrong-cookie',
        )
        message = self._create_message(payloads=[cookie_payload])

        handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        self.assertIsNotNone(l4_transfer.last_sent)
        parsed, parsed_len = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertEqual(parsed_len, len(l4_transfer.last_sent))
        self.assertIsInstance(parsed.payloads[0], Ikev2NotifyPayloadCookie)
        expected_cookie = handshake._expected_cookie  # pylint: disable=protected-access
        self.assertEqual(bytes(parsed.payloads[0].cookie), expected_cookie)

    def test_no_proposal_chosen_notify(self):
        l7_server = self._create_server(IkeServerConfiguration(response_mode=ServerResponseMode.NOTIFY))
        l4_transfer = L4TransferCapture('localhost', 0, self._socket_params())
        l7_server.l4_transfer = l4_transfer

        handshake = Ikev2ServerHandshake(l7_server, l7_server.configuration)
        message = self._create_message(payloads=[])

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        self.assertIsNotNone(l4_transfer.last_sent)
        parsed, parsed_len = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertEqual(parsed_len, len(l4_transfer.last_sent))
        self.assertIsInstance(parsed.payloads[0], Ikev2PayloadNotifyUnparsed)
        self.assertEqual(parsed.payloads[0].type, Ikev2NotifyType.NO_PROPOSAL_CHOSEN)

    def test_response_mode_partial_sends_truncated(self):
        l7_server = self._create_server(IkeServerConfiguration(response_mode=ServerResponseMode.PARTIAL))
        l4_transfer = L4TransferCapture('localhost', 0, self._socket_params())
        l7_server.l4_transfer = l4_transfer

        handshake = Ikev2ServerHandshake(l7_server, l7_server.configuration)
        message = self._create_message(payloads=[])

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        self.assertIsNotNone(l4_transfer.last_sent)
        self.assertEqual(len(l4_transfer.last_sent), IsakmpMessage.HEADER_SIZE + 1)


class _Ikev1ProposalFactory:
    @staticmethod
    def make_sa(encryption, key_length, hash_alg, dh_group):
        attrs = [
            Ikev1AttributeEncryptionAlgorithm(encryption),
            Ikev1AttributeKeyLength(key_length),
            Ikev1AttributeHashAlgorithm(hash_alg),
            Ikev1AttributeDiffieHellmanGroup(dh_group),
        ]
        transform = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=attrs,
        )
        proposal = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.ISAKMP,
            transforms=[transform],
        )
        return Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation=[Ikev1Situation.SIT_IDENTITY_ONLY],
            proposals=[proposal],
        )


class _Ikev2ProposalFactory:
    @staticmethod
    def make_sa(encryption, key_length, integrity, prf, dh_group):
        transforms = [
            Ikev2TransformEncryptionAlgorithm(encryption, key_length=key_length),
            Ikev2TransformIntegrity(integrity),
            Ikev2TransformPrf(prf),
            Ikev2TransformDhGroup(dh_group),
        ]
        proposal = Ikev2ProposalPayload(
            protocol_id=Ikev2ProtocolId.IKE,
            transforms=transforms,
        )
        return Ikev2PayloadSecurityAssociation(
            flags=set(),
            proposals=[proposal],
        )


class TestIkev1CipherSuiteMatching(unittest.TestCase, _TestIkeServerHandshakeHelpers):
    _MATCHING_CS = Ikev1CipherSuite(
        encryption_algorithm=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        diffie_hellman_group=DHParamWellKnown.RFC2539_1024_BIT_MODP_GROUP,
        hash_algorithm=Hash.SHA1,
    )

    def _make_handshake(self, cipher_suites):
        config = IkeServerConfiguration(ikev1_cipher_suites=cipher_suites)
        l7_server = self._create_server(config)
        l4_transfer = L4TransferCapture('localhost', 0, self._socket_params())
        l7_server.l4_transfer = l4_transfer
        handshake = Ikev1ServerHandshake(l7_server, l7_server.configuration)
        return handshake, l4_transfer

    def test_matching_proposal_accepted(self):
        handshake, l4_transfer = self._make_handshake([self._MATCHING_CS])
        sa_payload = _Ikev1ProposalFactory.make_sa(
            Ikev1EncryptionAlgorithm.AES_CBC, 128,
            Ikev1HashAlgorithm.SHA, Ikev1DiffieHellmanGroup.MODP_1024_BIT,
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_payload],
        )

        # Phase 1: SA exchange — server responds with selected SA and waits for KE
        handshake._process_handshake_message(message, None)  # pylint: disable=protected-access
        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertIsInstance(parsed.payloads[0], Ikev1PayloadSecurityAssociation)

        # Phase 2: KE+NONCE exchange — server responds with its own KE+NONCE
        ke_message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[Ikev1PayloadKeyExchange(key_exchange_data=b'\x00' * 128)],
        )
        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(ke_message, None)  # pylint: disable=protected-access
        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertIsInstance(parsed.payloads[0], Ikev1PayloadKeyExchange)

    def test_aggressive_mode_matching_proposal(self):
        handshake, l4_transfer = self._make_handshake([self._MATCHING_CS])
        sa_payload = _Ikev1ProposalFactory.make_sa(
            Ikev1EncryptionAlgorithm.AES_CBC, 128,
            Ikev1HashAlgorithm.SHA, Ikev1DiffieHellmanGroup.MODP_1024_BIT,
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev1ExchangeType.AGGRESSIVE,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_payload],
        )

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertIsInstance(parsed.payloads[0], Ikev1PayloadSecurityAssociation)

    def test_non_matching_proposal_rejected(self):
        non_matching_cipher_suite = Ikev1CipherSuite(
            encryption_algorithm=BlockCipher.AES_256,
            block_cipher_mode=BlockCipherMode.CBC,
            diffie_hellman_group=DHParamWellKnown.RFC2539_1024_BIT_MODP_GROUP,
            hash_algorithm=Hash.SHA1,
        )
        handshake, l4_transfer = self._make_handshake([non_matching_cipher_suite])
        sa_payload = _Ikev1ProposalFactory.make_sa(
            Ikev1EncryptionAlgorithm.AES_CBC, 128,
            Ikev1HashAlgorithm.SHA, Ikev1DiffieHellmanGroup.MODP_1024_BIT,
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_payload],
        )

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertEqual(parsed.payloads[0].notify_type, Ikev1NotifyType.NO_PROPOSAL_CHOSEN)

    def test_empty_config_accepts_first(self):
        handshake, l4_transfer = self._make_handshake([])
        sa_payload = _Ikev1ProposalFactory.make_sa(
            Ikev1EncryptionAlgorithm.AES_CBC, 128,
            Ikev1HashAlgorithm.SHA, Ikev1DiffieHellmanGroup.MODP_1024_BIT,
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_payload],
        )

        # Phase 1: SA exchange — server responds with selected SA and waits for KE
        handshake._process_handshake_message(message, None)  # pylint: disable=protected-access
        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertIsInstance(parsed.payloads[0], Ikev1PayloadSecurityAssociation)

        # Phase 2: KE+NONCE exchange — server responds with its own KE+NONCE
        ke_message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[Ikev1PayloadKeyExchange(key_exchange_data=b'\x00' * 128)],
        )
        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(ke_message, None)  # pylint: disable=protected-access
        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertIsInstance(parsed.payloads[0], Ikev1PayloadKeyExchange)

    def test_transform_missing_attribute_skipped(self):
        handshake, l4_transfer = self._make_handshake([self._MATCHING_CS])
        transform = Ikev1PayloadTransform(
            transform_id=Ikev1TransformId.KEY_IKE,
            attributes=[Ikev1AttributeHashAlgorithm(Ikev1HashAlgorithm.SHA)],
        )
        proposal = Ikev1PayloadProposal(
            protocol_id=Ikev1ProtocolId.ISAKMP, transforms=[transform],
        )
        sa_payload = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation=[Ikev1Situation.SIT_IDENTITY_ONLY],
            proposals=[proposal],
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_payload],
        )

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertEqual(parsed.payloads[0].notify_type, Ikev1NotifyType.NO_PROPOSAL_CHOSEN)

    def test_transform_invalid_key_length_skipped(self):
        handshake, l4_transfer = self._make_handshake([self._MATCHING_CS])
        sa_payload = _Ikev1ProposalFactory.make_sa(
            Ikev1EncryptionAlgorithm.AES_CBC, 64,
            Ikev1HashAlgorithm.SHA, Ikev1DiffieHellmanGroup.MODP_1024_BIT,
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_payload],
        )

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertEqual(parsed.payloads[0].notify_type, Ikev1NotifyType.NO_PROPOSAL_CHOSEN)

    def test_ecdh_curves_config_accepts_ecp256_rejects_sect163(self):
        """Server with curves config accepts ECP_256/ECP_384, rejects other ECDH groups."""
        config = get_ecdh_only_server_configuration()
        handshake, l4_transfer = self._make_handshake(config.ikev1_cipher_suites)

        # ECP_256 with AES_CBC/SHA should be accepted
        sa_ecp256 = _Ikev1ProposalFactory.make_sa(
            Ikev1EncryptionAlgorithm.AES_CBC, 128,
            Ikev1HashAlgorithm.SHA, Ikev1DiffieHellmanGroup.ECP_256_BIT,
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_ecp256],
        )
        handshake._process_handshake_message(message, None)  # pylint: disable=protected-access
        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertIsInstance(parsed.payloads[0], Ikev1PayloadSecurityAssociation)

        # EC2N_163_BIT_1 (SECT163R1) should be rejected
        handshake2, l4_transfer2 = self._make_handshake(config.ikev1_cipher_suites)
        sa_sect163 = _Ikev1ProposalFactory.make_sa(
            Ikev1EncryptionAlgorithm.AES_CBC, 128,
            Ikev1HashAlgorithm.SHA, Ikev1DiffieHellmanGroup.EC2N_163_BIT_1,
        )
        message2 = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=2, responder_spi=0,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_sect163],
        )
        with self.assertRaises(StopIteration):
            handshake2._process_handshake_message(message2, None)  # pylint: disable=protected-access
        parsed2, _ = IsakmpMessage.parse_immutable(l4_transfer2.last_sent)
        self.assertEqual(parsed2.payloads[0].notify_type, Ikev1NotifyType.NO_PROPOSAL_CHOSEN)


class TestIkev2CipherSuiteMatching(unittest.TestCase, _TestIkeServerHandshakeHelpers):
    _MATCHING_CS = Ikev2CipherSuite(
        encryption_algorithm=BlockCipher.AES_128,
        block_cipher_mode=BlockCipherMode.CBC,
        integrity_algorithm=MAC.SHA1,
        pseudorandom_function=MAC.SHA1,
        diffie_hellman_group=DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP,
    )

    def _make_handshake(self, cipher_suites):
        config = IkeServerConfiguration(ikev2_cipher_suites=cipher_suites)
        l7_server = self._create_server(config)
        l4_transfer = L4TransferCapture('localhost', 0, self._socket_params())
        l7_server.l4_transfer = l4_transfer
        handshake = Ikev2ServerHandshake(l7_server, l7_server.configuration)
        return handshake, l4_transfer

    def test_matching_proposal_accepted(self):
        handshake, l4_transfer = self._make_handshake([self._MATCHING_CS])
        sa_payload = _Ikev2ProposalFactory.make_sa(
            Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128,
            Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_payload],
        )

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertIsInstance(parsed.payloads[0], Ikev2PayloadSecurityAssociation)
        self.assertIsInstance(parsed.payloads[1], Ikev2PayloadKeyExchange)
        self.assertIsInstance(parsed.payloads[2], Ikev2PayloadNonce)

    def test_non_matching_proposal_rejected(self):
        non_matching_cipher_suite = Ikev2CipherSuite(
            encryption_algorithm=BlockCipher.AES_256,
            block_cipher_mode=BlockCipherMode.CBC,
            integrity_algorithm=MAC.SHA1,
            pseudorandom_function=MAC.SHA1,
            diffie_hellman_group=DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP,
        )
        handshake, l4_transfer = self._make_handshake([non_matching_cipher_suite])
        sa_payload = _Ikev2ProposalFactory.make_sa(
            Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128,
            Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_payload],
        )

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertIsInstance(parsed.payloads[0], Ikev2PayloadNotifyUnparsed)
        self.assertEqual(parsed.payloads[0].type, Ikev2NotifyType.NO_PROPOSAL_CHOSEN)

    def test_empty_config_accepts_first(self):
        handshake, l4_transfer = self._make_handshake([])
        sa_payload = _Ikev2ProposalFactory.make_sa(
            Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128,
            Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_payload],
        )

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertIsInstance(parsed.payloads[0], Ikev2PayloadSecurityAssociation)
        self.assertIsInstance(parsed.payloads[1], Ikev2PayloadKeyExchange)
        self.assertIsInstance(parsed.payloads[2], Ikev2PayloadNonce)

    def test_encryption_invalid_key_length_skipped(self):
        handshake, l4_transfer = self._make_handshake([self._MATCHING_CS])
        sa_payload = _Ikev2ProposalFactory.make_sa(
            Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 64,
            Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        )
        message = IsakmpMessage(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=1, responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.INITIATOR], message_id=0,
            payloads=[sa_payload],
        )

        with self.assertRaises(StopIteration):
            handshake._process_handshake_message(message, None)  # pylint: disable=protected-access

        parsed, _ = IsakmpMessage.parse_immutable(l4_transfer.last_sent)
        self.assertIsInstance(parsed.payloads[0], Ikev2PayloadNotifyUnparsed)
        self.assertEqual(parsed.payloads[0].type, Ikev2NotifyType.NO_PROPOSAL_CHOSEN)


class TestL7ServerIke(unittest.TestCase):
    def test_scheme(self):
        self.assertEqual(L7ClientIPsecBase.get_scheme(), L7ServerIke.get_scheme())

    def test_default_port(self):
        self.assertEqual(L7ServerIke.get_default_port(), 45000)


class TestIkev2GenerateKeNoncePayloadsEcdh(unittest.TestCase):
    def test_ecdh_group_forges_ecdh_key(self):
        sa = _Ikev2ProposalFactory.make_sa(
            Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128,
            Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
        )
        # pylint: disable=protected-access
        payloads = Ikev2ServerHandshake._generate_ke_nonce_payloads(sa)
        ke_payload = next(p for p in payloads if isinstance(p, Ikev2PayloadKeyExchange))
        self.assertEqual(ke_payload.dh_group, Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT)
        self.assertGreater(len(ke_payload.key_exchange_data), 0)
