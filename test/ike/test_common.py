# SPDX-License-Identifier: MPL-2.0

import unittest
import unittest.mock

from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1DiffieHellmanGroup,
    Ikev1EncryptionAlgorithm,
    Ikev1HashAlgorithm,
    Ikev1NotifyType,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2IntegrityAlgorithm,
    Ikev2NotifyType,
    Ikev2PseudorandomFunction,
)

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.ike.client import Ikev1SecurityAssociationProposalAlgorithms
from cryptolyzer.ike.common import Ikev1CipherSuite, Ikev2CipherSuite
from cryptolyzer.ike.dhparams import AnalyzerDHParams
from cryptolyzer.ike.exception import IsakmpNotify


class TestIkev1CipherSuite(unittest.TestCase):
    def test_from_proposal_algorithms(self):
        algorithms = Ikev1SecurityAssociationProposalAlgorithms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
            diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            hash_algorithm=Ikev1HashAlgorithm.MD5,
            authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
            key_length=128,
        )
        cipher_suite = Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(algorithms)
        self.assertEqual(cipher_suite.block_cipher_mode, algorithms.encryption_algorithm.value.block_cipher_mode)
        self.assertEqual(
            cipher_suite.diffie_hellman_group,
            algorithms.diffie_hellman_group.value.key_parameter,
        )
        self.assertEqual(cipher_suite.hash_algorithm, algorithms.hash_algorithm.value.hash)

    def test_from_proposal_algorithms_key_length_is_none_for_fixed_key_cipher(self):
        algorithms = Ikev1SecurityAssociationProposalAlgorithms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.DES3_CBC,
            diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            hash_algorithm=Ikev1HashAlgorithm.MD5,
            authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
            key_length=None,
        )
        cipher_suite = Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(algorithms)
        self.assertEqual(cipher_suite.block_cipher_mode, algorithms.encryption_algorithm.value.block_cipher_mode)

    def test_error_key_length_not_found(self):
        algorithms = Ikev1SecurityAssociationProposalAlgorithms(
            encryption_algorithm=Ikev1EncryptionAlgorithm.DES3_CBC,
            diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            hash_algorithm=Ikev1HashAlgorithm.MD5,
            authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
            key_length=9999,
        )
        with self.assertRaises(ValueError):
            Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(algorithms)


class TestIkev2CipherSuite(unittest.TestCase):
    def test_from_transform_ids(self):
        cipher_suite = Ikev2CipherSuite.from_transform_ids(
            encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_DES_IV64,
            integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_MD5,
            diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
            key_length=56,
        )
        self.assertEqual(
            cipher_suite.block_cipher_mode,
            Ikev2EncryptionAlgorithm.ENCR_DES_IV64.value.block_cipher_mode,
        )
        self.assertEqual(
            cipher_suite.integrity_algorithm,
            Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96.value.hmac,
        )
        self.assertEqual(
            cipher_suite.pseudorandom_function,
            Ikev2PseudorandomFunction.PRF_HMAC_MD5.value.mac,
        )
        self.assertEqual(
            cipher_suite.diffie_hellman_group,
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT.value.key_parameter,
        )

    def test_from_transform_ids_key_length_is_none_for_fixed_key_cipher(self):
        cipher_suite = Ikev2CipherSuite.from_transform_ids(
            encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_3DES,
            integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_MD5,
            diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
            key_length=None,
        )
        self.assertEqual(
            cipher_suite.block_cipher_mode,
            Ikev2EncryptionAlgorithm.ENCR_3DES.value.block_cipher_mode,
        )

    def test_error_key_length_not_found(self):
        with self.assertRaises(ValueError):
            Ikev2CipherSuite.from_transform_ids(
                encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_DES_IV64,
                integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
                pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_MD5,
                diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
                key_length=9999,
            )


class TestSendIkev2InitMessage(unittest.TestCase):
    @staticmethod
    def _make_analyzer_and_client():
        analyzer = AnalyzerDHParams()
        l7_client = unittest.mock.MagicMock()
        l7_client.l4_socket_params.throttle_delay = 0
        return analyzer, l7_client

    def test_returns_none_on_no_proposal_chosen(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev2_handshake.side_effect = IsakmpNotify(Ikev2NotifyType.NO_PROPOSAL_CHOSEN)
        # pylint: disable=protected-access
        result = analyzer._send_ikev2_init_message(l7_client, unittest.mock.MagicMock())
        self.assertIsNone(result)

    def test_raises_and_logs_unexpected_notify(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev2_handshake.side_effect = IsakmpNotify(Ikev2NotifyType.INVALID_SYNTAX)
        with self.assertRaises(IsakmpNotify) as ctx:
            analyzer._send_ikev2_init_message(  # pylint: disable=protected-access
                l7_client, unittest.mock.MagicMock(),
            )
        self.assertEqual(ctx.exception.notify, Ikev2NotifyType.INVALID_SYNTAX)

    def test_returns_none_on_no_response(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev2_handshake.side_effect = NetworkError(NetworkErrorType.NO_RESPONSE)
        result = analyzer._send_ikev2_init_message(  # pylint: disable=protected-access
            l7_client, unittest.mock.MagicMock(),
        )
        self.assertIsNone(result)

    def test_reraises_non_no_response_network_error(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev2_handshake.side_effect = NetworkError(NetworkErrorType.NO_CONNECTION)
        with self.assertRaises(NetworkError) as ctx:
            analyzer._send_ikev2_init_message(  # pylint: disable=protected-access
                l7_client, unittest.mock.MagicMock(),
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_returns_server_messages_on_success(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev2_handshake.return_value = {'server': 'messages'}
        result = analyzer._send_ikev2_init_message(  # pylint: disable=protected-access
            l7_client, unittest.mock.MagicMock(),
        )
        self.assertEqual(result, {'server': 'messages'})


class TestSendIkev1InitMessage(unittest.TestCase):
    @staticmethod
    def _make_analyzer_and_client():
        analyzer = AnalyzerDHParams()
        l7_client = unittest.mock.MagicMock()
        l7_client.l4_socket_params.throttle_delay = 0
        return analyzer, l7_client

    def test_returns_false_on_no_proposal_chosen(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev1_handshake.side_effect = IsakmpNotify(Ikev1NotifyType.NO_PROPOSAL_CHOSEN)
        result = analyzer._send_ikev1_init_message(  # pylint: disable=protected-access
            l7_client, Ikev1DiffieHellmanGroup.MODP_2048_BIT, unittest.mock.MagicMock(),
        )
        self.assertFalse(result)

    def test_returns_true_on_invalid_key_information(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev1_handshake.side_effect = IsakmpNotify(Ikev1NotifyType.INVALID_KEY_INFORMATION)
        result = analyzer._send_ikev1_init_message(  # pylint: disable=protected-access
            l7_client, Ikev1DiffieHellmanGroup.MODP_2048_BIT, unittest.mock.MagicMock(),
        )
        self.assertTrue(result)

    def test_raises_and_logs_unexpected_notify(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev1_handshake.side_effect = IsakmpNotify(Ikev1NotifyType.INVALID_PAYLOAD_TYPE)
        with self.assertRaises(IsakmpNotify) as ctx:
            analyzer._send_ikev1_init_message(  # pylint: disable=protected-access
                l7_client, Ikev1DiffieHellmanGroup.MODP_2048_BIT, unittest.mock.MagicMock(),
            )
        self.assertEqual(ctx.exception.notify, Ikev1NotifyType.INVALID_PAYLOAD_TYPE)

    def test_returns_false_on_no_response(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev1_handshake.side_effect = NetworkError(NetworkErrorType.NO_RESPONSE)
        result = analyzer._send_ikev1_init_message(  # pylint: disable=protected-access
            l7_client, Ikev1DiffieHellmanGroup.MODP_2048_BIT, unittest.mock.MagicMock(),
        )
        self.assertFalse(result)

    def test_reraises_non_no_response_network_error(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev1_handshake.side_effect = NetworkError(NetworkErrorType.NO_CONNECTION)
        with self.assertRaises(NetworkError) as ctx:
            analyzer._send_ikev1_init_message(  # pylint: disable=protected-access
                l7_client, Ikev1DiffieHellmanGroup.MODP_2048_BIT, unittest.mock.MagicMock(),
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_returns_true_on_success(self):
        analyzer, l7_client = self._make_analyzer_and_client()
        l7_client.do_ikev1_handshake.return_value = {}
        result = analyzer._send_ikev1_init_message(  # pylint: disable=protected-access
            l7_client, Ikev1DiffieHellmanGroup.MODP_2048_BIT, unittest.mock.MagicMock(),
        )
        self.assertTrue(result)
