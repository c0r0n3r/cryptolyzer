# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import unittest
import unittest.mock

from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1DiffieHellmanGroup,
    Ikev1EncryptionAlgorithm,
    Ikev1HashAlgorithm,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2IntegrityAlgorithm,
    Ikev2NotifyType,
    Ikev2PseudorandomFunction,
)

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

    def test_error_key_length_not_found(self):
        with self.assertRaises(ValueError):
            Ikev2CipherSuite.from_transform_ids(
                encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_DES_IV64,
                integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
                pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_MD5,
                diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
                key_length=9999,
            )


class TestSendIkev2InitMessageNoProposalChosen(unittest.TestCase):
    def test_returns_none_on_no_proposal_chosen(self):
        analyzer = AnalyzerDHParams()
        l7_client = unittest.mock.MagicMock()
        l7_client.l4_socket_params.throttle_delay = 0
        l7_client.do_ikev2_handshake.side_effect = IsakmpNotify(Ikev2NotifyType.NO_PROPOSAL_CHOSEN)
        # pylint: disable=protected-access
        result = analyzer._send_ikev2_init_message(l7_client, unittest.mock.MagicMock())
        self.assertIsNone(result)
