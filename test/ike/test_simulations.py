
import unittest
import unittest.mock

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode
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
    Ikev2PseudorandomFunction,
    Ikev2TransformType,
)
from cryptodatahub.ike.version import IkeVersion

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.__main__ import get_argument_parser
from cryptolyzer.ike.client import L7ClientIPsecBase
from cryptolyzer.ike.exception import IsakmpNotify
from cryptolyzer.ike.simulations import AnalyzerIkev1Simulations, AnalyzerIkev2Simulations


class TestAnalyzerSimulationsBase(unittest.TestCase):
    @staticmethod
    def _make_mock_client():
        return L7ClientIPsecBase.from_scheme(
            'ipsec', 'localhost', 500, L4TransferSocketParams(timeout=1.0), ip='127.0.0.1',
        )

    @staticmethod
    def _raise_notify(notify_type, server_messages=None):
        def _side_effect(*_args, **_kwargs):
            exception = IsakmpNotify(notify_type)
            exception.server_messages = {} if server_messages is None else server_messages
            raise exception
        return _side_effect

    @staticmethod
    def _configured_analyzer(
            encryption_algorithm='3des,aes128',
            hash_algorithm='sha256',
            authentication_method='psk',
            diffie_hellman_group='modp1536',
            proposals_format='strongswan',
    ):
        parser = get_argument_parser()
        arguments = parser.parse_args([
            'ikev1', 'simulations',
            '--encryption-algorithm', encryption_algorithm,
            '--hash-algorithm', hash_algorithm,
            '--authentication-method', authentication_method,
            '--diffie-hellman-group', diffie_hellman_group,
            '--proposals-format', proposals_format,
            'ipsec://localhost',
        ])
        analyzer = AnalyzerIkev1Simulations()
        analyzer.parse_arguments(parser, arguments)
        return parser, arguments, analyzer

    @staticmethod
    def _sa_response_ikev1(
            encryption_algorithm, key_length, hash_algorithm, authentication_method, diffie_hellman_group
    ):
        attributes = {
            Ikev1AttributeType.ENCRYPTION_ALGORITHM: encryption_algorithm,
            Ikev1AttributeType.KEY_LENGTH: key_length,
            Ikev1AttributeType.HASH_ALGORITHM: hash_algorithm,
            Ikev1AttributeType.AUTHENTICATION_METHOD: authentication_method,
            Ikev1AttributeType.GROUP_DESCRIPTION: diffie_hellman_group,
        }

        def _get_attribute_by_type(attribute_type):
            if attribute_type not in attributes:
                raise KeyError(attribute_type)
            attribute = unittest.mock.MagicMock()
            attribute.value = attributes[attribute_type]
            return attribute
        transform = unittest.mock.MagicMock()
        transform.get_attribute_by_type.side_effect = _get_attribute_by_type
        sa_payload = unittest.mock.MagicMock()
        sa_payload.proposals = [unittest.mock.MagicMock()]
        sa_payload.proposals[0].transforms = [transform]
        response_message = unittest.mock.MagicMock()
        response_message.get_payload_by_type.return_value = sa_payload
        return {Ikev1ExchangeType.IDENTITY_PROTECTION: [response_message]}

    @staticmethod
    def _configured_ikev2_analyzer(
            encryption_algorithm='aes128',
            pseudorandom_function='sha256',
            integrity_algorithm='sha256',
            diffie_hellman_group='modp2048',
            proposals_format='strongswan',
    ):
        parser = get_argument_parser()
        argv = [
            'ikev2', 'simulations',
            '--encryption-algorithm', encryption_algorithm,
            '--pseudorandom-function', pseudorandom_function,
            '--diffie-hellman-group', diffie_hellman_group,
            '--proposals-format', proposals_format,
        ]
        if integrity_algorithm is not None:
            argv += ['--integrity-algorithm', integrity_algorithm]
        argv.append('ipsec://localhost')
        arguments = parser.parse_args(argv)
        analyzer = AnalyzerIkev2Simulations()
        analyzer.parse_arguments(parser, arguments)
        return parser, arguments, analyzer

    @staticmethod
    def _sa_response_ikev2(encryption, key_length, pseudorandom_function, diffie_hellman_group, integrity):
        def _get_transform_by_type(transform_type):
            transform = unittest.mock.MagicMock()
            if transform_type == Ikev2TransformType.ENCR:
                transform.transform_id, transform.key_length = encryption, key_length
            elif transform_type == Ikev2TransformType.PRF:
                transform.transform_id = pseudorandom_function
            elif transform_type == Ikev2TransformType.DH:
                transform.transform_id = diffie_hellman_group
            else:  # Ikev2TransformType.INTEG
                if integrity is None:
                    raise KeyError(transform_type)
                transform.transform_id = integrity
            return transform

        sa_payload = unittest.mock.MagicMock()
        sa_payload.get_transform_by_type.side_effect = _get_transform_by_type
        response_message = unittest.mock.MagicMock()
        response_message.get_payload_by_type.return_value = sa_payload
        return {Ikev2ExchangeType.IKE_SA_INIT: response_message}


class TestAnalyzerIkev1SimulationsUnit(TestAnalyzerSimulationsBase):
    def test_get_name(self):
        self.assertEqual(AnalyzerIkev1Simulations.get_name(), 'simulations')

    def test_get_help(self):
        self.assertIn('proposal set', AnalyzerIkev1Simulations.get_help())

    def test_parse_arguments_resolves_key_length_to_distinct_ciphers(self):
        _, _, analyzer = self._configured_analyzer(encryption_algorithm='aes128,aes256')
        offered = analyzer._get_offered_encryption_algorithms()  # pylint: disable=protected-access
        self.assertEqual(
            [entry.encryption_algorithm for entry in offered],
            [BlockCipher.AES_128, BlockCipher.AES_256]
        )
        self.assertEqual(offered[0].block_cipher_mode, BlockCipherMode.CBC)

    def test_parse_arguments_deduplicates_repeated_token_keeping_order(self):
        _, _, analyzer = self._configured_analyzer(encryption_algorithm='aes256,aes128,aes256')
        offered = analyzer._get_offered_encryption_algorithms()  # pylint: disable=protected-access
        self.assertEqual(
            [entry.encryption_algorithm for entry in offered],
            [BlockCipher.AES_256, BlockCipher.AES_128]
        )

    def test_parse_arguments_bad_token(self):
        parser, arguments, _ = self._configured_analyzer()
        arguments.encryption_algorithm = 'no-such-cipher'
        with self.assertRaises(SystemExit):
            AnalyzerIkev1Simulations().parse_arguments(parser, arguments)

    def test_parse_arguments_empty_axis(self):
        parser, arguments, _ = self._configured_analyzer()
        arguments.hash_algorithm = ''
        with self.assertRaises(SystemExit):
            AnalyzerIkev1Simulations().parse_arguments(parser, arguments)

    def test_parse_arguments_too_many_transforms(self):
        parser = get_argument_parser()
        arguments = parser.parse_args([
            'ikev1', 'simulations',
            '--encryption-algorithm',
            'aes128,aes192,aes256,3des,des,blowfish128,blowfish192,blowfish256,'
            'camellia128,camellia192,camellia256,cast128,serpent128,serpent192,serpent256,twofish128',
            '--hash-algorithm', 'md5,sha1,sha256,sha384',
            '--authentication-method', 'psk',
            '--diffie-hellman-group', 'modp1536,modp2048,modp3072,modp4096',
            'ipsec://localhost',
        ])
        with self.assertRaises(SystemExit):
            AnalyzerIkev1Simulations().parse_arguments(parser, arguments)

    def test_get_algorithms_fixed_key_omits_key_length(self):
        _, _, analyzer = self._configured_analyzer(encryption_algorithm='3des,aes128')
        algorithms = analyzer._get_algorithms()  # pylint: disable=protected-access
        by_encryption = {algorithm.encryption_algorithm: algorithm.key_length for algorithm in algorithms}
        self.assertIsNone(by_encryption[Ikev1EncryptionAlgorithm.DES3_CBC])
        self.assertEqual(by_encryption[Ikev1EncryptionAlgorithm.AES_CBC], 128)

    def test_get_negotiated_cipher_suite_malformed_returns_none(self):
        _, _, analyzer = self._configured_analyzer()
        transform = unittest.mock.MagicMock()
        transform.get_attribute_by_type.side_effect = KeyError(Ikev1AttributeType.ENCRYPTION_ALGORITHM)
        sa_payload = unittest.mock.MagicMock()
        sa_payload.proposals = [unittest.mock.MagicMock()]
        sa_payload.proposals[0].transforms = [transform]
        response_message = unittest.mock.MagicMock()
        response_message.get_payload_by_type.return_value = sa_payload
        server_messages = {Ikev1ExchangeType.IDENTITY_PROTECTION: [response_message]}
        self.assertIsNone(
            analyzer._get_negotiated_cipher_suite(server_messages)  # pylint: disable=protected-access
        )


class TestAnalyzerIkev1Simulations(TestAnalyzerSimulationsBase):
    def test_accepted(self):
        _, _, analyzer = self._configured_analyzer()
        server_messages = self._sa_response_ikev1(
            Ikev1EncryptionAlgorithm.AES_CBC, 128,
            Ikev1HashAlgorithm.SHA2_256,
            Ikev1AuthenticationMethod.PRE_SHARED_KEY,
            Ikev1DiffieHellmanGroup.MODP_1536_BIT,
        )
        client = self._make_mock_client()
        with unittest.mock.patch.object(client, 'do_ikev1_handshake', return_value=server_messages):
            result = analyzer.analyze(client, IkeVersion.V1)

        self.assertEqual(list(result.succeeded_clients), ['custom'])
        self.assertEqual(result.failed_clients, {})
        probe = result.succeeded_clients['custom']
        self.assertIsNone(probe.notify)
        self.assertEqual(probe.negotiated.encryption_algorithm, BlockCipher.AES_128)
        self.assertEqual(probe.negotiated.block_cipher_mode, BlockCipherMode.CBC)

    def test_rejected_no_proposal_chosen(self):
        _, _, analyzer = self._configured_analyzer()
        client = self._make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake', side_effect=self._raise_notify(Ikev1NotifyType.NO_PROPOSAL_CHOSEN)
        ):
            result = analyzer.analyze(client, IkeVersion.V1)

        self.assertEqual(list(result.failed_clients), ['custom'])
        self.assertEqual(result.succeeded_clients, {})
        probe = result.failed_clients['custom']
        self.assertEqual(probe.notify, Ikev1NotifyType.NO_PROPOSAL_CHOSEN)
        self.assertIsNone(probe.negotiated)

    def test_invalid_key_information_without_sa_is_rejected(self):
        _, _, analyzer = self._configured_analyzer()
        client = self._make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake', side_effect=self._raise_notify(Ikev1NotifyType.INVALID_KEY_INFORMATION)
        ):
            result = analyzer.analyze(client, IkeVersion.V1)

        self.assertEqual(list(result.failed_clients), ['custom'])
        self.assertEqual(result.succeeded_clients, {})
        probe = result.failed_clients['custom']
        self.assertEqual(probe.notify, Ikev1NotifyType.INVALID_KEY_INFORMATION)
        self.assertIsNone(probe.negotiated)

    def test_invalid_key_information_with_sa_reports_negotiated(self):
        _, _, analyzer = self._configured_analyzer()
        server_messages = self._sa_response_ikev1(
            Ikev1EncryptionAlgorithm.DES3_CBC, None,
            Ikev1HashAlgorithm.SHA2_256,
            Ikev1AuthenticationMethod.PRE_SHARED_KEY,
            Ikev1DiffieHellmanGroup.MODP_1536_BIT,
        )
        client = self._make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake',
            side_effect=self._raise_notify(Ikev1NotifyType.INVALID_KEY_INFORMATION, server_messages),
        ):
            result = analyzer.analyze(client, IkeVersion.V1)

        probe = result.succeeded_clients['custom']
        self.assertEqual(probe.notify, Ikev1NotifyType.INVALID_KEY_INFORMATION)
        self.assertIsNotNone(probe.negotiated)

    def test_no_response(self):
        _, _, analyzer = self._configured_analyzer()
        client = self._make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake', side_effect=NetworkError(NetworkErrorType.NO_RESPONSE)
        ):
            result = analyzer.analyze(client, IkeVersion.V1)

        probe = result.failed_clients['custom']
        self.assertIsNone(probe.notify)
        self.assertIsNone(probe.negotiated)

    def test_unacceptable_notify_propagates(self):
        _, _, analyzer = self._configured_analyzer()
        client = self._make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev1_handshake', side_effect=self._raise_notify(Ikev1NotifyType.INVALID_EXCHANGE_TYPE)
        ):
            with self.assertRaises(IsakmpNotify):
                analyzer.analyze(client, IkeVersion.V1)


class TestAnalyzerIkev2SimulationsUnit(TestAnalyzerSimulationsBase):
    def test_get_name(self):
        self.assertEqual(AnalyzerIkev2Simulations.get_name(), 'simulations')

    def test_get_help(self):
        self.assertIn('proposal set', AnalyzerIkev2Simulations.get_help())

    def test_parse_arguments_resolves_key_length_to_distinct_ciphers(self):
        _, _, analyzer = self._configured_ikev2_analyzer(encryption_algorithm='aes128,aes256')
        offered = analyzer._get_offered_encryption_algorithms()  # pylint: disable=protected-access
        self.assertEqual(
            [entry.encryption_algorithm for entry in offered],
            [BlockCipher.AES_128, BlockCipher.AES_256]
        )
        self.assertEqual(offered[0].block_cipher_mode, BlockCipherMode.CBC)

    def test_parse_arguments_bad_token(self):
        parser, arguments, _ = self._configured_ikev2_analyzer()
        arguments.encryption_algorithm = 'no-such-cipher'
        with self.assertRaises(SystemExit):
            AnalyzerIkev2Simulations().parse_arguments(parser, arguments)

    def test_parse_arguments_empty_required_axis(self):
        parser, arguments, _ = self._configured_ikev2_analyzer()
        arguments.pseudorandom_function = ''
        with self.assertRaises(SystemExit):
            AnalyzerIkev2Simulations().parse_arguments(parser, arguments)

    def test_parse_arguments_non_aead_requires_integrity(self):
        parser, arguments, _ = self._configured_ikev2_analyzer()
        arguments.integrity_algorithm = ''
        with self.assertRaises(SystemExit):
            AnalyzerIkev2Simulations().parse_arguments(parser, arguments)

    def test_parse_arguments_aead_only_forbids_integrity(self):
        parser, arguments, _ = self._configured_ikev2_analyzer()
        arguments.encryption_algorithm = 'aes256gcm16'
        with self.assertRaises(SystemExit):
            AnalyzerIkev2Simulations().parse_arguments(parser, arguments)

    def test_parse_arguments_aead_only_without_integrity(self):
        _, _, analyzer = self._configured_ikev2_analyzer(encryption_algorithm='aes256gcm16', integrity_algorithm=None)
        offered = analyzer._get_offered_encryption_algorithms()  # pylint: disable=protected-access
        self.assertEqual([entry.encryption_algorithm for entry in offered], [BlockCipher.AES_256])

    def test_parse_arguments_mixed_aead_with_integrity(self):
        _, _, analyzer = self._configured_ikev2_analyzer(encryption_algorithm='aes128,aes256gcm16')
        offered = analyzer._get_offered_encryption_algorithms()  # pylint: disable=protected-access
        self.assertEqual(
            [entry.encryption_algorithm for entry in offered],
            [BlockCipher.AES_128, BlockCipher.AES_256]
        )

    def test_parse_arguments_none_integrity_non_aead_rejected(self):
        parser = get_argument_parser()
        arguments = parser.parse_args([
            'ikev2', 'simulations',
            '--encryption-algorithm', 'encr_aes_cbc/128',
            '--pseudorandom-function', 'prf_hmac_sha2_256',
            '--integrity-algorithm', 'none',
            '--diffie-hellman-group', 'modp_group_2048_bit',
            '--proposals-format', 'iana',
            'ipsec://localhost',
        ])
        with self.assertRaises(SystemExit):
            AnalyzerIkev2Simulations().parse_arguments(parser, arguments)

    def test_parse_arguments_none_integrity_aead_only_ok(self):
        # AEAD-only + INTEG=NONE is valid (RFC 7296 §3.3); NONE is dropped so the
        # integrity axis ends up empty
        parser = get_argument_parser()
        arguments = parser.parse_args([
            'ikev2', 'simulations',
            '--encryption-algorithm', 'encr_aes_gcm_16/256',
            '--pseudorandom-function', 'prf_hmac_sha2_256',
            '--integrity-algorithm', 'none',
            '--diffie-hellman-group', 'modp_group_2048_bit',
            '--proposals-format', 'iana',
            'ipsec://localhost',
        ])
        analyzer = AnalyzerIkev2Simulations()
        analyzer.parse_arguments(parser, arguments)
        offered = analyzer._get_offered_encryption_algorithms()  # pylint: disable=protected-access
        self.assertEqual([entry.encryption_algorithm for entry in offered], [BlockCipher.AES_256])
        self.assertEqual(analyzer._integrity_algorithms, [])  # pylint: disable=protected-access


class TestAnalyzerIkev2Simulations(TestAnalyzerSimulationsBase):
    def test_accepted(self):
        _, _, analyzer = self._configured_ikev2_analyzer()
        server_messages = self._sa_response_ikev2(
            Ikev2EncryptionAlgorithm.ENCR_AES_CBC, 128,
            Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
            Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA2_256_128,
        )
        client = self._make_mock_client()
        with unittest.mock.patch.object(client, 'do_ikev2_handshake', return_value=server_messages):
            result = analyzer.analyze(client, IkeVersion.V2)

        self.assertEqual(list(result.succeeded_clients), ['custom'])
        self.assertEqual(result.failed_clients, {})
        probe = result.succeeded_clients['custom']
        self.assertIsNone(probe.notify)
        self.assertEqual(probe.negotiated.encryption_algorithm, BlockCipher.AES_128)
        self.assertEqual(probe.negotiated.block_cipher_mode, BlockCipherMode.CBC)
        self.assertIsNotNone(probe.negotiated.integrity_algorithm)

    def test_accepted_aead_without_integrity(self):
        _, _, analyzer = self._configured_ikev2_analyzer(encryption_algorithm='aes256gcm16', integrity_algorithm=None)
        server_messages = self._sa_response_ikev2(
            Ikev2EncryptionAlgorithm.ENCR_AES_GCM_16, 256,
            Ikev2PseudorandomFunction.PRF_HMAC_SHA2_256,
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
            None,
        )
        client = self._make_mock_client()
        with unittest.mock.patch.object(client, 'do_ikev2_handshake', return_value=server_messages):
            result = analyzer.analyze(client, IkeVersion.V2)

        probe = result.succeeded_clients['custom']
        self.assertEqual(probe.negotiated.encryption_algorithm, BlockCipher.AES_256)
        self.assertIsNone(probe.negotiated.integrity_algorithm)

    def test_get_negotiated_cipher_suite_malformed_returns_none(self):
        _, _, analyzer = self._configured_ikev2_analyzer()
        sa_payload = unittest.mock.MagicMock()
        sa_payload.get_transform_by_type.side_effect = KeyError(Ikev2TransformType.ENCR)
        response_message = unittest.mock.MagicMock()
        response_message.get_payload_by_type.return_value = sa_payload
        server_messages = {Ikev2ExchangeType.IKE_SA_INIT: response_message}
        self.assertIsNone(
            analyzer._get_negotiated_cipher_suite(server_messages)  # pylint: disable=protected-access
        )

    def test_rejected_no_proposal_chosen(self):
        _, _, analyzer = self._configured_ikev2_analyzer()
        client = self._make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev2_handshake', side_effect=self._raise_notify(Ikev2NotifyType.NO_PROPOSAL_CHOSEN)
        ):
            result = analyzer.analyze(client, IkeVersion.V2)

        self.assertEqual(list(result.failed_clients), ['custom'])
        self.assertEqual(result.succeeded_clients, {})
        probe = result.failed_clients['custom']
        self.assertEqual(probe.notify, Ikev2NotifyType.NO_PROPOSAL_CHOSEN)
        self.assertIsNone(probe.negotiated)

    def test_invalid_ke_payload_is_accepted(self):
        _, _, analyzer = self._configured_ikev2_analyzer()
        client = self._make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev2_handshake', side_effect=self._raise_notify(Ikev2NotifyType.INVALID_KE_PAYLOAD)
        ):
            result = analyzer.analyze(client, IkeVersion.V2)

        probe = result.succeeded_clients['custom']
        self.assertEqual(probe.notify, Ikev2NotifyType.INVALID_KE_PAYLOAD)
        self.assertIsNone(probe.negotiated)

    def test_no_response(self):
        _, _, analyzer = self._configured_ikev2_analyzer()
        client = self._make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev2_handshake', side_effect=NetworkError(NetworkErrorType.NO_RESPONSE)
        ):
            result = analyzer.analyze(client, IkeVersion.V2)

        probe = result.failed_clients['custom']
        self.assertIsNone(probe.notify)
        self.assertIsNone(probe.negotiated)

    def test_unacceptable_notify_propagates(self):
        _, _, analyzer = self._configured_ikev2_analyzer()
        client = self._make_mock_client()
        with unittest.mock.patch.object(
            client, 'do_ikev2_handshake', side_effect=self._raise_notify(Ikev2NotifyType.INVALID_SYNTAX)
        ):
            with self.assertRaises(IsakmpNotify):
                analyzer.analyze(client, IkeVersion.V2)
