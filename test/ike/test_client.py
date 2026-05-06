# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import typing

import unittest

from cryptodatahub.ike.algorithm import (
    Ikev1AttributeType,
    Ikev1AuthenticationMethod,
    Ikev1DiffieHellmanGroup,
    Ikev1EncryptionAlgorithm,
    Ikev1ExchangeType,
    Ikev1HashAlgorithm,
    Ikev1NotifyType,
    Ikev1PayloadType,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2ExchangeType,
    Ikev2IntegrityAlgorithm,
    Ikev2NotifyType,
    Ikev2PayloadType,
    Ikev2ProtocolId,
    Ikev2PseudorandomFunction,
    Ikev2TransformType,
)

from cryptoparser.ike.isakmp import IsakmpFlags, IsakmpMessage
from cryptoparser.ike.ikev2 import Ikev2NotifyPayloadCookie, Ikev2PayloadNotifyUnparsed

from cryptolyzer.common.exception import SecurityError, SecurityErrorType
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4TransferBase, L4TransferSocketParams
from cryptolyzer.ike.client import (
    IKEClient,
    IKEv1ClientHandshake,
    Ikev1SecurityAssociationAlgorithms,
    Ikev1SecurityAssociationBase,
    Ikev1SecurityAssociationProposalAlgorithms,
    Ikev1SecurityAssociationSpecialization,
    IKEv2ClientHandshake,
    Ikev2SecurityAssociationAnyAlgorithm,
    Ikev2SecurityAssociationSpecialization,
    L7ClientIPsecBase,
)
from cryptolyzer.ike.exception import IsakmpNotify
from cryptolyzer.ike.versions import AnalyzerVersions

from .classes import (
    L4TransferDummy,
    L4TransferIkev1InvalidValueResponse,
    L4TransferIkev1NonceFirst,
    L4TransferIkev1UnexpectedExchangeType,
    L4TransferUnexpectedExchangeType,
    L7ServerIkeIkev1HeaderOnlyPartialPayload,
    L7ServerIkeIkev2AlwaysInvalidKePayload,
    L7ServerIkeIkev2HeaderOnlyPartialPayload,
    L7ServerIkeIkev2NonceFirst,
    L7ServerIkeNoProposalChosen,
    L7ServerIkeTest,
    L7ServerIke,
    L7ServerIkeNotify,
)


class TestIkev2SecurityAssociationSpecialization(unittest.TestCase):
    def test_ffdh_key_exchange_payload(self):
        dh_group = Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT
        message = Ikev2SecurityAssociationSpecialization(
            diffie_hellman_groups=(dh_group,),
        )

        key_exchange_payload = message.get_payload_by_type(Ikev2PayloadType.KE)
        self.assertEqual(key_exchange_payload.dh_group, dh_group)

        security_association_payload = message.get_payload_by_type(Ikev2PayloadType.SA)
        self.assertIsNotNone(security_association_payload)

        dh_transform = security_association_payload.get_transform_by_type(Ikev2TransformType.DH)
        self.assertIsNotNone(dh_transform)
        self.assertEqual(dh_transform.transform_id, dh_group)

        nonce_payload = message.get_payload_by_type(Ikev2PayloadType.NONCE)
        self.assertIsNotNone(nonce_payload)

    def test_ecdh_key_exchange_payload(self):
        dh_group = Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT
        message = Ikev2SecurityAssociationSpecialization(
            diffie_hellman_groups=(dh_group,),
        )

        security_association_payload = message.get_payload_by_type(Ikev2PayloadType.SA)
        self.assertIsNotNone(security_association_payload)

        dh_transform = security_association_payload.get_transform_by_type(Ikev2TransformType.DH)
        self.assertIsNotNone(dh_transform)
        self.assertEqual(dh_transform.transform_id, dh_group)

        key_exchange_payload = message.get_payload_by_type(Ikev2PayloadType.KE)
        self.assertEqual(key_exchange_payload.dh_group, dh_group)

        nonce_payload = message.get_payload_by_type(Ikev2PayloadType.NONCE)
        self.assertIsNotNone(nonce_payload)

    def test_cookie(self):
        cookie = b'0123456789abcdef'
        message = Ikev2SecurityAssociationSpecialization(
            cookie=cookie,
        )
        cookie_payload = message.get_payload_by_type(Ikev2PayloadType.NOTIFY)
        self.assertEqual(message.payloads[0], cookie_payload)
        self.assertEqual(cookie_payload.cookie, cookie)


class TestIkev1SecurityAssociationSpecialization(unittest.TestCase):
    def test_ffdh_key_exchange_payload(self):
        dh_group = Ikev1DiffieHellmanGroup.MODP_2048_BIT
        message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.AGGRESSIVE,
            diffie_hellman_groups=(dh_group,),
        )

        key_exchange_payload = message.get_payload_by_type(Ikev1PayloadType.KEY_EXCHANGE)
        self.assertIsNotNone(key_exchange_payload)

        nonce_payload = message.get_payload_by_type(Ikev1PayloadType.NONCE)
        self.assertIsNotNone(nonce_payload)

        security_association_payload = message.get_payload_by_type(Ikev1PayloadType.SECURITY_ASSOCIATION)
        self.assertIsNotNone(security_association_payload)

    def test_ecdh_key_exchange_payload(self):
        dh_group = Ikev1DiffieHellmanGroup.ECP_256_BIT
        message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.AGGRESSIVE,
            diffie_hellman_groups=(dh_group,),
        )

        key_exchange_payload = message.get_payload_by_type(Ikev1PayloadType.KEY_EXCHANGE)
        self.assertIsNotNone(key_exchange_payload)

        nonce_payload = message.get_payload_by_type(Ikev1PayloadType.NONCE)
        self.assertIsNotNone(nonce_payload)

        security_association_payload = message.get_payload_by_type(Ikev1PayloadType.SECURITY_ASSOCIATION)
        self.assertIsNotNone(security_association_payload)

    def test_multiple_dh_groups(self):
        ffdh_group = Ikev1DiffieHellmanGroup.MODP_2048_BIT
        ecdh_group = Ikev1DiffieHellmanGroup.ECP_256_BIT
        message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.AGGRESSIVE,
            diffie_hellman_groups=(ffdh_group, ecdh_group),
        )

        key_exchange_payload = message.get_payload_by_type(Ikev1PayloadType.KEY_EXCHANGE)
        self.assertIsNotNone(key_exchange_payload)

        nonce_payload = message.get_payload_by_type(Ikev1PayloadType.NONCE)
        self.assertIsNotNone(nonce_payload)

        security_association_payload = message.get_payload_by_type(Ikev1PayloadType.SECURITY_ASSOCIATION)
        self.assertIsNotNone(security_association_payload)

    def test_key_length(self):
        message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.AGGRESSIVE,
            encryption_algorithms=(Ikev1EncryptionAlgorithm.AES_CBC,),
            key_length=128,
        )
        security_association_payload = message.get_payload_by_type(Ikev1PayloadType.SECURITY_ASSOCIATION)
        self.assertIsNotNone(security_association_payload)
        for proposal in security_association_payload.proposals:
            for transform in proposal.transforms:
                key_length_attribute = transform.get_attribute_by_type(Ikev1AttributeType.KEY_LENGTH)
                self.assertIsNotNone(key_length_attribute)
                self.assertEqual(key_length_attribute.value, 128)


class TestIkev1SecurityAssociationAlgorithms(unittest.TestCase):
    def test_constructor(self):
        algorithms = [
            Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=Ikev1EncryptionAlgorithm.DES3_CBC,
                diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
                hash_algorithm=Ikev1HashAlgorithm.MD5,
                authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                key_length=128,
            ),
        ]
        message = Ikev1SecurityAssociationAlgorithms(
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            algorithms=algorithms,
        )
        sa_payload = message.get_payload_by_type(Ikev1PayloadType.SECURITY_ASSOCIATION)
        self.assertIsNotNone(sa_payload)
        self.assertGreater(len(sa_payload.proposals), 0)

    def test_aggressive_mode(self):
        algorithms = [
            Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
                diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
                hash_algorithm=Ikev1HashAlgorithm.SHA,
                authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                key_length=128,
            ),
        ]
        message = Ikev1SecurityAssociationAlgorithms(
            exchange_type=Ikev1ExchangeType.AGGRESSIVE,
            algorithms=algorithms,
        )
        key_exchange_payload = message.get_payload_by_type(Ikev1PayloadType.KEY_EXCHANGE)
        self.assertIsNotNone(key_exchange_payload)
        sa_payload = message.get_payload_by_type(Ikev1PayloadType.SECURITY_ASSOCIATION)
        self.assertIsNotNone(sa_payload)
        self.assertGreater(len(sa_payload.proposals), 0)


class TestIkev1SecurityAssociationBaseDhGroups(unittest.TestCase):
    def test_ffdh_group_only(self):
        proposals = Ikev1SecurityAssociationBase.get_proposals(
            encryption_algorithm=Ikev1EncryptionAlgorithm.DES3_CBC,
            diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            hash_algorithm=Ikev1HashAlgorithm.MD5,
            authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
        )
        ffdh, ecdh = Ikev1SecurityAssociationBase._get_dh_groups(proposals)  # pylint: disable=protected-access
        self.assertIsNotNone(ffdh)
        self.assertIsNone(ecdh)
        self.assertEqual(ffdh, Ikev1DiffieHellmanGroup.MODP_2048_BIT)

    def test_ecdh_group_only(self):
        proposals = Ikev1SecurityAssociationBase.get_proposals(
            encryption_algorithm=Ikev1EncryptionAlgorithm.DES3_CBC,
            diffie_hellman_group=Ikev1DiffieHellmanGroup.ECP_256_BIT,
            hash_algorithm=Ikev1HashAlgorithm.MD5,
            authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
        )
        ffdh, ecdh = Ikev1SecurityAssociationBase._get_dh_groups(proposals)  # pylint: disable=protected-access
        self.assertIsNone(ffdh)
        self.assertIsNotNone(ecdh)
        self.assertEqual(ecdh, Ikev1DiffieHellmanGroup.ECP_256_BIT)

    def test_both_ffdh_and_ecdh(self):
        ffdh_proposals = Ikev1SecurityAssociationBase.get_proposals(
            encryption_algorithm=Ikev1EncryptionAlgorithm.DES3_CBC,
            diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
            hash_algorithm=Ikev1HashAlgorithm.MD5,
            authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
        )
        ecdh_proposals = Ikev1SecurityAssociationBase.get_proposals(
            encryption_algorithm=Ikev1EncryptionAlgorithm.DES3_CBC,
            diffie_hellman_group=Ikev1DiffieHellmanGroup.ECP_256_BIT,
            hash_algorithm=Ikev1HashAlgorithm.MD5,
            authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
        )
        ffdh, ecdh = Ikev1SecurityAssociationBase._get_dh_groups(  # pylint: disable=protected-access
            ffdh_proposals + ecdh_proposals
        )
        self.assertIsNotNone(ffdh)
        self.assertIsNotNone(ecdh)
        self.assertEqual(ffdh, Ikev1DiffieHellmanGroup.MODP_2048_BIT)
        self.assertEqual(ecdh, Ikev1DiffieHellmanGroup.ECP_256_BIT)


class TestIkev1ClientHandshake(unittest.TestCase):
    def test_error_no_proposal_chosen(self):
        threaded_server = L7ServerIkeTest(L7ServerIkeNoProposalChosen(
            'localhost',
            0,
            L4TransferSocketParams(timeout=0.5),
            max_handshake_count=1,
        ))
        threaded_server.wait_for_server_listen()
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        client = L7ClientIPsecBase.from_scheme(
            'ipsec',
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
            ip=l4_transfer.bind_address,
        )

        init_message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            diffie_hellman_groups=(),
        )
        with self.assertRaises(IsakmpNotify) as ctx:
            client.do_ikev1_handshake(
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            )
        self.assertEqual(ctx.exception.notify, Ikev1NotifyType.NO_PROPOSAL_CHOSEN)

        threaded_server.join()

    def test_error_no_response_on_localhost_443(self):
        client = L7ClientIPsecBase.from_scheme(
            'ipsec',
            'localhost',
            443,
            L4TransferSocketParams(timeout=0.1),
        )

        init_message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            diffie_hellman_groups=(),
        )
        with self.assertRaises(NetworkError) as ctx:
            client.do_ikev1_handshake(
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_RESPONSE)

    def test_error_no_connection(self):
        threaded_server = L7ServerIkeTest(L7ServerIkeIkev1HeaderOnlyPartialPayload(
            'localhost',
            0,
            L4TransferSocketParams(timeout=0.5),
            max_handshake_count=1,
        ))
        threaded_server.wait_for_server_listen()
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        client = L7ClientIPsecBase.from_scheme(
            'ipsec',
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
            ip=l4_transfer.bind_address,
        )

        init_message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            diffie_hellman_groups=(),
        )
        with self.assertRaises(NetworkError) as ctx:
            client.do_ikev1_handshake(
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)

        threaded_server.join()

    def test_error_situation_not_supported(self):
        init_message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            diffie_hellman_groups=(),
        )
        transfer = L4TransferIkev1NonceFirst(
            'localhost',
            0,
            L4TransferSocketParams(timeout=0.5),
            init_message=init_message,
        )
        with self.assertRaises(IsakmpNotify) as ctx:
            IKEv1ClientHandshake().do_handshake(
                transfer,
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            )
        self.assertEqual(ctx.exception.notify, Ikev1NotifyType.SITUATION_NOT_SUPPORTED)

    def test_error_invalid_message(self):
        init_message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            diffie_hellman_groups=(),
        )
        transfer = L4TransferIkev1InvalidValueResponse('localhost', 0, L4TransferSocketParams(timeout=0.5))
        with self.assertRaises(SecurityError) as ctx:
            IKEv1ClientHandshake().do_handshake(
                transfer,
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            )
        self.assertEqual(ctx.exception.error, SecurityErrorType.UNPARSABLE_MESSAGE)

    def test_error_unparsable_message(self):
        init_message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            diffie_hellman_groups=(),
        )
        transfer = L4TransferIkev1UnexpectedExchangeType(
            'localhost',
            0,
            L4TransferSocketParams(timeout=0.5),
            init_message=init_message,
        )
        with self.assertRaises(SecurityError) as ctx:
            IKEv1ClientHandshake().do_handshake(
                transfer,
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            )
        self.assertEqual(ctx.exception.error, SecurityErrorType.UNPARSABLE_MESSAGE)

    def test_error_notify(self):
        threaded_server = L7ServerIkeTest(L7ServerIkeNotify(
            'localhost',
            0,
            L4TransferSocketParams(timeout=0.5),
            max_handshake_count=1,
        ))
        threaded_server.wait_for_server_listen()
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        client = L7ClientIPsecBase.from_scheme(
            'ipsec',
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
            ip=l4_transfer.bind_address,
        )

        init_message = Ikev1SecurityAssociationSpecialization(
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            diffie_hellman_groups=(),
        )
        with self.assertRaises(IsakmpNotify) as ctx:
            client.do_ikev1_handshake(
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            )
        self.assertEqual(ctx.exception.notify, Ikev1NotifyType.INVALID_PAYLOAD_TYPE)

        threaded_server.join()

    @staticmethod
    def _start_threaded_server(
        l7_server_class: typing.Type[L7ServerIke] = L7ServerIke,
        max_handshake_count: int = 2,
        socket_timeout: float = 0.5,
    ) -> L7ServerIkeTest:
        threaded_server = L7ServerIkeTest(l7_server_class(
            'localhost',
            0,
            L4TransferSocketParams(timeout=socket_timeout),
            max_handshake_count=max_handshake_count,
        ))
        threaded_server.wait_for_server_listen()
        return threaded_server

    @staticmethod
    def get_result(  # pylint: disable=too-many-arguments,too-many-positional-arguments
            proto,
            host,
            port,
            l4_socket_params=L4TransferSocketParams(),
            ip=None,
            analyzer=None
    ):
        if analyzer is None:
            analyzer = AnalyzerVersions()
        l7_client = L7ClientIPsecBase.from_scheme(proto, host, port, l4_socket_params, ip=ip)
        result = analyzer.analyze(l7_client, None)
        return l7_client, result

    def test_handshake(self):
        threaded_server = self._start_threaded_server()
        assert threaded_server.l7_server.l4_transfer is not None

        self.get_result(
            'ipsec',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
        )

        threaded_server.join()


class TestIkeClient(unittest.TestCase):
    def test_default_port(self):
        l7_client = L7ClientIPsecBase.from_scheme('ipsec', 'localhost')
        self.assertEqual(l7_client.port, 500)

    def test_error_plain_text_response(self):
        transfer = L4TransferDummy('localhost', 0, L4TransferSocketParams(timeout=0.5))
        transfer._buffer = bytearray(b'HTTP/1.1 400 Bad Request\r\n')  # pylint: disable=protected-access

        with self.assertRaises(SecurityError) as ctx:
            IKEClient.raise_response_error(transfer)

        self.assertEqual(ctx.exception.error, SecurityErrorType.PLAIN_TEXT_MESSAGE)
        self.assertEqual(transfer.buffer, bytearray())

    def test_error_unparsable_response(self):
        transfer = L4TransferDummy('localhost', 0, L4TransferSocketParams(timeout=0.5))
        transfer._buffer = bytearray(b'\xff\x00')  # pylint: disable=protected-access

        with self.assertRaises(SecurityError) as ctx:
            IKEClient.raise_response_error(transfer)

        self.assertEqual(ctx.exception.error, SecurityErrorType.UNPARSABLE_MESSAGE)
        self.assertEqual(transfer.buffer, bytearray())


class TestIkev2ClientHandshake(unittest.TestCase):
    """Test IKEv2 client handshake."""

    @staticmethod
    def _start_threaded_server(
        l7_server_class: typing.Type[L7ServerIke] = L7ServerIke,
        max_handshake_count: int = 2,
        socket_timeout: float = 0.5,
    ) -> L7ServerIkeTest:
        threaded_server = L7ServerIkeTest(l7_server_class(
            'localhost',
            0,
            L4TransferSocketParams(timeout=socket_timeout),
            max_handshake_count=max_handshake_count,
        ))
        threaded_server.wait_for_server_listen()

        return threaded_server

    @staticmethod
    def get_result(  # pylint: disable=too-many-arguments,too-many-positional-arguments
            proto,
            host,
            port,
            l4_socket_params=L4TransferSocketParams(),
            ip=None,
            analyzer=None
    ):
        if analyzer is None:
            analyzer = AnalyzerVersions()
        l7_client = L7ClientIPsecBase.from_scheme(proto, host, port, l4_socket_params, ip=ip)
        result = analyzer.analyze(l7_client, None)
        return l7_client, result

    def test_handshake(self):
        threaded_server = self._start_threaded_server()
        assert threaded_server.l7_server.l4_transfer is not None

        self.get_result(
            'ipsec',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
        )

        threaded_server.join()

    def test_error_no_response_on_localhost_443(self):
        client = L7ClientIPsecBase.from_scheme(
            'ipsec',
            'localhost',
            443,
            L4TransferSocketParams(timeout=0.1),
        )

        with self.assertRaises(NetworkError) as ctx:
            client.do_ikev2_handshake(
                init_message=Ikev2SecurityAssociationAnyAlgorithm(),
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_RESPONSE)

    def test_cookie_handling(self):
        # Cookie handling is a client-side behavior; test it without starting a real server.
        init_message = Ikev2SecurityAssociationSpecialization(
            encryption_algorithms=(tuple(Ikev2EncryptionAlgorithm)[0],),
            diffie_hellman_groups=(tuple(Ikev2DiffieHellmanGroup)[0],),
            pseudorandom_functions=(tuple(Ikev2PseudorandomFunction)[0],),
            integrity_algorithms=(tuple(Ikev2IntegrityAlgorithm)[0],),
        )

        cookie_value = b'0123456789abcdef'

        class _L4TransferCookieScript(L4TransferBase):
            def __init__(self, address, port, socket_params, ip=None):
                super().__init__(address, port, socket_params, ip)
                self._send_count = 0
                self._pending_recv = bytearray()
                self.sent_messages = []

            def _send(self, sendable_bytes):
                self.sent_messages.append(bytes(sendable_bytes))
                self._send_count += 1

                # 1st client send -> respond with COOKIE notify (forces retry)
                # 2nd client send -> respond with INVALID_SYNTAX notify (terminates quickly)
                if self._send_count == 1:
                    payload = Ikev2NotifyPayloadCookie(
                        flags=set(),
                        protocol_id=Ikev2ProtocolId.IKE,
                        type=Ikev2NotifyType.COOKIE,
                        spi=bytes(),
                        cookie=cookie_value,
                    )
                else:
                    payload = Ikev2PayloadNotifyUnparsed(
                        flags=set(),
                        protocol_id=Ikev2ProtocolId.IKE,
                        type=Ikev2NotifyType.INVALID_SYNTAX,
                        spi=b'',
                        data=b'',
                    )

                response = IsakmpMessage(
                    version=init_message.version,
                    initiator_spi=init_message.initiator_spi,
                    responder_spi=2,
                    exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
                    flags=[IsakmpFlags.RESPONSE],
                    message_id=0,
                    payloads=[payload],
                )
                self._pending_recv = bytearray(response.compose())
                return len(sendable_bytes)

            def _receive_bytes(self, receivable_byte_num, flags):  # pylint: disable=unused-argument
                if not self._pending_recv:
                    return b''
                datagram = bytes(self._pending_recv)
                self._pending_recv = bytearray()
                return datagram

            def _init_connection(self):
                return

            @classmethod
            def get_default_timeout(cls):
                return 1

        transfer = _L4TransferCookieScript('localhost', 0, L4TransferSocketParams(timeout=0.5))
        with self.assertRaises(IsakmpNotify) as ctx:
            IKEv2ClientHandshake().do_handshake(
                transfer,
                init_message=init_message,
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            )
        self.assertEqual(ctx.exception.notify, Ikev2NotifyType.INVALID_SYNTAX)

        # Cookie challenge should cause a retry, so we should have sent >= 2 datagrams.
        self.assertGreaterEqual(len(transfer.sent_messages), 2)

        # The retry must have COOKIE as the first payload.
        retry_msg, parsed_len = IsakmpMessage.parse_immutable(transfer.sent_messages[1])
        self.assertEqual(parsed_len, len(transfer.sent_messages[1]))
        self.assertIsInstance(retry_msg.payloads[0], Ikev2NotifyPayloadCookie)

    def test_error_invalid_message(self):
        threaded_server = self._start_threaded_server(L7ServerIkeIkev2NonceFirst, max_handshake_count=1)
        assert threaded_server.l7_server.l4_transfer is not None

        client = L7ClientIPsecBase.from_scheme(
            'ipsec',
            'localhost',
            threaded_server.l7_server.l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
        )

        with self.assertRaises(IsakmpNotify) as ctx:
            client.do_ikev2_handshake(
                init_message=Ikev2SecurityAssociationAnyAlgorithm(),
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            )
        self.assertEqual(ctx.exception.notify, Ikev2NotifyType.INVALID_SYNTAX)

        threaded_server.join()

    def test_error_invalid_ke_payload(self):
        threaded_server = self._start_threaded_server(L7ServerIkeIkev2AlwaysInvalidKePayload, max_handshake_count=1)
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        client = L7ClientIPsecBase.from_scheme(
            'ipsec',
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
            ip=l4_transfer.bind_address,
        )

        with self.assertRaises(IsakmpNotify) as ctx:
            client.do_ikev2_handshake(
                init_message=Ikev2SecurityAssociationAnyAlgorithm(),
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            )
        self.assertEqual(ctx.exception.notify, Ikev2NotifyType.INVALID_KE_PAYLOAD)

        threaded_server.join()

    def test_error_no_connection(self):
        threaded_server = self._start_threaded_server(L7ServerIkeIkev2HeaderOnlyPartialPayload, max_handshake_count=1)
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        client = L7ClientIPsecBase.from_scheme(
            'ipsec',
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
            ip=l4_transfer.bind_address,
        )

        with self.assertRaises(NetworkError) as ctx:
            client.do_ikev2_handshake(
                init_message=Ikev2SecurityAssociationAnyAlgorithm(),
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)

        threaded_server.join()

    def test_error_unparsable_message(self):
        init_message = Ikev2SecurityAssociationSpecialization(
            encryption_algorithms=(tuple(Ikev2EncryptionAlgorithm)[0],),
            diffie_hellman_groups=(tuple(Ikev2DiffieHellmanGroup)[0],),
            pseudorandom_functions=(tuple(Ikev2PseudorandomFunction)[0],),
            integrity_algorithms=(tuple(Ikev2IntegrityAlgorithm)[0],),
        )
        transfer = L4TransferUnexpectedExchangeType(
            'localhost',
            0,
            L4TransferSocketParams(timeout=0.5),
            init_message=init_message,
        )
        with self.assertRaises(SecurityError) as ctx:
            IKEv2ClientHandshake().do_handshake(
                transfer,
                init_message=init_message,
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            )
        self.assertEqual(ctx.exception.error, SecurityErrorType.UNPARSABLE_MESSAGE)
