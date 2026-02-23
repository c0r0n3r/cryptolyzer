# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

"""
Shared IKE test helpers.

This module is imported by multiple test files (client/server/versions/all).
Keep helpers small and deterministic.
"""

import random

from test.common.classes import TestThreadedServer

from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1DiffieHellmanGroup,
    Ikev1Doi,
    Ikev1EncryptionAlgorithm,
    Ikev1HashAlgorithm,
    Ikev1NotifyType,
    Ikev1ProtocolId,
    Ikev1PayloadType,
    Ikev1ExchangeType,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2ExchangeType,
    Ikev2IntegrityAlgorithm,
    Ikev2NotifyType,
    Ikev2ProtocolId,
    Ikev2PseudorandomFunction,
)

from cryptoparser.common.parse import ComposerBinary
from cryptoparser.ike.isakmp import IsakmpFlags, IsakmpMessage
from cryptoparser.ike.version import IsakmpVersion
from cryptoparser.ike.ikev1 import Ikev1PayloadNonce, Ikev1PayloadNotification
from cryptoparser.ike.ikev2 import (
    Ikev2NotifyPayloadInvalidKe,
    Ikev2PayloadNonce,
    Ikev2PayloadNotifyUnparsed,
)

from cryptolyzer.common.transfer import L4TransferBase, L4TransferSocketParams
from cryptolyzer.ike.client import Ikev1SecurityAssociationProposalAlgorithms
from cryptolyzer.ike.common import Ikev1CipherSuite, Ikev2CipherSuite
from cryptolyzer.ike.server import (
    IkeServerConfiguration,
    IkeServerHandshakeBase,
    Ikev1ServerHandshake,
    Ikev2ServerHandshake,
    L7ServerIke,
    ServerResponseMode,
)


def get_ffdh_only_server_configuration():
    """Server config with exactly 2 FFDH groups to shorten test run time."""
    ikev1_suites = [
        Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(
            Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
                diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_768_BIT,
                hash_algorithm=Ikev1HashAlgorithm.SHA,
                authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                key_length=128,
            )
        ),
        Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(
            Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
                diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_1024_BIT,
                hash_algorithm=Ikev1HashAlgorithm.SHA,
                authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                key_length=128,
            )
        ),
    ]
    ikev2_suites = [
        Ikev2CipherSuite.from_transform_ids(
            encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
            integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_768_BIT,
            key_length=128,
        ),
        Ikev2CipherSuite.from_transform_ids(
            encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
            integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
            key_length=128,
        ),
    ]
    return IkeServerConfiguration(
        ikev1_cipher_suites=ikev1_suites,
        ikev2_cipher_suites=ikev2_suites,
    )


def get_ffdh_single_server_configuration():
    """Server config with only MODP_2048 for IKEv2. Triggers RFC-compliant INVALID_KE_PAYLOAD
    when client sends KE for a different group (e.g. MODP_768) than server's selected group."""
    ikev1_suites = [
        Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(
            Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
                diffie_hellman_group=Ikev1DiffieHellmanGroup.MODP_2048_BIT,
                hash_algorithm=Ikev1HashAlgorithm.SHA,
                authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                key_length=128,
            )
        ),
    ]
    ikev2_suites = [
        Ikev2CipherSuite.from_transform_ids(
            encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
            integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
            key_length=128,
        ),
    ]
    return IkeServerConfiguration(
        ikev1_cipher_suites=ikev1_suites,
        ikev2_cipher_suites=ikev2_suites,
    )


def get_ecdh_only_server_configuration():
    """Server config with exactly 2 ECDH groups to shorten test run time."""
    ikev1_suites = [
        Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(
            Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
                diffie_hellman_group=Ikev1DiffieHellmanGroup.ECP_256_BIT,
                hash_algorithm=Ikev1HashAlgorithm.SHA,
                authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                key_length=128,
            )
        ),
        Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(
            Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=Ikev1EncryptionAlgorithm.AES_CBC,
                diffie_hellman_group=Ikev1DiffieHellmanGroup.ECP_384_BIT,
                hash_algorithm=Ikev1HashAlgorithm.SHA,
                authentication_method=Ikev1AuthenticationMethod.PRE_SHARED_KEY,
                key_length=128,
            )
        ),
    ]
    ikev2_suites = [
        Ikev2CipherSuite.from_transform_ids(
            encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
            integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT,
            key_length=128,
        ),
        Ikev2CipherSuite.from_transform_ids(
            encryption_transform_id=Ikev2EncryptionAlgorithm.ENCR_AES_CBC,
            integrity_transform_id=Ikev2IntegrityAlgorithm.AUTH_HMAC_SHA1_96,
            pseudorandom_transform_id=Ikev2PseudorandomFunction.PRF_HMAC_SHA1,
            diffie_hellman_transform_id=Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT,
            key_length=128,
        ),
    ]
    return IkeServerConfiguration(
        ikev1_cipher_suites=ikev1_suites,
        ikev2_cipher_suites=ikev2_suites,
    )


class L7ServerIkeTest(TestThreadedServer):
    """Thread wrapper for running an IKE server in tests."""

    def __init__(self, l7_server: L7ServerIke):
        self.l7_server = l7_server
        super().__init__(self.l7_server)

    def run(self):
        try:
            self.l7_server.do_ike_handshake()
        except Exception:  # pylint: disable=broad-except
            pass


class L4TransferDummy(L4TransferBase):
    """Test helper L4 transfer with an in-memory buffer."""

    def _send(self, sendable_bytes):
        return len(sendable_bytes)

    def _receive_bytes(self, receivable_byte_num, flags):  # pylint: disable=unused-argument
        return b''

    def _init_connection(self):
        return

    @classmethod
    def get_default_timeout(cls):
        return 1


class L4TransferCapture(L4TransferBase):
    """Test helper that captures the last datagram sent."""

    def __init__(self, address, port, socket_params=L4TransferSocketParams(), ip=None):
        super().__init__(address, port, socket_params, ip)
        self.last_sent = None

    def _send(self, sendable_bytes):
        self.last_sent = bytes(sendable_bytes)
        return len(sendable_bytes)

    def _receive_bytes(self, receivable_byte_num, flags):  # pylint: disable=unused-argument
        return b''

    def _init_connection(self):
        return

    @classmethod
    def get_default_timeout(cls):
        return 1


class L4TransferUnexpectedExchangeType(L4TransferBase):
    """
    Test helper L4 transfer that replies with a valid IKEv2 message
    but with an unexpected exchange type (IKE_INFORMATIONAL).
    """

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(self, address, port, socket_params, init_message, ip=None):
        super().__init__(address, port, socket_params, ip)
        self._init_message = init_message
        self._pending_recv = bytearray()

    def _send(self, sendable_bytes):  # pylint: disable=unused-argument
        response = IsakmpMessage(
            version=self._init_message.version,
            initiator_spi=self._init_message.initiator_spi,
            responder_spi=2,
            exchange_type=Ikev2ExchangeType.IKE_INFORMATIONAL,
            flags=[IsakmpFlags.RESPONSE],
            message_id=0,
            payloads=[Ikev2PayloadNonce(flags=set(), nonce_data=b'\x00' * 32)],
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


class L4TransferReceiveNotEnoughDataWithBuffer(L4TransferBase):
    """Test helper L4 transfer that raises NotEnoughData after partial receive."""

    def __init__(self, address, port, socket_params, ip=None):
        super().__init__(address, port, socket_params, ip)
        self._recv_call_count = 0

    def _send(self, sendable_bytes):
        return len(sendable_bytes)

    def _receive_bytes(self, receivable_byte_num, flags):  # pylint: disable=unused-argument
        if self._recv_call_count == 0:
            self._recv_call_count += 1
            return b'\x00'
        return b''

    def _init_connection(self):
        return

    @classmethod
    def get_default_timeout(cls):
        return 1


class L4TransferIkev1NonceFirst(L4TransferBase):
    """Test helper L4 transfer that replies with an IKEv1 NONCE-first message."""

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(self, address, port, socket_params, init_message, ip=None):
        super().__init__(address, port, socket_params, ip)
        self._init_message = init_message
        self._pending_recv = bytearray()

    def _send(self, sendable_bytes):  # pylint: disable=unused-argument
        response = IsakmpMessage(
            version=self._init_message.version,
            initiator_spi=self._init_message.initiator_spi,
            responder_spi=2,
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            flags=[IsakmpFlags.RESPONSE],
            message_id=0,
            payloads=[Ikev1PayloadNonce(nonce_data=b'\x00' * 32)],
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


class L4TransferIkev1InvalidValueResponse(L4TransferBase):
    """Test helper L4 transfer that replies with bytes failing IKEv1 parsing."""

    # ISAKMP header (28 bytes): invalid exchange_type (0xff) for IKEv1.
    _RESPONSE_BYTES = (
        (1).to_bytes(8, byteorder='big') +  # initiator_spi
        (2).to_bytes(8, byteorder='big') +  # responder_spi
        b'\x00' +  # next_payload: NONE
        b'\x10' +  # version: 1.0
        b'\xff' +  # exchange_type: invalid -> InvalidValue when parsing
        b'\x00' +  # flags
        b'\x00\x00\x00\x00' +  # message_id
        b'\x00\x00\x00\x1c'    # length: 28
    )

    def __init__(self, address, port, socket_params, ip=None):
        super().__init__(address, port, socket_params, ip)
        self._pending_recv = bytearray()

    def _send(self, sendable_bytes):  # pylint: disable=unused-argument
        self._pending_recv = bytearray(self._RESPONSE_BYTES)
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


class L4TransferIkev1UnexpectedExchangeType(L4TransferBase):
    """Test helper L4 transfer that replies with a valid IKEv1 message but unexpected exchange type."""

    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def __init__(self, address, port, socket_params, init_message, ip=None):
        super().__init__(address, port, socket_params, ip)
        self._init_message = init_message
        self._pending_recv = bytearray()

    def _send(self, sendable_bytes):  # pylint: disable=unused-argument
        # Reply with a valid message whose exchange_type is not in the client's
        # acceptable list (BASE is valid but unexpected for our client).
        response = IsakmpMessage(
            version=self._init_message.version,
            initiator_spi=self._init_message.initiator_spi,
            responder_spi=2,
            exchange_type=Ikev1ExchangeType.BASE,
            flags=[IsakmpFlags.RESPONSE],
            message_id=0,
            payloads=[Ikev1PayloadNonce(nonce_data=b'\x00' * 32)],
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


class _IkeServerHandshakeNoProposalChosen(IkeServerHandshakeBase):
    def _get_no_connection_nonce_payload(self):
        return Ikev1PayloadNonce(nonce_data=b'\x00' * 32)  # unused; overrides _process_handshake_message

    @staticmethod
    def compose_ikev1_message_with_real_first_payload(message: IsakmpMessage) -> bytearray:
        """
        Work around `IsakmpMessage.compose()` hard-coding IKEv1 Next Payload to SA.

        For IKEv1 NOTIFY responses, the first payload is NOTIFICATION, not SA.
        """
        header_composer = ComposerBinary()
        header_composer.compose_numeric(message.initiator_spi, 8)
        header_composer.compose_numeric(message.responder_spi, 8)

        payload_composer = ComposerBinary()
        for i, payload in enumerate(message.payloads):
            payload.next_payload = (
                Ikev1PayloadType.NONE
                if i == len(message.payloads) - 1
                else message.payloads[i + 1].get_payload_type()
            )
            payload_composer.compose_parsable(payload)

        header_composer.compose_numeric_enum_coded(
            message.payloads[0].get_payload_type() if message.payloads else Ikev1PayloadType.NONE,
        )
        header_composer.compose_parsable(message.version)
        header_composer.compose_numeric_enum_coded(message.exchange_type)
        header_composer.compose_numeric_flags(message.flags, 1)
        header_composer.compose_numeric(message.message_id, 4)
        header_composer.compose_numeric(message.HEADER_SIZE + payload_composer.composed_length, 4)

        return header_composer.composed_bytes + payload_composer.composed_bytes

    def _process_handshake_message(self, message, last_handshake_message_type):  # pylint: disable=unused-argument
        self.client_messages = {'ike_version': message.version.major, 'message': message}

        if self.configuration.response_mode == ServerResponseMode.NONE:
            raise StopIteration()

        responder_spi = self._get_responder_spi()
        if message.version.major == IsakmpVersion.V1:
            notify = Ikev1PayloadNotification(
                doi=Ikev1Doi.IPSEC,
                protocol_id=Ikev1ProtocolId.ISAKMP,
                spi_size=0,
                notify_type=Ikev1NotifyType.NO_PROPOSAL_CHOSEN,
                spi=b'',
                notification_data=b'',
            )
            response = IsakmpMessage(
                version=message.version,
                initiator_spi=message.initiator_spi,
                responder_spi=responder_spi,
                exchange_type=message.exchange_type,
                flags=[IsakmpFlags.RESPONSE],
                message_id=message.message_id,
                payloads=[notify],
            )
            self.l7_transfer.send(self.compose_ikev1_message_with_real_first_payload(response))
        elif message.version.major == IsakmpVersion.V2:
            notify = Ikev2PayloadNotifyUnparsed(
                flags=set(),
                protocol_id=Ikev2ProtocolId.IKE,
                type=Ikev2NotifyType.NO_PROPOSAL_CHOSEN,
                spi=b'',
                data=b'',
            )
            response = IsakmpMessage(
                version=message.version,
                initiator_spi=message.initiator_spi,
                responder_spi=responder_spi,
                exchange_type=message.exchange_type,
                flags=[IsakmpFlags.RESPONSE],
                message_id=message.message_id,
                payloads=[notify],
            )
            self.l7_transfer.send(response.compose())

        raise StopIteration()


class L7ServerIkeNoProposalChosen(L7ServerIke):
    """IKE test server that always answers with NO_PROPOSAL_CHOSEN."""

    def _get_handshake_class(self):
        super()._get_handshake_class()
        return _IkeServerHandshakeNoProposalChosen


class L7ServerIkeNotify(L7ServerIke):
    """IKE test server that answers with a configured NOTIFY (IKEv1 or IKEv2)."""

    # pylint: disable=too-many-arguments
    def __init__(
        self,
        address,
        port,
        l4_socket_params,
        *,
        notify_type_ikev2: Ikev2NotifyType = Ikev2NotifyType.INVALID_SYNTAX,
        notify_type_ikev1: Ikev1NotifyType = Ikev1NotifyType.INVALID_PAYLOAD_TYPE,
        **kwargs,
    ):
        self.notify_type_ikev2 = notify_type_ikev2
        self.notify_type_ikev1 = notify_type_ikev1
        super().__init__(address, port, l4_socket_params, **kwargs)

    def _get_handshake_class(self):
        super()._get_handshake_class()

        # Late-bind `self` into the handshake class via a closure.
        notify_type_ikev2 = self.notify_type_ikev2
        notify_type_ikev1 = self.notify_type_ikev1

        class _Handshake(IkeServerHandshakeBase):
            def _get_no_connection_nonce_payload(self):
                return Ikev2PayloadNonce(flags=set(), nonce_data=b'\x00' * 32)  # unused

            # pylint: disable=unused-argument
            def _process_handshake_message(self, message, last_handshake_message_type):
                self.client_messages = {'ike_version': message.version.major, 'message': message}
                if self.configuration.response_mode == ServerResponseMode.NONE:
                    raise StopIteration()

                responder_spi = self._get_responder_spi()
                if message.version.major == IsakmpVersion.V2:
                    notify = Ikev2PayloadNotifyUnparsed(
                        flags=set(),
                        protocol_id=Ikev2ProtocolId.IKE,
                        type=notify_type_ikev2,
                        spi=b'',
                        data=b'',
                    )
                    response = IsakmpMessage(
                        version=message.version,
                        initiator_spi=message.initiator_spi,
                        responder_spi=responder_spi,
                        exchange_type=message.exchange_type,
                        flags=[IsakmpFlags.RESPONSE],
                        message_id=message.message_id,
                        payloads=[notify],
                    )
                    self.l7_transfer.send(response.compose())
                else:
                    notify = Ikev1PayloadNotification(
                        doi=Ikev1Doi.IPSEC,
                        protocol_id=Ikev1ProtocolId.ISAKMP,
                        spi_size=0,
                        notify_type=notify_type_ikev1,
                        spi=b'',
                        notification_data=b'',
                    )
                    response = IsakmpMessage(
                        version=message.version,
                        initiator_spi=message.initiator_spi,
                        responder_spi=responder_spi,
                        exchange_type=message.exchange_type,
                        flags=[IsakmpFlags.RESPONSE],
                        message_id=message.message_id,
                        payloads=[notify],
                    )
                    self.l7_transfer.send(
                        _IkeServerHandshakeNoProposalChosen.compose_ikev1_message_with_real_first_payload(response)
                    )

                raise StopIteration()

        return _Handshake


class _Ikev2ServerHandshakeAlwaysInvalidKePayload(Ikev2ServerHandshake):
    def _process_handshake_message(self, message, last_handshake_message_type):  # pylint: disable=unused-argument
        self.client_messages = {'ike_version': message.version.major, 'message': message}

        if self.configuration.response_mode == ServerResponseMode.NONE:
            raise StopIteration()

        responder_spi = self._get_responder_spi()
        notify = Ikev2NotifyPayloadInvalidKe(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.INVALID_KE_PAYLOAD,
            spi=b'',
            dh_group=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        )
        response = IsakmpMessage(
            version=message.version,
            initiator_spi=message.initiator_spi,
            responder_spi=responder_spi,
            exchange_type=message.exchange_type,
            flags=[IsakmpFlags.RESPONSE],
            message_id=message.message_id,
            payloads=[notify],
        )
        self.l7_transfer.send(response.compose())
        raise StopIteration()


class L7ServerIkeIkev2AlwaysInvalidKePayload(L7ServerIke):
    """IKE test server that always responds with IKEv2 INVALID_KE_PAYLOAD notify."""

    def _get_handshake_class(self):
        handshake_class = super()._get_handshake_class()
        if handshake_class is Ikev2ServerHandshake:
            return _Ikev2ServerHandshakeAlwaysInvalidKePayload
        return handshake_class


class _Ikev2ServerHandshakeHeaderOnlyPartialPayload(IkeServerHandshakeBase):
    """IKEv2 handshake that replies with a *truncated* composed ISAKMP message."""

    def _get_no_connection_nonce_payload(self):
        return Ikev2PayloadNonce(flags=set(), nonce_data=b'\x00' * 32)

    def _process_handshake_message(self, message, last_handshake_message_type):  # pylint: disable=unused-argument
        self.client_messages = {'ike_version': message.version.major, 'message': message}
        if self.configuration.response_mode == ServerResponseMode.NONE:
            raise StopIteration()

        responder_spi = self._get_responder_spi()
        response = IsakmpMessage(
            version=message.version,
            initiator_spi=message.initiator_spi,
            responder_spi=responder_spi,
            exchange_type=message.exchange_type,
            flags=[IsakmpFlags.RESPONSE],
            message_id=message.message_id,
            payloads=[Ikev2PayloadNonce(flags=set(), nonce_data=b'\x00' * 32)],
        )
        composed = response.compose()
        self.l7_transfer.send(composed[:IsakmpMessage.HEADER_SIZE + 1])
        raise StopIteration()


class L7ServerIkeIkev2HeaderOnlyPartialPayload(L7ServerIke):
    """IKE test server that sends truncated response (response_mode=PARTIAL)."""

    def _get_handshake_class(self):
        handshake_class = super()._get_handshake_class()
        if handshake_class is Ikev2ServerHandshake:
            return _Ikev2ServerHandshakeHeaderOnlyPartialPayload
        return handshake_class


class _Ikev1ServerHandshakeHeaderOnlyPartialPayload(IkeServerHandshakeBase):
    """IKEv1 handshake that replies with a *truncated* composed ISAKMP message."""

    def _get_no_connection_nonce_payload(self):
        return Ikev1PayloadNonce(nonce_data=b'\x00' * 32)

    def _process_handshake_message(self, message, last_handshake_message_type):  # pylint: disable=unused-argument
        self.client_messages = {'ike_version': message.version.major, 'message': message}
        if self.configuration.response_mode == ServerResponseMode.NONE:
            raise StopIteration()

        responder_spi = self._get_responder_spi()
        response = IsakmpMessage(
            version=message.version,
            initiator_spi=message.initiator_spi,
            responder_spi=responder_spi,
            exchange_type=message.exchange_type,
            flags=[IsakmpFlags.RESPONSE],
            message_id=message.message_id,
            payloads=[Ikev1PayloadNonce(nonce_data=b'\x00' * 32)],
        )
        composed = response.compose()
        self.l7_transfer.send(composed[:IsakmpMessage.HEADER_SIZE + 1])
        raise StopIteration()


class L7ServerIkeIkev1HeaderOnlyPartialPayload(L7ServerIke):
    """IKE test server that replies with header + partial payload byte (IKEv1)."""

    def _get_handshake_class(self):
        handshake_class = super()._get_handshake_class()
        if handshake_class is Ikev1ServerHandshake:
            return _Ikev1ServerHandshakeHeaderOnlyPartialPayload
        return handshake_class


class _Ikev2ServerHandshakeNonceFirst(IkeServerHandshakeBase):
    """IKEv2 server handshake that sends a NONCE-first message."""

    def _get_no_connection_nonce_payload(self):
        return Ikev2PayloadNonce(flags=set(), nonce_data=b'\x00' * 32)

    def _process_handshake_message(self, message, last_handshake_message_type):  # pylint: disable=unused-argument
        self.client_messages = {'ike_version': message.version.major, 'message': message}
        if self.configuration.response_mode == ServerResponseMode.NONE:
            raise StopIteration()

        responder_spi = random.randint(1, 2**64 - 1)
        response = IsakmpMessage(
            version=message.version,
            initiator_spi=message.initiator_spi,
            responder_spi=responder_spi,
            exchange_type=message.exchange_type,
            flags=[IsakmpFlags.RESPONSE],
            message_id=message.message_id,
            payloads=[Ikev2PayloadNonce(flags=set(), nonce_data=b'\x00' * 32)],
        )
        self.l7_transfer.send(response.compose())
        raise StopIteration()


class L7ServerIkeIkev2NonceFirst(L7ServerIke):
    """IKE test server that responds with a NONCE-first IKEv2 message."""

    def _get_handshake_class(self):
        handshake_class = super()._get_handshake_class()
        if handshake_class is Ikev2ServerHandshake:
            return _Ikev2ServerHandshakeNonceFirst
        return handshake_class


def create_ike_server(
    server_class,
    *,
    max_handshake_count=2,
    timeout=0.5,
    configuration=None,
    **kwargs
):
    """Create and start a threaded IKE server. Returns L7ServerIkeTest ready for use.

    Uses same pattern as test_client._start_threaded_server: 'localhost', port 0.
    """
    if configuration is None:
        configuration = IkeServerConfiguration()
    threaded_server = L7ServerIkeTest(server_class(  # type: ignore[call-arg]
        'localhost',
        0,
        L4TransferSocketParams(timeout=timeout),
        configuration=configuration,
        max_handshake_count=max_handshake_count,
        **kwargs
    ))
    threaded_server.wait_for_server_listen()
    return threaded_server
