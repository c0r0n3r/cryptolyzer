# -*- coding: utf-8 -*-

import abc
import enum
import itertools
import random
import typing

import attr

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.ike.algorithm import (
    Ikev1Doi,
    Ikev1NotifyType,
    Ikev1ProtocolId,
    Ikev2NotifyType,
    Ikev2ProtocolId,
)

from cryptoparser.common.exception import InvalidType

from cryptoparser.ike.isakmp import IsakmpMessage, IsakmpFlags
from cryptoparser.ike.version import IsakmpVersion
from cryptoparser.ike.ikev1 import (
    Ikev1AttributeDiffieHellmanGroup,
    Ikev1AttributeEncryptionAlgorithm,
    Ikev1AttributeHashAlgorithm,
    Ikev1AttributeKeyLength,
    Ikev1PayloadNonce,
    Ikev1PayloadNotification,
    Ikev1PayloadProposal,
    Ikev1PayloadSecurityAssociation,
)
from cryptoparser.ike.ikev2 import (
    Ikev2NotifyPayloadCookie,
    Ikev2PayloadNonce,
    Ikev2PayloadNotifyUnparsed,
    Ikev2PayloadSecurityAssociation,
    Ikev2Proposal as Ikev2ProposalPayload,
    Ikev2TransformDhGroup,
    Ikev2TransformEncryptionAlgorithm,
    Ikev2TransformIntegrity,
    Ikev2TransformPrf,
)

from cryptolyzer.common.application import L7ServerBase, L7ServerHandshakeBase, L7ServerConfigurationBase
from cryptolyzer.common.transfer import L4ServerUDP
from cryptolyzer.ike.common import Ikev1CipherSuite, Ikev2CipherSuite


class ServerResponseMode(enum.Enum):
    """Single parameter: what the server sends back."""

    NOTIFY = 'notify'   # send notify (e.g. NO_PROPOSAL_CHOSEN) or normal response
    NONE = 'none'       # no response sent back (no accepted cipher / silent drop)
    PARTIAL = 'partial'  # send truncated (error / broken connection)


@attr.s
class IkeServerConfiguration(L7ServerConfigurationBase):
    ikev1_cipher_suites: typing.List[Ikev1CipherSuite] = attr.ib(
        converter=list,
        default=attr.Factory(list),
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(Ikev1CipherSuite),
        ),
    )
    ikev2_cipher_suites: typing.List[Ikev2CipherSuite] = attr.ib(
        converter=list,
        default=attr.Factory(list),
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(Ikev2CipherSuite),
        ),
    )
    response_mode: ServerResponseMode = attr.ib(
        default=ServerResponseMode.NOTIFY,
        validator=attr.validators.in_(ServerResponseMode),
    )
    cookie_challenge: bool = attr.ib(
        default=False,
        validator=attr.validators.instance_of(bool),
    )


@attr.s
class IkeServerHandshakeBase(L7ServerHandshakeBase):
    _expected_cookie: typing.Optional[bytes] = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(bytes)),
    )

    def _process_handshake_message(self, message, last_handshake_message_type):
        raise NotImplementedError()

    @staticmethod
    def _get_responder_spi() -> int:
        return random.randint(1, 2**64 - 1)

    def _handle_response_mode(self, message) -> bool:
        """Handle response_mode: NONE (don't send), PARTIAL (send truncated), NOTIFY (continue)."""
        if self.configuration.response_mode == ServerResponseMode.NONE:
            raise StopIteration()
        if self.configuration.response_mode == ServerResponseMode.PARTIAL:
            responder_spi = self._get_responder_spi()
            nonce_payload = self._get_no_connection_nonce_payload()
            response = IsakmpMessage(
                version=message.version,
                initiator_spi=message.initiator_spi,
                responder_spi=responder_spi,
                exchange_type=message.exchange_type,
                flags=[IsakmpFlags.RESPONSE],
                message_id=message.message_id,
                payloads=[nonce_payload],
            )
            composed = response.compose()
            self.l7_transfer.send(composed[:IsakmpMessage.HEADER_SIZE + 1])
            raise StopIteration()
        return False

    @abc.abstractmethod
    def _get_no_connection_nonce_payload(self):
        """Return the nonce payload for no_connection truncated response."""
        raise NotImplementedError()

    def _init_connection(self, last_handshake_message_type):  # pylint: disable=unused-argument
        return

    def _parse_record(self):
        message, parsed_length = IsakmpMessage.parse_immutable(self.l7_transfer.buffer)
        return message, parsed_length, True

    def _parse_message(self, record):
        return record

    def _process_non_handshake_message(self, message):
        self._process_handshake_message(message, None)

    def _process_invalid_message(self):
        raise StopIteration()

    def _process_not_enough_data(self):
        raise StopIteration()


class Ikev1ServerHandshake(IkeServerHandshakeBase):
    @staticmethod
    def _make_selected_sa(
        sa_payload: Ikev1PayloadSecurityAssociation,
        proposal: Ikev1PayloadProposal,
        transform_index: int = 0,
    ) -> Ikev1PayloadSecurityAssociation:
        selected_proposal = Ikev1PayloadProposal(
            protocol_id=proposal.protocol_id,
            transforms=proposal.transforms[transform_index:transform_index + 1],
            spi=proposal.spi,
        )
        selected_proposal.proposal_number = 1

        return Ikev1PayloadSecurityAssociation(
            doi=sa_payload.doi,
            situation=sa_payload.situation,
            proposals=[selected_proposal],
        )

    @staticmethod
    def _resolve_ikev1_transform(transform):
        """Resolve an IKEv1 transform's attributes into (encryption, mode, dh, hash) or None."""
        enc_attr = next(
            (a for a in transform.attributes if isinstance(a, Ikev1AttributeEncryptionAlgorithm)), None
        )
        hash_attr = next(
            (a for a in transform.attributes if isinstance(a, Ikev1AttributeHashAlgorithm)), None
        )
        dh_attr = next(
            (a for a in transform.attributes if isinstance(a, Ikev1AttributeDiffieHellmanGroup)), None
        )
        if enc_attr is None or hash_attr is None or dh_attr is None:
            return None

        key_len_attr = next(
            (a for a in transform.attributes if isinstance(a, Ikev1AttributeKeyLength)), None
        )
        key_length = key_len_attr.value if key_len_attr is not None else None
        enc_algorithm = enc_attr.value

        for bulk_cipher in enc_algorithm.value.bulk_ciphers:
            if bulk_cipher.value.key_size == key_length:
                return (
                    bulk_cipher,
                    enc_algorithm.value.block_cipher_mode,
                    dh_attr.value.value.key_parameter,
                    hash_attr.value.value.hash,
                )

        return None

    def _select_sa_from_client(
        self,
        sa_payload: Ikev1PayloadSecurityAssociation,
    ) -> typing.Optional[Ikev1PayloadSecurityAssociation]:
        if not sa_payload.proposals:
            return None

        if not self.configuration.ikev1_cipher_suites:
            return self._make_selected_sa(sa_payload, sa_payload.proposals[0])

        for proposal in sa_payload.proposals:
            for transform_index, transform in enumerate(proposal.transforms):
                resolved = self._resolve_ikev1_transform(transform)
                if resolved is None:
                    continue

                resolved_enc, resolved_mode, resolved_dh, resolved_hash = resolved
                for cipher_suite in self.configuration.ikev1_cipher_suites:
                    if (cipher_suite.encryption_algorithm == resolved_enc and
                            cipher_suite.block_cipher_mode == resolved_mode and
                            cipher_suite.diffie_hellman_group == resolved_dh and
                            cipher_suite.hash_algorithm == resolved_hash):
                        return self._make_selected_sa(sa_payload, proposal, transform_index)

        return None

    def _get_no_connection_nonce_payload(self):
        return Ikev1PayloadNonce(nonce_data=b'\x00' * 32)

    def _process_handshake_message(self, message, last_handshake_message_type):  # pylint: disable=unused-argument
        self.client_messages = {'ike_version': IsakmpVersion.V1, 'message': message}

        self._handle_response_mode(message)

        responder_spi = self._get_responder_spi()
        sa_payload = next((
            payload for payload in message.payloads
            if payload.get_payload_type() == Ikev1PayloadSecurityAssociation.get_payload_type()
        ), None)

        selected_sa = None
        if isinstance(sa_payload, Ikev1PayloadSecurityAssociation) and sa_payload.proposals:
            selected_sa = self._select_sa_from_client(sa_payload)

        if selected_sa is not None:
            response = IsakmpMessage(
                version=message.version,
                initiator_spi=message.initiator_spi,
                responder_spi=responder_spi,
                exchange_type=message.exchange_type,
                flags=[IsakmpFlags.RESPONSE],
                message_id=message.message_id,
                payloads=[selected_sa],
            )
            self.l7_transfer.send(response.compose())
            raise StopIteration()

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
        self.l7_transfer.send(response.compose())
        raise StopIteration()


class Ikev2ServerHandshake(IkeServerHandshakeBase):
    @staticmethod
    def _make_selected_sa(
        sa_payload: Ikev2PayloadSecurityAssociation,
        transforms: typing.Dict,
    ) -> Ikev2PayloadSecurityAssociation:
        selected_proposal = Ikev2ProposalPayload(
            protocol_id=sa_payload.proposals[0].protocol_id,
            transforms=list(transforms.values()),
            spi=sa_payload.proposals[0].spi,
        )

        return Ikev2PayloadSecurityAssociation(
            flags=sa_payload.flags,
            proposals=[selected_proposal],
        )

    @staticmethod
    def _resolve_ikev2_encryption(enc_t):
        """Resolve an IKEv2 encryption transform to (bulk_cipher, mode) or None."""
        for bulk_cipher in enc_t.transform_id.value.bulk_ciphers:
            if bulk_cipher.value.key_size == enc_t.key_length:
                return bulk_cipher, enc_t.transform_id.value.block_cipher_mode
        return None

    def _match_ikev2_proposal(self, proposal):
        """Try to match a single IKEv2 proposal against configured cipher suites.

        Returns a dict of selected transforms keyed by transform type, or None.
        """
        enc_transforms = [t for t in proposal.transforms if isinstance(t, Ikev2TransformEncryptionAlgorithm)]
        integ_transforms = [t for t in proposal.transforms if isinstance(t, Ikev2TransformIntegrity)]
        prf_transforms = [t for t in proposal.transforms if isinstance(t, Ikev2TransformPrf)]
        dh_transforms = [t for t in proposal.transforms if isinstance(t, Ikev2TransformDhGroup)]

        for enc_t in enc_transforms:
            resolved = self._resolve_ikev2_encryption(enc_t)
            if resolved is None:
                continue
            resolved_enc, resolved_mode = resolved

            for integ_t, prf_t, dh_t in itertools.product(integ_transforms, prf_transforms, dh_transforms):
                for cipher_suite in self.configuration.ikev2_cipher_suites:
                    if (cipher_suite.encryption_algorithm == resolved_enc and
                            cipher_suite.block_cipher_mode == resolved_mode and
                            cipher_suite.integrity_algorithm == integ_t.transform_id.value.hmac and
                            cipher_suite.pseudorandom_function == prf_t.transform_id.value.mac and
                            cipher_suite.diffie_hellman_group == dh_t.transform_id.value.key_parameter):
                        return {
                            enc_t.get_transform_type(): enc_t,
                            integ_t.get_transform_type(): integ_t,
                            prf_t.get_transform_type(): prf_t,
                            dh_t.get_transform_type(): dh_t,
                        }
        return None

    def _select_sa_from_client(
        self,
        sa_payload: Ikev2PayloadSecurityAssociation,
    ) -> typing.Optional[Ikev2PayloadSecurityAssociation]:
        if not sa_payload.proposals:
            return None

        if not self.configuration.ikev2_cipher_suites:
            proposal = sa_payload.proposals[0]
            selected_transforms = {}
            for transform in proposal.transforms:
                transform_type = transform.get_transform_type()
                if transform_type not in selected_transforms:
                    selected_transforms[transform_type] = transform
            return self._make_selected_sa(sa_payload, selected_transforms)

        for proposal in sa_payload.proposals:
            selected = self._match_ikev2_proposal(proposal)
            if selected is not None:
                return self._make_selected_sa(sa_payload, selected)

        return None

    def _get_no_connection_nonce_payload(self):
        return Ikev2PayloadNonce(flags=set(), nonce_data=b'\x00' * 32)

    def _process_handshake_message(self, message, last_handshake_message_type):  # pylint: disable=unused-argument
        self.client_messages = {'ike_version': IsakmpVersion.V2, 'message': message}

        self._handle_response_mode(message)

        if self.configuration.cookie_challenge:
            cookie_payload = next((
                payload for payload in message.payloads
                if isinstance(payload, Ikev2NotifyPayloadCookie)
            ), None)
            cookie_value = bytes(cookie_payload.cookie) if cookie_payload is not None else None

            if self._expected_cookie is None and cookie_value is None:
                self._expected_cookie = random.randbytes(16)

                responder_spi = self._get_responder_spi()
                notify_cookie = Ikev2NotifyPayloadCookie(
                    flags=set(),
                    protocol_id=Ikev2ProtocolId.IKE,
                    type=Ikev2NotifyType.COOKIE,
                    spi=bytes(),
                    cookie=self._expected_cookie,
                )
                response = IsakmpMessage(
                    version=message.version,
                    initiator_spi=message.initiator_spi,
                    responder_spi=responder_spi,
                    exchange_type=message.exchange_type,
                    flags=[IsakmpFlags.RESPONSE],
                    message_id=message.message_id,
                    payloads=[notify_cookie],
                )
                self.l7_transfer.send(response.compose())
                return

            if self._expected_cookie is not None and cookie_value != self._expected_cookie:
                responder_spi = self._get_responder_spi()
                notify_cookie = Ikev2NotifyPayloadCookie(
                    flags=set(),
                    protocol_id=Ikev2ProtocolId.IKE,
                    type=Ikev2NotifyType.COOKIE,
                    spi=bytes(),
                    cookie=self._expected_cookie,
                )
                response = IsakmpMessage(
                    version=message.version,
                    initiator_spi=message.initiator_spi,
                    responder_spi=responder_spi,
                    exchange_type=message.exchange_type,
                    flags=[IsakmpFlags.RESPONSE],
                    message_id=message.message_id,
                    payloads=[notify_cookie],
                )
                self.l7_transfer.send(response.compose())
                return

        responder_spi = self._get_responder_spi()
        sa_payload = None
        for payload in message.payloads:
            if isinstance(payload, Ikev2PayloadSecurityAssociation):
                sa_payload = payload
                break

        selected_sa = None
        if sa_payload is not None and sa_payload.proposals:
            selected_sa = self._select_sa_from_client(sa_payload)

        if selected_sa is not None:
            response = IsakmpMessage(
                version=message.version,
                initiator_spi=message.initiator_spi,
                responder_spi=responder_spi,
                exchange_type=message.exchange_type,
                flags=[IsakmpFlags.RESPONSE],
                message_id=message.message_id,
                payloads=[selected_sa],
            )
            self.l7_transfer.send(response.compose())
            raise StopIteration()

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


@attr.s
class L7ServerIkeBase(L7ServerBase):
    def __attrs_post_init__(self):
        if self.configuration is None:
            self.configuration = IkeServerConfiguration()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    @classmethod
    def _get_transfer_class(cls):
        return L4ServerUDP

    def _get_handshake_class(self):
        receivable_byte_num = 1
        while True:
            try:
                self.receive(receivable_byte_num)
                message, _ = IsakmpMessage.parse_immutable(self.buffer)
            except (InvalidType, InvalidValue):
                self.flush_buffer()
                if self.l4_transfer is not None:
                    self.l4_transfer.close_client()
                continue

            if message.version.major == IsakmpVersion.V1:
                return Ikev1ServerHandshake
            if message.version.major == IsakmpVersion.V2:
                return Ikev2ServerHandshake

            raise NotImplementedError(message.version)

    def _do_handshake(self, last_handshake_message_type):
        handshake_class = self._get_handshake_class()
        handshake_object = handshake_class(self, self.configuration)
        handshake_object.do_handshake(last_handshake_message_type)
        return handshake_object.client_messages

    def do_ike_handshake(self):
        return self._do_handshakes(last_handshake_message_type=None)


class L7ServerIke(L7ServerIkeBase):
    @classmethod
    def get_scheme(cls):
        return 'ipsec'

    @classmethod
    def get_default_port(cls):
        return 45000
