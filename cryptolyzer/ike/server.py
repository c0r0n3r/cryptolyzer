# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import abc
import enum
import itertools
import random
import typing

import attr

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, Hash, NamedGroup
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.ike.algorithm import (
    Ikev1Doi,
    Ikev1ExchangeType,
    Ikev1NotifyType,
    Ikev1ProtocolId,
    Ikev2NotifyType,
    Ikev2ProtocolId,
    MAC,
)

from cryptodatahub.ike.version import IkeVersion

from cryptoparser.common.exception import InvalidType
from cryptoparser.ike.isakmp import IsakmpMessage, IsakmpFlags
from cryptoparser.ike.ikev1 import (
    Ikev1AttributeDiffieHellmanGroup,
    Ikev1AttributeEncryptionAlgorithm,
    Ikev1AttributeHashAlgorithm,
    Ikev1AttributeKeyLength,
    Ikev1PayloadKeyExchange,
    Ikev1PayloadNonce,
    Ikev1PayloadNotification,
    Ikev1PayloadProposal,
    Ikev1PayloadSecurityAssociation,
)
from cryptoparser.ike.ikev2 import (
    Ikev2NotifyPayloadCookie,
    Ikev2NotifyPayloadInvalidKe,
    Ikev2PayloadKeyExchange,
    Ikev2PayloadNonce,
    Ikev2PayloadNotifyUnparsed,
    Ikev2PayloadSecurityAssociation,
    Ikev2PayloadType,
    Ikev2Proposal as Ikev2ProposalPayload,
    Ikev2TransformDhGroup,
    Ikev2TransformEncryptionAlgorithm,
    Ikev2TransformIntegrity,
    Ikev2TransformPrf,
    Ikev2TransformType,
)

from cryptolyzer.common.application import L7ServerBase, L7ServerHandshakeBase, L7ServerConfigurationBase
from cryptolyzer.common.dhparam import get_dh_ephemeral_key_forged, get_ecdh_ephemeral_key_forged, int_to_bytes
from cryptolyzer.common.transfer import L4ServerUDP
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.ike.common import Ikev1CipherSuite, Ikev2CipherSuite


class ServerResponseMode(enum.Enum):
    """Single parameter: what the server sends back."""

    NOTIFY = 'notify'   # send notify (e.g. NO_PROPOSAL_CHOSEN) or normal response
    NONE = 'none'       # no response sent back (no accepted cipher / silent drop)
    PARTIAL = 'partial'  # send truncated (error / broken connection)


@attr.s(frozen=True)
class IkeTransformResolvedBase:
    encryption_algorithm: BlockCipher = attr.ib(
        validator=attr.validators.instance_of(BlockCipher)
    )
    block_cipher_mode: typing.Optional[BlockCipherMode] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipherMode))
    )
    diffie_hellman_group: typing.Union[NamedGroup, DHParamWellKnown] = attr.ib(
        validator=attr.validators.instance_of((NamedGroup, DHParamWellKnown))
    )


@attr.s(frozen=True)
class Ikev1TransformResolved(IkeTransformResolvedBase):
    hash_algorithm: Hash = attr.ib(
        validator=attr.validators.instance_of(Hash)
    )


@attr.s(frozen=True)
class Ikev2TransformResolved(IkeTransformResolvedBase):
    integrity_algorithm: typing.Optional[MAC] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(MAC))
    )
    pseudorandom_function: typing.Optional[MAC] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(MAC))
    )


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

    def _process_handshake_message(
        self,
        message: IsakmpMessage,
        last_handshake_message_type: typing.Any,
    ) -> None:
        raise NotImplementedError()

    @staticmethod
    def _get_responder_spi() -> int:
        return random.randint(1, 2**64 - 1)

    def _handle_response_mode(self, message: IsakmpMessage) -> bool:
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
    def _get_no_connection_nonce_payload(self) -> typing.Any:
        """Return the nonce payload for no_connection truncated response."""
        raise NotImplementedError()

    def _init_connection(self, last_handshake_message_type: typing.Any) -> None:  # pylint: disable=unused-argument
        return

    def _parse_record(self) -> typing.Tuple[IsakmpMessage, int, bool]:
        message, parsed_length = IsakmpMessage.parse_immutable(self.l7_transfer.buffer)
        return message, parsed_length, True

    def _parse_message(self, record: typing.Any) -> typing.Any:
        return record

    def _process_non_handshake_message(self, message: IsakmpMessage) -> None:
        self._process_handshake_message(message, None)

    def _process_invalid_message(self) -> typing.NoReturn:
        raise StopIteration()

    def _process_not_enough_data(self) -> typing.NoReturn:
        raise StopIteration()


class Ikev1ServerHandshake(IkeServerHandshakeBase):
    _main_mode_session = None

    def _init_connection(self, last_handshake_message_type):
        self._main_mode_session = None

    @staticmethod
    def _generate_ke_payloads(proposals):
        ffdh_group = None
        ecdh_group = None
        for proposal in proposals:
            for transform in proposal.transforms:
                for attribute in transform.attributes:
                    if isinstance(attribute, Ikev1AttributeDiffieHellmanGroup):
                        dh_group = attribute.value
                        if isinstance(dh_group.value.key_parameter, DHParamWellKnown):
                            ffdh_group = dh_group
                        elif isinstance(dh_group.value.key_parameter, NamedGroup):
                            ecdh_group = dh_group
                        if ffdh_group or ecdh_group:
                            break

        payloads = []
        if ecdh_group:
            payloads.append(Ikev1PayloadKeyExchange(
                key_exchange_data=get_ecdh_ephemeral_key_forged(
                    ecdh_group.value.key_parameter, add_point_format_octet=False
                ),
            ))
        elif ffdh_group:
            payloads.append(Ikev1PayloadKeyExchange(
                key_exchange_data=int_to_bytes(
                    get_dh_ephemeral_key_forged(ffdh_group.value.key_parameter.value.parameter_numbers.p),
                    ffdh_group.value.key_parameter.value.key_size // 8
                )
            ))
        payloads.append(Ikev1PayloadNonce(nonce_data=random.randbytes(32)))
        return payloads

    @staticmethod
    def _make_selected_sa(
        sa_payload: Ikev1PayloadSecurityAssociation,
        proposal: Ikev1PayloadProposal,
        transform_index: int = 0,
    ) -> Ikev1PayloadSecurityAssociation:
        """Make a new SA payload with a single selected proposal and transform."""

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
    def _resolve_ikev1_transform(transform: typing.Any) -> typing.Optional[Ikev1TransformResolved]:
        """Resolve an IKEv1 transform's attributes into (encryption, mode, dh, hash) or None."""
        encryption_attribute = next(
            filter(lambda attribute: isinstance(attribute, Ikev1AttributeEncryptionAlgorithm), transform.attributes),
            None
        )
        hash_attribute = next(
            filter(lambda attribute: isinstance(attribute, Ikev1AttributeHashAlgorithm), transform.attributes),
            None
        )
        diffie_hellman_group_attribute = next(
            filter(lambda attribute: isinstance(attribute, Ikev1AttributeDiffieHellmanGroup), transform.attributes),
            None
        )

        if encryption_attribute is None or hash_attribute is None or diffie_hellman_group_attribute is None:
            return None

        key_length_attribute = next(
            filter(lambda attribute: isinstance(attribute, Ikev1AttributeKeyLength), transform.attributes),
            None
        )

        key_length = key_length_attribute.value if key_length_attribute is not None else None
        encryption_algorithm = encryption_attribute.value

        for bulk_cipher_entry in encryption_algorithm.value.bulk_ciphers:
            if bulk_cipher_entry.cipher.value.key_size == key_length:
                return Ikev1TransformResolved(
                    encryption_algorithm=bulk_cipher_entry.cipher,
                    block_cipher_mode=encryption_algorithm.value.block_cipher_mode,
                    diffie_hellman_group=diffie_hellman_group_attribute.value.value.key_parameter,
                    hash_algorithm=hash_attribute.value.value.hash,
                )

        return None

    def _select_sa_from_client(
        self,
        sa_payload: Ikev1PayloadSecurityAssociation,
    ) -> typing.Optional[Ikev1PayloadSecurityAssociation]:
        if not sa_payload.proposals:
            LogSingleton().log(level=60, msg=f'No proposals; version={IkeVersion.V1}')
            return None

        if not self.configuration.ikev1_cipher_suites:
            LogSingleton().log(level=60, msg=f'No cipher_suites config, accepting first; version={IkeVersion.V1}')
            return self._make_selected_sa(sa_payload, sa_payload.proposals[0])

        for proposal in sa_payload.proposals:
            for transform_index, transform in enumerate(proposal.transforms):
                resolved = self._resolve_ikev1_transform(transform)
                if resolved is None:
                    continue

                for cipher_suite in self.configuration.ikev1_cipher_suites:
                    if (cipher_suite.encryption_algorithm == resolved.encryption_algorithm and
                            cipher_suite.block_cipher_mode == resolved.block_cipher_mode and
                            cipher_suite.diffie_hellman_group == resolved.diffie_hellman_group and
                            cipher_suite.hash_algorithm == resolved.hash_algorithm):
                        return self._make_selected_sa(sa_payload, proposal, transform_index)
        return None

    def _get_no_connection_nonce_payload(self) -> Ikev1PayloadNonce:
        return Ikev1PayloadNonce(nonce_data=b'\x00' * 32)

    def _process_handshake_message(
        self,
        message: IsakmpMessage,
        last_handshake_message_type: typing.Any,
    ) -> typing.NoReturn:  # pylint: disable=unused-argument
        self.client_messages = {'ike_version': IkeVersion.V1, 'message': message}

        self._handle_response_mode(message)

        # Handle the 2nd message in Main Mode (KE+NONCE from client)
        if (getattr(self, '_main_mode_session', None) is not None and
                message.exchange_type == Ikev1ExchangeType.IDENTITY_PROTECTION):
            session = self._main_mode_session
            self._main_mode_session = None
            ke_payloads = self._generate_ke_payloads(session['proposals'])
            response = IsakmpMessage(
                version=session['version'],
                initiator_spi=session['initiator_spi'],
                responder_spi=session['responder_spi'],
                exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
                flags=[IsakmpFlags.RESPONSE],
                message_id=message.message_id,
                payloads=ke_payloads,
            )
            self.l7_transfer.send(response.compose())
            raise StopIteration()

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

            if message.exchange_type == Ikev1ExchangeType.IDENTITY_PROTECTION:
                # Main Mode: wait for the client's KE+NONCE (2nd message)
                self._main_mode_session = {
                    'responder_spi': responder_spi,
                    'proposals': selected_sa.proposals,
                    'version': message.version,
                    'initiator_spi': message.initiator_spi,
                }
                return

            raise StopIteration()

        LogSingleton().log(
            level=60,
            msg=f'No proposal chosen; version={message.version.major}, '
            f'initiator_spi={message.initiator_spi}, responder_spi={responder_spi}'
        )
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
    def _generate_ke_nonce_payloads(selected_sa):
        dh_transform = next((
            transform for transform in selected_sa.proposals[0].transforms
            if isinstance(transform, Ikev2TransformDhGroup)
        ), None)

        payloads = []
        if dh_transform is not None:
            dh_group = dh_transform.transform_id
            if isinstance(dh_group.value.key_parameter, NamedGroup):
                key_exchange_data = get_ecdh_ephemeral_key_forged(
                    dh_group.value.key_parameter, add_point_format_octet=False
                )
            else:
                key_exchange_data = int_to_bytes(
                    get_dh_ephemeral_key_forged(dh_group.value.key_parameter.value.parameter_numbers.p),
                    dh_group.value.key_parameter.value.key_size // 8
                )
            payloads.append(Ikev2PayloadKeyExchange(
                flags=set(),
                dh_group=dh_group,
                key_exchange_data=key_exchange_data,
            ))
        payloads.append(Ikev2PayloadNonce(
            flags=set(),
            nonce_data=random.randbytes(32),
        ))
        return payloads

    @staticmethod
    def _make_selected_sa(
        sa_payload: Ikev2PayloadSecurityAssociation,
        transforms: typing.Dict[typing.Any, typing.Any],
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
    def _resolve_ikev2_transform(
        encryption_transform: Ikev2TransformEncryptionAlgorithm,
        integrity_transform: Ikev2TransformIntegrity,
        pseudorandom_function_transform: Ikev2TransformPrf,
        diffie_hellman_group_transform: Ikev2TransformDhGroup,
    ) -> typing.Optional[Ikev2TransformResolved]:
        """Resolve IKEv2 transforms into (enc, mode, integrity, prf, dh) or None."""

        for bulk_cipher_entry in encryption_transform.transform_id.value.bulk_ciphers:
            if bulk_cipher_entry.cipher.value.key_size == encryption_transform.key_length:
                return Ikev2TransformResolved(
                    encryption_algorithm=bulk_cipher_entry.cipher,
                    block_cipher_mode=encryption_transform.transform_id.value.block_cipher_mode,
                    integrity_algorithm=integrity_transform.transform_id.value.hmac,
                    pseudorandom_function=pseudorandom_function_transform.transform_id.value.mac,
                    diffie_hellman_group=diffie_hellman_group_transform.transform_id.value.key_parameter,
                )

        return None

    def _match_ikev2_proposal(
        self,
        proposal: Ikev2ProposalPayload,
    ) -> typing.Optional[typing.Dict[typing.Any, typing.Any]]:
        """Try to match a single IKEv2 proposal against configured cipher suites.

        Returns a dict of selected transforms keyed by transform type, or None.
        """
        encription_transforms = list(filter(
            lambda transform: isinstance(transform, Ikev2TransformEncryptionAlgorithm),
            proposal.transforms
        ))
        integrity_transforms = list(filter(
            lambda transform: isinstance(transform, Ikev2TransformIntegrity),
            proposal.transforms
        ))
        prf_transforms = list(filter(
            lambda transform: isinstance(transform, Ikev2TransformPrf),
            proposal.transforms
        ))
        dh_group_transforms = list(filter(
            lambda transform: isinstance(transform, Ikev2TransformDhGroup),
            proposal.transforms
        ))

        for encryption_transform in encription_transforms:
            for integrity_transform, prf_transform, dh_group_transform in itertools.product(
                integrity_transforms,
                prf_transforms,
                dh_group_transforms,
            ):
                resolved = self._resolve_ikev2_transform(
                    encryption_transform,
                    integrity_transform,
                    prf_transform,
                    dh_group_transform,
                )
                if resolved is None:
                    continue

                for cipher_suite in self.configuration.ikev2_cipher_suites:
                    if (cipher_suite.encryption_algorithm == resolved.encryption_algorithm and
                            cipher_suite.block_cipher_mode == resolved.block_cipher_mode and
                            cipher_suite.integrity_algorithm == resolved.integrity_algorithm and
                            cipher_suite.pseudorandom_function == resolved.pseudorandom_function and
                            cipher_suite.diffie_hellman_group == resolved.diffie_hellman_group):
                        return {
                            encryption_transform.get_transform_type(): encryption_transform,
                            integrity_transform.get_transform_type(): integrity_transform,
                            prf_transform.get_transform_type(): prf_transform,
                            dh_group_transform.get_transform_type(): dh_group_transform,
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

    def _get_no_connection_nonce_payload(self) -> Ikev2PayloadNonce:
        return Ikev2PayloadNonce(flags=set(), nonce_data=b'\x00' * 32)

    def _handle_ikev2_cookie_challenge(self, message) -> bool:
        """Handle cookie challenge. Returns True if response was sent and caller should return."""
        cookie_payload = next((
            payload for payload in message.payloads
            if isinstance(payload, Ikev2NotifyPayloadCookie)
        ), None)
        cookie_value = bytes(cookie_payload.cookie) if cookie_payload is not None else None

        if self._expected_cookie is None and cookie_value is None:
            self._expected_cookie = random.randbytes(16)
        elif self._expected_cookie is not None and cookie_value != self._expected_cookie:
            pass
        else:
            return False

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
        return True

    def _send_ikev2_invalid_ke_response(self, message, responder_spi, selected_sa):
        selected_dh_transform = selected_sa.get_transform_by_type(Ikev2TransformType.DH)
        notify = Ikev2NotifyPayloadInvalidKe(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.INVALID_KE_PAYLOAD,
            spi=b'',
            dh_group=selected_dh_transform.transform_id,
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

    def _send_ikev2_sa_response(self, message, responder_spi, selected_sa):
        response = IsakmpMessage(
            version=message.version,
            initiator_spi=message.initiator_spi,
            responder_spi=responder_spi,
            exchange_type=message.exchange_type,
            flags=[IsakmpFlags.RESPONSE],
            message_id=message.message_id,
            payloads=[selected_sa] + self._generate_ke_nonce_payloads(selected_sa),
        )
        self.l7_transfer.send(response.compose())
        raise StopIteration()

    def _send_ikev2_no_proposal_chosen(self, message, responder_spi):
        LogSingleton().log(
            level=60,
            msg=f'No proposal chosen; version={message.version.major}, '
            f'initiator_spi={message.initiator_spi}, responder_spi={responder_spi}'
        )
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

    def _process_handshake_message(
        self,
        message: IsakmpMessage,
        last_handshake_message_type: typing.Any,
    ) -> None:  # pylint: disable=unused-argument
        self.client_messages = {'ike_version': IkeVersion.V2, 'message': message}

        self._handle_response_mode(message)

        if self.configuration.cookie_challenge and self._handle_ikev2_cookie_challenge(message):
            return

        responder_spi = self._get_responder_spi()
        try:
            sa_payload = message.get_payload_by_type(Ikev2PayloadType.SA)
        except KeyError:
            sa_payload = None

        selected_sa = None
        if sa_payload is not None and sa_payload.proposals:
            selected_sa = self._select_sa_from_client(sa_payload)

        if selected_sa is not None:
            try:
                selected_dh_transform = selected_sa.get_transform_by_type(Ikev2TransformType.DH)
                ke_payload = message.get_payload_by_type(Ikev2PayloadType.KE)
            except KeyError:
                selected_dh_transform = None
                ke_payload = None
            if (selected_dh_transform is not None and ke_payload is not None and
                    ke_payload.dh_group != selected_dh_transform.transform_id):
                self._send_ikev2_invalid_ke_response(message, responder_spi, selected_sa)
            self._send_ikev2_sa_response(message, responder_spi, selected_sa)

        self._send_ikev2_no_proposal_chosen(message, responder_spi)


@attr.s
class L7ServerIkeBase(L7ServerBase):
    def __attrs_post_init__(self) -> None:
        if self.configuration is None:
            self.configuration = IkeServerConfiguration()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls) -> str:
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls) -> int:
        raise NotImplementedError()

    @classmethod
    def _get_transfer_class(cls) -> typing.Type[L4ServerUDP]:
        return L4ServerUDP

    def _get_handshake_class(self) -> typing.Type[IkeServerHandshakeBase]:
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

            if message.version.major == IkeVersion.V1:
                return Ikev1ServerHandshake
            if message.version.major == IkeVersion.V2:
                return Ikev2ServerHandshake

            raise NotImplementedError(message.version)

    def _do_handshake(self, last_handshake_message_type: typing.Any) -> typing.Dict[str, typing.Any]:
        handshake_class = self._get_handshake_class()
        handshake_object = handshake_class(self, self.configuration)
        handshake_object.do_handshake(last_handshake_message_type)
        return handshake_object.client_messages

    def do_ike_handshake(self) -> typing.Dict[str, typing.Any]:
        return self._do_handshakes(last_handshake_message_type=None)


class L7ServerIke(L7ServerIkeBase):
    @classmethod
    def get_scheme(cls) -> str:
        return 'ipsec'

    @classmethod
    def get_default_port(cls) -> int:
        return 45000
