# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import abc
import itertools
import random
import typing

import attr

from cryptodatahub.common.algorithm import NamedGroup
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.ike.algorithm import (
    Ikev1AuthenticationMethod,
    Ikev1DiffieHellmanGroup,
    Ikev1Doi,
    Ikev1EncryptionAlgorithm,
    Ikev1ExchangeType,
    Ikev1HashAlgorithm,
    Ikev1LifeType,
    Ikev1NotifyLevel,
    Ikev1NotifyType,
    Ikev1PayloadType,
    Ikev1ProtocolId,
    Ikev1TransformId,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2ExchangeType,
    Ikev2IntegrityAlgorithm,
    Ikev2NotifyLevel,
    Ikev2NotifyType,
    Ikev2PayloadType,
    Ikev2ProtocolId,
    Ikev2PseudorandomFunction,
)

from cryptodatahub.ike.version import IkeVersion

from cryptoparser.common.exception import NotEnoughData, InvalidType
from cryptoparser.ike.isakmp import IsakmpMessage, IsakmpFlags
from cryptoparser.ike.version import IsakmpProtocolVersion
from cryptoparser.ike.ikev1 import (
    Ikev1Situation,
    Ikev1PayloadKeyExchange,
    Ikev1PayloadNonce,
    Ikev1PayloadProposal,
    Ikev1PayloadSecurityAssociation,
    Ikev1PayloadTransform,
    Ikev1AttributeDiffieHellmanGroup,
    Ikev1AttributeKeyLength,
    Ikev1AttributeLifeType,
    Ikev1AttributeLifeDuration,
    Ikev1AttributeAuthenticationMethod,
    Ikev1AttributeEncryptionAlgorithm,
    Ikev1AttributeHashAlgorithm,
)
from cryptoparser.ike.ikev2 import (
    Ikev2Proposal,
    Ikev2PayloadKeyExchange,
    Ikev2NotifyPayloadCookie,
    Ikev2PayloadNonce,
    Ikev2PayloadFlags,
    Ikev2PayloadSecurityAssociation,
    Ikev2PayloadDelete,
    Ikev2TransformDhGroup,
    Ikev2TransformEncryptionAlgorithm,
    Ikev2TransformIntegrity,
    Ikev2TransformPrf,
    Transform,
)

from cryptolyzer.common.exception import (
    SecurityError,
    SecurityErrorType,
    NetworkError,
    NetworkErrorType
)
from cryptolyzer.common.transfer import L4TransferBase

from cryptolyzer.common.dhparam import (
    get_dh_ephemeral_key_forged,
    get_ecdh_ephemeral_key_forged,
    int_to_bytes,
)
from cryptolyzer.common.transfer import L4ClientUDP, L7TransferBase
from cryptolyzer.ike.exception import IsakmpNotify


class Ikev2SecurityAssociationBase(IsakmpMessage):
    _TRANSFORM_CLASS_BY_TRANSFORM_ID = {
        Ikev2PseudorandomFunction: Ikev2TransformPrf,
        Ikev2DiffieHellmanGroup: Ikev2TransformDhGroup,
        Ikev2EncryptionAlgorithm: Ikev2TransformEncryptionAlgorithm,
        Ikev2IntegrityAlgorithm: Ikev2TransformIntegrity,
    }

    @classmethod
    def _get_proposals(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        cls,
        encryption_algorithms: typing.List[Ikev2EncryptionAlgorithm],
        diffie_hellman_groups: typing.List[Ikev2DiffieHellmanGroup],
        pseudorandom_functions: typing.List[Ikev2PseudorandomFunction],
        integrity_algorithms: typing.List[Ikev2IntegrityAlgorithm],
        ecdh_groups: typing.List[Ikev2DiffieHellmanGroup],
        ffdh_groups: typing.List[Ikev2DiffieHellmanGroup],
    ) -> typing.List[Ikev2Proposal]:
        proposals: typing.List[Ikev2Proposal] = []
        transforms: typing.List[Transform] = []
        for transform_ids in [pseudorandom_functions, integrity_algorithms, diffie_hellman_groups]:
            for transform_id in transform_ids:
                transform_class = cls._TRANSFORM_CLASS_BY_TRANSFORM_ID[type(transform_id)]
                transforms.append(transform_class(transform_id=transform_id))

        for transform_id in encryption_algorithms:
            transform_class = cls._TRANSFORM_CLASS_BY_TRANSFORM_ID[type(transform_id)]
            for bulk_cipher in transform_id.value.bulk_ciphers:
                key_size = bulk_cipher.cipher.value.key_size
                key_length = key_size if key_size is not None else 0
                transforms.append(transform_class(transform_id=transform_id, key_length=key_length))

        if ecdh_groups:
            proposals.append(Ikev2Proposal(
                protocol_id=Ikev2ProtocolId.IKE,
                transforms=transforms + list(map(Ikev2TransformDhGroup, ecdh_groups))
            ))

        if ffdh_groups:
            proposals.append(Ikev2Proposal(
                protocol_id=Ikev2ProtocolId.IKE,
                transforms=transforms + list(map(Ikev2TransformDhGroup, ffdh_groups))
            ))

        return proposals

    @classmethod
    def _get_payloads(
        cls,
        encryption_algorithms: typing.List[Ikev2EncryptionAlgorithm],
        diffie_hellman_groups: typing.List[Ikev2DiffieHellmanGroup],
        pseudorandom_functions: typing.List[Ikev2PseudorandomFunction],
        integrity_algorithms: typing.List[Ikev2IntegrityAlgorithm],
        cookie: typing.Optional[typing.Union[bytes, bytearray]] = None,
        nonce: typing.Optional[typing.Union[bytes, bytearray]] = None,
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        payloads = []

        # Cookie payload must be the first payload
        if cookie is not None:
            payloads.append(Ikev2NotifyPayloadCookie(
                flags=set(),
                protocol_id=Ikev2ProtocolId.IKE,
                type=Ikev2NotifyType.COOKIE,
                spi=bytes(),
                cookie=cookie,
            ))

        ecdh_groups = list(filter(
            lambda dh_group: isinstance(dh_group.value.key_parameter, NamedGroup),
            diffie_hellman_groups
        ))
        ffdh_groups = list(filter(
            lambda dh_group: isinstance(dh_group.value.key_parameter, DHParamWellKnown),
            diffie_hellman_groups
        ))
        proposals = cls._get_proposals(
            encryption_algorithms=encryption_algorithms,
            diffie_hellman_groups=diffie_hellman_groups,
            pseudorandom_functions=pseudorandom_functions,
            integrity_algorithms=integrity_algorithms,
            ecdh_groups=ecdh_groups,
            ffdh_groups=ffdh_groups,
        )
        payload_security_association = Ikev2PayloadSecurityAssociation(
            flags=set([Ikev2PayloadFlags.CRITICAL, ]),
            proposals=proposals
        )
        payloads.append(payload_security_association)

        if list(diffie_hellman_groups) == list(Ikev2DiffieHellmanGroup):
            dh_group = ecdh_groups[0] if ecdh_groups else ffdh_groups[0]
        else:
            dh_group = diffie_hellman_groups[0]

        if isinstance(dh_group.value.key_parameter, NamedGroup):
            payload_key_exchange = Ikev2PayloadKeyExchange(
                flags=set(),
                dh_group=dh_group,
                key_exchange_data=get_ecdh_ephemeral_key_forged(
                    dh_group.value.key_parameter, add_point_format_octet=False
                ),
            )
            payloads.append(payload_key_exchange)
        elif isinstance(dh_group.value.key_parameter, DHParamWellKnown):
            payload_key_exchange = Ikev2PayloadKeyExchange(
                flags=set(),
                dh_group=dh_group,
                key_exchange_data=int_to_bytes(
                    get_dh_ephemeral_key_forged(dh_group.value.key_parameter.value.parameter_numbers.p),
                    dh_group.value.key_parameter.value.key_size // 8
                )
            )
            payloads.append(payload_key_exchange)

        if nonce is None:
            nonce = random.randbytes(32)
        payloads.append(Ikev2PayloadNonce(
            flags=set(),
            nonce_data=nonce,
        ))

        return payloads


class Ikev2SecurityAssociationSpecialization(Ikev2SecurityAssociationBase):
    def __init__(
            self,
            encryption_algorithms=tuple(Ikev2EncryptionAlgorithm),
            diffie_hellman_groups=tuple(Ikev2DiffieHellmanGroup),
            pseudorandom_functions=tuple(Ikev2PseudorandomFunction),
            integrity_algorithms=tuple(Ikev2IntegrityAlgorithm),
            cookie=None,
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        payloads = self._get_payloads(
            encryption_algorithms=encryption_algorithms,
            diffie_hellman_groups=diffie_hellman_groups,
            pseudorandom_functions=pseudorandom_functions,
            integrity_algorithms=integrity_algorithms,
            cookie=cookie,
        )

        super().__init__(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=random.randint(0, 2**64 - 1),
            responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.INITIATOR],
            message_id=0,
            payloads=payloads
        )


class Ikev2SecurityAssociationAnyAlgorithm(Ikev2SecurityAssociationBase):
    def __init__(self, cookie=None):
        payloads = self._get_payloads(
            encryption_algorithms=list(Ikev2EncryptionAlgorithm),
            diffie_hellman_groups=list(Ikev2DiffieHellmanGroup),
            pseudorandom_functions=list(Ikev2PseudorandomFunction),
            integrity_algorithms=list(Ikev2IntegrityAlgorithm),
            cookie=cookie,
        )

        initiator_spi = random.randint(0, 2**64 - 1)
        super().__init__(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=initiator_spi,
            responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.INITIATOR],
            message_id=0,
            payloads=payloads,
        )


class Ikev1SecurityAssociationBase(IsakmpMessage):
    _TRANSFORM_CLASS_BY_TRANSFORM_ID = {
        Ikev1HashAlgorithm: Ikev1AttributeHashAlgorithm,
        Ikev1EncryptionAlgorithm: Ikev1AttributeEncryptionAlgorithm,
        Ikev1DiffieHellmanGroup: Ikev1AttributeDiffieHellmanGroup,
        Ikev1AuthenticationMethod: Ikev1AttributeAuthenticationMethod,
    }

    @classmethod
    def get_key_lengths(cls, encryption_algorithm):
        bulk_ciphers = list(encryption_algorithm.value.bulk_ciphers)
        single_key_size = len(bulk_ciphers) == 1
        if single_key_size:
            return [None]

        return [
            bulk_cipher.cipher.value.key_size
            for bulk_cipher in bulk_ciphers
            if bulk_cipher.cipher.value.key_size is not None
        ]

    @classmethod
    def get_proposals(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        cls,
        encryption_algorithm: Ikev1EncryptionAlgorithm,
        diffie_hellman_group: Ikev1DiffieHellmanGroup,
        hash_algorithm: Ikev1HashAlgorithm,
        authentication_method: Ikev1AuthenticationMethod,
        key_length: typing.Optional[int] = None,
    ) -> typing.List[Ikev1PayloadProposal]:
        key_lengths: typing.List[int] = []
        if key_length is None:
            key_lengths.extend(cls.get_key_lengths(encryption_algorithm))
        else:
            key_lengths.append(key_length)

        proposals = []
        for _key_length in key_lengths:
            attributes = [
                Ikev1AttributeEncryptionAlgorithm(encryption_algorithm),
                Ikev1AttributeHashAlgorithm(hash_algorithm),
                Ikev1AttributeDiffieHellmanGroup(diffie_hellman_group),
                Ikev1AttributeAuthenticationMethod(authentication_method),
                Ikev1AttributeLifeType(value=Ikev1LifeType.SECONDS),
                Ikev1AttributeLifeDuration(value=86400),
            ]

            if _key_length is not None:
                attributes.append(Ikev1AttributeKeyLength(_key_length))

            proposal = Ikev1PayloadProposal(
                protocol_id=Ikev1ProtocolId.ISAKMP,
                transforms=[Ikev1PayloadTransform(
                    transform_id=Ikev1TransformId.KEY_IKE,
                    attributes=attributes,
                )],
            )

            proposals.append(proposal)

        return proposals

    @classmethod
    # pylint: disable=too-many-arguments,too-many-positional-arguments
    def _get_proposals(
        cls,
        encryption_algorithms: typing.List[Ikev1EncryptionAlgorithm],
        diffie_hellman_groups: typing.List[Ikev1DiffieHellmanGroup],
        hash_algorithms: typing.List[Ikev1HashAlgorithm],
        authentication_methods: typing.List[Ikev1AuthenticationMethod],
        key_length: typing.Optional[int] = None,
    ) -> typing.List[Ikev1PayloadProposal]:
        proposals = []
        for encryption_algorithm in encryption_algorithms:
            for hash_algorithm in hash_algorithms:
                for diffie_hellman_group in diffie_hellman_groups:
                    for authentication_method in authentication_methods:
                        proposals.extend(cls.get_proposals(
                            encryption_algorithm,
                            diffie_hellman_group,
                            hash_algorithm,
                            authentication_method,
                            key_length,
                        ))

        return proposals

    @classmethod
    def _get_dh_groups(
        cls,
        proposals: typing.List[Ikev1PayloadProposal]
    ) -> typing.Tuple[typing.Optional[Ikev1DiffieHellmanGroup], typing.Optional[Ikev1DiffieHellmanGroup]]:
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

                        if ffdh_group and ecdh_group:
                            return ffdh_group, ecdh_group

        return ffdh_group, ecdh_group

    @classmethod
    def get_key_exchange_payloads(cls, proposals: typing.List[Ikev1PayloadProposal]):
        payloads = []
        ffdh_group, ecdh_group = cls._get_dh_groups(proposals)

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

        payloads.append(Ikev1PayloadNonce(
            nonce_data=random.randbytes(32)
        ))

        return payloads

    @classmethod
    def _get_payloads(
        cls,
        proposals: typing.List[Ikev1PayloadProposal],
    ):
        payloads = []

        payload_security_association = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation=[Ikev1Situation.SIT_IDENTITY_ONLY],
            proposals=proposals
        )
        payloads.append(payload_security_association)

        return payloads


class Ikev1SecurityAssociationSpecialization(Ikev1SecurityAssociationBase):
    def __init__(
            self,
            exchange_type: Ikev1ExchangeType,
            encryption_algorithms=tuple(Ikev1EncryptionAlgorithm),
            diffie_hellman_groups=tuple(Ikev1DiffieHellmanGroup),
            hash_algorithms=tuple(Ikev1HashAlgorithm),
            authentication_methods=tuple(Ikev1AuthenticationMethod),
            key_length=None,
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        proposals = list(self._get_proposals(
            encryption_algorithms=encryption_algorithms,
            diffie_hellman_groups=diffie_hellman_groups,
            hash_algorithms=hash_algorithms,
            authentication_methods=authentication_methods,
            key_length=key_length,
        ))

        payloads = self._get_payloads(proposals=proposals)
        if exchange_type == Ikev1ExchangeType.AGGRESSIVE:
            payloads = self.get_key_exchange_payloads(proposals) + payloads

        initiator_spi = random.randint(0, 2**64 - 1)
        super().__init__(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=initiator_spi,
            responder_spi=0,
            exchange_type=exchange_type,
            flags=[IsakmpFlags.INITIATOR],
            message_id=0,
            payloads=payloads
        )


@attr.s
class Ikev1SecurityAssociationProposalAlgorithms():
    encryption_algorithm: Ikev1EncryptionAlgorithm = attr.ib(
        validator=attr.validators.instance_of(Ikev1EncryptionAlgorithm)
    )
    diffie_hellman_group: Ikev1DiffieHellmanGroup = attr.ib(
        validator=attr.validators.instance_of(Ikev1DiffieHellmanGroup)
    )
    hash_algorithm: Ikev1HashAlgorithm = attr.ib(
        validator=attr.validators.instance_of(Ikev1HashAlgorithm)
    )
    key_length: typing.Optional[int] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(int))
    )
    authentication_method: Ikev1AuthenticationMethod = attr.ib(
        validator=attr.validators.instance_of(Ikev1AuthenticationMethod),
        eq=False
    )


class Ikev1SecurityAssociationAlgorithms(Ikev1SecurityAssociationBase):
    def __init__(
        self,
        exchange_type: Ikev1ExchangeType,
        algorithms: typing.List[Ikev1SecurityAssociationProposalAlgorithms]
    ):
        proposals = list(itertools.chain.from_iterable([
            self.get_proposals(
                encryption_algorithm=algorithm.encryption_algorithm,
                diffie_hellman_group=algorithm.diffie_hellman_group,
                hash_algorithm=algorithm.hash_algorithm,
                authentication_method=algorithm.authentication_method,
                key_length=algorithm.key_length,
            )
            for algorithm in algorithms
        ]))

        payloads = self._get_payloads(proposals=proposals)
        if exchange_type == Ikev1ExchangeType.AGGRESSIVE:
            payloads = self.get_key_exchange_payloads(proposals) + payloads

        initiator_spi = random.randint(0, 2**64 - 1)
        super().__init__(
            version=IsakmpProtocolVersion(IkeVersion.V1, 0),
            initiator_spi=initiator_spi,
            responder_spi=0,
            exchange_type=exchange_type,
            flags=[IsakmpFlags.INITIATOR],
            message_id=0,
            payloads=payloads
        )


class Ikev1SecurityAssociationMandatoryMostPopular(Ikev1SecurityAssociationSpecialization):
    def __init__(self, exchange_type: Ikev1ExchangeType):
        super().__init__(
            exchange_type=exchange_type,
            encryption_algorithms=[Ikev1EncryptionAlgorithm.AES_CBC],
            diffie_hellman_groups=[
                Ikev1DiffieHellmanGroup.MODP_2048_BIT,
                Ikev1DiffieHellmanGroup.MODP_3072_BIT,
                Ikev1DiffieHellmanGroup.ECP_256_BIT,
            ],
            hash_algorithms=[
                Ikev1HashAlgorithm.SHA,
                Ikev1HashAlgorithm.SHA2_256,
            ],
            authentication_methods=[
                Ikev1AuthenticationMethod.RSA_SIGNATURES,
                Ikev1AuthenticationMethod.ECDSA,
                Ikev1AuthenticationMethod.ECDSA_SHA_256_P_256,
            ],
        )


@attr.s
class IKEClient():
    _last_processed_message_type: typing.Optional[Ikev2ExchangeType] = attr.ib(init=False, default=None)
    server_messages: typing.Dict[Ikev2ExchangeType, typing.List[IsakmpMessage]] = attr.ib(init=False, default={})

    @classmethod
    def raise_response_error(cls, transfer):
        response_is_plain_text = transfer.buffer and transfer.buffer_is_plain_text
        transfer.flush_buffer()

        if response_is_plain_text:
            raise SecurityError(SecurityErrorType.PLAIN_TEXT_MESSAGE)

        raise SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE)

    @abc.abstractmethod
    def do_handshake(self, transfer, init_message, last_exchange_type):
        raise NotImplementedError()


class IKEv2ClientHandshake(IKEClient):
    def _process_handshake_message(self, message, last_exchange_type):
        self.server_messages[message.exchange_type] = message

        if message.exchange_type == last_exchange_type:
            raise StopIteration()

    @classmethod
    def _process_non_handshake_message(cls, message):
        try:
            payload = message.get_payload_by_type(Ikev2PayloadType.NOTIFY)
            notify_type = payload.type
            if notify_type == Ikev2NotifyType.COOKIE:
                raise IsakmpNotify(notify_type, payload)
            if notify_type.value.level == Ikev2NotifyLevel.ERROR:
                raise IsakmpNotify(notify_type, payload)
        except KeyError as e:
            raise IsakmpNotify(Ikev2NotifyType.INVALID_SYNTAX) from e

    @classmethod
    def _process_invalid_message(cls, transfer):
        cls.raise_response_error(transfer)

    @classmethod
    def _send_isakmp_message(cls, transfer, isakmp_message):
        isakmp_message_bytes = isakmp_message.compose()
        transfer.send(isakmp_message_bytes)

    @classmethod
    def _get_cookie_payload(cls, init_message):
        payload_cookie = init_message.payloads[0]
        cookie_value = bytes(payload_cookie.cookie)

        cookie_payload = Ikev2NotifyPayloadCookie(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.COOKIE,
            spi=bytes(),
            cookie=cookie_value,
        )

        return cookie_payload

    def do_handshake(
            self,
            transfer,
            init_message,
            last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT
    ):
        self.server_messages = {}
        transfer.flush_buffer()

        self._send_isakmp_message(transfer, init_message)

        receivable_byte_num = 0
        while True:
            try:
                message, parsed_length = IsakmpMessage.parse_immutable(transfer.buffer)
                transfer.flush_buffer(parsed_length)

                if message.exchange_type != Ikev2ExchangeType.IKE_SA_INIT:
                    raise InvalidType()

                if message.payloads[0].get_payload_type() == Ikev2PayloadType.SA:
                    self._process_handshake_message(message, last_exchange_type)
                else:
                    self._process_non_handshake_message(message)
            except IsakmpNotify as e:
                if e.notify == Ikev2NotifyType.INVALID_KE_PAYLOAD:
                    raise

                if e.notify != Ikev2NotifyType.COOKIE:
                    raise

                cookie_payload = self._get_cookie_payload(message)
                init_message.payloads = [cookie_payload] + init_message.payloads
                self._send_isakmp_message(transfer, init_message)

                continue
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            except (InvalidType, InvalidValue):
                self._process_invalid_message(transfer)
            except StopIteration:
                delete_payload = Ikev2PayloadDelete(
                    flags=set(),
                    protocol_id=Ikev2ProtocolId.IKE,
                    spis=[]
                )
                delete_message = IsakmpMessage(
                    initiator_spi=init_message.initiator_spi,
                    responder_spi=message.responder_spi,
                    version=init_message.version,
                    exchange_type=Ikev2ExchangeType.IKE_INFORMATIONAL,
                    flags=[],
                    message_id=1,
                    payloads=[delete_payload]
                )
                self._send_isakmp_message(transfer, delete_message)
                return

            try:
                transfer.receive(receivable_byte_num)
            except NotEnoughData as e:
                if transfer.buffer:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION) from e

                raise NetworkError(NetworkErrorType.NO_RESPONSE) from e


class IKEv1ClientHandshake(IKEClient):
    _ACCEPTABLE_EXCHANGE_TYPES = [
        Ikev1ExchangeType.IDENTITY_PROTECTION,
        Ikev1ExchangeType.AGGRESSIVE,
        Ikev1ExchangeType.INFORMATIONAL
    ]
    _ACCEPTABLE_PAYLOAD_TYPES = [
        Ikev1PayloadType.SECURITY_ASSOCIATION,
        Ikev1PayloadType.KEY_EXCHANGE
    ]

    def _process_handshake_message(self, message, last_exchange_type):
        if message.exchange_type not in self.server_messages:
            self.server_messages[message.exchange_type] = []

        self.server_messages[message.exchange_type].append(message)

        if message.exchange_type not in self._ACCEPTABLE_EXCHANGE_TYPES:
            raise StopIteration()  # pragma: no cover

        if message.exchange_type == last_exchange_type:
            raise StopIteration()

    @classmethod
    def _process_non_handshake_message(cls, message):
        try:
            payload = message.get_payload_by_type(Ikev1PayloadType.NOTIFICATION)
            notify_type = payload.notify_type
            if notify_type == Ikev1NotifyType.NO_PROPOSAL_CHOSEN:
                raise IsakmpNotify(notify_type)
            if notify_type.value.level == Ikev1NotifyLevel.ERROR:
                raise IsakmpNotify(notify_type)
        except KeyError as e:
            raise IsakmpNotify(Ikev1NotifyType.SITUATION_NOT_SUPPORTED) from e

    @classmethod
    def _process_invalid_message(cls, transfer):
        cls.raise_response_error(transfer)

    @classmethod
    def _send_isakmp_message(cls, transfer, isakmp_message):
        isakmp_message_bytes = isakmp_message.compose()
        transfer.send(isakmp_message_bytes)

    def do_handshake(
            self,
            transfer,
            init_message,
            last_exchange_type=Ikev1ExchangeType.AUTHENTICATION_ONLY
    ):
        self.server_messages = {}
        transfer.flush_buffer()

        self._send_isakmp_message(transfer, init_message)

        receivable_byte_num = 0
        while True:
            try:
                responder_message, parsed_length = IsakmpMessage.parse_immutable(transfer.buffer)
                transfer.flush_buffer(parsed_length)

                if responder_message.exchange_type not in self._ACCEPTABLE_EXCHANGE_TYPES:
                    raise InvalidType()

                if responder_message.payloads[0].get_payload_type() in self._ACCEPTABLE_PAYLOAD_TYPES:
                    self._process_handshake_message(responder_message, last_exchange_type)
                else:
                    self._process_non_handshake_message(responder_message)
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            except (InvalidType, InvalidValue):
                self._process_invalid_message(transfer)
            except StopIteration:
                if (last_exchange_type == Ikev1ExchangeType.IDENTITY_PROTECTION and
                        len(self.server_messages[Ikev1ExchangeType.IDENTITY_PROTECTION]) < 2):
                    payload_security_association = responder_message.get_payload_by_type(
                        Ikev1PayloadType.SECURITY_ASSOCIATION
                    )
                    key_exchange_payloads = Ikev1SecurityAssociationBase.get_key_exchange_payloads(
                        payload_security_association.proposals
                    )
                    key_exchange_message = IsakmpMessage(
                        version=init_message.version,
                        initiator_spi=init_message.initiator_spi,
                        responder_spi=responder_message.responder_spi,
                        exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
                        flags=[],
                        message_id=0,
                        payloads=key_exchange_payloads
                    )
                    self._send_isakmp_message(transfer, key_exchange_message)
                    continue

                return

            try:
                transfer.receive(receivable_byte_num)
            except NotEnoughData as e:
                if transfer.buffer:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION) from e

                raise NetworkError(NetworkErrorType.NO_RESPONSE) from e


@attr.s
class L7ClientIPsecBase(L7TransferBase, metaclass=abc.ABCMeta):
    l4_transfer: typing.Optional[L4TransferBase] = attr.ib(init=False, default=None)

    @classmethod
    def get_scheme(cls):
        return 'ipsec'

    @classmethod
    def get_default_port(cls):
        return 500

    def _init_connection(self):
        assert self.port is not None
        assert self.l4_socket_params is not None

        l4_transfer = L4ClientUDP(self.address, self.port, self.l4_socket_params, self.ip)
        l4_transfer.init_connection()

        self.l4_transfer = l4_transfer

    def _do_handshake(
            self,
            l7_client,
            init_message,
            last_exchange_type
    ):
        self.init_connection()

        try:
            l7_client.do_handshake(self, init_message, last_exchange_type)
        finally:
            self._close_connection()

        return l7_client.server_messages

    def do_ikev1_handshake(
            self,
            init_message,
            last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION
    ):
        return self._do_handshake(
            IKEv1ClientHandshake(),
            init_message,
            last_exchange_type
        )

    def do_ikev2_handshake(
            self,
            init_message,
            last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT
    ):
        return self._do_handshake(
            IKEv2ClientHandshake(),
            init_message,
            last_exchange_type
        )
