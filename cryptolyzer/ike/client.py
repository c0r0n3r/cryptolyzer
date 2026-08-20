# SPDX-License-Identifier: MPL-2.0

# pylint: disable=too-many-lines

import abc
import itertools
import secrets
import typing

import attr

from cryptodatahub.common.parameter import ECParamWellKnown
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
    Ikev2HashAlgorithm,
    Ikev2IntegrityAlgorithm,
    Ikev2NotifyLevel,
    Ikev2NotifyType,
    Ikev2PayloadType,
    Ikev2ProtocolId,
    Ikev2PseudorandomFunction,
    Ikev2CertificateType,
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
    Ikev1PayloadCertificateRequest,
    Ikev1CertificateType,
)
from cryptoparser.ike.ikev2 import (
    Ikev2Proposal,
    Ikev2PayloadKeyExchange,
    Ikev2NotifyPayloadCookie,
    Ikev2PayloadCertificateRequest,
    Ikev2PayloadNonce,
    Ikev2PayloadNotifyBase,
    Ikev2PayloadFlags,
    Ikev2NotifyPayloadSignatureHashAlgorithms,
    Ikev2PayloadSecurityAssociation,
    Ikev2PayloadDelete,
    Ikev2TransformDhGroup,
    Ikev2TransformEncryptionAlgorithm,
    Ikev2TransformIntegrity,
    Ikev2TransformPrf,
    Transform,
)

from cryptolyzer.common.utils import LogSingleton
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
from cryptolyzer.common.crypto import EphemeralKeyExchangeBase
from cryptolyzer.common.transfer import L4ClientUDP, L7TransferBase
from cryptolyzer.ike.crypto import dhe_ephemeral_material_backend
from cryptolyzer.ike.exception import IsakmpNotify
from cryptolyzer.ike.isakmp import parse_ike_message


class IkeSecurityAssociationBase(IsakmpMessage):
    @staticmethod
    def _split_dh_groups(dh_groups, backend_supported=None):
        ffdh_groups = [
            dh_group for dh_group in dh_groups
            if isinstance(dh_group.value.key_parameter, DHParamWellKnown)
        ]
        ecdh_groups = [
            dh_group for dh_group in dh_groups
            if isinstance(dh_group.value.key_parameter, ECParamWellKnown)
            and (backend_supported is None or dh_group in backend_supported)
        ]
        return ffdh_groups, ecdh_groups

    @staticmethod
    def get_encryption_algorithm_key_lengths(encryption_algorithm):
        # RFC 7296 §3.3.5: fixed-key entries (single bulk_ciphers) MUST omit
        # the Key Length attribute → use None as the wire-level marker.
        # Variable-key entries enumerate one wire-level transform per
        # bulk_ciphers entry, each carrying its per-cipher key_size.
        bulk_ciphers = list(encryption_algorithm.value.bulk_ciphers)
        if len(bulk_ciphers) == 1:
            return [None]
        return [
            bulk_cipher.cipher.value.key_size
            for bulk_cipher in bulk_ciphers
            if bulk_cipher.cipher.value.key_size is not None
        ]

    @staticmethod
    def _build_key_exchange_data(dh_group, ephemeral=None):
        if ephemeral is not None:
            return dhe_ephemeral_material_backend.key_exchange_wire_bytes(dh_group, ephemeral)
        key_parameter = dh_group.value.key_parameter
        if isinstance(key_parameter, ECParamWellKnown):
            return get_ecdh_ephemeral_key_forged(key_parameter, add_point_format_octet=False)
        if isinstance(key_parameter, DHParamWellKnown):
            return int_to_bytes(
                get_dh_ephemeral_key_forged(key_parameter.value.parameter_numbers.p),
                key_parameter.value.field_size // 8,
            )
        return None


class Ikev2SecurityAssociationBase(IkeSecurityAssociationBase):
    _TRANSFORM_CLASS_BY_TRANSFORM_ID = {
        Ikev2PseudorandomFunction: Ikev2TransformPrf,
        Ikev2DiffieHellmanGroup: Ikev2TransformDhGroup,
        Ikev2EncryptionAlgorithm: Ikev2TransformEncryptionAlgorithm,
        Ikev2IntegrityAlgorithm: Ikev2TransformIntegrity,
    }

    @classmethod
    def expand_encryption_algorithms_to_tuples(cls, encryption_algorithms):
        return [
            (encryption_algorithm, key_length)
            for encryption_algorithm in encryption_algorithms
            for key_length in cls.get_encryption_algorithm_key_lengths(encryption_algorithm)
        ]

    @classmethod
    def _get_proposals(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        cls,
        encryption_algorithm_tuples: list[tuple[Ikev2EncryptionAlgorithm, typing.Optional[int]]],
        diffie_hellman_groups: list[Ikev2DiffieHellmanGroup],
        pseudorandom_functions: list[Ikev2PseudorandomFunction],
        integrity_algorithms: list[Ikev2IntegrityAlgorithm],
        ecdh_groups: list[Ikev2DiffieHellmanGroup],
        ffdh_groups: list[Ikev2DiffieHellmanGroup],
    ) -> list[Ikev2Proposal]:
        # RFC 7296 §2.7 / §3.3 and RFC 5282 §8: an IKE SA proposal that
        # contains AEAD (combined-mode) encryption MUST NOT carry a
        # non-NONE integrity transform; conversely, a non-AEAD proposal
        # requires integrity. If both cipher families are offered they
        # MUST live in separate proposals within the same SA payload.
        aead_encryption_algorithm_tuples = [
            encryption_algorithm_tuple
            for encryption_algorithm_tuple in encryption_algorithm_tuples
            if encryption_algorithm_tuple[0].value.aead
        ]
        non_aead_encryption_algorithm_tuples = [
            encryption_algorithm_tuple
            for encryption_algorithm_tuple in encryption_algorithm_tuples
            if not encryption_algorithm_tuple[0].value.aead
        ]
        non_none_integrity_algorithms = [
            integrity_algorithm
            for integrity_algorithm in integrity_algorithms
            if integrity_algorithm != Ikev2IntegrityAlgorithm.NONE
        ]

        proposals: list[Ikev2Proposal] = []
        if non_aead_encryption_algorithm_tuples and non_none_integrity_algorithms:
            proposals.extend(cls._build_proposals_for_family(
                non_aead_encryption_algorithm_tuples,
                diffie_hellman_groups,
                pseudorandom_functions,
                non_none_integrity_algorithms,
                ecdh_groups,
                ffdh_groups,
            ))
        if aead_encryption_algorithm_tuples:
            # RFC 7296 §3.3: AEAD proposal "MUST either offer no integrity
            # algorithm or a single integrity algorithm of 'NONE', with no
            # integrity algorithm being the RECOMMENDED method."
            proposals.extend(cls._build_proposals_for_family(
                aead_encryption_algorithm_tuples,
                diffie_hellman_groups,
                pseudorandom_functions,
                [],
                ecdh_groups,
                ffdh_groups,
            ))
        return proposals

    @classmethod
    def _build_proposals_for_family(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        cls,
        encryption_algorithm_tuples: list[tuple[Ikev2EncryptionAlgorithm, typing.Optional[int]]],
        diffie_hellman_groups: list[Ikev2DiffieHellmanGroup],
        pseudorandom_functions: list[Ikev2PseudorandomFunction],
        integrity_algorithms: list[Ikev2IntegrityAlgorithm],
        ecdh_groups: list[Ikev2DiffieHellmanGroup],
        ffdh_groups: list[Ikev2DiffieHellmanGroup],
    ) -> list[Ikev2Proposal]:
        transforms: list[Transform] = []
        for transform_ids in [pseudorandom_functions, integrity_algorithms, diffie_hellman_groups]:
            for transform_id in transform_ids:
                transform_class = cls._TRANSFORM_CLASS_BY_TRANSFORM_ID[type(transform_id)]
                transforms.append(transform_class(transform_id=transform_id))

        # Each (encryption_algorithm, key_length) tuple becomes exactly one
        # wire-level transform; the analyzer drives per-key-size granularity
        # by enumerating these tuples (see get_encryption_algorithm_key_lengths).
        for transform_id, key_length in encryption_algorithm_tuples:
            transform_class = cls._TRANSFORM_CLASS_BY_TRANSFORM_ID[type(transform_id)]
            transforms.append(transform_class(
                transform_id=transform_id,
                key_length=key_length,
            ))

        proposals: list[Ikev2Proposal] = []
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
    def append_key_exchange_payload(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        cls,
        payloads: list[typing.Any],
        diffie_hellman_groups: list[Ikev2DiffieHellmanGroup],
        ecdh_groups: list[Ikev2DiffieHellmanGroup],
        ffdh_groups: list[Ikev2DiffieHellmanGroup],
        ephemeral_key_exchange: typing.Optional[EphemeralKeyExchangeBase],
        key_exchange_dh_group: typing.Optional[Ikev2DiffieHellmanGroup],
    ) -> None:
        if key_exchange_dh_group is not None:
            dh_group = key_exchange_dh_group
        elif list(diffie_hellman_groups) == list(Ikev2DiffieHellmanGroup):
            dh_group = ecdh_groups[0] if ecdh_groups else ffdh_groups[0]
        else:
            dh_group = diffie_hellman_groups[0]

        key_exchange_data = cls._build_key_exchange_data(dh_group, ephemeral=ephemeral_key_exchange)
        if key_exchange_data is not None:
            payload_key_exchange = Ikev2PayloadKeyExchange(
                flags=set(),
                dh_group=dh_group,
                key_exchange_data=key_exchange_data,
            )
            LogSingleton().log(
                level=40,
                msg=f'Sending KE payload; length={len(payload_key_exchange.key_exchange_data) * 8}'
            )
            payloads.append(payload_key_exchange)

    @classmethod
    def _get_payloads(
        cls,
        encryption_algorithm_tuples: list[tuple[Ikev2EncryptionAlgorithm, typing.Optional[int]]],
        diffie_hellman_groups: list[Ikev2DiffieHellmanGroup],
        pseudorandom_functions: list[Ikev2PseudorandomFunction],
        integrity_algorithms: list[Ikev2IntegrityAlgorithm],
        cookie: typing.Optional[typing.Union[bytes, bytearray]] = None,
        nonce: typing.Optional[typing.Union[bytes, bytearray]] = None,
        key_exchange_dh_group: typing.Optional[Ikev2DiffieHellmanGroup] = None,
        extra_notify_payloads: typing.Optional[typing.Iterable[Ikev2PayloadNotifyBase]] = None,
        cert_request: typing.Optional[typing.Union[bytes, bytearray]] = None,
        ephemeral_key_exchange: typing.Optional[EphemeralKeyExchangeBase] = None,
        signature_hash_algorithms: typing.Optional[typing.Iterable[Ikev2HashAlgorithm]] = None,
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        payloads = []

        # Cookie payload must be the first payload
        if cookie is not None:
            payloads.append(Ikev2NotifyPayloadCookie(
                flags=set(),
                protocol_id=Ikev2ProtocolId.IKE,
                type=Ikev2NotifyType.COOKIE,
                spi=b'',
                cookie=cookie,
            ))

        ffdh_groups, ecdh_groups = cls._split_dh_groups(diffie_hellman_groups)
        payloads.append(Ikev2PayloadSecurityAssociation(
            flags=set([Ikev2PayloadFlags.CRITICAL, ]),
            proposals=cls._get_proposals(
                encryption_algorithm_tuples=encryption_algorithm_tuples,
                diffie_hellman_groups=diffie_hellman_groups,
                pseudorandom_functions=pseudorandom_functions,
                integrity_algorithms=integrity_algorithms,
                ecdh_groups=ecdh_groups,
                ffdh_groups=ffdh_groups,
            ),
        ))

        cls.append_key_exchange_payload(
            payloads, diffie_hellman_groups, ecdh_groups, ffdh_groups,
            ephemeral_key_exchange, key_exchange_dh_group,
        )

        if nonce is None:
            nonce = secrets.token_bytes(32)
        payloads.append(Ikev2PayloadNonce(
            flags=set(),
            nonce_data=nonce,
        ))

        if extra_notify_payloads is not None:
            payloads.extend(extra_notify_payloads)

        if cert_request is not None:
            payloads.append(Ikev2PayloadCertificateRequest(
                flags=set(),
                cert_encoding=Ikev2CertificateType.X509_CERTIFICATE_SIGNATURE,
                certification_authority=cert_request,
            ))

        if signature_hash_algorithms is not None:
            payloads.append(Ikev2NotifyPayloadSignatureHashAlgorithms(
                flags=set(),
                protocol_id=Ikev2ProtocolId.IKE,
                type=Ikev2NotifyType.SIGNATURE_HASH_ALGORITHMS,
                spi=b'',
                hash_algorithms=tuple(signature_hash_algorithms),
            ))

        return payloads


class Ikev2SecurityAssociationSpecialization(Ikev2SecurityAssociationBase):
    def __init__(
            self,
            encryption_algorithm_tuples=None,
            diffie_hellman_groups=tuple(Ikev2DiffieHellmanGroup),
            pseudorandom_functions=tuple(Ikev2PseudorandomFunction),
            integrity_algorithms=tuple(Ikev2IntegrityAlgorithm),
            cookie=None,
            key_exchange_dh_group=None,
            nonce=None,
            cert_request=None,
            ephemeral_key_exchange=None,
            signature_hash_algorithms=None,
            initiator_spi=None,
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        if encryption_algorithm_tuples is None:
            encryption_algorithm_tuples = self.expand_encryption_algorithms_to_tuples(
                Ikev2EncryptionAlgorithm
            )
        payloads = self._get_payloads(
            encryption_algorithm_tuples=encryption_algorithm_tuples,
            diffie_hellman_groups=diffie_hellman_groups,
            pseudorandom_functions=pseudorandom_functions,
            integrity_algorithms=integrity_algorithms,
            cookie=cookie,
            key_exchange_dh_group=key_exchange_dh_group,
            nonce=nonce,
            cert_request=cert_request,
            ephemeral_key_exchange=ephemeral_key_exchange,
            signature_hash_algorithms=signature_hash_algorithms,
        )

        super().__init__(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=secrets.randbits(64) if initiator_spi is None else initiator_spi,
            responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.INITIATOR],
            message_id=0,
            payloads=payloads
        )


class Ikev2SecurityAssociationAnyAlgorithm(Ikev2SecurityAssociationBase):
    def __init__(self, cookie=None, extra_notify_payloads=None, key_exchange_dh_group=None):
        payloads = self._get_payloads(
            encryption_algorithm_tuples=self.expand_encryption_algorithms_to_tuples(
                Ikev2EncryptionAlgorithm
            ),
            diffie_hellman_groups=list(Ikev2DiffieHellmanGroup),
            pseudorandom_functions=list(Ikev2PseudorandomFunction),
            integrity_algorithms=list(Ikev2IntegrityAlgorithm),
            cookie=cookie,
            key_exchange_dh_group=key_exchange_dh_group,
            extra_notify_payloads=extra_notify_payloads,
        )

        initiator_spi = secrets.randbits(64)
        super().__init__(
            version=IsakmpProtocolVersion(IkeVersion.V2, 0),
            initiator_spi=initiator_spi,
            responder_spi=0,
            exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            flags=[IsakmpFlags.INITIATOR],
            message_id=0,
            payloads=payloads,
        )


class Ikev1SecurityAssociationBase(IkeSecurityAssociationBase):
    _TRANSFORM_CLASS_BY_TRANSFORM_ID = {
        Ikev1HashAlgorithm: Ikev1AttributeHashAlgorithm,
        Ikev1EncryptionAlgorithm: Ikev1AttributeEncryptionAlgorithm,
        Ikev1DiffieHellmanGroup: Ikev1AttributeDiffieHellmanGroup,
        Ikev1AuthenticationMethod: Ikev1AttributeAuthenticationMethod,
    }

    @classmethod
    def get_proposals(  # pylint: disable=too-many-arguments,too-many-positional-arguments
        cls,
        encryption_algorithm: Ikev1EncryptionAlgorithm,
        diffie_hellman_group: Ikev1DiffieHellmanGroup,
        hash_algorithm: Ikev1HashAlgorithm,
        authentication_method: Ikev1AuthenticationMethod,
        key_length: typing.Optional[int] = None,
    ) -> list[Ikev1PayloadProposal]:
        key_lengths: list[int] = []
        if key_length is None:
            key_lengths.extend(cls.get_encryption_algorithm_key_lengths(encryption_algorithm))
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
    def _get_proposals(
        cls,
        encryption_algorithms: list[Ikev1EncryptionAlgorithm],
        diffie_hellman_groups: list[Ikev1DiffieHellmanGroup],
        hash_algorithms: list[Ikev1HashAlgorithm],
        authentication_methods: list[Ikev1AuthenticationMethod],
        key_length: typing.Optional[int] = None,
    ) -> list[Ikev1PayloadProposal]: # pylint: disable=too-many-arguments,too-many-positional-arguments
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
        proposals: list[Ikev1PayloadProposal]
    ) -> tuple[typing.Optional[Ikev1DiffieHellmanGroup], typing.Optional[Ikev1DiffieHellmanGroup]]:
        dh_groups = [
            attribute.value
            for proposal in proposals
            for transform in proposal.transforms
            for attribute in transform.attributes
            if isinstance(attribute, Ikev1AttributeDiffieHellmanGroup)
        ]
        backend_supported = frozenset(dhe_ephemeral_material_backend.supported_ikev1_dh_groups())
        ffdh_groups, ecdh_groups = cls._split_dh_groups(dh_groups, backend_supported=backend_supported)
        return (
            ffdh_groups[0] if ffdh_groups else None,
            ecdh_groups[0] if ecdh_groups else None,
        )

    @classmethod
    def get_key_exchange_payloads(cls, proposals: list[Ikev1PayloadProposal]):
        payloads = []
        ffdh_group, ecdh_group = cls._get_dh_groups(proposals)

        if ffdh_group is None and ecdh_group is None:
            raise ValueError('no supported Diffie-Hellman group in proposals')

        if ecdh_group:
            ephemeral = dhe_ephemeral_material_backend.create_ephemeral_material(ecdh_group)
            payloads.append(Ikev1PayloadKeyExchange(
                key_exchange_data=cls._build_key_exchange_data(ecdh_group, ephemeral=ephemeral),
            ))
        elif ffdh_group:
            payloads.append(Ikev1PayloadKeyExchange(
                key_exchange_data=cls._build_key_exchange_data(ffdh_group),
            ))

        payloads.append(Ikev1PayloadNonce(
            nonce_data=secrets.token_bytes(32)
        ))

        return payloads

    @classmethod
    def _get_payloads(
        cls,
        proposals: list[Ikev1PayloadProposal],
        cert_request: typing.Optional[bytes] = None,
    ):
        payloads = []

        payload_security_association = Ikev1PayloadSecurityAssociation(
            doi=Ikev1Doi.IPSEC,
            situation=[Ikev1Situation.SIT_IDENTITY_ONLY],
            proposals=proposals
        )
        payloads.append(payload_security_association)

        if cert_request is not None:
            payloads.append(Ikev1PayloadCertificateRequest(
                cert_encoding=Ikev1CertificateType.X509_CERTIFICATE_SIGNATURE,
                certification_authority=cert_request,
            ))

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

        initiator_spi = secrets.randbits(64)
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
class Ikev1SecurityAssociationProposalAlgorithms:
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
        algorithms: list[Ikev1SecurityAssociationProposalAlgorithms]
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

        initiator_spi = secrets.randbits(64)
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
class IKEClient:
    _last_processed_message_type: typing.Optional[Ikev2ExchangeType] = attr.ib(init=False, default=None)
    server_messages: dict[Ikev2ExchangeType, list[IsakmpMessage]] = attr.ib(init=False, default={})

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
        notifies = message.get_payloads_by_type(Ikev2PayloadType.NOTIFY)
        if not notifies:
            raise IsakmpNotify(Ikev2NotifyType.INVALID_SYNTAX)
        for payload in notifies:
            if payload.type == Ikev2NotifyType.COOKIE:
                raise IsakmpNotify(payload.type, payload)
            if payload.type.value.level == Ikev2NotifyLevel.ERROR:
                raise IsakmpNotify(payload.type, payload)

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
            spi=b'',
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
                message, parsed_length = parse_ike_message(transfer.buffer)
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
        notifies = message.get_payloads_by_type(Ikev1PayloadType.NOTIFICATION)
        if not notifies:
            raise IsakmpNotify(Ikev1NotifyType.SITUATION_NOT_SUPPORTED)
        for payload in notifies:
            if payload.notify_type == Ikev1NotifyType.NO_PROPOSAL_CHOSEN:
                raise IsakmpNotify(payload.notify_type)
            if payload.notify_type.value.level == Ikev1NotifyLevel.ERROR:
                raise IsakmpNotify(payload.notify_type)

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
                responder_message, parsed_length = parse_ike_message(transfer.buffer)
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
                    if key_exchange_payloads:
                        ke_data = key_exchange_payloads[0].key_exchange_data
                        LogSingleton().log(
                            level=40,
                            msg=f'Sending KE payload; length={len(ke_data) * 8}'
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
        except IsakmpNotify as e:
            e.server_messages = l7_client.server_messages
            raise
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
