# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import typing

import attr

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, NamedGroup, Hash
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.ike.algorithm import (
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2IntegrityAlgorithm,
    Ikev2PseudorandomFunction,
    MAC,
)

from cryptolyzer.ike.client import Ikev1SecurityAssociationProposalAlgorithms


@attr.s
class Ikev1CipherSuite:
    """
    :class: Negotiable IKEv1 cipher suite.
    """

    encryption_algorithm: BlockCipher = attr.ib(
        validator=attr.validators.instance_of(BlockCipher)
    )
    block_cipher_mode: typing.Optional[BlockCipherMode] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipherMode))
    )
    diffie_hellman_group: typing.Union[NamedGroup, DHParamWellKnown, str] = attr.ib(
        validator=attr.validators.instance_of((NamedGroup, DHParamWellKnown))
    )
    hash_algorithm: Hash = attr.ib(
        validator=attr.validators.instance_of(Hash)
    )

    @classmethod
    def from_ikev1_security_association_proposal_algorithms(
        cls,
        algorithms: Ikev1SecurityAssociationProposalAlgorithms
    ):
        for encryption_algorithm in algorithms.encryption_algorithm.value.bulk_ciphers:
            if encryption_algorithm.value.key_size == algorithms.key_length:
                break
        else:
            raise ValueError(
                f'Key length {algorithms.key_length} not found for '
                f'encryption algorithm {algorithms.encryption_algorithm}'
            )

        return cls(
            encryption_algorithm=encryption_algorithm,
            block_cipher_mode=algorithms.encryption_algorithm.value.block_cipher_mode,
            diffie_hellman_group=algorithms.diffie_hellman_group.value.key_parameter,
            hash_algorithm=algorithms.hash_algorithm.value.hash,
        )


@attr.s(frozen=True)
class Ikev2CipherSuite:
    """
    :class: Negotiable IKEv2 cipher suite.
    """

    encryption_algorithm: BlockCipher = attr.ib(
        validator=attr.validators.instance_of(BlockCipher)
    )
    block_cipher_mode: typing.Optional[BlockCipherMode] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipherMode))
    )
    pseudorandom_function: MAC = attr.ib(
        validator=attr.validators.instance_of(MAC)
    )
    diffie_hellman_group: typing.Union[NamedGroup, DHParamWellKnown] = attr.ib(
        validator=attr.validators.instance_of((NamedGroup, DHParamWellKnown))
    )
    integrity_algorithm: typing.Optional[MAC] = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(MAC))
    )

    @classmethod
    def from_transform_ids(
        cls,
        encryption_transform_id: Ikev2EncryptionAlgorithm,
        integrity_transform_id: Ikev2IntegrityAlgorithm,
        pseudorandom_transform_id: Ikev2PseudorandomFunction,
        diffie_hellman_transform_id: Ikev2DiffieHellmanGroup,
        key_length: int,
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        for encryption_algorithm in encryption_transform_id.value.bulk_ciphers:
            if encryption_algorithm.value.key_size == key_length:
                break
        else:
            raise ValueError(
                f'Key length {key_length} not found for '
                f'encryption algorithm {encryption_transform_id}'
            )

        integrity_algorithm = None if integrity_transform_id.value.hmac is None else integrity_transform_id.value.hmac
        return cls(
            encryption_algorithm=encryption_algorithm,
            block_cipher_mode=encryption_transform_id.value.block_cipher_mode,
            pseudorandom_function=pseudorandom_transform_id.value.mac,
            diffie_hellman_group=diffie_hellman_transform_id.value.key_parameter,
            integrity_algorithm=integrity_algorithm,
        )
