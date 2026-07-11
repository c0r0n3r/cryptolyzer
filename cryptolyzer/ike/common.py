# SPDX-License-Identifier: MPL-2.0

import abc
import typing

import attr

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, NamedGroup, Hash
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.ike.algorithm import (
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
    MAC,
)

from cryptolyzer.common.analyzer import AnalyzerIKEBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.ike.client import (
    Ikev1SecurityAssociationBase,
    Ikev1SecurityAssociationProposalAlgorithms,
)
from cryptolyzer.ike.exception import IsakmpNotify


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
        bulk_ciphers = list(algorithms.encryption_algorithm.value.bulk_ciphers)
        for bulk_cipher_entry in bulk_ciphers:
            if bulk_cipher_entry.cipher.value.key_size == algorithms.key_length:
                break
        else:
            if len(bulk_ciphers) == 1 and algorithms.key_length is None:
                bulk_cipher_entry = bulk_ciphers[0]
            else:
                raise ValueError(
                    f'Key length {algorithms.key_length} not found for '
                    f'encryption algorithm {algorithms.encryption_algorithm}'
                )

        return cls(
            encryption_algorithm=bulk_cipher_entry.cipher,
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
        bulk_ciphers = list(encryption_transform_id.value.bulk_ciphers)
        for bulk_cipher_entry in bulk_ciphers:
            if bulk_cipher_entry.cipher.value.key_size == key_length:
                break
        else:
            if len(bulk_ciphers) == 1 and key_length is None:
                bulk_cipher_entry = bulk_ciphers[0]
            else:
                raise ValueError(
                    f'Key length {key_length} not found for '
                    f'encryption algorithm {encryption_transform_id}'
                )

        integrity_algorithm = integrity_transform_id.value.hmac
        return cls(
            encryption_algorithm=bulk_cipher_entry.cipher,
            block_cipher_mode=encryption_transform_id.value.block_cipher_mode,
            pseudorandom_function=pseudorandom_transform_id.value.mac,
            diffie_hellman_group=diffie_hellman_transform_id.value.key_parameter,
            integrity_algorithm=integrity_algorithm,
        )


class AnalyzerIKECommonBase(AnalyzerIKEBase):
    @classmethod
    @abc.abstractmethod
    def get_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_dh_group_name(cls):
        raise NotImplementedError()

    @classmethod
    def _get_ikev1_algorithms_for_dh_groups(cls, dh_groups: Ikev1DiffieHellmanGroup):
        algorithms = []
        for dh_group in dh_groups:
            for encryption_algorithm in Ikev1EncryptionAlgorithm:
                key_lengths = Ikev1SecurityAssociationBase.get_key_lengths(encryption_algorithm)
                for key_length in key_lengths:
                    for hash_algorithm in Ikev1HashAlgorithm:
                        for authentication_method in Ikev1AuthenticationMethod:
                            algorithms.append(Ikev1SecurityAssociationProposalAlgorithms(
                                encryption_algorithm=encryption_algorithm,
                                diffie_hellman_group=dh_group,
                                hash_algorithm=hash_algorithm,
                                authentication_method=authentication_method,
                                key_length=key_length,
                            ))
        return algorithms

    def _send_ikev1_init_message(self, l7_client, dh_group, init_message):
        """Send one Main Mode message 1 probe and report whether the server accepted it.

        Returns ``True`` when the server accepted the offered Diffie-Hellman group:
          - ``INVALID_KEY_INFORMATION`` notify (multi-Proposal probing —
            responder picked a Diffie-Hellman group different from initiator's
            Key Exchange payload);
          - clean Phase-1 completion through Main Mode message 4 with no
            notify (the only path libreswan takes, and the path strict-RFC-2409
            single-Proposal probing always takes).

        Returns ``False`` for ``NO_PROPOSAL_CHOSEN`` and ``NO_RESPONSE``.
        Any other notify or network error propagates up.
        """
        self._before_probe(l7_client)
        try:
            l7_client.do_ikev1_handshake(
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION
            )
        except IsakmpNotify as e:
            if e.notify == Ikev1NotifyType.NO_PROPOSAL_CHOSEN:
                LogSingleton().log(
                    level=40,
                    msg=f'No proposal chosen; group_type={self._get_dh_group_name()}, group={dh_group.name}'
                )
                return False
            if e.notify == Ikev1NotifyType.INVALID_KEY_INFORMATION:
                return True

            LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
            raise
        except NetworkError as e:
            if e.error == NetworkErrorType.NO_RESPONSE:
                addr = f'{l7_client.address}:{l7_client.port}'
                LogSingleton().log(level=60, msg=f'No response from server; address={addr}')
                return False
            raise

        return True

    def _send_ikev2_init_message(self, l7_client, init_message):
        self._before_probe(l7_client)

        try:
            server_messages = l7_client.do_ikev2_handshake(
                init_message=init_message,
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT
            )
        except IsakmpNotify as e:
            if e.notify == Ikev2NotifyType.NO_PROPOSAL_CHOSEN:
                group_name = self._get_dh_group_name()
                LogSingleton().log(
                    level=40,
                    msg=f'No proposal chosen; group_type={group_name}'
                )
                return None

            LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
            raise
        except NetworkError as e:
            if e.error == NetworkErrorType.NO_RESPONSE:
                addr = f'{l7_client.address}:{l7_client.port}'
                LogSingleton().log(level=60, msg=f'No response from server; address={addr}')
                return None
            raise

        return server_messages
