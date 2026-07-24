# SPDX-License-Identifier: MPL-2.0

import abc
import typing

import attr

from cryptodatahub.common.algorithm import BlockCipher, BlockCipherMode, Hash
from cryptodatahub.common.pqc import KeyParameter, validate_key_parameter
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

from cryptolyzer.common.analyzer import AnalyzerBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.ike.client import (
    Ikev1SecurityAssociationBase,
    Ikev1SecurityAssociationProposalAlgorithms,
    L7ClientIPsecBase,
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
    diffie_hellman_group: KeyParameter = attr.ib(
        validator=validate_key_parameter()
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
    diffie_hellman_group: KeyParameter = attr.ib(
        validator=validate_key_parameter()
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


@attr.s(frozen=True)
class IkeProbeResult:
    """
    :class: Data class for IKE_SA_INIT probe result. Which fields are set classifies the responder's reaction:

        * ``server_messages`` only — the responder answered the offer cleanly.
        * ``notify`` only — the responder rejected the offer with an acceptable notify.
        * both — the responder selected a transform and then sent a notify.
        * neither — the responder did not respond.

    :param server_messages: Per-exchange-type mapping the handshake returned, left unvalidated so that a test can pass
        a mock. ``None`` when the responder sent no message.
    :param notify: Notify the responder replied with. ``None`` when it answered with a selected transform only.
    """

    server_messages: typing.Optional[
        dict[typing.Union[Ikev1ExchangeType, Ikev2ExchangeType], typing.Any]
    ] = attr.ib()
    notify: typing.Optional[typing.Union[Ikev1NotifyType, Ikev2NotifyType]] = attr.ib(default=None)


class AnalyzerIKEBase(AnalyzerBase):
    _MAX_PROPOSALS_PER_INIT_MESSAGE = 128

    @classmethod
    def set_strict_rfc_2409_compliance(cls, enabled):
        cls._MAX_PROPOSALS_PER_INIT_MESSAGE = 1 if enabled else 128

    @classmethod
    @abc.abstractmethod
    def get_name(cls):
        raise NotImplementedError()

    @classmethod
    def get_clients(cls):
        return [
            L7ClientIPsecBase
        ]

    @classmethod
    def get_default_scheme(cls):
        return 'ipsec'

    def analyze(self, analyzable, protocol_version):  # pylint: disable=arguments-differ,unused-argument
        self._reset_probe_throttle()

    def _probe_ike_sa_init(
        self,
        analyzable,
        handshake_callable: typing.Callable,
        acceptable_notify_types: typing.Container[typing.Union[Ikev1NotifyType, Ikev2NotifyType]] = (),
    ) -> IkeProbeResult:
        """
        Send one IKE_SA_INIT through handshake_callable and classify the responder's reaction.

        Returns an IkeProbeResult: server_messages set when the responder answered the offer,
        notify set when it rejected the offer with an acceptable notify, both None on NO_RESPONSE.
        Both are set when the responder selected a transform and then sent an acceptable notify
        (e.g. IKEv1 INVALID_KEY_INFORMATION after the forged key exchange): the selected transform
        rides in server_messages, the reason in notify. An unacceptable notify or any other network
        error is re-raised.
        """
        self._before_probe(analyzable)
        try:
            server_messages = handshake_callable()
        except IsakmpNotify as e:
            if e.notify not in acceptable_notify_types:
                raise
            LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
            # normalise a falsy (empty-dict) server_messages to None so callers can treat
            # "no selected transform" uniformly and never index into an empty dict
            server_messages = getattr(e, 'server_messages', None) or None
            return IkeProbeResult(server_messages=server_messages, notify=e.notify)
        except NetworkError as e:
            if e.error == NetworkErrorType.NO_RESPONSE:
                addr = f'{analyzable.address}:{analyzable.port}'
                LogSingleton().log(level=60, msg=f'No response from server; address={addr}')
                return IkeProbeResult(server_messages=None, notify=None)
            raise
        return IkeProbeResult(server_messages=server_messages, notify=None)


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
                key_lengths = Ikev1SecurityAssociationBase.get_encryption_algorithm_key_lengths(encryption_algorithm)
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
