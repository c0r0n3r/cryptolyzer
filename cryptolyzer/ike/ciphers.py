# -*- coding: utf-8 -*-

import collections
import typing

import attr

from cryptodatahub.common.algorithm import (
    BlockCipher,
    BlockCipherMode,
    Hash,
    MAC,
    NamedGroup,
    NamedGroupType,
)
from cryptodatahub.common.parameter import DHParamWellKnown
from cryptodatahub.ike.algorithm import (
    Ikev1AttributeType,
    Ikev1EncryptionAlgorithm,
    Ikev1ExchangeType,
    Ikev1NotifyType,
    Ikev1DiffieHellmanGroup,
    Ikev1HashAlgorithm,
    Ikev1AuthenticationMethod,
    Ikev1PayloadType,
    Ikev2EncryptionAlgorithm,
    Ikev2PseudorandomFunction,
    Ikev2IntegrityAlgorithm,
    Ikev2DiffieHellmanGroup,
    Ikev2ExchangeType,
    Ikev2NotifyType,
    Ikev2PayloadType,
    Ikev2TransformType,
)

from cryptodatahub.ike.version import IkeVersion
from cryptoparser.ike.isakmp import IsakmpMessage
from cryptoparser.ike.ikev1 import Ikev1PayloadSecurityAssociation, Ikev1PayloadTransform
from cryptoparser.ike.ikev2 import Ikev2PayloadSecurityAssociation, Ikev2NotifyPayloadInvalidKe

from cryptolyzer.common.analyzer import AnalyzerIKEBase
from cryptolyzer.common.result import AnalyzerResultIKE
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.common.exception import NetworkError, NetworkErrorType

from cryptolyzer.ike.client import (
    Ikev1SecurityAssociationProposalAlgorithms,
    Ikev1SecurityAssociationAlgorithms,
    Ikev2SecurityAssociationBase,
    Ikev2SecurityAssociationSpecialization,
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
        if len(bulk_ciphers) == 1:
            encryption_algorithm = bulk_ciphers[0]
        else:
            for encryption_algorithm in bulk_ciphers:
                if encryption_algorithm.cipher.value.key_size == algorithms.key_length:
                    break
            else:
                raise ValueError(
                    f'Key length {algorithms.key_length} not found for '
                    f'encryption algorithm {algorithms.encryption_algorithm}'
                )

        return cls(
            encryption_algorithm=encryption_algorithm.cipher,
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
        key_length: typing.Optional[int],
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        # RFC 7296 §3.3.5: fixed-key IKE encryption entries (single
        # bulk_ciphers element — e.g. ENCR_3DES, ENCR_IDEA,
        # ENCR_CHACHA20_POLY1305) MUST NOT carry a Key Length attribute,
        # so key_length is None on the wire. Take the single bulk cipher
        # directly. Variable-key entries (multiple bulk_ciphers — AES,
        # Camellia, Blowfish, …) match the wire key_length to the
        # corresponding per-keysize cipher.
        bulk_ciphers = encryption_transform_id.value.bulk_ciphers
        if len(bulk_ciphers) == 1:
            encryption_algorithm = bulk_ciphers[0].cipher
        else:
            for bulk_cipher in bulk_ciphers:
                if bulk_cipher.cipher.value.key_size == key_length:
                    encryption_algorithm = bulk_cipher.cipher
                    break
            else:
                raise ValueError(
                    f'Key length {key_length} not found for '
                    f'encryption algorithm {encryption_transform_id}'
                )

        return cls(
            encryption_algorithm=encryption_algorithm,
            block_cipher_mode=encryption_transform_id.value.block_cipher_mode,
            pseudorandom_function=pseudorandom_transform_id.value.mac,
            diffie_hellman_group=diffie_hellman_transform_id.value.key_parameter,
            integrity_algorithm=(
                integrity_transform_id.value.hmac if integrity_transform_id.value.hmac is not None else None
            ),
        )


@attr.s(frozen=True)
class IkeEncryptionAlgorithmEntry:
    """A single accepted entry on the encryption transform axis: a (bulk cipher, mode) pair."""

    encryption_algorithm: BlockCipher = attr.ib(
        validator=attr.validators.instance_of(BlockCipher)
    )
    block_cipher_mode: typing.Optional[BlockCipherMode] = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(BlockCipherMode))
    )


@attr.s
class AnalyzerResultIkev1Ciphers(AnalyzerResultIKE):
    """Per-axis IKEv1 transform support reported by the responder."""

    encryption_algorithms: typing.List[IkeEncryptionAlgorithmEntry] = attr.ib(
        validator=attr.validators.deep_iterable(
            attr.validators.instance_of(IkeEncryptionAlgorithmEntry)
        )
    )
    hash_algorithms: typing.List[Hash] = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(Hash))
    )
    diffie_hellman_groups: typing.List[typing.Union[NamedGroup, DHParamWellKnown]] = attr.ib(
        validator=attr.validators.deep_iterable(
            attr.validators.instance_of((NamedGroup, DHParamWellKnown))
        )
    )


@attr.s
class AnalyzerResultIkev2Ciphers(AnalyzerResultIKE):
    """Per-axis IKEv2 transform support reported by the responder."""

    encryption_algorithms: typing.List[IkeEncryptionAlgorithmEntry] = attr.ib(
        validator=attr.validators.deep_iterable(
            attr.validators.instance_of(IkeEncryptionAlgorithmEntry)
        )
    )
    pseudorandom_functions: typing.List[MAC] = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(MAC))
    )
    integrity_algorithms: typing.List[MAC] = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(MAC))
    )
    diffie_hellman_groups: typing.List[typing.Union[NamedGroup, DHParamWellKnown]] = attr.ib(
        validator=attr.validators.deep_iterable(
            attr.validators.instance_of((NamedGroup, DHParamWellKnown))
        )
    )


class AnalyzerCiphers(AnalyzerIKEBase):
    """Enumerate cipher suites supported by an IKE responder.

    Core enumeration concept (applies to both IKEv1 and IKEv2):

    Each probe offers only the *unconfirmed* candidates for the axis under
    test; algorithms already confirmed by the server are removed before the
    next probe.  This means a NO_PROPOSAL_CHOSEN response unambiguously
    signals exhaustion: the server rejected a set that contained only new
    candidates, so no more are supported.  One confirmed value per axis is
    retained as an anchor to keep offers valid — a completely empty proposal
    would be rejected with NO_PROPOSAL_CHOSEN even before the server checks
    whether it supports anything, masking the exhaustion signal with a
    structural error.
    """

    @classmethod
    def get_name(cls):
        return 'ciphers'

    @classmethod
    def get_help(cls):
        return 'Check which transforms supported by the server(s)'

    @staticmethod
    def _get_algorithm_from_server_messages_ikev1(
        server_messages: typing.Dict,
    ) -> Ikev1SecurityAssociationProposalAlgorithms:
        response_message = server_messages[Ikev1ExchangeType.IDENTITY_PROTECTION][0]
        sa_payload: Ikev1PayloadSecurityAssociation = response_message.get_payload_by_type(
            Ikev1PayloadType.SECURITY_ASSOCIATION
        )
        transform: Ikev1PayloadTransform = sa_payload.proposals[0].transforms[0]

        encryption_algorithm = transform.get_attribute_by_type(
            Ikev1AttributeType.ENCRYPTION_ALGORITHM
        ).value
        bulk_ciphers = encryption_algorithm.value.bulk_ciphers
        if len(bulk_ciphers) == 1:
            key_length = None
        else:
            key_length = transform.get_attribute_by_type(Ikev1AttributeType.KEY_LENGTH).value
        return Ikev1SecurityAssociationProposalAlgorithms(
            encryption_algorithm=encryption_algorithm,
            diffie_hellman_group=transform.get_attribute_by_type(Ikev1AttributeType.GROUP_DESCRIPTION).value,
            hash_algorithm=transform.get_attribute_by_type(Ikev1AttributeType.HASH_ALGORITHM).value,
            authentication_method=transform.get_attribute_by_type(Ikev1AttributeType.AUTHENTICATION_METHOD).value,
            key_length=key_length,
        )

    @classmethod
    def _send_ikev1_init_message(cls, l7_client, init_message, algorithms):
        try:
            server_messages = l7_client.do_ikev1_handshake(
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION
            )
        except IsakmpNotify as e:
            if e.notify == Ikev1NotifyType.NO_PROPOSAL_CHOSEN:
                LogSingleton().log(level=40, msg='No proposal chosen')
                raise StopIteration(None) from e

            if e.notify == Ikev1NotifyType.INVALID_KEY_INFORMATION:
                if Ikev1ExchangeType.IDENTITY_PROTECTION in e.server_messages:
                    raise StopIteration(
                        cls._get_algorithm_from_server_messages_ikev1(e.server_messages)
                    ) from e
                raise

            LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
            for algorithm in algorithms:
                cls._log_cipher_suite_offered_ikev1(
                    Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(algorithm)
                )
            raise
        except NetworkError as e:
            if e.error == NetworkErrorType.NO_RESPONSE:
                LogSingleton().log(level=60, msg=f'No response from server; address={l7_client}')
                raise StopIteration(None) from e
            raise

        raise StopIteration(
            cls._get_algorithm_from_server_messages_ikev1(server_messages)
        )

    @classmethod
    def _get_ikev1_algorithms_for_dh_group_and_auth(
        cls,
        dh_group: Ikev1DiffieHellmanGroup,
        authentication_method: Ikev1AuthenticationMethod,
    ) -> typing.List[Ikev1SecurityAssociationProposalAlgorithms]:
        algorithms = []
        for encryption_algorithm in Ikev1EncryptionAlgorithm:
            bulk_ciphers = list(encryption_algorithm.value.bulk_ciphers)
            if len(bulk_ciphers) == 1:
                key_lengths = [None]
            else:
                key_lengths = [
                    bulk_cipher.cipher.value.key_size
                    for bulk_cipher in bulk_ciphers
                ]
            for key_length in key_lengths:
                for hash_algorithm in Ikev1HashAlgorithm:
                    algorithms.append(Ikev1SecurityAssociationProposalAlgorithms(
                        encryption_algorithm=encryption_algorithm,
                        diffie_hellman_group=dh_group,
                        hash_algorithm=hash_algorithm,
                        authentication_method=authentication_method,
                        key_length=key_length,
                    ))
        return algorithms

    def _probe_ikev1_auth_method(
        self,
        l7_client,
        dh_group: Ikev1DiffieHellmanGroup,
        authentication_method: Ikev1AuthenticationMethod,
        working_auth_method: typing.Optional[Ikev1AuthenticationMethod],
    ) -> typing.Tuple[
        bool,
        typing.List[Ikev1SecurityAssociationProposalAlgorithms],
        typing.Optional[Ikev1AuthenticationMethod],
    ]:
        """Probe all (ENCR, HASH) combinations for one (DH group, auth method) pair.

        Returns (auth_method_supported, found_algorithms, working_auth_method).
        auth_method_supported is False when INVALID_KEY_INFORMATION was received
        indicating the server rejected the authentication method before cipher
        comparison. working_auth_method is updated on the first confirmed suite.
        """
        checkable_algorithms = self._get_ikev1_algorithms_for_dh_group_and_auth(
            dh_group, authentication_method
        )
        checkable_algorithms_subsets = [
            checkable_algorithms[i:i + self._MAX_PROPOSALS_PER_INIT_MESSAGE].copy()
            for i in range(0, len(checkable_algorithms), self._MAX_PROPOSALS_PER_INIT_MESSAGE)
        ]
        found_algorithms = []
        for index, checkable_algorithms_subset in enumerate(checkable_algorithms_subsets):
            while checkable_algorithms_subset:
                self._before_probe(l7_client)
                try:
                    self._send_ikev1_init_message(
                        l7_client=l7_client,
                        init_message=Ikev1SecurityAssociationAlgorithms(
                            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
                            algorithms=checkable_algorithms_subset
                        ),
                        algorithms=checkable_algorithms_subset
                    )
                except IsakmpNotify as e:
                    if e.notify == Ikev1NotifyType.INVALID_KEY_INFORMATION:
                        return False, found_algorithms, working_auth_method
                    raise
                except StopIteration as e:
                    if e.value is None:
                        break
                    algorithm = e.value
                    if working_auth_method is None:
                        working_auth_method = authentication_method
                    self._log_cipher_suite_offered_ikev1(
                        Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(algorithm)
                    )
                    found_algorithms.append(algorithm)
                    for algorithm_subset in checkable_algorithms_subsets[index:]:
                        while True:
                            try:
                                algorithm_subset.remove(algorithm)
                            except ValueError:
                                break
        return True, found_algorithms, working_auth_method

    def _analyze_ikev1(self, l7_client) -> typing.List[Ikev1CipherSuite]:
        """Enumerate IKEv1 transform support by sweeping DH groups and auth methods.

        IKEv1 Phase 1 (Main Mode, RFC 2409 §5.1) bundles encryption algorithm,
        hash algorithm, authentication method, and Diffie-Hellman group into a
        single transform, so DH group cannot be swept independently. The outer
        loop iterates every DH group; for each DH group the inner loop sweeps
        authentication methods and probes all (ENCR, HASH) combinations with
        that fixed (DH group, auth method) pair.

        Authentication-method lock-in: RFC 2409 §5 shows that in Main Mode all
        authentication methods allow full cipher negotiation — ENCR and HASH are
        unconstrained regardless of which auth method is used. Once a server
        confirms any cipher suite for a given DH group with any authentication
        method, the same (ENCR, HASH) space applies to every other supported
        auth method. The first authentication method that is reached by the
        server (i.e. does not return INVALID_KEY_INFORMATION) is therefore
        locked in and reused for all subsequent DH group sweeps, avoiding
        redundant probing.

        INVALID_KEY_INFORMATION without an SA response signals that the
        authentication method itself was rejected before SA negotiation reached
        the cipher comparison stage. This is implementation-defined behaviour
        (strongswan-observed; RFC 2408 §5.7 formally defines this notify for
        invalid KE payload data). NO_PROPOSAL_CHOSEN means the server processed
        the SA offer but accepted none of the (ENCR, HASH) proposals for the
        current (DH group, auth method) pair.
        """
        supported_algorithms = []
        working_auth_method = None
        for dh_group in Ikev1DiffieHellmanGroup:
            auth_methods_to_try = (
                [working_auth_method] if working_auth_method is not None
                else list(Ikev1AuthenticationMethod)
            )
            for authentication_method in auth_methods_to_try:
                auth_method_supported, found_algorithms, working_auth_method = (
                    self._probe_ikev1_auth_method(
                        l7_client, dh_group, authentication_method, working_auth_method
                    )
                )
                supported_algorithms.extend(found_algorithms)
                if auth_method_supported:
                    break

        return list(map(
            Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms,
            supported_algorithms
        ))

    @staticmethod
    def _send_ikev2_init_message(
        l7_client,
        init_message,
    ) -> typing.Optional[typing.Dict[Ikev2ExchangeType, IsakmpMessage]]:
        try:
            server_messages = l7_client.do_ikev2_handshake(
                init_message=init_message,
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT
            )
        except IsakmpNotify as e:
            if e.notify == Ikev2NotifyType.NO_PROPOSAL_CHOSEN:
                LogSingleton().log(level=40, msg='No proposal chosen')
                return None

            LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
            raise
        except NetworkError as e:
            if e.error == NetworkErrorType.NO_RESPONSE:
                LogSingleton().log(level=60, msg=f'No response from server; address={l7_client}')
                return None

            raise

        return server_messages

    @staticmethod
    def _get_cipher_suite_from_server_messages_ikev2(server_messages) -> Ikev2CipherSuite:
        ike_sa_init_message = server_messages[Ikev2ExchangeType.IKE_SA_INIT]
        sa_payload: Ikev2PayloadSecurityAssociation = ike_sa_init_message.get_payload_by_type(Ikev2PayloadType.SA)
        dh_group = sa_payload.get_transform_by_type(Ikev2TransformType.DH).transform_id
        encryption_algorithm = sa_payload.get_transform_by_type(Ikev2TransformType.ENCR).transform_id
        pseudorandom_function = sa_payload.get_transform_by_type(Ikev2TransformType.PRF).transform_id
        try:
            integrity_algorithm = sa_payload.get_transform_by_type(Ikev2TransformType.INTEG).transform_id
        except KeyError:
            integrity_algorithm = Ikev2IntegrityAlgorithm.NONE
        key_length = sa_payload.get_transform_by_type(Ikev2TransformType.ENCR).key_length

        return Ikev2CipherSuite.from_transform_ids(
            encryption_transform_id=encryption_algorithm,
            integrity_transform_id=integrity_algorithm,
            pseudorandom_transform_id=pseudorandom_function,
            diffie_hellman_transform_id=dh_group,
            key_length=key_length,
        )

    @staticmethod
    def _handle_invalid_ke_payload_ikev2(
        notify_payload: Ikev2NotifyPayloadInvalidKe,
        diffie_hellman_groups: typing.List[Ikev2DiffieHellmanGroup],
        accepted_dh_groups: typing.Set[Ikev2DiffieHellmanGroup],
    ) -> typing.Optional[Ikev2DiffieHellmanGroup]:
        """Apply RFC 7296 §1.2 INVALID_KE_PAYLOAD retry rule.

        The responder-selected Diffie-Hellman group is known to be supported
        — record it. Return the suggested DH so the caller keys the next
        probe's KE payload for it; the full SA proposal (including the DH
        list) is preserved (RFC downgrade-prevention requirement). Returns
        None when the suggested group is not in the current DH list,
        signalling no further progress is possible.
        """
        suggested_dh = notify_payload.dh_group
        if suggested_dh not in diffie_hellman_groups:
            return None
        accepted_dh_groups.add(suggested_dh)
        return suggested_dh

    @staticmethod
    def _get_response_key_ikev2(transform_type, sa_payload):
        # ENCR entries enumerated per (transform_id, key_length) wire tuple
        # (RFC 7296 §3.3.5 — same transform_id may appear with different Key
        # Length attributes). All other transform types are single-valued.
        transform = sa_payload.get_transform_by_type(transform_type)
        if transform_type == Ikev2TransformType.ENCR:
            return (transform.transform_id, transform.key_length)
        return transform.transform_id

    def _probe_ikev2_phase(self, l7_client, algorithms, transform_type, key_exchange_dh):
        """Sweep one transform axis until exhaustion or no server-confirmed anchor.

        Returns (cipher_suites, anchor, last_sa_payload, key_exchange_dh,
        accepted_dh_groups) where anchor is the last server-confirmed key for
        transform_type, or None when no SA response was received for this axis.
        accepted_dh_groups contains DH groups confirmed via INVALID_KE_PAYLOAD.
        """
        cipher_suites = []
        anchor = None
        last_sa_payload = None
        accepted_dh_groups = set()
        while True:
            self._before_probe(l7_client)
            try:
                server_messages = self._send_ikev2_init_message(
                    l7_client,
                    Ikev2SecurityAssociationSpecialization(
                        encryption_algorithm_tuples=algorithms[Ikev2TransformType.ENCR],
                        diffie_hellman_groups=algorithms[Ikev2TransformType.DH],
                        pseudorandom_functions=algorithms[Ikev2TransformType.PRF],
                        integrity_algorithms=algorithms[Ikev2TransformType.INTEG],
                        key_exchange_dh_group=key_exchange_dh,
                    ),
                )
            except IsakmpNotify as e:
                if e.notify == Ikev2NotifyType.INVALID_KE_PAYLOAD:
                    suggested_dh = self._handle_invalid_ke_payload_ikev2(
                        typing.cast(Ikev2NotifyPayloadInvalidKe, e.payload),
                        algorithms[Ikev2TransformType.DH],
                        accepted_dh_groups,
                    )
                    if suggested_dh is None:
                        break
                    key_exchange_dh = suggested_dh
                    continue
                LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
                raise

            if server_messages is None:
                break  # NO_PROPOSAL_CHOSEN — this axis is exhausted

            cipher_suite = self._get_cipher_suite_from_server_messages_ikev2(server_messages)
            self._log_cipher_suite_offered_ikev2(cipher_suite)

            last_sa_payload = server_messages[Ikev2ExchangeType.IKE_SA_INIT].get_payload_by_type(
                Ikev2PayloadType.SA
            )
            cipher_suites.append(cipher_suite)
            try:
                response_key = self._get_response_key_ikev2(transform_type, last_sa_payload)
            except KeyError:
                # No transform of this type in the response (AEAD response on
                # the INTEG axis); this branch's axis enumeration is complete.
                break
            anchor = response_key
            if response_key in algorithms[transform_type]:
                algorithms[transform_type].remove(response_key)
            if not algorithms[transform_type]:
                break

        return cipher_suites, anchor, last_sa_payload, key_exchange_dh, accepted_dh_groups

    def _analyze_ikev2(self, l7_client):
        """Enumerate IKEv2 transform support as two independent branches.

        Non-AEAD and AEAD encryption form structurally distinct proposal
        families (RFC 5282 §8 / RFC 7296 §3.3): non-AEAD carries an INTEG
        transform, AEAD does not. Enumerate each family in its own phased
        sweep, narrowing every visited axis to a single server-confirmed
        anchor before moving to the next axis. The accepted_dh_groups set
        captures DHs surfaced only via INVALID_KE notifications when no
        complete cipher suite was captured for them.
        """
        all_encr_tuples = Ikev2SecurityAssociationBase.expand_encryption_algorithms_to_tuples(
            Ikev2EncryptionAlgorithm
        )
        non_aead_encr_tuples = [t for t in all_encr_tuples if not t[0].value.aead]
        aead_encr_tuples = [t for t in all_encr_tuples if t[0].value.aead]
        non_aead_integ = [
            integ for integ in Ikev2IntegrityAlgorithm if integ != Ikev2IntegrityAlgorithm.NONE
        ]

        cipher_suites: typing.List[Ikev2CipherSuite] = []
        accepted_dh_groups: typing.Set[Ikev2DiffieHellmanGroup] = set()

        # RFC 9370 hybrid post-quantum KEMs (ML-KEM) negotiate via
        # IKE_INTERMEDIATE after IKE_SA_INIT, not as classical DH transforms
        # in the initial exchange. Skip them here — the SA_INIT KE payload
        # has no defined encoding for HYBRID_PQS public keys.
        classical_dh_groups = [
            dh for dh in Ikev2DiffieHellmanGroup
            if not (isinstance(dh.value.key_parameter, NamedGroup)
                    and dh.value.key_parameter.value.group_type == NamedGroupType.HYBRID_PQS)
        ]

        if non_aead_encr_tuples:
            cipher_suites.extend(self._enumerate_branch_ikev2(
                l7_client,
                collections.OrderedDict([
                    (Ikev2TransformType.ENCR, non_aead_encr_tuples),
                    (Ikev2TransformType.DH, list(classical_dh_groups)),
                    (Ikev2TransformType.PRF, list(Ikev2PseudorandomFunction)),
                    (Ikev2TransformType.INTEG, non_aead_integ),
                ]),
                accepted_dh_groups,
            ))

        if aead_encr_tuples:
            cipher_suites.extend(self._enumerate_branch_ikev2(
                l7_client,
                collections.OrderedDict([
                    (Ikev2TransformType.ENCR, aead_encr_tuples),
                    (Ikev2TransformType.DH, list(classical_dh_groups)),
                    (Ikev2TransformType.PRF, list(Ikev2PseudorandomFunction)),
                    # AEAD proposal carries no integrity transforms.
                    (Ikev2TransformType.INTEG, []),
                ]),
                accepted_dh_groups,
            ))

        return cipher_suites, accepted_dh_groups

    @staticmethod
    def _log_cipher_suite_offered_ikev1(cipher_suite):
        mode = cipher_suite.block_cipher_mode.name if cipher_suite.block_cipher_mode is not None else 'NONE'
        LogSingleton().log(
            level=60,
            msg=(
                'Server offers cipher suite; '
                f'encr={str(cipher_suite.encryption_algorithm.value)}, '
                f'mode={mode}, '
                f'hash={str(cipher_suite.hash_algorithm.value)}, '
                f'dh={str(cipher_suite.diffie_hellman_group.value)}'
            )
        )

    @staticmethod
    def _log_cipher_suite_offered_ikev2(cipher_suite):
        mode = cipher_suite.block_cipher_mode.name if cipher_suite.block_cipher_mode is not None else 'NONE'
        integ = (
            str(cipher_suite.integrity_algorithm.value)
            if cipher_suite.integrity_algorithm
            else 'NONE'
        )
        LogSingleton().log(
            level=60,
            msg=(
                'Server offers cipher suite; '
                f'encr={str(cipher_suite.encryption_algorithm.value)}, '
                f'mode={mode}, '
                f'integ={integ}, '
                f'prf={str(cipher_suite.pseudorandom_function.value)}, '
                f'dh={str(cipher_suite.diffie_hellman_group.value)}'
            )
        )

    def _enumerate_branch_ikev2(self, l7_client, algorithms, accepted_dh_groups):
        """Enumerate one proposal family (AEAD or non-AEAD) via phased sweeps.

        Phases run in order: ENCR → DH → PRF → INTEG.  Each phase sweeps one
        axis while all preceding axes are already anchored to a single
        server-confirmed value (see AnalyzerCiphers docstring for why this
        matters).

        Phase-transition pre-seeding: at the start of each phase the last
        successful SA payload is inspected for the new phase's axis.  If it
        contains a value that is still in the candidate list, that value is
        removed from candidates before the first probe — the server already
        revealed its preference and re-offering it would just confirm it again
        rather than discover anything new.  If removal empties the candidate
        list (nothing new remains to discover) the phase is skipped entirely
        and the anchor is set directly from the pre-seed value.
        """
        cipher_suites: typing.List[Ikev2CipherSuite] = []
        key_exchange_dh: typing.Optional[Ikev2DiffieHellmanGroup] = None
        last_sa_payload = None
        for transform_type in (
            Ikev2TransformType.ENCR,
            Ikev2TransformType.DH,
            Ikev2TransformType.PRF,
            Ikev2TransformType.INTEG,
        ):
            # Skip phases whose axis is empty (e.g. INTG axis of AEAD branch).
            if not algorithms[transform_type]:
                continue
            # Pre-seed the anchor from the last confirmed SA payload so the
            # first probe of this phase is not a repeat of the previous phase's
            # last — the server would select the same value again.
            anchor = None
            if last_sa_payload is not None:
                try:
                    preseed_key = self._get_response_key_ikev2(transform_type, last_sa_payload)
                    if preseed_key in algorithms[transform_type]:
                        anchor = preseed_key
                        algorithms[transform_type].remove(preseed_key)
                except KeyError:
                    pass
            if anchor is not None and not algorithms[transform_type]:
                algorithms[transform_type] = [anchor]
                continue
            phase_cipher_suites, phase_anchor, phase_last_sa_payload, key_exchange_dh, phase_accepted_dh_groups = (
                self._probe_ikev2_phase(
                    l7_client, algorithms, transform_type, key_exchange_dh
                )
            )
            cipher_suites.extend(phase_cipher_suites)
            accepted_dh_groups.update(phase_accepted_dh_groups)
            if phase_last_sa_payload is not None:
                last_sa_payload = phase_last_sa_payload
            if phase_anchor is not None:
                anchor = phase_anchor

            # Narrow this axis to its anchor for the remaining phases so any
            # later NO_PROPOSAL_CHOSEN unambiguously points at the new axis.
            if anchor is not None:
                algorithms[transform_type] = [anchor]
            else:
                # No server-confirmed value for this axis — proceeding would
                # only repeat unsupported probes, so stop the branch here.
                break

        return cipher_suites

    def analyze(self, analyzable, protocol_version: IkeVersion):
        """
        :type analyzable: AnalyzerTargetIKE
        :type protocol_version: IkeVersion
        """
        super().analyze(analyzable, protocol_version)
        if protocol_version == IkeVersion.V1:
            cipher_suites = self._analyze_ikev1(analyzable)
            return AnalyzerResultIkev1Ciphers(
                target=analyzable,
                encryption_algorithms=self._dedup_preserve_order(
                    IkeEncryptionAlgorithmEntry(
                        encryption_algorithm=cipher_suite.encryption_algorithm,
                        block_cipher_mode=cipher_suite.block_cipher_mode,
                    )
                    for cipher_suite in cipher_suites
                ),
                hash_algorithms=self._dedup_preserve_order(
                    cipher_suite.hash_algorithm for cipher_suite in cipher_suites
                ),
                diffie_hellman_groups=self._dedup_preserve_order(
                    cipher_suite.diffie_hellman_group for cipher_suite in cipher_suites
                ),
            )
        if protocol_version == IkeVersion.V2:
            cipher_suites, accepted_dh_transforms = self._analyze_ikev2(analyzable)
            # DH groups suggested via INVALID_KE are known supported even
            # though no complete cipher suite was captured for them; surface
            # them on the DH axis next to those collected from successful
            # responses.
            dh_groups_from_suites = [
                cipher_suite.diffie_hellman_group for cipher_suite in cipher_suites
            ]
            dh_groups_from_invalid_ke = [
                dh_transform.value.key_parameter for dh_transform in accepted_dh_transforms
            ]
            return AnalyzerResultIkev2Ciphers(
                target=analyzable,
                encryption_algorithms=self._dedup_preserve_order(
                    IkeEncryptionAlgorithmEntry(
                        encryption_algorithm=cipher_suite.encryption_algorithm,
                        block_cipher_mode=cipher_suite.block_cipher_mode,
                    )
                    for cipher_suite in cipher_suites
                ),
                pseudorandom_functions=self._dedup_preserve_order(
                    cipher_suite.pseudorandom_function for cipher_suite in cipher_suites
                ),
                integrity_algorithms=self._dedup_preserve_order(
                    cs.integrity_algorithm
                    for cs in cipher_suites
                    if cs.integrity_algorithm is not None
                ),
                diffie_hellman_groups=self._dedup_preserve_order(
                    dh_groups_from_suites + dh_groups_from_invalid_ke
                ),
            )

        raise NotImplementedError(protocol_version)

    @staticmethod
    def _dedup_preserve_order(items):
        # dict preserves insertion order in Python 3.7+
        return list(dict.fromkeys(items))
