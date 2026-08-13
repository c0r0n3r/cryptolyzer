
import argparse
import collections
import math
import typing

import attr

from cryptodatahub.common.entity import Entity
from cryptodatahub.common.exception import InvalidProposalToken

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
    Ikev2PseudorandomFunction,
    Ikev2TransformType,
)
from cryptodatahub.ike.version import IkeVersion

from cryptolyzer.ike.common import AnalyzerIKEBase
from cryptolyzer.common.result import AnalyzerResultIKE, AnalyzerTargetIke

from cryptolyzer.ike.ciphers import (
    IkeEncryptionAlgorithmEntry,
    Ikev1CipherSuite,
    Ikev1TransformAxes,
    Ikev2CipherSuite,
    Ikev2TransformAxes,
)
from cryptolyzer.ike.client import (
    Ikev1SecurityAssociationBase,
    Ikev1SecurityAssociationProposalAlgorithms,
    Ikev1SecurityAssociationSingleProposal,
    Ikev2SecurityAssociationSpecialization,
)


class AnalyzerSimulationsBase(AnalyzerIKEBase):
    _CUSTOM_CLIENT_NAME = 'custom'

    def __init__(self) -> None:
        super().__init__()
        self._encryption_algorithms: list[
            tuple[typing.Union[Ikev1EncryptionAlgorithm, Ikev2EncryptionAlgorithm], typing.Optional[int]]
        ] = []
        self._diffie_hellman_groups: list[
            typing.Union[Ikev1DiffieHellmanGroup, Ikev2DiffieHellmanGroup]
        ] = []

    @classmethod
    def get_name(cls) -> str:
        return 'simulations'

    @classmethod
    def get_help(cls) -> str:
        return 'Check whether a proposal set offered by a client is accepted by the server(s)'

    @staticmethod
    def _split_tokens(value: str) -> list[str]:
        return [token.strip() for token in value.split(',') if token.strip()]

    @classmethod
    def _get_deduplicated_axis_algorithms(
            cls,
            enum_class: typing.Any,
            entity: typing.Optional[Entity],
            axis_argument: str,
    ) -> list[typing.Any]:
        """Resolve the comma-separated tokens of one proposal axis, keeping the order they were given in and dropping
        repetitions: a repeated token would offer a redundant transform and count toward the per-proposal transform
        limit."""
        return list(dict.fromkeys(
            enum_class.from_proposal_token(entity, token)
            for token in cls._split_tokens(axis_argument)
        ))

    @staticmethod
    def _get_proposals_format_entity(proposals_format: str) -> typing.Optional[Entity]:
        return None if proposals_format == 'iana' else Entity[proposals_format.upper()]

    def _get_offered_encryption_algorithms(self) -> list[IkeEncryptionAlgorithmEntry]:
        entries = []
        for encryption_algorithm, key_length in self._encryption_algorithms:
            bulk_cipher = next(
                candidate for candidate in encryption_algorithm.value.bulk_ciphers
                if candidate.cipher.value.key_size == key_length
            )
            entry = IkeEncryptionAlgorithmEntry(
                encryption_algorithm=bulk_cipher.cipher,
                block_cipher_mode=encryption_algorithm.value.block_cipher_mode,
            )

            if entry not in entries:
                entries.append(entry)

        return entries


@attr.s
class Ikev1ProposalProbeResult:
    offered: Ikev1TransformAxes = attr.ib(
        validator=attr.validators.instance_of(Ikev1TransformAxes)
    )
    negotiated: typing.Optional[Ikev1CipherSuite] = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(Ikev1CipherSuite))
    )
    notify: typing.Optional[Ikev1NotifyType] = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.in_(Ikev1NotifyType))
    )


@attr.s
class AnalyzerResultIkev1Simulations(AnalyzerResultIKE):
    succeeded_clients: dict[str, Ikev1ProposalProbeResult] = attr.ib(
        validator=attr.validators.deep_mapping(
            key_validator=attr.validators.instance_of(str),
            value_validator=attr.validators.instance_of(Ikev1ProposalProbeResult),
        )
    )
    failed_clients: dict[str, Ikev1ProposalProbeResult] = attr.ib(
        validator=attr.validators.deep_mapping(
            key_validator=attr.validators.instance_of(str),
            value_validator=attr.validators.instance_of(Ikev1ProposalProbeResult),
        )
    )


class AnalyzerIkev1Simulations(AnalyzerSimulationsBase):
    # the IKEv1 Proposal payload's "# of Transforms" field is one octet (RFC 2408
    # §3.5), so at most 255 offered combinations fit in the single Proposal
    _MAX_TRANSFORMS_PER_PROPOSAL = 255
    _ACCEPTABLE_NOTIFY_TYPES = (
        Ikev1NotifyType.NO_PROPOSAL_CHOSEN,
        Ikev1NotifyType.INVALID_KEY_INFORMATION,
    )

    def __init__(self) -> None:
        super().__init__()
        self._hash_algorithms: list[Ikev1HashAlgorithm] = []
        self._authentication_methods: list[Ikev1AuthenticationMethod] = []

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '--encryption-algorithm', required=True, metavar='TOKENS',
            help='comma-separated encryption algorithm tokens (e.g. aes128,aes256)'
        )
        parser.add_argument(
            '--hash-algorithm', required=True, metavar='TOKENS',
            help='comma-separated hash algorithm tokens (e.g. sha256)'
        )
        parser.add_argument(
            '--authentication-method', required=True, metavar='TOKENS',
            help='comma-separated authentication method tokens (e.g. psk)'
        )
        parser.add_argument(
            '--diffie-hellman-group', required=True, metavar='TOKENS',
            help='comma-separated Diffie-Hellman group tokens (e.g. modp1536)'
        )
        parser.add_argument(
            '--proposals-format', choices=['strongswan', 'libreswan', 'openswan', 'iana'], default='strongswan',
            help='token dialect of the axis arguments (default: %(default)s)'
        )

    def parse_arguments(self, parser: argparse.ArgumentParser, arguments: argparse.Namespace) -> None:
        try:
            entity = self._get_proposals_format_entity(arguments.proposals_format)
            self._encryption_algorithms = self._get_deduplicated_axis_algorithms(
                Ikev1EncryptionAlgorithm, entity, arguments.encryption_algorithm
            )
            self._hash_algorithms = self._get_deduplicated_axis_algorithms(
                Ikev1HashAlgorithm, entity, arguments.hash_algorithm
            )
            self._authentication_methods = self._get_deduplicated_axis_algorithms(
                Ikev1AuthenticationMethod, entity, arguments.authentication_method
            )
            self._diffie_hellman_groups = self._get_deduplicated_axis_algorithms(
                Ikev1DiffieHellmanGroup, entity, arguments.diffie_hellman_group
            )
        except InvalidProposalToken as e:
            parser.error(str(e))

        axes = (
            self._encryption_algorithms,
            self._hash_algorithms,
            self._authentication_methods,
            self._diffie_hellman_groups,
        )

        if not all(axes):
            parser.error('each axis argument must resolve to at least one algorithm')

        transform_count = math.prod(len(axis) for axis in axes)
        if transform_count > self._MAX_TRANSFORMS_PER_PROPOSAL:
            parser.error(
                f'the offered proposal set expands to {transform_count} transforms, more than the '
                f'{self._MAX_TRANSFORMS_PER_PROPOSAL} that fit in one IKEv1 Proposal payload'
            )

    def _get_algorithms(self) -> list[Ikev1SecurityAssociationProposalAlgorithms]:
        return [
            Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=encryption_algorithm,
                diffie_hellman_group=diffie_hellman_group,
                hash_algorithm=hash_algorithm,
                authentication_method=authentication_method,
                key_length=Ikev1SecurityAssociationBase.get_wire_key_length(encryption_algorithm, key_length),
            )
            for encryption_algorithm, key_length in self._encryption_algorithms
            for hash_algorithm in self._hash_algorithms
            for authentication_method in self._authentication_methods
            for diffie_hellman_group in self._diffie_hellman_groups
        ]

    @staticmethod
    def _get_negotiated_cipher_suite(server_messages: dict) -> typing.Optional[Ikev1CipherSuite]:
        try:
            response_message = server_messages[Ikev1ExchangeType.IDENTITY_PROTECTION][0]
            sa_payload = response_message.get_payload_by_type(Ikev1PayloadType.SECURITY_ASSOCIATION)
            transform = sa_payload.proposals[0].transforms[0]
            encryption_algorithm = transform.get_attribute_by_type(Ikev1AttributeType.ENCRYPTION_ALGORITHM).value
            key_length = (
                None if len(encryption_algorithm.value.bulk_ciphers) == 1
                else transform.get_attribute_by_type(Ikev1AttributeType.KEY_LENGTH).value
            )
            algorithm = Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=encryption_algorithm,
                diffie_hellman_group=transform.get_attribute_by_type(Ikev1AttributeType.GROUP_DESCRIPTION).value,
                hash_algorithm=transform.get_attribute_by_type(Ikev1AttributeType.HASH_ALGORITHM).value,
                authentication_method=transform.get_attribute_by_type(Ikev1AttributeType.AUTHENTICATION_METHOD).value,
                key_length=key_length,
            )
        except (KeyError, IndexError):
            return None

        return Ikev1CipherSuite.from_ikev1_security_association_proposal_algorithms(algorithm)

    def analyze(self, analyzable, protocol_version: IkeVersion) -> AnalyzerResultIkev1Simulations:
        super().analyze(analyzable, protocol_version)

        algorithms = self._get_algorithms()
        probe_result = self._probe_ike_sa_init(
            analyzable,
            lambda: analyzable.do_ikev1_handshake(
                init_message=Ikev1SecurityAssociationSingleProposal(
                    exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
                    algorithms=algorithms,
                ),
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            ),
            self._ACCEPTABLE_NOTIFY_TYPES,
        )

        if probe_result.notify is not None:
            # NO_PROPOSAL_CHOSEN rejects outright. INVALID_KEY_INFORMATION means "proposal accepted, forged key exchange
            # rejected" ONLY when a Main # Mode SA was returned first (matching the ciphers analyzer); as a # first
            # reply with no SA it is an authentication-method rejection # (strongswan-observed), i.e. the offer was not
            # accepted
            notify = probe_result.notify
            accepted = (
                notify == Ikev1NotifyType.INVALID_KEY_INFORMATION and probe_result.server_messages is not None
            )
            negotiated = self._get_negotiated_cipher_suite(probe_result.server_messages) if accepted else None
        elif probe_result.server_messages is not None:
            accepted, negotiated, notify = True, self._get_negotiated_cipher_suite(probe_result.server_messages), None
        else:
            accepted, negotiated, notify = False, None, None

        probe_result = Ikev1ProposalProbeResult(
            offered=Ikev1TransformAxes(
                encryption_algorithms=self._get_offered_encryption_algorithms(),
                hash_algorithms=[
                    hash_algorithm.value.hash for hash_algorithm in self._hash_algorithms
                ],
                authentication_methods=list(self._authentication_methods),
                diffie_hellman_groups=[
                    diffie_hellman_group.value.key_parameter
                    for diffie_hellman_group in self._diffie_hellman_groups
                ],
            ),
            negotiated=negotiated,
            notify=notify,
        )

        succeeded_clients: dict[str, Ikev1ProposalProbeResult] = collections.OrderedDict()
        failed_clients: dict[str, Ikev1ProposalProbeResult] = collections.OrderedDict()
        if accepted:
            succeeded_clients[self._CUSTOM_CLIENT_NAME] = probe_result
        else:
            failed_clients[self._CUSTOM_CLIENT_NAME] = probe_result

        return AnalyzerResultIkev1Simulations(
            target=AnalyzerTargetIke.from_l7_client(analyzable),
            succeeded_clients=succeeded_clients,
            failed_clients=failed_clients,
        )


@attr.s
class Ikev2ProposalProbeResult:
    """Outcome of offering one user-supplied IKEv2 proposal set to a responder.

    :param offered: the per-axis algorithm set that was offered.
    :param negotiated: the transform combination the responder selected, when it answered with a full SA.
    :param notify: the notify the responder replied with, when it did not answer with a selected SA.
    """

    offered: Ikev2TransformAxes = attr.ib(
        validator=attr.validators.instance_of(Ikev2TransformAxes)
    )
    negotiated: typing.Optional[Ikev2CipherSuite] = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(Ikev2CipherSuite))
    )
    notify: typing.Optional[Ikev2NotifyType] = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.in_(Ikev2NotifyType))
    )


@attr.s
class AnalyzerResultIkev2Simulations(AnalyzerResultIKE):
    """
    :class: Analyzer result relates to the simulated IKEv2 proposal sets.

    :param succeeded_clients: the clients whose offered proposal set the responder accepted, keyed by client name.
    :param failed_clients: the clients whose offered proposal set the responder rejected, keyed by client name.
    """

    succeeded_clients: dict[str, Ikev2ProposalProbeResult] = attr.ib(
        validator=attr.validators.deep_mapping(
            key_validator=attr.validators.instance_of(str),
            value_validator=attr.validators.instance_of(Ikev2ProposalProbeResult),
        )
    )
    failed_clients: dict[str, Ikev2ProposalProbeResult] = attr.ib(
        validator=attr.validators.deep_mapping(
            key_validator=attr.validators.instance_of(str),
            value_validator=attr.validators.instance_of(Ikev2ProposalProbeResult),
        )
    )


class AnalyzerIkev2Simulations(AnalyzerSimulationsBase):
    _ACCEPTABLE_NOTIFY_TYPES = (
        Ikev2NotifyType.NO_PROPOSAL_CHOSEN,
        Ikev2NotifyType.INVALID_KE_PAYLOAD,
    )

    def __init__(self) -> None:
        super().__init__()
        self._pseudorandom_functions: list[Ikev2PseudorandomFunction] = []
        self._integrity_algorithms: list[Ikev2IntegrityAlgorithm] = []

    @classmethod
    def add_arguments(cls, parser: argparse.ArgumentParser) -> None:
        parser.add_argument(
            '--encryption-algorithm', required=True, metavar='TOKENS',
            help='comma-separated encryption algorithm tokens (e.g. aes128,aes256gcm16)'
        )
        parser.add_argument(
            '--pseudorandom-function', required=True, metavar='TOKENS',
            help='comma-separated pseudorandom function tokens (e.g. prfsha256)'
        )
        parser.add_argument(
            '--integrity-algorithm', default='', metavar='TOKENS',
            help='comma-separated integrity algorithm tokens (e.g. sha256); '
                 'required for non-AEAD encryption, forbidden for AEAD-only'
        )
        parser.add_argument(
            '--diffie-hellman-group', required=True, metavar='TOKENS',
            help='comma-separated Diffie-Hellman group tokens (e.g. modp2048)'
        )
        parser.add_argument(
            '--proposals-format', choices=['strongswan', 'libreswan', 'openswan', 'iana'], default='strongswan',
            help='token dialect of the axis arguments (default: %(default)s)'
        )

    def parse_arguments(self, parser: argparse.ArgumentParser, arguments: argparse.Namespace) -> None:
        # an explicit INTEG=NONE is the RFC 7296 §3.3 "no integrity" marker, not a real integrity algorithm, so it is
        # dropped here to agree with the AEAD/non-AEAD checks below and the proposal builder (which also filters NONE)
        try:
            entity = self._get_proposals_format_entity(arguments.proposals_format)
            self._encryption_algorithms = self._get_deduplicated_axis_algorithms(
                Ikev2EncryptionAlgorithm, entity, arguments.encryption_algorithm
            )
            self._pseudorandom_functions = self._get_deduplicated_axis_algorithms(
                Ikev2PseudorandomFunction, entity, arguments.pseudorandom_function
            )
            self._integrity_algorithms = [
                integrity_algorithm
                for integrity_algorithm in self._get_deduplicated_axis_algorithms(
                    Ikev2IntegrityAlgorithm, entity, arguments.integrity_algorithm
                )
                if integrity_algorithm != Ikev2IntegrityAlgorithm.NONE
            ]
            self._diffie_hellman_groups = self._get_deduplicated_axis_algorithms(
                Ikev2DiffieHellmanGroup, entity, arguments.diffie_hellman_group
            )
        except InvalidProposalToken as e:
            parser.error(str(e))

        if not all((self._encryption_algorithms, self._pseudorandom_functions, self._diffie_hellman_groups)):
            parser.error('each required axis argument must resolve to at least one algorithm')

        # RFC 7296 §3.3 + RFC 5282 §8: non-AEAD encryption needs an integrity algorithm; AEAD-only encryption must not
        # contain any one (a mixed AEAD + non-AEAD offer with integrity is valid -- it is split into two proposals)
        has_non_aead = any(
            not encryption_algorithm.value.aead for encryption_algorithm, _ in self._encryption_algorithms
        )
        if has_non_aead and not self._integrity_algorithms:
            parser.error('non-AEAD encryption requires at least one integrity algorithm')
        if not has_non_aead and self._integrity_algorithms:
            parser.error('AEAD-only encryption must not carry an integrity algorithm')

    @staticmethod
    def _get_negotiated_cipher_suite(server_messages: dict) -> typing.Optional[Ikev2CipherSuite]:
        try:
            sa_payload = server_messages[Ikev2ExchangeType.IKE_SA_INIT].get_payload_by_type(Ikev2PayloadType.SA)
            encryption_transform = sa_payload.get_transform_by_type(Ikev2TransformType.ENCR)
            pseudorandom_transform = sa_payload.get_transform_by_type(Ikev2TransformType.PRF)
            diffie_hellman_transform = sa_payload.get_transform_by_type(Ikev2TransformType.DH)
            try:
                integrity_transform_id = sa_payload.get_transform_by_type(Ikev2TransformType.INTEG).transform_id
            except KeyError:
                integrity_transform_id = Ikev2IntegrityAlgorithm.NONE
            return Ikev2CipherSuite.from_transform_ids(
                encryption_transform_id=encryption_transform.transform_id,
                integrity_transform_id=integrity_transform_id,
                pseudorandom_transform_id=pseudorandom_transform.transform_id,
                diffie_hellman_transform_id=diffie_hellman_transform.transform_id,
                key_length=encryption_transform.key_length,
            )
        except (KeyError, ValueError):
            return None

    def analyze(self, analyzable, protocol_version: IkeVersion) -> AnalyzerResultIkev2Simulations:
        super().analyze(analyzable, protocol_version)

        probe_result = self._probe_ike_sa_init(
            analyzable,
            lambda: analyzable.do_ikev2_handshake(
                init_message=Ikev2SecurityAssociationSpecialization(
                    encryption_algorithm_tuples=self._encryption_algorithms,
                    diffie_hellman_groups=self._diffie_hellman_groups,
                    pseudorandom_functions=self._pseudorandom_functions,
                    integrity_algorithms=self._integrity_algorithms,
                    key_exchange_dh_group=self._diffie_hellman_groups[0],
                ),
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            ),
            self._ACCEPTABLE_NOTIFY_TYPES,
        )

        if probe_result.notify is not None:
            notify = probe_result.notify
            accepted = notify != Ikev2NotifyType.NO_PROPOSAL_CHOSEN
            negotiated = None
        elif probe_result.server_messages is not None:
            accepted, negotiated, notify = True, self._get_negotiated_cipher_suite(probe_result.server_messages), None
        else:
            accepted, negotiated, notify = False, None, None

        probe_result = Ikev2ProposalProbeResult(
            offered=Ikev2TransformAxes(
                encryption_algorithms=self._get_offered_encryption_algorithms(),
                pseudorandom_functions=[
                    pseudorandom_function.value.mac for pseudorandom_function in self._pseudorandom_functions
                ],
                integrity_algorithms=[
                    integrity_algorithm.value.hmac for integrity_algorithm in self._integrity_algorithms
                ],
                diffie_hellman_groups=[
                    diffie_hellman_group.value.key_parameter
                    for diffie_hellman_group in self._diffie_hellman_groups
                ],
            ),
            negotiated=negotiated,
            notify=notify,
        )

        succeeded_clients: dict[str, Ikev2ProposalProbeResult] = collections.OrderedDict()
        failed_clients: dict[str, Ikev2ProposalProbeResult] = collections.OrderedDict()
        if accepted:
            succeeded_clients[self._CUSTOM_CLIENT_NAME] = probe_result
        else:
            failed_clients[self._CUSTOM_CLIENT_NAME] = probe_result

        return AnalyzerResultIkev2Simulations(
            target=AnalyzerTargetIke.from_l7_client(analyzable),
            succeeded_clients=succeeded_clients,
            failed_clients=failed_clients,
        )
