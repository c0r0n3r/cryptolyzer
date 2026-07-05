
import abc

from cryptodatahub.ike.algorithm import (
    Ikev1DiffieHellmanGroup,
    Ikev1ExchangeType,
    Ikev1NotifyType,
    Ikev1PayloadType,
    Ikev2DiffieHellmanGroup,
    Ikev2IntegrityAlgorithm,
    Ikev2PseudorandomFunction,
    Ikev2ExchangeType,
    Ikev2NotifyType,
    Ikev2PayloadType,
    Ikev2TransformType,
)

from cryptodatahub.ike.version import IkeVersion

from cryptolyzer.ike.client import (
    Ikev1SecurityAssociationAlgorithms,
    Ikev2SecurityAssociationSpecialization,
)
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.ike.common import AnalyzerIKECommonBase
from cryptolyzer.ike.exception import IsakmpNotify


class AnalyzerDHBase(AnalyzerIKECommonBase):
    """
    Base class for Diffie-Hellman group analyzers.
    """

    @classmethod
    @abc.abstractmethod
    def get_name(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_help(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_dh_groups(cls, dh_group_type):
        raise NotImplementedError()

    def _check_ikev1_key_reuse(self, l7_client, init_message):
        try_count = 3
        key_exchange_data = []
        for _ in range(try_count):
            self._before_probe(l7_client)
            init_message.initiator_spi = init_message.initiator_spi + 1
            try:
                server_messages = l7_client.do_ikev1_handshake(
                    init_message=init_message,
                    last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION
                )
            except IsakmpNotify as e:
                # A server that accepts the group only via INVALID_KEY_INFORMATION
                # never returns a Key Exchange payload, so key reuse cannot be
                # determined.
                if e.notify == Ikev1NotifyType.INVALID_KEY_INFORMATION:
                    return None
                raise

            key_exchange_message = server_messages[Ikev1ExchangeType.IDENTITY_PROTECTION][-1]
            key_exchange_payload = key_exchange_message.get_payload_by_type(Ikev1PayloadType.KEY_EXCHANGE)
            key_exchange_data.append(bytes(key_exchange_payload.key_exchange_data))

        return len(set(key_exchange_data)) < try_count

    def _analyze_ikev1(self, l7_client):
        key_reused = None
        accepted_dh_groups = []
        checkable_dh_groups = self._get_dh_groups(Ikev1DiffieHellmanGroup)
        for checkable_dh_group in checkable_dh_groups:
            accepted = False
            algorithms = self._get_ikev1_algorithms_for_dh_groups([checkable_dh_group])
            for algorithm_subset in range(0, len(algorithms), self._MAX_PROPOSALS_PER_INIT_MESSAGE):
                init_message = Ikev1SecurityAssociationAlgorithms(
                    exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
                    algorithms=algorithms[
                        algorithm_subset:algorithm_subset
                        + self._MAX_PROPOSALS_PER_INIT_MESSAGE
                    ]
                )

                if self._send_ikev1_init_message(
                    l7_client=l7_client,
                    dh_group=checkable_dh_group,
                    init_message=init_message,
                ):
                    # Server accepted the offered Diffie-Hellman group
                    # (either via INVALID_KEY_INFORMATION or via clean
                    # Main Mode message 4) — one confirmation per group is
                    # enough.
                    accepted = True
                    break

            if accepted:
                if key_reused is None:
                    key_reused = self._check_ikev1_key_reuse(l7_client, init_message)

                group_name = self._get_dh_group_name()
                LogSingleton().log(
                    level=60,
                    msg=f'Server offered; group_type={group_name}, group={checkable_dh_group}'
                )
                accepted_dh_groups.append(checkable_dh_group)

        return accepted_dh_groups, key_reused

    def _check_ikev2_key_reuse(self, l7_client, init_message):
        try_count = 3
        key_exchange_data = []
        for _ in range(try_count):
            self._before_probe(l7_client)
            init_message.initiator_spi = init_message.initiator_spi + 1
            server_messages = l7_client.do_ikev2_handshake(
                init_message=init_message,
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT
            )
            key_exchange_message = server_messages[Ikev2ExchangeType.IKE_SA_INIT]
            key_exchange_payload = key_exchange_message.get_payload_by_type(Ikev2PayloadType.KE)
            key_exchange_data.append(bytes(key_exchange_payload.key_exchange_data))

        return len(set(key_exchange_data)) < try_count

    def _analyze_ikev2(self, l7_client):
        key_reused = None
        accepted_dh_groups = []
        checkable_dh_groups = self._get_dh_groups(Ikev2DiffieHellmanGroup)
        while checkable_dh_groups:
            self._before_probe(l7_client)

            try:
                init_message = Ikev2SecurityAssociationSpecialization(
                    diffie_hellman_groups=checkable_dh_groups,
                    integrity_algorithms=list(Ikev2IntegrityAlgorithm),
                    pseudorandom_functions=list(Ikev2PseudorandomFunction),
                )

                server_messages = self._send_ikev2_init_message(l7_client, init_message)
            except IsakmpNotify as e:
                if e.notify == Ikev2NotifyType.INVALID_KE_PAYLOAD:
                    dh_group = e.payload.dh_group
                    accepted_dh_groups.append(dh_group)
                    checkable_dh_groups.remove(dh_group)
                    continue

                LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
                raise

            if server_messages is None:
                break

            dh_group = None
            ike_sa_init_message = server_messages[Ikev2ExchangeType.IKE_SA_INIT]
            dh_group = ike_sa_init_message.get_payload_by_type(
                Ikev2PayloadType.SA
            ).get_transform_by_type(Ikev2TransformType.DH).transform_id
            assert dh_group is not None

            if not accepted_dh_groups and key_reused is None:
                key_reused = self._check_ikev2_key_reuse(l7_client, init_message)

            LogSingleton().log(
                level=60, msg=f'Server offered; group_type={self._get_dh_group_name()}, group={dh_group}'
            )

            checkable_dh_groups.remove(dh_group)
            accepted_dh_groups.append(dh_group)

        return accepted_dh_groups, key_reused

    def _analyze(self, analyzable, protocol_version: IkeVersion):
        """
        :type analyzable: AnalyzerTargetIKE
        :type protocol_version: IkeVersion
        """
        if protocol_version == IkeVersion.V2:
            return self._analyze_ikev2(analyzable)

        if protocol_version == IkeVersion.V1:
            return self._analyze_ikev1(analyzable)

        raise NotImplementedError()
