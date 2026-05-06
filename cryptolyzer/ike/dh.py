# -*- coding: utf-8 -*-

import abc

from cryptodatahub.ike.algorithm import (
    Ikev1DiffieHellmanGroup,
    Ikev1EncryptionAlgorithm,
    Ikev1ExchangeType,
    Ikev1HashAlgorithm,
    Ikev1AuthenticationMethod,
    Ikev1NotifyType,
    Ikev1PayloadType,
    Ikev2DiffieHellmanGroup,
    Ikev2EncryptionAlgorithm,
    Ikev2IntegrityAlgorithm,
    Ikev2PseudorandomFunction,
    Ikev2ExchangeType,
    Ikev2NotifyType,
    Ikev2PayloadType,
    Ikev2TransformType,
)

from cryptoparser.ike.version import IsakmpVersion

from cryptolyzer.common.analyzer import AnalyzerIKEBase
from cryptolyzer.ike.client import (
    Ikev1SecurityAssociationProposalAlgorithms,
    Ikev1SecurityAssociationAlgorithms,
    Ikev2SecurityAssociationSpecialization,
)
from cryptolyzer.ike.exception import IsakmpNotify
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.common.exception import NetworkError, NetworkErrorType


class AnalyzerDHBase(AnalyzerIKEBase):
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

    @abc.abstractmethod
    def analyze(self, analyzable, protocol_version: IsakmpVersion):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_dh_groups(cls, dh_group_type):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_dh_group_name(cls):
        raise NotImplementedError()

    @classmethod
    def _check_ikev1_key_reuse(cls, l7_client, init_message):
        try_count = 3
        key_exchange_data = []
        for _ in range(try_count):
            init_message.initiator_spi = init_message.initiator_spi + 1
            server_messages = l7_client.do_ikev1_handshake(
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION
            )
            key_exchange_message = server_messages[Ikev1ExchangeType.IDENTITY_PROTECTION][-1]
            key_exchange_payload = key_exchange_message.get_payload_by_type(Ikev1PayloadType.KEY_EXCHANGE)
            key_exchange_data.append(bytes(key_exchange_payload.key_exchange_data))

        return len(set(key_exchange_data)) < try_count

    def _send_ikev1_init_message(self, l7_client, dh_group, init_message, check_key_reuse):
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
                return

            if e.notify == Ikev1NotifyType.INVALID_KEY_INFORMATION:
                raise StopIteration() from e

            LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
            raise
        except NetworkError as e:
            if e.error == NetworkErrorType.NO_RESPONSE:
                addr = f'{l7_client.address}:{l7_client.port}'
                LogSingleton().log(level=60, msg=f'No response from server; address={addr}')
            else:
                raise
        else:
            if check_key_reuse:
                key_reused = self._check_ikev1_key_reuse(l7_client, init_message)
            else:
                key_reused = None

            raise StopIteration(key_reused)

    @classmethod
    def _get_algorithms_for_dh_group(cls, dh_group: Ikev1DiffieHellmanGroup):
        dh_groups = []
        for encryption_algorithm in Ikev1EncryptionAlgorithm:
            key_lengths = [
                bulk_cipher.value.key_size
                for bulk_cipher in encryption_algorithm.value.bulk_ciphers
                if bulk_cipher.value.key_size is not None
            ]
            for key_length in key_lengths:
                for hash_algorithm in Ikev1HashAlgorithm:
                    for authentication_method in Ikev1AuthenticationMethod:
                        dh_groups.append(Ikev1SecurityAssociationProposalAlgorithms(
                            encryption_algorithm=encryption_algorithm,
                            diffie_hellman_group=dh_group,
                            hash_algorithm=hash_algorithm,
                            authentication_method=authentication_method,
                            key_length=key_length,
                        ))
        return dh_groups

    def _analyze_ikev1(self, l7_client):
        key_reused = None
        accepted_dh_groups = []
        checkable_dh_groups = self._get_dh_groups(Ikev1DiffieHellmanGroup)
        for checkable_dh_group in checkable_dh_groups:
            dh_groups = []
            try:
                dh_groups = self._get_algorithms_for_dh_group(checkable_dh_group)
                for algorithm_subset in range(0, len(dh_groups), self._MAX_PROPOSALS_PER_INIT_MESSAGE):
                    self._send_ikev1_init_message(
                        l7_client=l7_client,
                        dh_group=checkable_dh_group,
                        init_message=Ikev1SecurityAssociationAlgorithms(
                            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
                            algorithms=dh_groups[
                                algorithm_subset:algorithm_subset
                                + self._MAX_PROPOSALS_PER_INIT_MESSAGE
                            ]
                        ),
                        check_key_reuse=key_reused is None
                    )
            except StopIteration as e:
                if key_reused is None or e.value is True:
                    key_reused = e.value

                group_name = self._get_dh_group_name()
                LogSingleton().log(
                    level=60,
                    msg=f'Server offered; group_type={group_name}, group={checkable_dh_group}'
                )
                accepted_dh_groups.append(checkable_dh_group)

        return accepted_dh_groups, key_reused

    @classmethod
    def _check_ikev2_key_reuse(cls, l7_client, init_message):
        try_count = 3
        key_exchange_data = []
        for _ in range(try_count):
            init_message.initiator_spi = init_message.initiator_spi + 1
            server_messages = l7_client.do_ikev2_handshake(
                init_message=init_message,
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT
            )
            key_exchange_message = server_messages[Ikev2ExchangeType.IKE_SA_INIT]
            key_exchange_payload = key_exchange_message.get_payload_by_type(Ikev2PayloadType.KE)
            key_exchange_data.append(bytes(key_exchange_payload.key_exchange_data))

        return len(set(key_exchange_data)) < try_count and len(key_exchange_data) == try_count

    def _analyze_ikev2(self, l7_client):
        key_reused = None
        accepted_dh_groups = []
        checkable_dh_groups = self._get_dh_groups(Ikev2DiffieHellmanGroup)
        while checkable_dh_groups:
            init_message = Ikev2SecurityAssociationSpecialization(
                diffie_hellman_groups=checkable_dh_groups,
                encryption_algorithms=list(Ikev2EncryptionAlgorithm),
                integrity_algorithms=list(Ikev2IntegrityAlgorithm),
                pseudorandom_functions=list(Ikev2PseudorandomFunction),
            )

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
                        msg=f'No proposal chosen; group_type={group_name}, '
                        f'group={checkable_dh_groups[0].name}'
                    )
                    break

                if e.notify == Ikev2NotifyType.INVALID_KE_PAYLOAD:
                    dh_group = e.payload.dh_group
                    accepted_dh_groups.append(dh_group)
                    checkable_dh_groups.remove(dh_group)
                    del checkable_dh_groups[0]
                    continue

                LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
                raise
            except NetworkError as e:
                if e.error == NetworkErrorType.NO_RESPONSE:
                    addr = f'{l7_client.address}:{l7_client.port}'
                    LogSingleton().log(level=60, msg=f'No response from server; address={addr}')
                    break

                raise

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

    def _analyze(self, analyzable, protocol_version: IsakmpVersion):
        """
        :type analyzable: AnalyzerTargetIKE
        :type protocol_version: IsakmpVersion
        """

        if protocol_version == IsakmpVersion.V2:
            return self._analyze_ikev2(analyzable)

        if protocol_version == IsakmpVersion.V1:
            return self._analyze_ikev1(analyzable)

        raise NotImplementedError()
