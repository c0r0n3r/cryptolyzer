
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

from cryptolyzer.ike.common import AnalyzerIKEBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.ike.client import (
    Ikev1SecurityAssociationAlgorithms,
    Ikev1SecurityAssociationProposalAlgorithms,
    Ikev2SecurityAssociationSpecialization,
)
from cryptolyzer.ike.common import AnalyzerIKECommonBase
from cryptolyzer.ike.crypto import (
    _NegotiatedIkev1Transforms,
    _NegotiatedIkev2Transforms,
)
from cryptolyzer.ike.exception import IsakmpNotify


class AnalyzerDHBase(AnalyzerIKECommonBase):
    """
    Base class for Diffie-Hellman group analyzers.
    """

    _KEY_REUSE_TRY_COUNT = 3

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
        key_exchange_data = []
        for _ in range(self._KEY_REUSE_TRY_COUNT):
            self._before_probe(l7_client)
            init_message.initiator_spi = init_message.initiator_spi + 1
            try:
                server_messages = l7_client.do_ikev1_handshake(
                    init_message=init_message,
                    last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION
                )
            except IsakmpNotify as e:
                # A server that accepts the group only via INVALID_KEY_INFORMATION # never returns a Key Exchange
                # payload, so key reuse cannot be # determined.
                if e.notify == Ikev1NotifyType.INVALID_KEY_INFORMATION:
                    return None
                raise

            key_exchange_message = server_messages[Ikev1ExchangeType.IDENTITY_PROTECTION][-1]
            try:
                key_exchange_payload = key_exchange_message.get_payload_by_type(Ikev1PayloadType.KEY_EXCHANGE)
            except KeyError:
                return None

            key_exchange_data.append(bytes(key_exchange_payload.key_exchange_data))

        return len(set(key_exchange_data)) < self._KEY_REUSE_TRY_COUNT

    def _analyze_ikev1(self, l7_client):
        accepted_dh_groups, first_transforms = self.discover_supported_ikev1_dh_groups(
            l7_client,
            self._get_dh_groups(Ikev1DiffieHellmanGroup),
            before_probe=self._before_probe,
        )
        key_reused = None
        if accepted_dh_groups and first_transforms is not None:
            # Reuse the exact ``(encr, hash, auth, dh, key_length)`` combo the responder picked during discovery so the
            # key-reuse probe sends a single-proposal init the server is guaranteed to# accept (avoids re-batching the
            # full cross-product, whose first ``_MAX_PROPOSALS_PER_INIT_MESSAGE`` slice may # exclude the responder's
            # preferred cipher).
            proposal = Ikev1SecurityAssociationProposalAlgorithms(
                encryption_algorithm=first_transforms.encryption_algorithm,
                diffie_hellman_group=first_transforms.dh_group,
                hash_algorithm=first_transforms.hash_algorithm,
                authentication_method=first_transforms.authentication_method,
                key_length=first_transforms.key_length,
            )
            init_message = Ikev1SecurityAssociationAlgorithms(
                exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
                algorithms=[proposal],
            )
            key_reused = self._check_ikev1_key_reuse(l7_client, init_message)

        return accepted_dh_groups, key_reused

    def _check_ikev2_key_reuse(self, l7_client, init_message):
        key_exchange_data = []
        for _ in range(self._KEY_REUSE_TRY_COUNT):
            self._before_probe(l7_client)
            init_message.initiator_spi = init_message.initiator_spi + 1
            try:
                server_messages = l7_client.do_ikev2_handshake(
                    init_message=init_message,
                    last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT
                )
            except IsakmpNotify:
                return None
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise
                return None
            try:
                key_exchange_message = server_messages[Ikev2ExchangeType.IKE_SA_INIT]
                key_exchange_payload = key_exchange_message.get_payload_by_type(Ikev2PayloadType.KE)
            except KeyError:
                return None
            key_exchange_data.append(bytes(key_exchange_payload.key_exchange_data))

        return len(set(key_exchange_data)) < self._KEY_REUSE_TRY_COUNT

    def _analyze_ikev2(self, l7_client):
        accepted_dh_groups, _ = self.discover_supported_ikev2_dh_groups(
            l7_client,
            self._get_dh_groups(Ikev2DiffieHellmanGroup),
            before_probe=self._before_probe,
        )
        key_reused = None
        if accepted_dh_groups:
            init_message = Ikev2SecurityAssociationSpecialization(
                diffie_hellman_groups=[accepted_dh_groups[0]],
                integrity_algorithms=list(Ikev2IntegrityAlgorithm),
                pseudorandom_functions=list(Ikev2PseudorandomFunction),
            )
            key_reused = self._check_ikev2_key_reuse(l7_client, init_message)

        return accepted_dh_groups, key_reused

    def _analyze(self, analyzable, protocol_version: IkeVersion):
        if protocol_version == IkeVersion.V2:
            return self._analyze_ikev2(analyzable)

        if protocol_version == IkeVersion.V1:
            return self._analyze_ikev1(analyzable)

        raise NotImplementedError()

    @staticmethod
    def _build_ikev1_init_message_for_dh_group(dh_group, algorithm_subset):
        del dh_group
        return Ikev1SecurityAssociationAlgorithms(
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            algorithms=algorithm_subset,
        )

    @classmethod
    def _try_ikev1_dh_group_probe(cls, l7_client, dh_group, before_probe):
        """Probe ``l7_client`` with one IKEv1 dh_group in a Main-Mode SA.

        Returns ``(accepted, transforms)``:

        * ``(False, None)`` — server replied ``NO_PROPOSAL_CHOSEN`` (log emitted).
        * ``(True, None)`` — server replied ``INVALID_KEY_INFORMATION`` (accepted the DH group but rejected the
          initiator's KE; no SA payload to extract from).
        * ``(True, transforms)`` — clean Main-Mode msg 2/4 exchange; transforms come from the responder's SA payload.
        """
        algorithms = cls._get_ikev1_algorithms_for_dh_groups([dh_group])
        for algorithm_subset in range(
                0, len(algorithms),
                AnalyzerIKEBase._MAX_PROPOSALS_PER_INIT_MESSAGE,  # pylint: disable=protected-access
        ):
            subset = algorithms[
                algorithm_subset:algorithm_subset
                + AnalyzerIKEBase._MAX_PROPOSALS_PER_INIT_MESSAGE  # pylint: disable=protected-access
            ]
            init_message = cls._build_ikev1_init_message_for_dh_group(dh_group, subset)
            if before_probe is not None:
                before_probe(l7_client)
            try:
                server_messages = l7_client.do_ikev1_handshake(
                    init_message=init_message,
                    last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
                )
            except IsakmpNotify as e:
                if e.notify == Ikev1NotifyType.NO_PROPOSAL_CHOSEN:
                    LogSingleton().log(
                        level=40,
                        msg=f'No proposal chosen; group={dh_group.name}',
                    )
                    continue
                if e.notify == Ikev1NotifyType.INVALID_KEY_INFORMATION:
                    identity_protection_messages = getattr(e, 'server_messages', {}).get(
                        Ikev1ExchangeType.IDENTITY_PROTECTION, [],
                    )
                    if identity_protection_messages:
                        try:
                            sa_payload = identity_protection_messages[0].get_payload_by_type(
                                Ikev1PayloadType.SECURITY_ASSOCIATION,
                            )
                        except KeyError:
                            return True, None
                        return True, _NegotiatedIkev1Transforms.from_message(sa_payload)
                    return True, None
                LogSingleton().log(level=60, msg=f'Notify response from server; notify={e.notify}')
                raise

            identity_protection_messages = server_messages.get(
                Ikev1ExchangeType.IDENTITY_PROTECTION, [],
            )
            if not identity_protection_messages:
                continue
            sa_response = identity_protection_messages[0]
            try:
                sa_payload = sa_response.get_payload_by_type(
                    Ikev1PayloadType.SECURITY_ASSOCIATION,
                )
            except KeyError:
                return True, None
            return True, _NegotiatedIkev1Transforms.from_message(sa_payload)

        return False, None

    @classmethod
    def discover_supported_ikev1_dh_groups(
            cls,
            l7_client,
            preferred_dh_groups,
            before_probe=None,
            stop_on_first_accepted=False,
    ):
        """Probe ``l7_client`` with ``preferred_dh_groups`` and return the subset the IKEv1 responder accepted. See
        module docstring for semantics.
        """
        accepted_dh_groups = []
        first_transforms = None
        invalid_ki_retried: set = set()
        checkable_dh_groups = list(preferred_dh_groups)

        while checkable_dh_groups:
            dh_group = checkable_dh_groups[0]
            try:
                accepted, transforms = cls._try_ikev1_dh_group_probe(
                    l7_client, dh_group, before_probe,
                )
            except NetworkError as e:
                if e.error == NetworkErrorType.NO_RESPONSE:
                    addr = f'{l7_client.address}:{l7_client.port}'
                    LogSingleton().log(level=60, msg=f'No response from server; address={addr}')
                    break
                raise

            if not accepted:
                checkable_dh_groups.pop(0)
                continue

            if dh_group not in accepted_dh_groups:
                LogSingleton().log(
                    level=60,
                    msg=f'Server offered; group={str(dh_group.value)}',
                )
                accepted_dh_groups.append(dh_group)
            if first_transforms is None and transforms is not None:
                first_transforms = transforms

            if stop_on_first_accepted:
                if first_transforms is not None:
                    break
                if dh_group in invalid_ki_retried:
                    break
                invalid_ki_retried.add(dh_group)
                continue

            checkable_dh_groups.pop(0)

        return accepted_dh_groups, first_transforms

    @staticmethod
    def _handle_invalid_ke_payload(
            dh_group,
            accepted_dh_groups,
            checkable_dh_groups,
            invalid_ke_retried,
            stop_on_first_accepted,
    ):
        """Update discovery state after INVALID_KE_PAYLOAD; return the new
        ``checkable_dh_groups`` list, or ``None`` to signal the discovery
        loop to break.
        """
        accepted_dh_groups.append(dh_group)
        if stop_on_first_accepted:
            if dh_group in invalid_ke_retried:
                return None
            invalid_ke_retried.add(dh_group)
            return [dh_group]
        if dh_group not in checkable_dh_groups:
            return None
        checkable_dh_groups.remove(dh_group)
        return checkable_dh_groups

    @classmethod
    def discover_supported_ikev2_dh_groups(
            cls,
            l7_client,
            preferred_dh_groups,
            before_probe=None,
            stop_on_first_accepted=False,
    ):
        """Probe ``l7_client`` with ``preferred_dh_groups`` and return the
        subset the IKEv2 responder accepted. See module docstring for
        semantics.
        """
        accepted_dh_groups = []
        first_transforms = None
        checkable_dh_groups = list(preferred_dh_groups)
        invalid_ke_retried: set = set()
        while checkable_dh_groups:
            if before_probe is not None:
                before_probe(l7_client)
            try:
                init_message = Ikev2SecurityAssociationSpecialization(
                    diffie_hellman_groups=checkable_dh_groups,
                    integrity_algorithms=list(Ikev2IntegrityAlgorithm),
                    pseudorandom_functions=list(Ikev2PseudorandomFunction),
                )
                try:
                    server_messages = l7_client.do_ikev2_handshake(
                        init_message=init_message,
                        last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT
                    )
                except NetworkError as e:
                    if e.error == NetworkErrorType.NO_RESPONSE:
                        addr = f'{l7_client.address}:{l7_client.port}'
                        LogSingleton().log(level=60, msg=f'No response from server; address={addr}')
                        break
                    raise
            except IsakmpNotify as e:
                if e.notify == Ikev2NotifyType.INVALID_KE_PAYLOAD:
                    dh_group = e.payload.dh_group
                    LogSingleton().log(level=60, msg=f'Server offered; group={str(dh_group.value)}')
                    checkable_dh_groups = cls._handle_invalid_ke_payload(
                        dh_group, accepted_dh_groups, checkable_dh_groups, invalid_ke_retried, stop_on_first_accepted,
                    )
                    if checkable_dh_groups is None:
                        break
                    continue

                if e.notify == Ikev2NotifyType.NO_PROPOSAL_CHOSEN:
                    LogSingleton().log(
                        level=40, msg='No proposal chosen',
                    )
                    break

                LogSingleton().log(
                    level=60, msg=f'Notify response from server; notify={e.notify}',
                )
                raise

            sa_payload = server_messages[Ikev2ExchangeType.IKE_SA_INIT].get_payload_by_type(
                Ikev2PayloadType.SA,
            )
            dh_group = sa_payload.get_transform_by_type(Ikev2TransformType.DH).transform_id

            if first_transforms is None:
                first_transforms = _NegotiatedIkev2Transforms.from_message(sa_payload)

            LogSingleton().log(
                level=60, msg=f'Server offered; group={str(dh_group.value)}'
            )

            try:
                checkable_dh_groups.remove(dh_group)
            except ValueError:
                accepted_dh_groups.append(dh_group)
                break
            accepted_dh_groups.append(dh_group)
            if stop_on_first_accepted:
                break

        return (
            cls._order_accepted_by_preference(accepted_dh_groups, preferred_dh_groups),
            first_transforms,
        )

    @staticmethod
    def _order_accepted_by_preference(accepted, preferred):
        """Return ``accepted`` reordered by ``preferred`` first; entries not
        in ``preferred`` retain their discovery order at the tail.
        """
        accepted_set = set(accepted)
        return [g for g in preferred if g in accepted_set] + [
            g for g in accepted if g not in preferred
        ]
