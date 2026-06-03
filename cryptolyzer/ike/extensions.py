# SPDX-License-Identifier: MPL-2.0

import typing

import attr

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.ike.algorithm import (
    IkeVendorId,
    Ikev1ExchangeType,
    Ikev1PayloadType,
    Ikev2DiffieHellmanGroup,
    Ikev2ExchangeType,
    Ikev2NotifyType,
    Ikev2PayloadType,
    Ikev2ProtocolId,
)
from cryptodatahub.ike.version import IkeVersion

from cryptoparser.ike.ikev2 import (
    Ikev2NotifyPayloadChildlessIkev2Supported,
    Ikev2NotifyPayloadIkev2FragmentationSupported,
    Ikev2NotifyPayloadIntermediateExchangeSupported,
    Ikev2NotifyPayloadRedirectSupported,
    Ikev2NotifyPayloadUsePpk,
    Ikev2PayloadNotifyBase,
)
from cryptoparser.ike.isakmp import IsakmpMessage

from cryptolyzer.common.analyzer import AnalyzerIKEBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.result import AnalyzerResultIKE, AnalyzerTargetIke

from cryptolyzer.ike.client import (
    Ikev1SecurityAssociationMandatoryMostPopular,
    Ikev2SecurityAssociationAnyAlgorithm,
    L7ClientIPsecBase,
)
from cryptolyzer.ike.exception import IsakmpNotify


@attr.s
class AnalyzerResultIkev1Extensions(AnalyzerResultIKE):
    """IKEv1 extensions advertised by the responder during Phase 1."""

    nat_traversal_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'NAT Traversal Supported'},
    )
    dead_peer_detection_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Dead Peer Detection Supported'},
    )
    vendor_ids = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.in_(IkeVendorId)
        ),
        metadata={'human_readable_name': 'Vendor IDs'},
    )


@attr.s
class AnalyzerResultIkev2Extensions(AnalyzerResultIKE):  # pylint: disable=too-many-instance-attributes
    """IKEv2 extensions advertised by the responder during IKE_SA_INIT."""

    ikev2_fragmentation_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'IKEv2 Fragmentation Supported'},
    )
    signature_hash_algorithms_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Signature Hash Algorithms Supported'},
    )
    intermediate_exchange_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Intermediate Exchange Supported'},
    )
    use_ppk_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Use PPK Supported'},
    )
    redirect_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Redirect Supported'},
    )
    childless_ikev2_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Childless IKEv2 Supported'},
    )
    multiple_auth_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'Multiple Auth Supported'},
    )
    nat_detection_source_ip_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'NAT Detection Source IP Supported'},
    )
    nat_detection_destination_ip_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'NAT Detection Destination IP Supported'},
    )
    nat_traversal_supported = attr.ib(
        validator=attr.validators.instance_of(bool),
        metadata={'human_readable_name': 'NAT Traversal Supported'},
    )
    vendor_ids = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.in_(IkeVendorId)
        ),
        metadata={'human_readable_name': 'Vendor IDs'},
    )


class AnalyzerExtensions(AnalyzerIKEBase):
    _NOTIFY_TO_ATTRIBUTE = {
        Ikev2NotifyType.IKEV2_FRAGMENTATION_SUPPORTED: 'ikev2_fragmentation_supported',
        Ikev2NotifyType.SIGNATURE_HASH_ALGORITHMS: 'signature_hash_algorithms_supported',
        Ikev2NotifyType.INTERMEDIATE_EXCHANGE_SUPPORTED: 'intermediate_exchange_supported',
        Ikev2NotifyType.USE_PPK: 'use_ppk_supported',
        Ikev2NotifyType.REDIRECT_SUPPORTED: 'redirect_supported',
        Ikev2NotifyType.CHILDLESS_IKEV2_SUPPORTED: 'childless_ikev2_supported',
        Ikev2NotifyType.MULTIPLE_AUTH_SUPPORTED: 'multiple_auth_supported',
        Ikev2NotifyType.NAT_DETECTION_SOURCE_IP: 'nat_detection_source_ip_supported',
        Ikev2NotifyType.NAT_DETECTION_DESTINATION_IP: 'nat_detection_destination_ip_supported',
    }

    _IKEV2_ATTRIBUTES = tuple(_NOTIFY_TO_ATTRIBUTE.values()) + ('nat_traversal_supported',)

    _NAT_TRAVERSAL_VENDOR_IDS = frozenset([
        IkeVendorId.RFC3947_NAT_T,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_00,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_01,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_02,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_02N,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_03,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_04,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_05,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_06,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_07,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_08,
        IkeVendorId.DRAFT_IETF_IPSEC_NAT_T_IKE_09,
    ])

    @classmethod
    def get_name(cls) -> str:
        return 'extensions'

    @classmethod
    def get_help(cls) -> str:
        return (
            'Check which IKE protocol extensions advertised by the server(s) '
            'during the initial SA setup phase'
        )

    @classmethod
    def _get_attributes_ikev2(
            cls, ike_sa_init: IsakmpMessage,
    ) -> dict[str, bool]:
        attributes = {attr_name: False for attr_name in cls._IKEV2_ATTRIBUTES}
        for payload in ike_sa_init.get_payloads_by_type(Ikev2PayloadType.NOTIFY):
            attr_name = cls._NOTIFY_TO_ATTRIBUTE.get(payload.type)
            if attr_name is None:
                continue
            attributes[attr_name] = True
        attributes['nat_traversal_supported'] = (
            attributes['nat_detection_source_ip_supported'] or
            attributes['nat_detection_destination_ip_supported']
        )
        return attributes

    @staticmethod
    def _get_vendor_ids_ikev2(ike_sa_init: IsakmpMessage) -> list[IkeVendorId]:
        vendor_ids = []
        for payload in ike_sa_init.get_payloads_by_type(Ikev2PayloadType.VENDOR_ID):
            try:
                known = IkeVendorId.from_binary(payload.vendor_id)
            except InvalidValue:
                continue
            if known not in vendor_ids:
                vendor_ids.append(known)
        return vendor_ids

    @staticmethod
    def _get_initiator_notify_payloads_ikev2() -> list[Ikev2PayloadNotifyBase]:
        return [
            Ikev2NotifyPayloadIkev2FragmentationSupported(
                flags=set(),
                protocol_id=Ikev2ProtocolId.IKE,
                type=Ikev2NotifyType.IKEV2_FRAGMENTATION_SUPPORTED,
                spi=b'',
            ),
            Ikev2NotifyPayloadUsePpk(
                flags=set(),
                protocol_id=Ikev2ProtocolId.IKE,
                type=Ikev2NotifyType.USE_PPK,
                spi=b'',
            ),
            Ikev2NotifyPayloadIntermediateExchangeSupported(
                flags=set(),
                protocol_id=Ikev2ProtocolId.IKE,
                type=Ikev2NotifyType.INTERMEDIATE_EXCHANGE_SUPPORTED,
                spi=b'',
            ),
            Ikev2NotifyPayloadChildlessIkev2Supported(
                flags=set(),
                protocol_id=Ikev2ProtocolId.IKE,
                type=Ikev2NotifyType.CHILDLESS_IKEV2_SUPPORTED,
                spi=b'',
            ),
            Ikev2NotifyPayloadRedirectSupported(
                flags=set(),
                protocol_id=Ikev2ProtocolId.IKE,
                type=Ikev2NotifyType.REDIRECT_SUPPORTED,
                spi=b'',
            ),
        ]

    def _do_ikev2_handshake(
            self, analyzable: L7ClientIPsecBase,
    ) -> typing.Optional[dict[Ikev2ExchangeType, IsakmpMessage]]:
        self._before_probe(analyzable)
        init_message = Ikev2SecurityAssociationAnyAlgorithm(
            extra_notify_payloads=self._get_initiator_notify_payloads_ikev2(),
        )
        try:
            return analyzable.do_ikev2_handshake(
                init_message=init_message,
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            )
        except IsakmpNotify as e:
            if e.notify != Ikev2NotifyType.INVALID_KE_PAYLOAD:
                return None
            return self._do_ikev2_handshake_on_invalid_ke_payload(analyzable, e.payload.dh_group)
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise
            return None

    def _do_ikev2_handshake_on_invalid_ke_payload(
            self, analyzable: L7ClientIPsecBase, dh_group: Ikev2DiffieHellmanGroup,
    ) -> typing.Optional[dict[Ikev2ExchangeType, IsakmpMessage]]:
        # RFC 7296 §1.2: responder uses INVALID_KE_PAYLOAD to advertise the
        # DH group it expects. Retry once with that group.
        self._before_probe(analyzable)
        try:
            init_message = Ikev2SecurityAssociationAnyAlgorithm(
                extra_notify_payloads=self._get_initiator_notify_payloads_ikev2(),
                key_exchange_dh_group=dh_group,
            )
            return analyzable.do_ikev2_handshake(
                init_message=init_message,
                last_exchange_type=Ikev2ExchangeType.IKE_SA_INIT,
            )
        except IsakmpNotify:
            return None
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise
            return None

    def _analyze_ikev2(
            self, analyzable: L7ClientIPsecBase,
    ) -> tuple[dict[str, bool], list[IkeVendorId]]:
        server_messages = self._do_ikev2_handshake(analyzable)
        if server_messages is None:
            return {attr_name: False for attr_name in self._IKEV2_ATTRIBUTES}, []

        ike_sa_init = server_messages[Ikev2ExchangeType.IKE_SA_INIT]
        attributes = self._get_attributes_ikev2(ike_sa_init)
        vendor_ids = self._get_vendor_ids_ikev2(ike_sa_init)
        return attributes, vendor_ids

    @staticmethod
    def _get_vendor_ids_ikev1(
            server_messages: dict[Ikev1ExchangeType, list[IsakmpMessage]],
    ) -> list[IkeVendorId]:
        vendor_ids = []
        for message in server_messages.get(Ikev1ExchangeType.IDENTITY_PROTECTION, []):
            for payload in message.get_payloads_by_type(Ikev1PayloadType.VENDOR_ID):
                try:
                    known = IkeVendorId.from_binary(payload.vendor_id)
                except InvalidValue:
                    continue
                if known not in vendor_ids:
                    vendor_ids.append(known)
        return vendor_ids

    def _do_ikev1_handshake(
            self, analyzable: L7ClientIPsecBase,
    ) -> typing.Optional[dict[Ikev1ExchangeType, list[IsakmpMessage]]]:
        self._before_probe(analyzable)
        init_message = Ikev1SecurityAssociationMandatoryMostPopular(
            exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
        )
        try:
            return analyzable.do_ikev1_handshake(
                init_message=init_message,
                last_exchange_type=Ikev1ExchangeType.IDENTITY_PROTECTION,
            )
        except IsakmpNotify as e:
            server_messages = getattr(e, 'server_messages', {})
            if Ikev1ExchangeType.IDENTITY_PROTECTION in server_messages:
                return server_messages
            return None
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise
            return None

    def _analyze_ikev1(
            self, analyzable: L7ClientIPsecBase,
    ) -> tuple[bool, bool, list[IkeVendorId]]:
        server_messages = self._do_ikev1_handshake(analyzable)
        if server_messages is None:
            return False, False, []

        vendor_ids = self._get_vendor_ids_ikev1(server_messages)
        nat_traversal_supported = any(
            entry in self._NAT_TRAVERSAL_VENDOR_IDS for entry in vendor_ids
        )
        dead_peer_detection_supported = IkeVendorId.RFC3706_DPD in vendor_ids
        return nat_traversal_supported, dead_peer_detection_supported, vendor_ids

    def analyze(
            self, analyzable: L7ClientIPsecBase, protocol_version: IkeVersion,
    ) -> typing.Union[AnalyzerResultIkev1Extensions, AnalyzerResultIkev2Extensions]:
        super().analyze(analyzable, protocol_version)

        target = AnalyzerTargetIke.from_l7_client(analyzable)
        if protocol_version == IkeVersion.V2:
            attributes, vendor_ids = self._analyze_ikev2(analyzable)
            return AnalyzerResultIkev2Extensions(
                target=target,
                vendor_ids=vendor_ids,
                **attributes,
            )
        if protocol_version == IkeVersion.V1:
            nat_traversal_supported, dead_peer_detection_supported, vendor_ids = (
                self._analyze_ikev1(analyzable)
            )
            return AnalyzerResultIkev1Extensions(
                target=target,
                nat_traversal_supported=nat_traversal_supported,
                dead_peer_detection_supported=dead_peer_detection_supported,
                vendor_ids=vendor_ids,
            )

        raise NotImplementedError()
