# SPDX-License-Identifier: MPL-2.0

import unittest
from unittest import mock

from cryptodatahub.ike.algorithm import (
    IkeVendorId,
    Ikev1ExchangeType,
    Ikev2DiffieHellmanGroup,
    Ikev2ExchangeType,
    Ikev2NotifyType,
    Ikev2ProtocolId,
)
from cryptodatahub.ike.version import IkeVersion

from cryptoparser.ike.ikev1 import Ikev1PayloadVendorId
from cryptoparser.ike.ikev2 import (
    Ikev2NotifyPayloadChildlessIkev2Supported,
    Ikev2NotifyPayloadHttpCertLookupSupported,
    Ikev2NotifyPayloadIkev2FragmentationSupported,
    Ikev2NotifyPayloadIntermediateExchangeSupported,
    Ikev2NotifyPayloadNatDetectionDestinationIp,
    Ikev2NotifyPayloadNatDetectionSourceIp,
    Ikev2NotifyPayloadRedirectSupported,
    Ikev2NotifyPayloadUsePpk,
    Ikev2PayloadVendorId,
)

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.ike.client import L7ClientIPsecBase
from cryptolyzer.ike.exception import IsakmpNotify
from cryptolyzer.ike.extensions import AnalyzerExtensions
from cryptolyzer.ike.server import IkeServerConfiguration, L7ServerIke, ServerResponseMode

from .classes import (
    L7ServerIkeIkev2AlwaysInvalidKePayload,
    create_ike_server,
    get_ecdh_only_server_configuration,
)


_IKEV2_ATTRIBUTES = AnalyzerExtensions._IKEV2_ATTRIBUTES  # pylint: disable=protected-access


class TestAnalyzerExtensionsName(unittest.TestCase):
    def test_get_name(self):
        self.assertEqual(AnalyzerExtensions.get_name(), 'extensions')

    def test_get_help(self):
        self.assertIsInstance(AnalyzerExtensions.get_help(), str)


class TestAnalyzerExtensionsIkev2InitiatorNotifies(unittest.TestCase):
    # pylint: disable=protected-access
    def test_carries_five_notifies(self):
        self.assertEqual(len(AnalyzerExtensions._get_initiator_notify_payloads_ikev2()), 5)

    def test_carries_fragmentation_use_ppk_intermediate_childless_redirect(self):
        notifies = AnalyzerExtensions._get_initiator_notify_payloads_ikev2()
        self.assertEqual(
            {type(n) for n in notifies},
            {
                Ikev2NotifyPayloadIkev2FragmentationSupported,
                Ikev2NotifyPayloadUsePpk,
                Ikev2NotifyPayloadIntermediateExchangeSupported,
                Ikev2NotifyPayloadChildlessIkev2Supported,
                Ikev2NotifyPayloadRedirectSupported,
            },
        )

    def test_redirect_supported_advertised(self):
        types = {n.type for n in AnalyzerExtensions._get_initiator_notify_payloads_ikev2()}
        self.assertIn(Ikev2NotifyType.REDIRECT_SUPPORTED, types)

    def test_all_use_ike_protocol(self):
        for notify in AnalyzerExtensions._get_initiator_notify_payloads_ikev2():
            self.assertEqual(notify.protocol_id, Ikev2ProtocolId.IKE)
            self.assertEqual(notify.spi, b'')


def _fake_message(payloads):
    message = mock.MagicMock()
    message.payloads = list(payloads)
    message.get_payloads_by_type.side_effect = lambda payload_type: [
        payload for payload in payloads
        if payload.get_payload_type() == payload_type
    ]
    return message


class TestAnalyzerExtensionsIkev2Unit(unittest.TestCase):
    """Exercise the IKEv2 collect loop branches with a mocked handshake."""

    @staticmethod
    def _vid_payload(binary_hex):
        return Ikev2PayloadVendorId(flags=set(), vendor_id=bytes.fromhex(binary_hex))

    @staticmethod
    def _status_notify(notify_type):
        return Ikev2NotifyPayloadIkev2FragmentationSupported(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=notify_type,
            spi=b'',
        )

    @staticmethod
    def _ike_auth_only_notify():
        return Ikev2NotifyPayloadHttpCertLookupSupported(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.HTTP_CERT_LOOKUP_SUPPORTED,
            spi=b'',
        )

    @staticmethod
    def _run_with_payloads(payloads):
        analyzable = mock.MagicMock()
        analyzable.do_ikev2_handshake.return_value = {
            Ikev2ExchangeType.IKE_SA_INIT: _fake_message(payloads),
        }
        # pylint: disable=protected-access
        return AnalyzerExtensions()._analyze_ikev2(analyzable)

    def test_known_vendor_id_added(self):
        _attributes, vendor_ids = self._run_with_payloads([
            self._vid_payload('4a131c81070358455c5728f20e95452f'),
        ])
        self.assertEqual(vendor_ids, [IkeVendorId.RFC3947_NAT_T])

    def test_unknown_vendor_id_dropped(self):
        _attributes, vendor_ids = self._run_with_payloads([
            self._vid_payload('deadbeefdeadbeef'),
        ])
        self.assertEqual(vendor_ids, [])

    def test_duplicate_vendor_id_deduped(self):
        _attributes, vendor_ids = self._run_with_payloads([
            self._vid_payload('4a131c81070358455c5728f20e95452f'),
            self._vid_payload('4a131c81070358455c5728f20e95452f'),
        ])
        self.assertEqual(vendor_ids, [IkeVendorId.RFC3947_NAT_T])

    def test_ike_auth_only_notify_filtered(self):
        attributes, vendor_ids = self._run_with_payloads([
            self._ike_auth_only_notify(),
        ])
        self.assertEqual(vendor_ids, [])
        for attr_name in _IKEV2_ATTRIBUTES:
            self.assertFalse(attributes[attr_name], attr_name)

    def test_fragmentation_notify_sets_attribute(self):
        attributes, _vendor_ids = self._run_with_payloads([
            self._status_notify(Ikev2NotifyType.IKEV2_FRAGMENTATION_SUPPORTED),
        ])
        self.assertTrue(attributes['ikev2_fragmentation_supported'])

    def test_use_ppk_notify_sets_attribute(self):
        attributes, _vendor_ids = self._run_with_payloads([
            self._status_notify(Ikev2NotifyType.USE_PPK),
        ])
        self.assertTrue(attributes['use_ppk_supported'])

    def test_intermediate_exchange_notify_sets_attribute(self):
        attributes, _vendor_ids = self._run_with_payloads([
            self._status_notify(Ikev2NotifyType.INTERMEDIATE_EXCHANGE_SUPPORTED),
        ])
        self.assertTrue(attributes['intermediate_exchange_supported'])

    def test_redirect_notify_sets_attribute(self):
        attributes, _vendor_ids = self._run_with_payloads([
            self._status_notify(Ikev2NotifyType.REDIRECT_SUPPORTED),
        ])
        self.assertTrue(attributes['redirect_supported'])

    def test_childless_notify_sets_attribute(self):
        attributes, _vendor_ids = self._run_with_payloads([
            self._status_notify(Ikev2NotifyType.CHILDLESS_IKEV2_SUPPORTED),
        ])
        self.assertTrue(attributes['childless_ikev2_supported'])

    def test_signature_hash_algorithms_notify_sets_attribute(self):
        attributes, _vendor_ids = self._run_with_payloads([
            self._status_notify(Ikev2NotifyType.SIGNATURE_HASH_ALGORITHMS),
        ])
        self.assertTrue(attributes['signature_hash_algorithms_supported'])

    def test_multiple_auth_notify_sets_attribute(self):
        attributes, _vendor_ids = self._run_with_payloads([
            self._status_notify(Ikev2NotifyType.MULTIPLE_AUTH_SUPPORTED),
        ])
        self.assertTrue(attributes['multiple_auth_supported'])

    def test_nat_detection_source_ip_notify_sets_attribute(self):
        payload = Ikev2NotifyPayloadNatDetectionSourceIp(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.NAT_DETECTION_SOURCE_IP,
            spi=b'',
            hash_data=b'\x00' * 20,
        )
        attributes, _vendor_ids = self._run_with_payloads([payload])
        self.assertTrue(attributes['nat_detection_source_ip_supported'])
        self.assertTrue(attributes['nat_traversal_supported'])

    def test_nat_detection_destination_ip_notify_sets_attribute(self):
        payload = Ikev2NotifyPayloadNatDetectionDestinationIp(
            flags=set(),
            protocol_id=Ikev2ProtocolId.IKE,
            type=Ikev2NotifyType.NAT_DETECTION_DESTINATION_IP,
            spi=b'',
            hash_data=b'\x00' * 20,
        )
        attributes, _vendor_ids = self._run_with_payloads([payload])
        self.assertTrue(attributes['nat_detection_destination_ip_supported'])
        self.assertTrue(attributes['nat_traversal_supported'])

    def test_network_error_on_first_attempt_returns_all_false(self):
        analyzable = mock.MagicMock()
        analyzable.do_ikev2_handshake.side_effect = NetworkError(NetworkErrorType.NO_RESPONSE)
        # pylint: disable=protected-access
        attributes, vendor_ids = AnalyzerExtensions()._analyze_ikev2(analyzable)
        self.assertEqual(vendor_ids, [])
        for attr_name in _IKEV2_ATTRIBUTES:
            self.assertFalse(attributes[attr_name], attr_name)

    def test_non_invalid_ke_notify_does_not_retry(self):
        analyzable = mock.MagicMock()
        analyzable.do_ikev2_handshake.side_effect = IsakmpNotify(
            notify=Ikev2NotifyType.NO_PROPOSAL_CHOSEN,
        )
        # pylint: disable=protected-access
        _attributes, vendor_ids = AnalyzerExtensions()._analyze_ikev2(analyzable)
        self.assertEqual(vendor_ids, [])
        self.assertEqual(analyzable.do_ikev2_handshake.call_count, 1)

    def test_no_connection_error_on_first_attempt_is_reraised(self):
        analyzable = mock.MagicMock()
        analyzable.do_ikev2_handshake.side_effect = NetworkError(NetworkErrorType.NO_CONNECTION)
        # pylint: disable=protected-access
        with self.assertRaises(NetworkError):
            AnalyzerExtensions()._analyze_ikev2(analyzable)

    def test_no_connection_error_on_retry_is_reraised(self):
        analyzable = mock.MagicMock()
        analyzable.l4_socket_params = None
        analyzable.do_ikev2_handshake.side_effect = [
            IsakmpNotify(
                notify=Ikev2NotifyType.INVALID_KE_PAYLOAD,
                payload=mock.MagicMock(dh_group=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT),
            ),
            NetworkError(NetworkErrorType.NO_CONNECTION),
        ]
        # pylint: disable=protected-access
        with self.assertRaises(NetworkError):
            AnalyzerExtensions()._analyze_ikev2(analyzable)

    def test_no_response_error_on_retry_returns_all_false(self):
        analyzable = mock.MagicMock()
        analyzable.l4_socket_params = None
        analyzable.do_ikev2_handshake.side_effect = [
            IsakmpNotify(
                notify=Ikev2NotifyType.INVALID_KE_PAYLOAD,
                payload=mock.MagicMock(dh_group=Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT),
            ),
            NetworkError(NetworkErrorType.NO_RESPONSE),
        ]
        # pylint: disable=protected-access
        attributes, vendor_ids = AnalyzerExtensions()._analyze_ikev2(analyzable)
        self.assertEqual(vendor_ids, [])
        for attr_name in _IKEV2_ATTRIBUTES:
            self.assertFalse(attributes[attr_name], attr_name)


class TestAnalyzerExtensionsIkev1Unit(unittest.TestCase):
    """Exercise the IKEv1 collect loop branches with a mocked handshake."""

    @staticmethod
    def _vid_payload(binary_hex):
        return Ikev1PayloadVendorId(vendor_id=bytes.fromhex(binary_hex))

    @staticmethod
    def _run_with_payloads(payloads):
        analyzable = mock.MagicMock()
        analyzable.do_ikev1_handshake.return_value = {
            Ikev1ExchangeType.IDENTITY_PROTECTION: [_fake_message(payloads)],
        }
        # pylint: disable=protected-access
        return AnalyzerExtensions()._analyze_ikev1(analyzable)

    def test_rfc3947_vid_sets_nat_traversal_supported(self):
        nat_traversal_supported, dead_peer_detection_supported, vendor_ids = (
            self._run_with_payloads([
                self._vid_payload('4a131c81070358455c5728f20e95452f'),
            ])
        )
        self.assertTrue(nat_traversal_supported)
        self.assertFalse(dead_peer_detection_supported)
        self.assertEqual(vendor_ids, [IkeVendorId.RFC3947_NAT_T])

    def test_nat_t_draft_vid_sets_nat_traversal_supported(self):
        nat_traversal_supported, _dpd, _vendor_ids = self._run_with_payloads([
            self._vid_payload('7d9419a65310ca6f2c179d9215529d56'),  # draft -03
        ])
        self.assertTrue(nat_traversal_supported)

    def test_rfc3706_vid_sets_dead_peer_detection_supported(self):
        nat_traversal_supported, dead_peer_detection_supported, vendor_ids = (
            self._run_with_payloads([
                self._vid_payload('afcad71368a1f1c96b8696fc77570100'),
            ])
        )
        self.assertTrue(dead_peer_detection_supported)
        self.assertFalse(nat_traversal_supported)
        self.assertEqual(vendor_ids, [IkeVendorId.RFC3706_DPD])

    def test_unknown_vid_dropped_and_flags_false(self):
        nat_traversal_supported, dead_peer_detection_supported, vendor_ids = (
            self._run_with_payloads([
                self._vid_payload('deadbeefdeadbeef'),
            ])
        )
        self.assertFalse(nat_traversal_supported)
        self.assertFalse(dead_peer_detection_supported)
        self.assertEqual(vendor_ids, [])

    def test_handshake_failure_returns_all_false(self):
        analyzable = mock.MagicMock()
        analyzable.do_ikev1_handshake.side_effect = NetworkError(NetworkErrorType.NO_RESPONSE)
        # pylint: disable=protected-access
        nat_traversal_supported, dead_peer_detection_supported, vendor_ids = (
            AnalyzerExtensions()._analyze_ikev1(analyzable)
        )
        self.assertFalse(nat_traversal_supported)
        self.assertFalse(dead_peer_detection_supported)
        self.assertEqual(vendor_ids, [])

    def test_isakmp_notify_returns_all_false(self):
        analyzable = mock.MagicMock()
        analyzable.do_ikev1_handshake.side_effect = IsakmpNotify(
            notify=Ikev2NotifyType.NO_PROPOSAL_CHOSEN,
        )
        # pylint: disable=protected-access
        nat_traversal_supported, dead_peer_detection_supported, vendor_ids = (
            AnalyzerExtensions()._analyze_ikev1(analyzable)
        )
        self.assertFalse(nat_traversal_supported)
        self.assertFalse(dead_peer_detection_supported)
        self.assertEqual(vendor_ids, [])

    def test_no_connection_error_is_reraised(self):
        analyzable = mock.MagicMock()
        analyzable.do_ikev1_handshake.side_effect = NetworkError(NetworkErrorType.NO_CONNECTION)
        # pylint: disable=protected-access
        with self.assertRaises(NetworkError):
            AnalyzerExtensions()._analyze_ikev1(analyzable)

    def test_isakmp_notify_with_identity_protection_messages_returns_server_messages(self):
        analyzable = mock.MagicMock()
        server_messages = {Ikev1ExchangeType.IDENTITY_PROTECTION: [mock.MagicMock()]}
        notify = IsakmpNotify(notify=Ikev2NotifyType.NO_PROPOSAL_CHOSEN)
        notify.server_messages = server_messages
        analyzable.do_ikev1_handshake.side_effect = notify
        result = AnalyzerExtensions()._do_ikev1_handshake(analyzable)  # pylint: disable=protected-access
        self.assertEqual(result, server_messages)

    def test_duplicate_vid_deduped(self):
        nat_traversal_supported, _dpd, vendor_ids = self._run_with_payloads([
            self._vid_payload('4a131c81070358455c5728f20e95452f'),
            self._vid_payload('4a131c81070358455c5728f20e95452f'),
        ])
        self.assertEqual(vendor_ids, [IkeVendorId.RFC3947_NAT_T])
        self.assertTrue(nat_traversal_supported)

    def test_vids_across_multiple_messages(self):
        first = _fake_message([self._vid_payload('4a131c81070358455c5728f20e95452f')])
        second = _fake_message([self._vid_payload('afcad71368a1f1c96b8696fc77570100')])
        analyzable = mock.MagicMock()
        analyzable.do_ikev1_handshake.return_value = {
            Ikev1ExchangeType.IDENTITY_PROTECTION: [first, second],
        }
        # pylint: disable=protected-access
        nat_traversal_supported, dead_peer_detection_supported, vendor_ids = (
            AnalyzerExtensions()._analyze_ikev1(analyzable)
        )
        self.assertTrue(nat_traversal_supported)
        self.assertTrue(dead_peer_detection_supported)
        self.assertEqual(
            set(vendor_ids),
            {IkeVendorId.RFC3947_NAT_T, IkeVendorId.RFC3706_DPD},
        )


class TestAnalyzerExtensionsIkev1(unittest.TestCase):
    def test_analyze_dispatches_to_ikev1_path(self):
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=IkeServerConfiguration(response_mode=ServerResponseMode.NONE),
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        analyzer = AnalyzerExtensions()
        l7_client = L7ClientIPsecBase.from_scheme(
            'ipsec', 'localhost', l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
            ip=l4_transfer.bind_address,
        )
        result = analyzer.analyze(l7_client, IkeVersion.V1)
        self.assertFalse(result.nat_traversal_supported)
        self.assertFalse(result.dead_peer_detection_supported)
        self.assertEqual(result.vendor_ids, [])
        threaded_server.join()


class TestAnalyzerExtensionsIkev2(unittest.TestCase):
    @staticmethod
    def _get_result(host, port, l4_socket_params=None, ip=None):
        if l4_socket_params is None:
            l4_socket_params = L4TransferSocketParams(timeout=0.5)
        analyzer = AnalyzerExtensions()
        l7_client = L7ClientIPsecBase.from_scheme('ipsec', host, port, l4_socket_params, ip=ip)
        return analyzer.analyze(l7_client, IkeVersion.V2)

    def test_no_response_returns_all_false(self):
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=IkeServerConfiguration(response_mode=ServerResponseMode.NONE),
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
            ip=l4_transfer.bind_address,
        )
        self.assertEqual(result.vendor_ids, [])
        for attr_name in _IKEV2_ATTRIBUTES:
            self.assertFalse(getattr(result, attr_name), attr_name)
        threaded_server.join()

    def test_always_invalid_ke_payload_fails_after_retry(self):
        threaded_server = create_ike_server(
            L7ServerIkeIkev2AlwaysInvalidKePayload,
            configuration=get_ecdh_only_server_configuration(),
            timeout=10.0,
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10.0),
            ip=l4_transfer.bind_address,
        )
        self.assertEqual(result.vendor_ids, [])
        threaded_server.join()

    def test_ecdh_server_completes_sa_init(self):
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=get_ecdh_only_server_configuration(),
            timeout=10.0,
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=10.0),
            ip=l4_transfer.bind_address,
        )
        self.assertIsInstance(result.vendor_ids, list)
        threaded_server.join()


if __name__ == '__main__':
    unittest.main()
