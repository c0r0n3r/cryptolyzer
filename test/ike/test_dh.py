
"""
Common test base for DH group analyzers.
"""

import unittest
import unittest.mock

from test.common.classes import (
    OFFLINE_CLIENT_L4_SOCKET_PARAMS,
    OFFLINE_PARTIAL_RESPONSE_L4_SOCKET_PARAMS,
    TestLoggerBase,
)

from cryptodatahub.ike.algorithm import (
    Ikev1DiffieHellmanGroup,
    Ikev1ExchangeType,
    Ikev1NotifyType,
    Ikev2DiffieHellmanGroup,
    Ikev2ExchangeType,
    Ikev2NotifyType,
)
from cryptodatahub.ike.version import IkeVersion
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.ike.client import L7ClientIPsecBase
from cryptolyzer.ike.dh import AnalyzerDHBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.ike.exception import IsakmpNotify
from cryptolyzer.ike.server import IkeServerConfiguration, L7ServerIke, ServerResponseMode

from .classes import L7ServerIkeNotify, create_ike_server


class TestAnalyzerDHBase(TestLoggerBase):
    """Base class for DH group analyzer tests."""

    @classmethod
    def setUpClass(cls):
        if cls is TestAnalyzerDHBase:
            raise unittest.SkipTest('Base class for DH analyzers, only derived classes should be run')

    @classmethod
    def get_analyzer_class(cls) -> type[AnalyzerDHBase]:
        raise NotImplementedError('Subclass must implement get_analyzer_class')

    @classmethod
    def get_expected_groups_ikev1(cls) -> tuple[Ikev1DiffieHellmanGroup, ...]:
        raise NotImplementedError('Subclass must implement get_expected_groups_ikev1')

    @classmethod
    def get_expected_groups_ikev2(cls) -> tuple[Ikev2DiffieHellmanGroup, ...]:
        raise NotImplementedError('Subclass must implement get_expected_groups_ikev2')

    @classmethod
    def get_server_config(cls) -> IkeServerConfiguration:
        raise NotImplementedError('Subclass must implement get_server_config')

    @classmethod
    def get_no_proposal_config(cls) -> IkeServerConfiguration:
        raise NotImplementedError('Subclass must implement get_no_proposal_config')

    @classmethod
    def get_max_handshakes(cls) -> int:
        return 90

    def _get_result(  # pylint: disable=too-many-arguments,too-many-positional-arguments
            self, host, port, protocol_version, l4_socket_params=None, ip=None):
        if l4_socket_params is None:
            l4_socket_params = OFFLINE_CLIENT_L4_SOCKET_PARAMS
        analyzer = self.get_analyzer_class()()
        l7_client = L7ClientIPsecBase.from_scheme('ipsec', host, port, l4_socket_params, ip=ip)
        return analyzer.analyze(l7_client, protocol_version)

    def _run_test_success(self, protocol_version, expected_groups):
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=self.get_server_config(),
            max_handshake_count=self.get_max_handshakes(),
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            protocol_version,
            ip=l4_transfer.bind_address,
        )

        self.assertCountEqual(result.groups, expected_groups)
        log_output = '\n'.join(self.get_log_lines())
        self.assertNotIn('No response from server', log_output)
        threaded_server.join()

    @staticmethod
    def _make_mock_client():
        l7_client = L7ClientIPsecBase.from_scheme(
            'ipsec', 'localhost', 65535, L4TransferSocketParams(timeout=0.1, throttle_delay=0)
        )
        l7_client.do_ikev1_handshake = unittest.mock.MagicMock()
        l7_client.do_ikev2_handshake = unittest.mock.MagicMock()
        return l7_client

    def _run_test_no_proposal_chosen(self, protocol_version):
        l7_client = self._make_mock_client()
        if protocol_version == IkeVersion.V1:
            l7_client.do_ikev1_handshake.side_effect = IsakmpNotify(Ikev1NotifyType.NO_PROPOSAL_CHOSEN)
        else:
            l7_client.do_ikev2_handshake.side_effect = IsakmpNotify(Ikev2NotifyType.NO_PROPOSAL_CHOSEN)

        analyzer = self.get_analyzer_class()()
        result = analyzer.analyze(l7_client, protocol_version)

        self.assertEqual(len(result.groups), 0)
        self.assertGreater(
            l7_client.do_ikev1_handshake.call_count if protocol_version == IkeVersion.V1
            else l7_client.do_ikev2_handshake.call_count,
            0,
            'Analyzer must probe at least one Diffie-Hellman group',
        )
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('No proposal chosen', log_output)

    def test_ikev1(self):
        self._run_test_success(IkeVersion.V1, self.get_expected_groups_ikev1())

    def test_ikev2(self):
        self._run_test_success(IkeVersion.V2, self.get_expected_groups_ikev2())

    def test_ikev1_no_proposal_chosen(self):
        self._run_test_no_proposal_chosen(IkeVersion.V1)

    def test_ikev2_no_proposal_chosen(self):
        self._run_test_no_proposal_chosen(IkeVersion.V2)

    def _run_test_no_response(self, protocol_version):
        l7_client = self._make_mock_client()
        no_response = NetworkError(NetworkErrorType.NO_RESPONSE)
        if protocol_version == IkeVersion.V1:
            l7_client.do_ikev1_handshake.side_effect = no_response
        else:
            l7_client.do_ikev2_handshake.side_effect = no_response

        analyzer = self.get_analyzer_class()()
        result = analyzer.analyze(l7_client, protocol_version)

        self.assertEqual(len(result.groups), 0)
        self.assertGreater(
            l7_client.do_ikev1_handshake.call_count if protocol_version == IkeVersion.V1
            else l7_client.do_ikev2_handshake.call_count,
            0,
            'Analyzer must probe at least one Diffie-Hellman group',
        )
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('No response', log_output)

    def test_ikev1_no_response(self):
        self._run_test_no_response(IkeVersion.V1)

    def test_ikev2_no_response(self):
        self._run_test_no_response(IkeVersion.V2)

    def _run_test_no_connection(self, protocol_version):
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=IkeServerConfiguration(response_mode=ServerResponseMode.PARTIAL),
            max_handshake_count=1,
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        with self.assertRaises(NetworkError) as ctx:
            self._get_result(
                'localhost',
                l4_transfer.bind_port,
                protocol_version,
                l4_socket_params=OFFLINE_PARTIAL_RESPONSE_L4_SOCKET_PARAMS,
                ip=l4_transfer.bind_address,
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)
        threaded_server.join()

    def test_ikev1_no_connection(self):
        self._run_test_no_connection(IkeVersion.V1)

    def test_ikev2_no_connection(self):
        self._run_test_no_connection(IkeVersion.V2)

    def test_ikev1_error_notify_is_raised(self):
        threaded_server = create_ike_server(
            L7ServerIkeNotify,
            notify_type_ikev2=Ikev2NotifyType.NO_PROPOSAL_CHOSEN,
            notify_type_ikev1=Ikev1NotifyType.INVALID_PAYLOAD_TYPE,
            max_handshake_count=1,
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        with self.assertRaises(IsakmpNotify) as ctx:
            self._get_result(
                'localhost',
                l4_transfer.bind_port,
                IkeVersion.V1,
                ip=l4_transfer.bind_address,
            )
        self.assertEqual(ctx.exception.notify, Ikev1NotifyType.INVALID_PAYLOAD_TYPE)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('Notify response from server', log_output)
        threaded_server.join()

    def test_ikev2_error_notify_is_raised(self):
        threaded_server = create_ike_server(
            L7ServerIkeNotify,
            notify_type_ikev2=Ikev2NotifyType.INVALID_SYNTAX,
            max_handshake_count=1,
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        with self.assertRaises(IsakmpNotify) as ctx:
            self._get_result(
                'localhost',
                l4_transfer.bind_port,
                IkeVersion.V2,
                ip=l4_transfer.bind_address,
            )
        self.assertEqual(ctx.exception.notify, Ikev2NotifyType.INVALID_SYNTAX)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('Notify', log_output)
        threaded_server.join()


class TestDiscoverSupportedIkev2DhGroups(TestLoggerBase):
    """Direct tests for the module-level
    :func:`cryptolyzer.ike.dh.discover_supported_ikev2_dh_groups` helper
    that both :class:`AnalyzerDHParams` / :class:`AnalyzerCurves` and
    :class:`cryptolyzer.ike.pubkeys.AnalyzerPublicKeys` share."""

    @staticmethod
    def _make_mock_client():
        l7_client = L7ClientIPsecBase.from_scheme(
            'ipsec', 'localhost', 65535, L4TransferSocketParams(timeout=0.1, throttle_delay=0)
        )
        l7_client.do_ikev2_handshake = unittest.mock.MagicMock()
        return l7_client

    def test_returns_empty_list_on_no_response(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev2_handshake.side_effect = NetworkError(NetworkErrorType.NO_RESPONSE)
        result, transforms = AnalyzerDHBase.discover_supported_ikev2_dh_groups(
            l7_client, [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
        )
        self.assertEqual(result, [])
        self.assertIsNone(transforms)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('No response from server', log_output)

    def test_returns_empty_list_on_no_proposal_chosen(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev2_handshake.side_effect = IsakmpNotify(Ikev2NotifyType.NO_PROPOSAL_CHOSEN)
        result, transforms = AnalyzerDHBase.discover_supported_ikev2_dh_groups(
            l7_client, [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
        )
        self.assertEqual(result, [])
        self.assertIsNone(transforms)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('No proposal chosen', log_output)

    def test_reraises_non_no_response_network_error(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev2_handshake.side_effect = NetworkError(NetworkErrorType.NO_CONNECTION)
        with self.assertRaises(NetworkError) as ctx:
            AnalyzerDHBase.discover_supported_ikev2_dh_groups(
                l7_client, [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_reraises_unexpected_notify(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev2_handshake.side_effect = IsakmpNotify(Ikev2NotifyType.INVALID_SYNTAX)
        with self.assertRaises(IsakmpNotify) as ctx:
            AnalyzerDHBase.discover_supported_ikev2_dh_groups(
                l7_client, [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            )
        self.assertEqual(ctx.exception.notify, Ikev2NotifyType.INVALID_SYNTAX)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('Notify response from server', log_output)

    def test_invalid_ke_payload_with_unknown_group_breaks(self):
        l7_client = self._make_mock_client()
        payload = unittest.mock.MagicMock()
        payload.dh_group = Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT
        l7_client.do_ikev2_handshake.side_effect = IsakmpNotify(
            Ikev2NotifyType.INVALID_KE_PAYLOAD, payload
        )
        result, transforms = AnalyzerDHBase.discover_supported_ikev2_dh_groups(
            l7_client, [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
        )
        self.assertEqual(result, [Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT])
        self.assertIsNone(transforms)

    def test_before_probe_called_before_each_handshake(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev2_handshake.side_effect = NetworkError(NetworkErrorType.NO_RESPONSE)
        before_probe = unittest.mock.MagicMock()
        AnalyzerDHBase.discover_supported_ikev2_dh_groups(
            l7_client,
            [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            before_probe=before_probe,
        )
        before_probe.assert_called_once_with(l7_client)

    def test_invalid_ke_payload_stop_on_first_accepted_retries_once_then_breaks(self):
        # ``_handle_invalid_ke_payload``'s stop_on_first_accepted branch:
        # first INVALID_KE_PAYLOAD for a group records + retries that
        # single group once; the second INVALID_KE_PAYLOAD for the
        # same (now-retried) group breaks the discovery loop instead
        # of retrying forever.
        l7_client = self._make_mock_client()
        payload = unittest.mock.MagicMock()
        payload.dh_group = Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT
        l7_client.do_ikev2_handshake.side_effect = IsakmpNotify(
            Ikev2NotifyType.INVALID_KE_PAYLOAD, payload
        )
        result, transforms = AnalyzerDHBase.discover_supported_ikev2_dh_groups(
            l7_client, [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            stop_on_first_accepted=True,
        )
        # ``_handle_invalid_ke_payload`` appends the suggested group on
        # every INVALID_KE_PAYLOAD response, including the retry — the
        # duplicate reflects that both the initial and the retried
        # attempt name the same responder-suggested group.
        self.assertEqual(
            result,
            [Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT, Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT],
        )
        self.assertIsNone(transforms)
        self.assertEqual(l7_client.do_ikev2_handshake.call_count, 2)

    def test_responder_picks_dh_group_outside_checkable_list_breaks(self):
        # Defensive branch: if the responder's SA_INIT reply picks a DH
        # group that isn't in ``checkable_dh_groups`` (e.g. one the
        # analyzer never offered), ``checkable_dh_groups.remove`` raises
        # ``ValueError`` — the loop records the unexpected group as
        # accepted anyway and breaks rather than looping forever.
        l7_client = self._make_mock_client()
        unexpected_dh_group = Ikev2DiffieHellmanGroup.ECP_GROUP_384_BIT
        sa_payload = unittest.mock.MagicMock()
        sa_payload.get_transform_by_type.return_value.transform_id = unexpected_dh_group
        ike_sa_init_message = unittest.mock.MagicMock()
        ike_sa_init_message.get_payload_by_type.return_value = sa_payload
        l7_client.do_ikev2_handshake.return_value = {
            Ikev2ExchangeType.IKE_SA_INIT: ike_sa_init_message,
        }

        with unittest.mock.patch(
                'cryptolyzer.ike.dh._NegotiatedIkev2Transforms.from_message',
                return_value=unittest.mock.sentinel.transforms,
        ):
            result, transforms = AnalyzerDHBase.discover_supported_ikev2_dh_groups(
                l7_client, [Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT],
            )
        self.assertEqual(result, [unexpected_dh_group])
        self.assertIs(transforms, unittest.mock.sentinel.transforms)
        l7_client.do_ikev2_handshake.assert_called_once()

    def test_stop_on_first_accepted_breaks_after_clean_accept(self):
        l7_client = self._make_mock_client()
        accepted_group = Ikev2DiffieHellmanGroup.ECP_GROUP_256_BIT
        sa_payload = unittest.mock.MagicMock()
        sa_payload.get_transform_by_type.return_value.transform_id = accepted_group
        ike_sa_init_message = unittest.mock.MagicMock()
        ike_sa_init_message.get_payload_by_type.return_value = sa_payload
        l7_client.do_ikev2_handshake.return_value = {
            Ikev2ExchangeType.IKE_SA_INIT: ike_sa_init_message,
        }

        with unittest.mock.patch(
                'cryptolyzer.ike.dh._NegotiatedIkev2Transforms.from_message',
                return_value=unittest.mock.sentinel.transforms,
        ):
            result, transforms = AnalyzerDHBase.discover_supported_ikev2_dh_groups(
                l7_client, [accepted_group], stop_on_first_accepted=True,
            )
        self.assertEqual(result, [accepted_group])
        self.assertIs(transforms, unittest.mock.sentinel.transforms)
        l7_client.do_ikev2_handshake.assert_called_once()


class TestDiscoverSupportedIkev1DhGroups(TestLoggerBase):
    """Direct tests for the module-level
    :func:`cryptolyzer.ike.dh.discover_supported_ikev1_dh_groups` helper
    that :class:`AnalyzerDHParams` / :class:`AnalyzerCurves` and
    :class:`cryptolyzer.ike.pubkeys.AnalyzerPublicKeys` share.

    Sibling to :class:`TestDiscoverSupportedIkev2DhGroups`; the shape
    of each test mirrors the IKEv2 case exactly so the two helpers'
    NO_RESPONSE / NO_PROPOSAL_CHOSEN / unexpected-notify / before_probe
    contracts stay in lockstep.
    """

    @staticmethod
    def _make_mock_client():
        l7_client = L7ClientIPsecBase.from_scheme(
            'ipsec', 'localhost', 65535, L4TransferSocketParams(timeout=0.1, throttle_delay=0)
        )
        l7_client.do_ikev1_handshake = unittest.mock.MagicMock()
        return l7_client

    def test_returns_empty_list_on_no_response(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev1_handshake.side_effect = NetworkError(NetworkErrorType.NO_RESPONSE)
        result, transforms = AnalyzerDHBase.discover_supported_ikev1_dh_groups(
            l7_client, [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
        )
        self.assertEqual(result, [])
        self.assertIsNone(transforms)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('No response from server', log_output)

    def test_returns_empty_list_on_no_proposal_chosen(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev1_handshake.side_effect = IsakmpNotify(Ikev1NotifyType.NO_PROPOSAL_CHOSEN)
        result, transforms = AnalyzerDHBase.discover_supported_ikev1_dh_groups(
            l7_client, [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
        )
        self.assertEqual(result, [])
        self.assertIsNone(transforms)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('No proposal chosen', log_output)

    def test_invalid_key_information_marks_accepted_without_transforms(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev1_handshake.side_effect = IsakmpNotify(
            Ikev1NotifyType.INVALID_KEY_INFORMATION,
        )
        result, transforms = AnalyzerDHBase.discover_supported_ikev1_dh_groups(
            l7_client,
            [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
            stop_on_first_accepted=True,
        )
        self.assertEqual(result, [Ikev1DiffieHellmanGroup.MODP_2048_BIT])
        self.assertIsNone(transforms)

    def test_reraises_non_no_response_network_error(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev1_handshake.side_effect = NetworkError(NetworkErrorType.NO_CONNECTION)
        with self.assertRaises(NetworkError) as ctx:
            AnalyzerDHBase.discover_supported_ikev1_dh_groups(
                l7_client, [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_reraises_unexpected_notify(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev1_handshake.side_effect = IsakmpNotify(
            Ikev1NotifyType.INVALID_PAYLOAD_TYPE,
        )
        with self.assertRaises(IsakmpNotify) as ctx:
            AnalyzerDHBase.discover_supported_ikev1_dh_groups(
                l7_client, [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
            )
        self.assertEqual(ctx.exception.notify, Ikev1NotifyType.INVALID_PAYLOAD_TYPE)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('Notify response from server', log_output)

    def test_before_probe_called_before_each_handshake(self):
        l7_client = self._make_mock_client()
        l7_client.do_ikev1_handshake.side_effect = NetworkError(NetworkErrorType.NO_RESPONSE)
        before_probe = unittest.mock.MagicMock()
        AnalyzerDHBase.discover_supported_ikev1_dh_groups(
            l7_client,
            [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
            before_probe=before_probe,
        )
        before_probe.assert_called_once_with(l7_client)

    def test_invalid_key_information_extracts_transforms_from_server_messages(self):
        # RFC 2409 App. A — a Phase-1 responder that accepted the SA in
        # msg 2 but rejected the msg 3 KE still returns msg 2 on the
        # ``IsakmpNotify.server_messages`` attribute; ``_try_ikev1_dh_group_probe``
        # pulls the picked transforms from it instead of returning None.
        l7_client = self._make_mock_client()
        message = unittest.mock.Mock()
        sa_payload = unittest.mock.Mock()
        message.get_payload_by_type.return_value = sa_payload
        notify = IsakmpNotify(Ikev1NotifyType.INVALID_KEY_INFORMATION)
        notify.server_messages = {Ikev1ExchangeType.IDENTITY_PROTECTION: [message]}
        l7_client.do_ikev1_handshake.side_effect = notify

        with unittest.mock.patch(
                'cryptolyzer.ike.dh._NegotiatedIkev1Transforms.from_message',
                return_value=unittest.mock.sentinel.transforms,
        ) as mock_extract:
            result, transforms = AnalyzerDHBase.discover_supported_ikev1_dh_groups(
                l7_client, [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
            )
        self.assertEqual(result, [Ikev1DiffieHellmanGroup.MODP_2048_BIT])
        self.assertIs(transforms, unittest.mock.sentinel.transforms)
        mock_extract.assert_called_once_with(sa_payload)

    def test_invalid_key_information_with_server_messages_missing_sa_payload(self):
        # Same msg-2-on-the-notify path, but the recorded message has
        # no SECURITY_ASSOCIATION payload — the KeyError from
        # ``get_payload_by_type`` must be swallowed and treated as
        # "accepted, no transforms" rather than propagating.
        l7_client = self._make_mock_client()
        message = unittest.mock.Mock()
        message.get_payload_by_type.side_effect = KeyError()
        notify = IsakmpNotify(Ikev1NotifyType.INVALID_KEY_INFORMATION)
        notify.server_messages = {Ikev1ExchangeType.IDENTITY_PROTECTION: [message]}
        l7_client.do_ikev1_handshake.side_effect = notify

        result, transforms = AnalyzerDHBase.discover_supported_ikev1_dh_groups(
            l7_client, [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
        )
        self.assertEqual(result, [Ikev1DiffieHellmanGroup.MODP_2048_BIT])
        self.assertIsNone(transforms)

    def test_clean_response_without_identity_protection_messages_continues(self):
        # A clean (non-notify) handshake reply whose server_messages
        # dict has no IDENTITY_PROTECTION entry for this proposal batch
        # must fall through to the next algorithm subset rather than
        # crash or misreport acceptance.
        l7_client = self._make_mock_client()
        l7_client.do_ikev1_handshake.return_value = {}
        result, transforms = AnalyzerDHBase.discover_supported_ikev1_dh_groups(
            l7_client, [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
        )
        self.assertEqual(result, [])
        self.assertIsNone(transforms)

    def test_clean_response_missing_security_association_payload(self):
        # Clean (non-notify) Main-Mode msg 2/4 reply, but the message
        # carries no SECURITY_ASSOCIATION payload — accepted, but no
        # transforms to extract.
        l7_client = self._make_mock_client()
        message = unittest.mock.Mock()
        message.get_payload_by_type.side_effect = KeyError()
        l7_client.do_ikev1_handshake.return_value = {
            Ikev1ExchangeType.IDENTITY_PROTECTION: [message],
        }
        result, transforms = AnalyzerDHBase.discover_supported_ikev1_dh_groups(
            l7_client, [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
        )
        self.assertEqual(result, [Ikev1DiffieHellmanGroup.MODP_2048_BIT])
        self.assertIsNone(transforms)

    def test_stop_on_first_accepted_breaks_immediately_when_transforms_found(self):
        # When the very first accepted group already comes with
        # transforms (a clean Main-Mode SA response, not an
        # INVALID_KEY_INFORMATION retry), stop_on_first_accepted breaks
        # without ever touching the retry bookkeeping.
        l7_client = self._make_mock_client()
        message = unittest.mock.Mock()
        message.get_payload_by_type.return_value = unittest.mock.Mock()
        l7_client.do_ikev1_handshake.return_value = {
            Ikev1ExchangeType.IDENTITY_PROTECTION: [message],
        }

        with unittest.mock.patch(
                'cryptolyzer.ike.dh._NegotiatedIkev1Transforms.from_message',
                return_value=unittest.mock.sentinel.transforms,
        ):
            result, transforms = AnalyzerDHBase.discover_supported_ikev1_dh_groups(
                l7_client, [Ikev1DiffieHellmanGroup.MODP_2048_BIT],
                stop_on_first_accepted=True,
            )
        self.assertEqual(result, [Ikev1DiffieHellmanGroup.MODP_2048_BIT])
        self.assertIs(transforms, unittest.mock.sentinel.transforms)
        l7_client.do_ikev1_handshake.assert_called_once()
