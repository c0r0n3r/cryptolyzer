# -*- coding: utf-8 -*-

import unittest
import unittest.mock

from cryptodatahub.ike.algorithm import (
    Ikev1DiffieHellmanGroup,
    Ikev1NotifyType,
    Ikev2DiffieHellmanGroup,
    Ikev2NotifyType,
)
from cryptodatahub.ike.version import IkeVersion
from cryptolyzer.ike.dhparams import AnalyzerDHParams
from cryptolyzer.ike.exception import IsakmpNotify
from cryptolyzer.ike.server import IkeServerConfiguration, L7ServerIke

from .classes import (
    create_ike_server,
    get_ffdh_only_server_configuration,
    get_ecdh_only_server_configuration,
    get_ffdh_single_server_configuration,
    L7ServerIkeNotify,
)
from .test_dh import TestAnalyzerDHBase


class TestAnalyzerDHParamsUnit(unittest.TestCase):
    def test_get_name(self):
        self.assertEqual(AnalyzerDHParams.get_name(), 'dhparams')

    def test_get_help(self):
        self.assertIsInstance(AnalyzerDHParams.get_help(), str)

    def test_ikev2_error_notify_in_key_reuse_check(self):
        analyzer = AnalyzerDHParams()
        l7_client = unittest.mock.MagicMock()
        l7_client.l4_socket_params.throttle_delay = 0
        with unittest.mock.patch.object(
            analyzer,
            '_check_ikev2_key_reuse',
            side_effect=IsakmpNotify(Ikev2NotifyType.INVALID_SYNTAX),
        ):
            with self.assertRaises(IsakmpNotify) as ctx:
                analyzer._analyze_ikev2(l7_client)  # pylint: disable=protected-access
        self.assertEqual(ctx.exception.notify, Ikev2NotifyType.INVALID_SYNTAX)

    def test_ikev1_unexpected_notify_in_key_reuse_check(self):
        analyzer = AnalyzerDHParams()
        l7_client = unittest.mock.MagicMock()
        l7_client.l4_socket_params.throttle_delay = 0
        l7_client.do_ikev1_handshake.side_effect = IsakmpNotify(Ikev1NotifyType.PAYLOAD_MALFORMED)
        with self.assertRaises(IsakmpNotify) as ctx:
            analyzer._check_ikev1_key_reuse(  # pylint: disable=protected-access
                l7_client, unittest.mock.MagicMock()
            )
        self.assertEqual(ctx.exception.notify, Ikev1NotifyType.PAYLOAD_MALFORMED)


class TestAnalyzerDHParams(TestAnalyzerDHBase):
    @classmethod
    def get_analyzer_class(cls):
        return AnalyzerDHParams

    @classmethod
    def get_expected_groups_ikev1(cls):
        return (
            Ikev1DiffieHellmanGroup.MODP_768_BIT,
            Ikev1DiffieHellmanGroup.MODP_1024_BIT,
        )

    @classmethod
    def get_expected_groups_ikev2(cls):
        return (
            Ikev2DiffieHellmanGroup.MODP_GROUP_768_BIT,
            Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT,
        )

    @classmethod
    def get_server_config(cls) -> IkeServerConfiguration:
        return get_ffdh_only_server_configuration()

    @classmethod
    def get_no_proposal_config(cls) -> IkeServerConfiguration:
        return get_ecdh_only_server_configuration()

    @classmethod
    def get_max_handshakes(cls):
        return 500  # FFDH groups × many algorithm subsets; server must respond to each

    def test_ikev2_invalid_ke_payload(self):
        configuration = get_ffdh_single_server_configuration()
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=configuration,
            max_handshake_count=self.get_max_handshakes(),
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            IkeVersion.V2,
            ip=l4_transfer.bind_address,
        )
        self.assertEqual(
            [Ikev2DiffieHellmanGroup.MODP_GROUP_2048_BIT],
            result.groups,
            'Analyzer should retry after INVALID_KE_PAYLOAD and succeed with MODP_2048',
        )
        threaded_server.join()

    def test_ikev1_invalid_key_information(self):
        configuration = get_ffdh_single_server_configuration()
        threaded_server = create_ike_server(
            L7ServerIkeNotify,
            configuration=configuration,
            notify_type_ikev1=Ikev1NotifyType.INVALID_KEY_INFORMATION,
            max_handshake_count=self.get_max_handshakes(),
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            IkeVersion.V1,
            ip=l4_transfer.bind_address,
        )
        # Server should have caused the analyzer to record at least one offered group
        self.assertGreater(len(result.groups), 0)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('Server offered', log_output)
        threaded_server.join()
