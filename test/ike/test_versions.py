# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from unittest import mock

from test.common.classes import TestLoggerBase
from test.ike.classes import (
    L7ServerIkeIkev2HeaderOnlyPartialPayload,
    L7ServerIkeNoProposalChosen,
    L7ServerIkeNotify,
    create_ike_server,
)

from cryptodatahub.ike.algorithm import Ikev1NotifyType, Ikev2NotifyType
from cryptoparser.ike.version import IsakmpProtocolVersion, IsakmpVersion

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4ClientUDP, L4TransferSocketParams

from cryptolyzer.ike.client import L7ClientIPsecBase
from cryptolyzer.ike.exception import IsakmpNotify
from cryptolyzer.ike.server import IkeServerConfiguration, L7ServerIke, ServerResponseMode
from cryptolyzer.ike.versions import AnalyzerVersions


class TestIkeVersions(TestLoggerBase):
    @staticmethod
    def _get_result(host, port, l4_socket_params=L4TransferSocketParams(), ip=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientIPsecBase.from_scheme('ipsec', host, port, l4_socket_params, ip=ip)
        return analyzer.analyze(l7_client, None)

    def test_error_network_ikev2_is_reraised(self):
        threaded_server = create_ike_server(
            L7ServerIkeIkev2HeaderOnlyPartialPayload,
            max_handshake_count=1,
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        with self.assertRaises(NetworkError) as ctx:
            self._get_result(
                'localhost',
                l4_transfer.bind_port,
                L4TransferSocketParams(timeout=0.5),
                ip=l4_transfer.bind_address,
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)
        threaded_server.join()

    def test_error_network_ikev1_is_reraised(self):
        call_count = {'n': 0}

        def _send_side_effect(_self, sendable_bytes):
            call_count['n'] += 1
            if call_count['n'] == 1:
                return len(sendable_bytes)
            return 0

        with mock.patch.object(L4ClientUDP, '_send', new=_send_side_effect):
            with self.assertRaises(NetworkError) as ctx:
                self._get_result('localhost', 500, L4TransferSocketParams(timeout=0.1))

        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_no_connection(self):
        threaded_server = create_ike_server(
            L7ServerIkeIkev2HeaderOnlyPartialPayload,
            max_handshake_count=1,
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        with self.assertRaises(NetworkError) as ctx:
            self._get_result(
                'localhost',
                l4_transfer.bind_port,
                L4TransferSocketParams(timeout=0.5),
                ip=l4_transfer.bind_address,
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)
        threaded_server.join()

    def test_no_response(self):
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
        self.assertEqual(result.versions, [])
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('No response from server', log_output)
        threaded_server.join()

    def test_cookie(self):
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=IkeServerConfiguration(cookie_challenge=True),
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
            ip=l4_transfer.bind_address,
        )
        self.assertEqual(
            result.versions,
            [
                IsakmpProtocolVersion(IsakmpVersion.V1, 0),
                IsakmpProtocolVersion(IsakmpVersion.V2, 0),
            ],
        )
        log_output = '\n'.join(self.get_log_lines())
        self.assertNotIn('No response from server', log_output)
        threaded_server.join()

    def test_error_notify_ikev2_is_raised(self):
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
                L4TransferSocketParams(timeout=0.5),
                ip=l4_transfer.bind_address,
            )
        self.assertEqual(ctx.exception.notify, Ikev2NotifyType.INVALID_SYNTAX)

        threaded_server.join()

    def test_error_notify_ikev1_is_raised(self):
        threaded_server = create_ike_server(
            L7ServerIkeNotify,
            notify_type_ikev2=Ikev2NotifyType.NO_PROPOSAL_CHOSEN,
            notify_type_ikev1=Ikev1NotifyType.INVALID_PAYLOAD_TYPE,
            max_handshake_count=2,
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        with self.assertRaises(IsakmpNotify) as ctx:
            self._get_result(
                'localhost',
                l4_transfer.bind_port,
                L4TransferSocketParams(timeout=0.5),
                ip=l4_transfer.bind_address,
            )
        self.assertEqual(ctx.exception.notify, Ikev1NotifyType.INVALID_PAYLOAD_TYPE)

        threaded_server.join()

    def test_no_proposal_chosen(self):
        threaded_server = create_ike_server(L7ServerIkeNoProposalChosen)
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=2),
            ip=l4_transfer.bind_address,
        )

        self.assertEqual(
            result.versions,
            [
                IsakmpProtocolVersion(IsakmpVersion.V1, 0),
                IsakmpProtocolVersion(IsakmpVersion.V2, 0),
            ],
        )

        threaded_server.join()

    def test_versions(self):
        threaded_server = create_ike_server(L7ServerIke)
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            L4TransferSocketParams(timeout=0.5),
            ip=l4_transfer.bind_address,
        )

        self.assertEqual(
            result.versions,
            [
                IsakmpProtocolVersion(IsakmpVersion.V1, 0),
                IsakmpProtocolVersion(IsakmpVersion.V2, 0),
            ],
        )
        log_output = '\n'.join(self.get_log_lines())
        self.assertNotIn('No response from server', log_output)
        threaded_server.join()

    def test_real(self):
        result = self._get_result('moon.strongswan.org', 500, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertEqual(
            result.versions,
            [IsakmpProtocolVersion(IsakmpVersion.V1, 0), IsakmpProtocolVersion(IsakmpVersion.V2, 0)],
        )

        result = self._get_result('82.138.51.230', 500, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertEqual(
            result.versions,
            [IsakmpProtocolVersion(IsakmpVersion.V2, 0)],
        )

        result = self._get_result('public-vpn-213.opengw.net', 500, l4_socket_params=L4TransferSocketParams(timeout=10))
        self.assertEqual(
            result.versions,
            [IsakmpProtocolVersion(IsakmpVersion.V1, 0)],
        )
