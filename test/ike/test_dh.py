# -*- coding: utf-8 -*-

"""
Common test base for DH group analyzers.
"""

import typing
import unittest

from test.common.classes import TestLoggerBase

from cryptodatahub.ike.algorithm import (
    Ikev1DiffieHellmanGroup,
    Ikev1NotifyType,
    Ikev2DiffieHellmanGroup,
    Ikev2NotifyType,
)
from cryptoparser.ike.version import IsakmpVersion
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
    def get_analyzer_class(cls) -> typing.Type[AnalyzerDHBase]:
        raise NotImplementedError('Subclass must implement get_analyzer_class')

    @classmethod
    def get_expected_groups_ikev1(cls) -> typing.Tuple[Ikev1DiffieHellmanGroup, ...]:
        raise NotImplementedError('Subclass must implement get_expected_groups_ikev1')

    @classmethod
    def get_expected_groups_ikev2(cls) -> typing.Tuple[Ikev2DiffieHellmanGroup, ...]:
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

    @classmethod
    def get_server_timeout(cls) -> float:
        return 0.5

    @classmethod
    def get_client_timeout(cls) -> float:
        return 0.5

    def _get_result(  # pylint: disable=too-many-arguments,too-many-positional-arguments
            self, host, port, protocol_version, l4_socket_params=None, ip=None):
        if l4_socket_params is None:
            l4_socket_params = L4TransferSocketParams(timeout=self.get_client_timeout())
        analyzer = self.get_analyzer_class()()
        l7_client = L7ClientIPsecBase.from_scheme('ipsec', host, port, l4_socket_params, ip=ip)
        return analyzer.analyze(l7_client, protocol_version)

    def _run_test_success(self, protocol_version, expected_groups):
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=self.get_server_config(),
            max_handshake_count=self.get_max_handshakes(),
            timeout=self.get_server_timeout(),
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

    def _run_test_no_proposal_chosen(self, protocol_version):
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=self.get_no_proposal_config(),
            max_handshake_count=self.get_max_handshakes(),
            timeout=self.get_server_timeout(),
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            protocol_version,
            ip=l4_transfer.bind_address,
        )

        self.assertEqual(len(result.groups), 0)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('No proposal chosen', log_output)
        threaded_server.join()

    def test_ikev1(self):
        self._run_test_success(IsakmpVersion.V1, self.get_expected_groups_ikev1())

    def test_ikev2(self):
        self._run_test_success(IsakmpVersion.V2, self.get_expected_groups_ikev2())

    def test_ikev1_no_proposal_chosen(self):
        self._run_test_no_proposal_chosen(IsakmpVersion.V1)

    def test_ikev2_no_proposal_chosen(self):
        self._run_test_no_proposal_chosen(IsakmpVersion.V2)

    def _run_test_no_response(self, protocol_version):
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=IkeServerConfiguration(response_mode=ServerResponseMode.NONE),
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            protocol_version,
            l4_socket_params=L4TransferSocketParams(timeout=0.5),
            ip=l4_transfer.bind_address,
        )

        self.assertEqual(len(result.groups), 0)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('No response', log_output)
        threaded_server.join()

    def test_ikev1_no_response(self):
        self._run_test_no_response(IsakmpVersion.V1)

    def test_ikev2_no_response(self):
        self._run_test_no_response(IsakmpVersion.V2)

    def _run_test_no_connection(self, protocol_version):
        threaded_server = create_ike_server(
            L7ServerIke,
            configuration=IkeServerConfiguration(response_mode=ServerResponseMode.PARTIAL),
            max_handshake_count=1,
            timeout=2.0,
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        with self.assertRaises(NetworkError) as ctx:
            self._get_result(
                'localhost',
                l4_transfer.bind_port,
                protocol_version,
                l4_socket_params=L4TransferSocketParams(timeout=2.0),
                ip=l4_transfer.bind_address,
            )
        self.assertEqual(ctx.exception.error, NetworkErrorType.NO_CONNECTION)
        threaded_server.join()

    def test_ikev1_no_connection(self):
        self._run_test_no_connection(IsakmpVersion.V1)

    def test_ikev2_no_connection(self):
        self._run_test_no_connection(IsakmpVersion.V2)

    def test_ikev1_error_notify_is_raised(self):
        threaded_server = create_ike_server(
            L7ServerIkeNotify,
            notify_type_ikev2=Ikev2NotifyType.NO_PROPOSAL_CHOSEN,
            notify_type_ikev1=Ikev1NotifyType.INVALID_PAYLOAD_TYPE,
            max_handshake_count=1,
            timeout=self.get_server_timeout(),
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        with self.assertRaises(IsakmpNotify) as ctx:
            self._get_result(
                'localhost',
                l4_transfer.bind_port,
                IsakmpVersion.V1,
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
            timeout=self.get_server_timeout(),
        )
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        with self.assertRaises(IsakmpNotify) as ctx:
            self._get_result(
                'localhost',
                l4_transfer.bind_port,
                IsakmpVersion.V2,
                ip=l4_transfer.bind_address,
            )
        self.assertEqual(ctx.exception.notify, Ikev2NotifyType.INVALID_SYNTAX)
        log_output = '\n'.join(self.get_log_lines())
        self.assertIn('Notify', log_output)
        threaded_server.join()
