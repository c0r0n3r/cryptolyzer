# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from unittest import mock
import unittest

from test.common.classes import OFFLINE_CLIENT_L4_SOCKET_PARAMS
from test.ike.classes import create_ike_server

from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.ike.all import AnalyzerAll
from cryptolyzer.ike.client import L7ClientIPsecBase
from cryptolyzer.ike.server import L7ServerIke
from cryptolyzer.ike.versions import AnalyzerVersions


class TestIkeAll(unittest.TestCase):
    @staticmethod
    def _get_result(host, port, l4_socket_params=L4TransferSocketParams(), ip=None):
        analyzer = AnalyzerAll()
        l7_client = L7ClientIPsecBase.from_scheme('ipsec', host, port, l4_socket_params, ip=ip)
        return analyzer.analyze(l7_client, None)

    def test_metadata(self):
        self.assertEqual(AnalyzerAll.get_name(), 'all')
        self.assertIn('Check all supported', AnalyzerAll.get_help())
        self.assertEqual(AnalyzerAll.get_clients(), [])

    def test_markdown(self):
        threaded_server = create_ike_server(L7ServerIke)
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None

        result = self._get_result(
            'localhost',
            l4_transfer.bind_port,
            OFFLINE_CLIENT_L4_SOCKET_PARAMS,
            ip=l4_transfer.bind_address,
        )
        markdown_result = result.as_markdown()

        self.assertIn('Supported Protocol Versions', markdown_result)
        self.assertIn('Protocol Versions', markdown_result)
        self.assertIn('IKEv1', markdown_result)
        self.assertIn('IKEv2', markdown_result)

        threaded_server.join()

    def test_missing_parts(self):
        threaded_server = create_ike_server(L7ServerIke)
        l4_transfer = threaded_server.l7_server.l4_transfer
        assert l4_transfer is not None
        host = 'localhost'
        port = l4_transfer.bind_port
        ip = l4_transfer.bind_address

        with mock.patch.object(AnalyzerVersions, 'analyze', side_effect=RuntimeError('boom')):
            result = self._get_result(host, port, OFFLINE_CLIENT_L4_SOCKET_PARAMS, ip=ip)
        self.assertEqual(result.versions, None)

        result = self._get_result(host, port, OFFLINE_CLIENT_L4_SOCKET_PARAMS, ip=ip)
        self.assertNotEqual(result.versions, None)

        threaded_server.join()
