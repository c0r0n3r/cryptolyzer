from test.common.markers import live_server
from test.common.classes import OFFLINE_CLIENT_L4_SOCKET_PARAMS, OFFLINE_L4_SOCKET_PARAMS
# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from cryptodatahub.ssh.algorithm import SshKexAlgorithm

from cryptolyzer.common.exception import NetworkError

from cryptolyzer.ssh.client import L7ClientSsh, SshDisconnect
from cryptolyzer.ssh.dhparams import AnalyzerDHParams
from cryptolyzer.ssh.server import (
    DEFAULT_SSH_SERVER_DH_GROUP_EXCHANGE_GROUPS,
    L7ServerSsh,
    SshServerConfiguration,
)

from .classes import L7ServerSshTest, TestSshCases


class TestSshDHParams(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port=None, l4_socket_params=OFFLINE_CLIENT_L4_SOCKET_PARAMS, ip=None):
        analyzer = AnalyzerDHParams()
        l7_client = L7ClientSsh(host, port, l4_socket_params, ip=ip)
        result = analyzer.analyze(l7_client)
        return result

    @live_server
    def test_real_gex(self):
        result = self.get_result('github.com', 22)
        self.assertEqual(result.key_exchange, None)
        self.assertEqual(result.group_exchange.gex_algorithms, [SshKexAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256])
        self.assertEqual(
            [key_size.value for key_size in result.group_exchange.key_sizes],
            [2048, 3072, 4096, 6144, 7680, 8192]
        )
        self.assertTrue(result.group_exchange.bounds_tolerated)
        log_lines = self.pop_log_lines()
        for idx, key_size in enumerate(result.group_exchange.key_sizes):
            self.assertIn(
                f'Server offers custom DH public parameter with size {key_size}-bit (SSH 2.0)',
                log_lines[idx]
            )

        result = self.get_result('gitlab.com', 22)
        self.assertEqual(result.key_exchange.kex_algorithms, [
            SshKexAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256,
            SshKexAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA1,
        ])
        self.assertEqual(result.group_exchange, None)

    @staticmethod
    def _start_offline_server(**configuration_overrides):
        server_configuration = SshServerConfiguration(key_exchange_reply=True, **configuration_overrides)
        threaded_server = L7ServerSshTest(L7ServerSsh(
            'localhost', 0, OFFLINE_L4_SOCKET_PARAMS, configuration=server_configuration
        ))
        threaded_server.start()

        return threaded_server

    def test_gex_bounds_tolerated(self):
        threaded_server = self._start_offline_server()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        self.assertEqual(
            [key_size.value for key_size in result.group_exchange.key_sizes],
            [2048, 3072, 4096, 6144, 8192]
        )
        self.assertTrue(result.group_exchange.bounds_tolerated)
        self.assertIn(SshKexAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256, result.key_exchange.kex_algorithms)
        self.assertIn('diffie-hellman-group', result.as_markdown())

        log_stream = '\n'.join(self.pop_log_lines())
        for key_size in result.group_exchange.key_sizes:
            with self.subTest(key_size=key_size):
                self.assertIn(
                    f'Server offers custom DH public parameter with size {key_size.value}-bit', log_stream
                )

    def test_gex_bounds_not_tolerated(self):
        threaded_server = self._start_offline_server(
            dh_group_exchange_groups=(DEFAULT_SSH_SERVER_DH_GROUP_EXCHANGE_GROUPS[0],),
            dh_group_exchange_bounds_tolerated=False,
        )

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        self.assertEqual([key_size.value for key_size in result.group_exchange.key_sizes], [2048])
        self.assertFalse(result.group_exchange.bounds_tolerated)

    def test_dhparams_with_algorithm_limit(self):
        server_configuration = SshServerConfiguration(max_remote_algorithm_count=50)
        threaded_server = L7ServerSshTest(L7ServerSsh(
            'localhost', 0, OFFLINE_L4_SOCKET_PARAMS, configuration=server_configuration
        ))
        threaded_server.start()

        try:
            result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
            self.assertIsNotNone(result)
        except (NetworkError, SshDisconnect, StopIteration):
            pass
