# -*- coding: utf-8 -*-

from cryptodatahub.ssh.algorithm import SshKexAlgorithm

from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.ssh.client import L7ClientSsh
from cryptolyzer.ssh.dhparams import AnalyzerDHParams

from .classes import TestSshCases


class TestSshDHParams(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port=None, l4_socket_params=L4TransferSocketParams(timeout=5), ip=None):
        analyzer = AnalyzerDHParams()
        l7_client = L7ClientSsh(host, port, l4_socket_params, ip=ip)
        result = analyzer.analyze(l7_client)
        return result

    def test_real_no_gex(self):
        result = self.get_result('bitbucket.com', 22)
        self.assertEqual(result.group_exchange, None)

    def test_real_gex(self):
        result = self.get_result('git.launchpad.net', 22)
        self.assertEqual(result.key_exchange.kex_algorithms, [SshKexAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA1, ])
        self.assertEqual(result.group_exchange.gex_algorithms, [
            SshKexAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256,
            SshKexAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA1,
        ])
        self.assertEqual(
            [key_size.value for key_size in result.group_exchange.key_sizes],
            [2048, 3072, 4096, 6144, 7680, 8192]
        )
        self.assertFalse(result.group_exchange.bounds_tolerated)
        log_lines = self.pop_log_lines()
        for idx, key_size in enumerate(result.group_exchange.key_sizes):
            self.assertEqual(
                f'Server offers custom DH public parameter with size {key_size}-bit (SSH 2.0)',
                log_lines[idx + 1]
            )

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
