# -*- coding: utf-8 -*-

from cryptoparser.ssh.ciphersuite import SshKexAlgorithm

from cryptolyzer.ssh.client import L7ClientSsh
from cryptolyzer.ssh.dhparams import AnalyzerDHParams

from .classes import TestSshCases


class TestSshDHParams(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port=None, timeout=None, ip=None):
        analyzer = AnalyzerDHParams()
        l7_client = L7ClientSsh(host, port, timeout, ip=ip)
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
        self.assertEqual(result.group_exchange.key_sizes, [2048, 3072, 4096, 6144, 7680, 8192])
        self.assertFalse(result.group_exchange.bounds_tolerated)

        result = self.get_result('github.com', 22)
        self.assertEqual(result.key_exchange, None)
        self.assertEqual(result.group_exchange.gex_algorithms, [SshKexAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256])
        self.assertEqual(result.group_exchange.key_sizes, [2048, 3072, 4096, 6144, 7680, 8192])
        self.assertTrue(result.group_exchange.bounds_tolerated)

        result = self.get_result('gitlab.com', 22)
        self.assertEqual(result.key_exchange.kex_algorithms, [
            SshKexAlgorithm.DIFFIE_HELLMAN_GROUP16_SHA512,
            SshKexAlgorithm.DIFFIE_HELLMAN_GROUP18_SHA512,
            SshKexAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA256,
            SshKexAlgorithm.DIFFIE_HELLMAN_GROUP14_SHA1,
        ])
        self.assertEqual(result.group_exchange.gex_algorithms, [SshKexAlgorithm.DIFFIE_HELLMAN_GROUP_EXCHANGE_SHA256])
        self.assertEqual(result.group_exchange.key_sizes, [2048, 3072, 4096, 6144, 7680, 8192])
        self.assertTrue(result.group_exchange.bounds_tolerated)
