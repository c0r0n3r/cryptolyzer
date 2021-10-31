# -*- coding: utf-8 -*-

from cryptoparser.ssh.ciphersuite import SshKexAlgorithm, SshEncryptionAlgorithm, SshMacAlgorithm

from cryptolyzer.common.result import AnalyzerTargetSsh

from cryptolyzer.ssh.client import L7ClientSsh
from cryptolyzer.ssh.server import L7ServerSsh
from cryptolyzer.ssh.ciphers import AnalyzerCiphers, AnalyzerResultCiphers

from .classes import TestSshCases, L7ServerSshTest


class TestSshCiphers(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port=None, timeout=None, ip=None):
        analyzer = AnalyzerCiphers()
        l7_client = L7ClientSsh(host, port, timeout, ip=ip)
        result = analyzer.analyze(l7_client)
        return result

    def test_ciphers_unknown(self):
        analyzer_result = AnalyzerResultCiphers(
            target=AnalyzerTargetSsh('tls', 'one.one.one.one', '1.1.1.1', 443),
            kex_algorithms=('kex_algorithm', ),
            host_key_algorithms=('host_key_algorithm', ),
            encryption_algorithms_client_to_server=('encryption_algorithm_client_to_server', ),
            encryption_algorithms_server_to_client=('encryption_algorithm_server_to_client', ),
            mac_algorithms_client_to_server=('mac_algorithm_client_to_server', ),
            mac_algorithms_server_to_client=('mac_algorithm_server_to_client', ),
            compression_algorithms_client_to_server=('compression_algorithm_client_to_server', ),
            compression_algorithms_server_to_client=('compression_algorithm_server_to_client', ),
        )
        self.assertTrue(analyzer_result.as_json())
        self.assertTrue(analyzer_result.as_markdown())

    def test_ciphers(self):
        threaded_server = L7ServerSshTest(L7ServerSsh('localhost', 0, timeout=0.2))
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.kex_algorithms, list(SshKexAlgorithm))
        self.assertEqual(result.encryption_algorithms_client_to_server, list(SshEncryptionAlgorithm))
        self.assertEqual(result.encryption_algorithms_server_to_client, list(SshEncryptionAlgorithm))
        self.assertEqual(result.mac_algorithms_client_to_server, list(SshMacAlgorithm))
        self.assertEqual(result.mac_algorithms_server_to_client, list(SshMacAlgorithm))

    def test_real(self):
        self.get_result('github.com')
        self.get_result('gitlab.com')
