# -*- coding: utf-8 -*-

from cryptodatahub.ssh.algorithm import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)

from cryptolyzer.common.result import AnalyzerTargetSsh
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.ssh.client import L7ClientSsh
from cryptolyzer.ssh.server import L7ServerSsh
from cryptolyzer.ssh.ciphers import AnalyzerCiphers, AnalyzerResultCiphers

from .classes import TestSshCases, L7ServerSshTest


class TestSshCiphers(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port=None, l4_socket_params=L4TransferSocketParams(), ip=None):
        analyzer = AnalyzerCiphers()
        l7_client = L7ClientSsh(host, port, l4_socket_params, ip=ip)
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
            hassh_fingerprint=''
        )
        self.assertTrue(analyzer_result.as_json())
        self.assertTrue(analyzer_result.as_markdown())

    def test_ciphers(self):
        threaded_server = L7ServerSshTest(L7ServerSsh('localhost', 0, L4TransferSocketParams(timeout=0.2)))
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.kex_algorithms, list(SshKexAlgorithm))
        self.assertEqual(result.host_key_algorithms, list(SshHostKeyAlgorithm))
        self.assertEqual(result.encryption_algorithms_client_to_server, list(SshEncryptionAlgorithm))
        self.assertEqual(result.encryption_algorithms_server_to_client, list(SshEncryptionAlgorithm))
        self.assertEqual(result.mac_algorithms_client_to_server, list(SshMacAlgorithm))
        self.assertEqual(result.mac_algorithms_server_to_client, list(SshMacAlgorithm))
        self.assertEqual(result.compression_algorithms_client_to_server, list(SshCompressionAlgorithm))
        self.assertEqual(result.compression_algorithms_server_to_client, list(SshCompressionAlgorithm))
        log_lines = self.get_log_lines()
        kex_algorithms = ', '.join(map(lambda kex_algorithm: kex_algorithm.value.code, SshKexAlgorithm))
        self.assertIn(f'Server offers KEX algorithms {kex_algorithms} (SSH 2.0)', log_lines[0])
        host_key_algorithms = ', '.join(map(lambda kex_algorithm: kex_algorithm.value.code, SshHostKeyAlgorithm))
        self.assertIn(f'Server offers host key algorithms {host_key_algorithms} (SSH 2.0)', log_lines[1])
        encryption_algorithms = ', '.join(map(
            lambda encryption_algorithm: encryption_algorithm.value.code,
            SshEncryptionAlgorithm
        ))
        self.assertIn(
            f'Server offers encryption algorithms client to server {encryption_algorithms} (SSH 2.0)',
            log_lines[2]
        )
        self.assertIn(
            f'Server offers encryption algorithms server to client {encryption_algorithms} (SSH 2.0)',
            log_lines[3]
        )
        mac_algorithms = ', '.join(map(lambda mac_algorithm: mac_algorithm.value.code, SshMacAlgorithm))
        self.assertIn(f'Server offers MAC algorithms client to server {mac_algorithms} (SSH 2.0)', log_lines[4])
        self.assertIn(f'Server offers MAC algorithms server to client {mac_algorithms} (SSH 2.0)', log_lines[5])

    def test_real(self):
        self.get_result('github.com')
        self.get_result('gitlab.com')
