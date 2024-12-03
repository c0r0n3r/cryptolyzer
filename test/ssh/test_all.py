# -*- coding: utf-8 -*-

from unittest import mock

from cryptodatahub.ssh.algorithm import SshKexAlgorithm
from cryptoparser.ssh.version import SshVersion, SshProtocolVersion

from cryptolyzer.common.result import AnalyzerTargetSsh
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.ssh.all import AnalyzerAll
from cryptolyzer.ssh.ciphers import AnalyzerResultCiphers
from cryptolyzer.ssh.client import L7ClientSsh

from .classes import TestSshCases


class TestSshAll(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port, l4_socket_params=L4TransferSocketParams(), ip=None):
        analyzer = AnalyzerAll()
        l7_client = L7ClientSsh.from_scheme('ssh', host, port, l4_socket_params, ip)
        result = analyzer.analyze(l7_client)
        return result

    def test_is_dhe_supported(self):
        target = AnalyzerTargetSsh('ssh', 'one.one.one.one', '1.1.1.1', 443, None)
        self.assertEqual(AnalyzerAll.is_dhe_supported(
            AnalyzerResultCiphers(
                target,
                kex_algorithms=[],
                host_key_algorithms=[],
                encryption_algorithms_client_to_server=[],
                encryption_algorithms_server_to_client=[],
                mac_algorithms_client_to_server=[],
                mac_algorithms_server_to_client=[],
                compression_algorithms_client_to_server=[],
                compression_algorithms_server_to_client=[],
                hassh_fingerprint=''
            )
        ), None)

        self.assertEqual(AnalyzerAll.is_dhe_supported(
            AnalyzerResultCiphers(
                target,
                kex_algorithms=[
                    SshKexAlgorithm.ECDH_SHA2_NISTP256,
                    SshKexAlgorithm.DIFFIE_HELLMAN_GROUP1_SHA1,
                ],
                host_key_algorithms=[],
                encryption_algorithms_client_to_server=[],
                encryption_algorithms_server_to_client=[],
                mac_algorithms_client_to_server=[],
                mac_algorithms_server_to_client=[],
                compression_algorithms_client_to_server=[],
                compression_algorithms_server_to_client=[],
                hassh_fingerprint=''
            ),
        ), SshProtocolVersion(SshVersion.SSH2))

    def test_markdown(self):
        result = self.get_result('github.com', 22)
        markdown_result = result.as_markdown()

        target_index = markdown_result.find('Target')
        self.assertNotEqual(target_index, -1)
        target_index = markdown_result.find('Target', target_index + 1)
        self.assertEqual(target_index, -1)

    def test_missing_parts(self):
        with mock.patch.object(AnalyzerAll, 'is_dhe_supported', return_value=None):
            result = self.get_result('github.com', 22)

        self.assertEqual(result.dhparams, None)
        self.assertNotEqual(result.versions, None)

        result = self.get_result('github.com', 22)
        self.assertNotEqual(result.ciphers, None)
        self.assertNotEqual(result.dhparams, None)
        self.assertNotEqual(result.versions, None)
