# SPDX-License-Identifier: MPL-2.0

from unittest import mock
from test.common.markers import live_server
from test.common.classes import OFFLINE_CLIENT_L4_SOCKET_PARAMS, OFFLINE_L4_SOCKET_PARAMS

from cryptodatahub.ssh.algorithm import SshHostKeyAlgorithm, SshKexAlgorithm
from cryptoparser.ssh.version import SshVersion, SshProtocolVersion

from cryptolyzer.common.result import AnalyzerTargetSsh

from cryptolyzer.ssh.all import AnalyzerAll
from cryptolyzer.ssh.ciphers import AnalyzerResultCiphers
from cryptolyzer.ssh.client import L7ClientSsh
from cryptolyzer.ssh.server import L7ServerSsh, SshServerConfiguration

from .classes import L7ServerSshTest, TestSshCases


class TestSshAll(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port, l4_socket_params=OFFLINE_CLIENT_L4_SOCKET_PARAMS, ip=None):
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

    @staticmethod
    def _start_offline_server():
        server_configuration = SshServerConfiguration(
            key_exchange_reply=True,
            server_host_key_algorithms=[SshHostKeyAlgorithm.SSH_RSA],
        )
        threaded_server = L7ServerSshTest(L7ServerSsh(
            'localhost', 0, OFFLINE_L4_SOCKET_PARAMS, configuration=server_configuration
        ))
        threaded_server.start()

        return threaded_server

    def test_offline_full(self):
        threaded_server = self._start_offline_server()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        self.assertIsNotNone(result.versions)
        self.assertIsNotNone(result.ciphers)
        self.assertIsNotNone(result.dhparams)
        self.assertEqual(len(result.pubkeys.public_keys), 1)

        markdown_result = result.as_markdown()
        target_index = markdown_result.find('Target')
        self.assertNotEqual(target_index, -1)
        self.assertEqual(markdown_result.find('Target', target_index + 1), -1)

    def test_offline_missing_dhparams(self):
        threaded_server = self._start_offline_server()

        with mock.patch.object(AnalyzerAll, 'is_dhe_supported', return_value=None):
            result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)

        self.assertIsNone(result.dhparams)
        self.assertIsNotNone(result.versions)
        self.assertIsNotNone(result.ciphers)

    @live_server
    def test_markdown(self):
        result = self.get_result('github.com', 22)
        markdown_result = result.as_markdown()

        target_index = markdown_result.find('Target')
        self.assertNotEqual(target_index, -1)
        target_index = markdown_result.find('Target', target_index + 1)
        self.assertEqual(target_index, -1)

    @live_server
    def test_missing_parts(self):
        with mock.patch.object(AnalyzerAll, 'is_dhe_supported', return_value=None):
            result = self.get_result('github.com', 22)

        self.assertEqual(result.dhparams, None)
        self.assertNotEqual(result.versions, None)

        result = self.get_result('github.com', 22)
        self.assertNotEqual(result.ciphers, None)
        self.assertNotEqual(result.dhparams, None)
        self.assertNotEqual(result.versions, None)
