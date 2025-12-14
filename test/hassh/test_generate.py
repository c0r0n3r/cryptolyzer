# -*- coding: utf-8 -*-

import time

from test.common.classes import TestThreadedServer, TestLoggerBase


from cryptodatahub.ssh.algorithm import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)

from cryptolyzer.common.exception import NetworkError
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.hassh.generate import AnalyzerGenerate
from cryptolyzer.ssh.client import L7ClientSsh, SshKeyExchangeInitAnyAlgorithm
from cryptolyzer.ssh.server import L7ServerSsh, SshServerConfiguration


class AnalyzerThread(TestThreadedServer):
    def __init__(self, configuration=None):
        self.l7_server = L7ServerSsh('localhost', 0, configuration=configuration)
        super().__init__(self.l7_server)

        self.analyzer = AnalyzerGenerate()
        self.result = None

    def run(self):
        self.result = self.analyzer.analyze(self.l7_server)


class TestHASSHGenerate(TestLoggerBase):
    @staticmethod
    def get_result(key_exchange_init_message):
        analyzer_thread = AnalyzerThread(SshServerConfiguration())
        analyzer_thread.wait_for_server_listen()

        l7_client = L7ClientSsh(
            analyzer_thread.l7_server.address,
            analyzer_thread.l7_server.l4_transfer.bind_port,
            ip=analyzer_thread.l7_server.ip
        )
        l7_client.do_handshake(key_exchange_init_message=key_exchange_init_message)

        analyzer_thread.join()
        return analyzer_thread.result

    def test_error_no_connection(self):
        with self.assertRaisesRegex(NetworkError, 'connection to target cannot be established'):
            configuration = SshServerConfiguration()
            l7_server = L7ServerSsh('localhost', 0, L4TransferSocketParams(timeout=0.1), configuration=configuration)
            l7_server.init_connection()
            analyzer = AnalyzerGenerate()
            analyzer.analyze(l7_server)
            time.sleep(1)

    def test_tag_minimal(self):
        def get_sorted_enum(enum_class):
            return tuple(sorted(enum_class, key=lambda algorithm: algorithm.name))

        key_exchange_init_message = SshKeyExchangeInitAnyAlgorithm(
            kex_algorithms=get_sorted_enum(SshKexAlgorithm),
            host_key_algorithms=get_sorted_enum(SshHostKeyAlgorithm),
            encryption_algorithms_client_to_server=get_sorted_enum(SshEncryptionAlgorithm),
            encryption_algorithms_server_to_client=get_sorted_enum(SshEncryptionAlgorithm),
            mac_algorithms_client_to_server=get_sorted_enum(SshMacAlgorithm),
            mac_algorithms_server_to_client=get_sorted_enum(SshMacAlgorithm),
            compression_algorithms_client_to_server=get_sorted_enum(SshCompressionAlgorithm),
            compression_algorithms_server_to_client=get_sorted_enum(SshCompressionAlgorithm),
        )

        result = self.get_result(key_exchange_init_message)
        self.assertEqual(result.target, '8effcf59ef85dc9e494617cdc5fe0517')
        self.assertEqual(
            self.log_stream.getvalue(),
            f'Client offers SSH key exchange init which HASSH fingerprint is "{result.target}"\n'
        )
