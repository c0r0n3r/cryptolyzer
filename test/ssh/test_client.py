# -*- coding: utf-8 -*-

import unittest

from cryptoparser.ssh.subprotocol import SshReasonCode, SshKexAlgorithmVector
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.exception import (
    NetworkError,
    NetworkErrorType,
)

from cryptolyzer.ssh.client import L7ClientSsh, SshKeyExchangeInitKeyExchangeDHE
from cryptolyzer.ssh.exception import SshDisconnect
from cryptolyzer.ssh.server import L7ServerSsh
from cryptolyzer.ssh.versions import AnalyzerVersions

from .classes import L7ServerSshTest


class TestSshDisconnect(unittest.TestCase):
    def test_repr_and_str(self):
        alert = SshDisconnect(SshReasonCode.PROTOCOL_ERROR, 'protocol error')
        self.assertEqual(str(alert), repr(alert))


class TestL7ClientBase(unittest.TestCase):
    @staticmethod
    def get_result(host, port=22, timeout=None, ip=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientSsh(host, port, timeout, ip=ip)
        result = analyzer.analyze(l7_client)
        return result


class TestSshClientHandshake(TestL7ClientBase):
    def test_error_no_response(self):
        l7_client = L7ClientSsh('ssh.blinkenshell.org', 2222, timeout=0.5)
        with self.assertRaises(NetworkError) as context_manager:
            l7_client.do_handshake(key_exchange_init_message=SshKeyExchangeInitKeyExchangeDHE(), last_message_type=-1)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)

    def test_error_disconnect(self):
        threaded_server = L7ServerSshTest(L7ServerSsh('localhost', 0, timeout=0.2))
        threaded_server.start()

        l7_client = L7ClientSsh('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        with self.assertRaises(SshDisconnect) as context_manager:
            key_exchange_init_message = SshKeyExchangeInitKeyExchangeDHE()
            key_exchange_init_message.kex_algorithms = SshKexAlgorithmVector([
                kex_algorithm
                for kex_algorithm in key_exchange_init_message.kex_algorithms
                if kex_algorithm.value.key_size is not None
            ])
            l7_client.do_handshake(key_exchange_init_message=key_exchange_init_message, last_message_type=None)
        self.assertEqual(context_manager.exception.reason, SshReasonCode.HOST_NOT_ALLOWED_TO_CONNECT)

    def test_ssh_client(self):
        threaded_server = L7ServerSshTest(L7ServerSsh('localhost', 0, timeout=0.2))
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.protocol_versions, [SshProtocolVersion(SshVersion.SSH2, )])
