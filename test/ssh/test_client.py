# -*- coding: utf-8 -*-

import unittest
from unittest import mock

from cryptodatahub.common.algorithm import NamedGroup

from cryptoparser.ssh.subprotocol import (
    SshDHKeyExchangeReply,
    SshKexAlgorithmVector,
    SshMessageCode,
    SshReasonCode,
)
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.ssh.client import (
    L7ClientSsh,
    SshKeyExchangeInitKeyExchangeDHE,
    SshKeyExchangeInitKeyExchangeECDHE,
    SSH_KEX_ALGORITHMS_TO_NAMED_GROUP,
)
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
    def get_result(host, port=22, l4_socket_params=L4TransferSocketParams(), ip=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientSsh(host, port, l4_socket_params, ip=ip)
        result = analyzer.analyze(l7_client)
        return result


class TestSshClientHandshake(TestL7ClientBase):
    @mock.patch('cryptolyzer.ssh.client.SSH_KEX_ALGORITHMS_TO_NAMED_GROUP', {})
    def test_error_kex_not_implemented(self):
        l7_client = L7ClientSsh('github.com', l4_socket_params=L4TransferSocketParams(timeout=0.5))
        with self.assertRaises(NotImplementedError):
            l7_client.do_handshake(key_exchange_init_message=SshKeyExchangeInitKeyExchangeECDHE(), last_message_type=-1)

    def test_error_disconnect(self):
        threaded_server = L7ServerSshTest(L7ServerSsh(
            'localhost', 0, l4_socket_params=L4TransferSocketParams(timeout=0.2)
        ))
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

    def test_kex_ecdhe(self):
        l7_client = L7ClientSsh('github.com')
        key_exchange_init_message = SshKeyExchangeInitKeyExchangeECDHE()
        key_exchange_init_message.kex_algorithms = SshKexAlgorithmVector(filter(
            lambda kex_algorithm: SSH_KEX_ALGORITHMS_TO_NAMED_GROUP.get(kex_algorithm, None) in [
                NamedGroup.CURVE25519,
                NamedGroup.CURVE448,
            ],
            key_exchange_init_message.kex_algorithms
        ))
        server_messages = l7_client.do_handshake(
            key_exchange_init_message=key_exchange_init_message,
            last_message_type=SshMessageCode.NEWKEYS
        )
        self.assertIn(SshDHKeyExchangeReply, server_messages.keys())

        l7_client = L7ClientSsh('github.com')
        key_exchange_init_message = SshKeyExchangeInitKeyExchangeECDHE()
        key_exchange_init_message.kex_algorithms = SshKexAlgorithmVector(filter(
            lambda kex_algorithm: SSH_KEX_ALGORITHMS_TO_NAMED_GROUP.get(kex_algorithm, None) not in [
                NamedGroup.CURVE25519,
                NamedGroup.CURVE448,
            ],
            key_exchange_init_message.kex_algorithms
        ))
        server_messages = l7_client.do_handshake(
            key_exchange_init_message=key_exchange_init_message,
            last_message_type=SshMessageCode.NEWKEYS
        )
        self.assertIn(SshDHKeyExchangeReply, server_messages.keys())

    def test_ssh_client(self):
        threaded_server = L7ServerSshTest(L7ServerSsh('localhost', 0, L4TransferSocketParams(timeout=0.2)))
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.protocol_versions, [SshProtocolVersion(SshVersion.SSH2, )])
