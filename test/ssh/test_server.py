# -*- coding: utf-8 -*-

import unittest

from cryptoparser.ssh.subprotocol import SshDisconnectMessage
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.ssh.client import L7ClientSsh
from cryptolyzer.ssh.exception import SshDisconnect, SshReasonCode
from cryptolyzer.ssh.server import L7ServerSsh
from cryptolyzer.ssh.versions import AnalyzerVersions

from .classes import L7ServerSshTest, TestSshMessageInvalid


class TestL7ServerBase(unittest.TestCase):
    @staticmethod
    def get_result(host, port, timeout=None, ip=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientSsh(host, port, timeout, ip=ip)
        result = analyzer.analyze(l7_client)
        return result


class TestSshServerDefaults(TestL7ServerBase):
    def test_l7_server_defaults(self):
        threaded_server = L7ServerSshTest(L7ServerSsh.from_scheme('ssh', 'localhost'))
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.versions, [SshProtocolVersion(SshVersion.SSH2), ])


class TestSshServerHandshake(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = L7ServerSshTest(L7ServerSsh('localhost', 0, timeout=0.5))
        self.threaded_server.start()
        self.l7_client = L7ClientSsh('localhost', self.threaded_server.l7_server.l4_transfer.bind_port)

    def test_error_non_handshake_message(self):
        with self.assertRaises(SshDisconnect) as context_manager:
            self.l7_client.do_handshake(
                key_exchange_init_message=SshDisconnectMessage(SshReasonCode.BY_APPLICATION, 'by application')
            )
        self.assertEqual(context_manager.exception.reason, SshReasonCode.PROTOCOL_ERROR)

    def test_error_invalid_message(self):
        with self.assertRaises(SshDisconnect) as context_manager:
            self.l7_client.do_handshake(key_exchange_init_message=TestSshMessageInvalid())
        self.assertEqual(context_manager.exception.reason, SshReasonCode.PROTOCOL_ERROR)

    def test_ssh_client(self):
        result = self.get_result('localhost', self.threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.versions, [SshProtocolVersion(SshVersion.SSH2, )])
