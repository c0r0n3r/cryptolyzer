# -*- coding: utf-8 -*-

import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.ssh.record import SshRecordInit
from cryptoparser.ssh.subprotocol import SshDisconnectMessage, SshProtocolMessage, SshSoftwareVersionUnparsed
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.transfer import L4ClientTCP

from cryptolyzer.ssh.client import L7ClientSsh
from cryptolyzer.ssh.exception import SshReasonCode
from cryptolyzer.ssh.server import L7ServerSsh, SshServerHandshake
from cryptolyzer.ssh.versions import AnalyzerVersions

from .classes import L7ServerSshTest


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
        self.assertEqual(result.protocol_versions, [SshProtocolVersion(SshVersion.SSH2), ])


class TestSshServerHandshake(TestL7ServerBase):
    def setUp(self):
        self.threaded_server = L7ServerSshTest(L7ServerSsh('localhost', 0, timeout=0.5))
        self.threaded_server.start()
        self.l7_client = L7ClientSsh('localhost', self.threaded_server.l7_server.l4_transfer.bind_port)

    @staticmethod
    def _receive_as_many_as_possibe_and_close(l4_client):
        try:
            while True:
                l4_client.receive(1)
        except NotEnoughData:
            pass

        l4_client.close()

    @mock.patch.object(
        SshServerHandshake, '_parse_record',
        return_value=(SshRecordInit(SshDisconnectMessage(SshReasonCode.BY_APPLICATION, 'by application')), False)
    )
    def test_error_non_handshake_message(self, _):
        l4_client = L4ClientTCP('localhost', self.threaded_server.l7_server.l4_transfer.bind_port)
        l4_client.init_connection()

        l4_client.send(SshProtocolMessage(
            SshProtocolVersion(SshVersion.SSH2, 0),
            SshSoftwareVersionUnparsed('software_version')
        ).compose())
        l4_client.send(SshRecordInit(SshDisconnectMessage(SshReasonCode.BY_APPLICATION, 'by application')).compose())
        SshRecordInit(SshDisconnectMessage(SshReasonCode.PROTOCOL_ERROR, 'protocol error', 'en')).compose()
        self._receive_as_many_as_possibe_and_close(l4_client)

    def test_error_invalid_message(self):
        l4_client = L4ClientTCP('localhost', self.threaded_server.l7_server.l4_transfer.bind_port)
        l4_client.init_connection()
        l4_client.send(SshProtocolMessage(
            SshProtocolVersion(SshVersion.SSH2, 0),
            SshSoftwareVersionUnparsed('software_version')
        ).compose())
        l4_client.send(b'\x00\x00\x00\x05\x00\x00\x00\x00\xff')
        self._receive_as_many_as_possibe_and_close(l4_client)

    def test_ssh_client(self):
        result = self.get_result('localhost', self.threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.protocol_versions, [SshProtocolVersion(SshVersion.SSH2, )])
