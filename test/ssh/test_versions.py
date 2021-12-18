# -*- coding: utf-8 -*-

from cryptolyzer.ssh.client import L7ClientSsh, SshProtocolMessageDefault
from cryptolyzer.ssh.server import L7ServerSsh
from cryptolyzer.ssh.versions import AnalyzerVersions

from .classes import TestSshCases, L7ServerSshTest


class TestL7ClientBase(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port=None, timeout=None, ip=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientSsh(host, port, timeout, ip=ip)
        result = analyzer.analyze(l7_client)
        return result


class TestSshVersions(TestL7ClientBase):
    def test_versions(self):
        protocol_message_default = SshProtocolMessageDefault()
        threaded_server = L7ServerSshTest(L7ServerSsh('localhost', 0, timeout=0.2))
        threaded_server.start()

        result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
        self.assertEqual(result.protocol_versions, [protocol_message_default.protocol_version, ])
        self.assertEqual(result.software_version, protocol_message_default.software_version)
