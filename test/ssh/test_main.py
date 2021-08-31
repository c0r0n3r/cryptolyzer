# -*- coding: utf-8 -*-

from test.common.classes import TestMainBase

import test.ssh.test_ciphers
import test.ssh.test_dhparams
import test.ssh.test_versions

import urllib3

import six

from cryptolyzer.ssh.analyzer import ProtocolHandlerSshAllSupportedVersions
from cryptolyzer.ssh.ciphers import AnalyzerCiphers
from cryptolyzer.ssh.server import L7ServerSsh

from .classes import L7ServerSshTest


class TestMain(TestMainBase):
    def setUp(self):
        self.threaded_server = L7ServerSshTest(L7ServerSsh('localhost', 0, timeout=1))
        self.threaded_server.start()

        self.host = 'localhost'
        self.port = self.threaded_server.l7_server.l4_transfer.bind_port
        self.address = '{}:{}'.format(self.host, self.port)

    def test_ciphers(self):
        self.assertEqual(
            self._get_test_analyzer_result_json('ssh2', 'ciphers', self.address),
            test.ssh.test_ciphers.TestSshCiphers.get_result(six.u(self.host), self.port).as_json() + '\n'
        )

    def test_dhparams(self):
        result = test.ssh.test_dhparams.TestSshDHParams.get_result('gitlab.com', 22)
        self.assertEqual(
            self._get_test_analyzer_result_json('ssh2', 'dhparams', 'gitlab.com'),
            result.as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('ssh2', 'dhparams', 'gitlab.com'),
            result.as_markdown() + '\n',
        )

    def test_versions(self):
        self.assertEqual(
            self._get_test_analyzer_result_json('ssh', 'versions', self.address),
            test.ssh.test_versions.TestSshVersions.get_result(six.u(self.host), self.port).as_json() + '\n',
        )

    def test_all_versions(self):
        url = urllib3.util.parse_url('ssh://' + self.address)
        self.assertEqual(
            self._get_test_analyzer_result_json('ssh', 'ciphers', self.address),
            ProtocolHandlerSshAllSupportedVersions().analyze(AnalyzerCiphers(), url).as_json() + '\n'
        )
