# -*- coding: utf-8 -*-

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import sys

from test.common.classes import TestMainBase

import test.ssh.test_ciphers
import test.ssh.test_dhparams
import test.ssh.test_versions
import test.ssh.test_vulnerabilities

import urllib3


from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.ssh.analyzer import ProtocolHandlerSshVersionIndependent
from cryptolyzer.ssh.server import L7ServerSsh
from cryptolyzer.ssh.versions import AnalyzerVersions

from cryptolyzer.__main__ import main, get_argument_parser, get_protocol_handler_analyzer_and_uris

from cryptolyzer.hassh.generate import AnalyzerGenerate

from .classes import L7ServerSshTest


class TestMain(TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return main

    def setUp(self):
        self.threaded_server = L7ServerSshTest(L7ServerSsh('localhost', 0, L4TransferSocketParams(timeout=2)))
        self.threaded_server.start()

        self.host = 'localhost'
        self.port = self.threaded_server.l7_server.l4_transfer.bind_port
        self.address = f'{self.host}:{self.port}'

    def test_ciphers(self):
        self.assertEqual(
            self._get_test_analyzer_result_json('ssh2', 'ciphers', self.address),
            test.ssh.test_ciphers.TestSshCiphers.get_result(self.host, self.port).as_json() + '\n'
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
            test.ssh.test_versions.TestSshVersions.get_result(self.host, self.port).as_json() + '\n',
        )

    def test_vulns(self):
        result = test.ssh.test_vulnerabilities.TestSshVulnerabilities.get_result('gitlab.com', 22)
        self.assertEqual(
            self._get_test_analyzer_result_json('ssh', 'vulns', 'gitlab.com'),
            result.as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('ssh', 'vulns', 'gitlab.com'),
            result.as_markdown() + '\n'
        )

    def test_all_versions(self):
        url = urllib3.util.parse_url('ssh://' + self.address)
        self.assertEqual(
            self._get_test_analyzer_result_json('ssh', 'versions', self.address),
            ProtocolHandlerSshVersionIndependent().analyze(AnalyzerVersions(), url).as_json() + '\n'
        )

    def test_arguments_hassh_generate(self):
        with patch.object(sys, 'argv', ['cryptolyzer', 'hassh', 'generate', 'localhost']), \
                patch.object(AnalyzerGenerate, 'analyze', return_value=None):
            parser = get_argument_parser()
            arguments = parser.parse_args()
            protocol_handler, analyzer, uris = get_protocol_handler_analyzer_and_uris(parser, arguments)
            self.assertEqual(list(map(lambda uri: uri.scheme, uris)), [analyzer.get_default_scheme()])
            protocol_handler.analyze(analyzer, uris[0])
