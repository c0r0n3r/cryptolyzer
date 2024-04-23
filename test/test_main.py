# -*- coding: utf-8 -*-

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import sys
import os

from test.common.classes import TestMainBase

import test.ja3.test_decode
import test.ja3.test_generate

import test.tls.test_ciphers
import test.tls.test_curves
import test.tls.test_dhparams
import test.tls.test_extensions
import test.tls.test_pubkeys
import test.tls.test_pubkeyreq
import test.tls.test_sigalgos
import test.tls.test_simulations
import test.tls.test_versions
import test.tls.test_vulnerabilities
import test.tls.test_all

import colorama
import six

from cryptoparser.common.base import Serializable, SerializableTextEncoder

from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello

from cryptolyzer.common.utils import SerializableTextEncoderHighlighted
from cryptolyzer.__main__ import main, get_argument_parser, get_protocol_handler_analyzer_and_uris
from cryptolyzer.ja3.generate import AnalyzerGenerate
from cryptolyzer.tls.versions import AnalyzerVersions


class TestMain(TestMainBase):
    def setUp(self):
        self.main_func = main

    def _test_runtime_error(self, argv, error_msg):
        with patch.object(sys, 'stdout', new_callable=six.StringIO) as stdout, \
                patch.object(sys, 'argv', argv):

            main()
            self.assertEqual(stdout.getvalue().split(os.linesep)[1], '* Error: ' + error_msg)

    def test_argument_parsing(self):
        self._test_argument_help('cryptolyzer')

        self._test_argument_error(
            ['cryptolyzer', 'unsupportedprotocol'],
            'error: argument protocol: invalid choice: \'unsupportedprotocol\''
        )
        self._test_argument_error(
            ['cryptolyzer', 'tls', 'unsupportedanalyzer'],
            'error: argument analyzer: invalid choice: \'unsupportedanalyzer\''
        )
        self._test_argument_error(
            ['cryptolyzer', 'tls', 'versions', 'unsupportedprotocol://localhost'],
            'error: unsupported protocol: unsupportedprotocol'
        )
        self._test_argument_error(
            ['cryptolyzer', '--socket-timeout', '-1', 'tls', 'versions', 'unsupportedprotocol://localhost'],
            'error: argument -t/--socket-timeout: -1.0 socket timeout must be a positive integer value'
        )
        self._test_argument_error(
            ['cryptolyzer', 'ja3', 'decode', 'unsupportedformat://tag'],
            'error: unsupported protocol: unsupportedformat'
        )

    def test_runtime_error(self):
        self._test_runtime_error(
            ['cryptolyzer', 'tls', 'versions', 'unresolvable.hostname'],
            'address of the target cannot be resolved'
        )

    def test_analyzer_uris_non_ip(self):
        self._get_test_analyzer_result_json('tls', 'versions', 'dns.google#non-ip-address')

    def test_analyzer_uris_ipv4(self):
        self.assertIn('8.8.8.8', self._get_test_analyzer_result_json('tls', 'versions', 'dns.google#8.8.8.8'))
        self.assertIn('8.8.8.8', self._get_test_analyzer_result_markdown('tls', 'versions', 'dns.google#8.8.8.8'))

    def _check_higlighted_output(self, func, func_arguments, cli_arguments):
        result = func(**func_arguments)

        colorama.init()
        Serializable.post_text_encoder = SerializableTextEncoderHighlighted()
        self.assertEqual(
            self._get_test_analyzer_result_highlighted(**cli_arguments),
            result.as_markdown() + '\n',
        )
        Serializable.post_text_encoder = SerializableTextEncoder()
        colorama.deinit()

    def test_analyzer_output_highlighted(self):
        func = test.tls.test_vulnerabilities.TestTlsVulnerabilities.get_result
        func_arguments, cli_arguments = self._get_arguments('tls', 'vulns', 'dh1024.badssl.com', 443, timeout=10)
        self._check_higlighted_output(func, func_arguments, cli_arguments)

        func_arguments, cli_arguments = self._get_arguments('tls', 'vulns', 'null.badssl.com', 443, timeout=10)
        self._check_higlighted_output(func, func_arguments, cli_arguments)

        func_arguments, cli_arguments = self._get_arguments('tls', 'vulns', 'rc4.badssl.com', 443, timeout=10)
        self._check_higlighted_output(func, func_arguments, cli_arguments)

        func_arguments, cli_arguments = self._get_arguments('tls', 'vulns', 'novell.com', 443)
        self._check_higlighted_output(func, func_arguments, cli_arguments)

        with patch.object(AnalyzerVersions, '_analyze_inappropriate_version_fallback', return_value=True):
            func = test.tls.test_versions.TestTlsVersions.get_result
            func_arguments, cli_arguments = self._get_arguments('tls', 'versions', 'badssl.com', 443, timeout=10)
            self._check_higlighted_output(func, func_arguments, cli_arguments)

    def test_analyzer_output_tls_ciphers(self):
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1),
            'ciphers',
            'rc4-md5.badssl.com',
            443,
            timeout=10
        )
        result = test.tls.test_ciphers.TestTlsCiphers.get_result(**func_arguments)
        self.assertEqual(
            self._get_test_analyzer_result_json(**cli_arguments),
            result.as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown(**cli_arguments),
            result.as_markdown() + '\n'
        )

        func_arguments, cli_arguments = self._get_arguments(
            'tls',
            'all',
            'rc4-md5.badssl.com',
            443,
            timeout=10
        )
        all_result = test.tls.test_all.TestTlsAll.get_result(**func_arguments)
        result_markdown = result._as_markdown_without_target(result, 0)  # pylint: disable=protected-access
        self.assertTrue(result_markdown in all_result.as_markdown())

    def test_analyzer_output_tls_pubkeyreq(self):
        result = test.tls.test_pubkeyreq.TestTlsPublicKeyRequest.get_result(
            'client.badssl.com', 443, TlsProtocolVersion(TlsVersion.TLS1_2), timeout=10
        )
        self.assertEqual(
            self._get_test_analyzer_result_json('tls1_2', 'pubkeyreq', 'client.badssl.com:443', timeout=10),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('tls1_2', 'pubkeyreq', 'client.badssl.com:443', timeout=10),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_tls_curves(self):
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1_2),
            'curves',
            'ecc256.badssl.com',
            443,
            timeout=10
        )
        result = test.tls.test_curves.TestTlsCurves.get_result(**func_arguments)
        self.assertEqual(
            self._get_test_analyzer_result_json(**cli_arguments),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown(**cli_arguments),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_tls_dhparams(self):
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1_2),
            'dhparams',
            'dh2048.badssl.com',
            443,
            timeout=10
        )
        result = test.tls.test_dhparams.TestTlsDHParams.get_result(**func_arguments)
        self.assertEqual(
            self._get_test_analyzer_result_json(**cli_arguments),
            result.as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown(**cli_arguments),
            result.as_markdown() + '\n'
        )

    def test_analyzer_output_tls_extensions(self):
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1_2),
            'extensions',
            'dh2048.badssl.com',
            443,
            timeout=10
        )
        result = test.tls.test_extensions.TestTlsExtensions.get_result(**func_arguments)
        self.assertEqual(
            self._get_test_analyzer_result_json(**cli_arguments),
            result.as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown(**cli_arguments),
            result.as_markdown() + '\n'
        )

    def test_analyzer_output_tls_pubkeys(self):
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1_2),
            'pubkeys',
            'www.cloudflare.com',
            443,
        )
        result = test.tls.test_pubkeys.TestTlsPubKeys.get_result(**func_arguments)
        self.assertEqual(
            self._get_test_analyzer_result_json(**cli_arguments),
            result.as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown(**cli_arguments),
            result.as_markdown() + '\n'
        )

    def test_analyzer_output_tls_sigalgos(self):
        func_arguments, cli_arguments = self._get_arguments(
            TlsProtocolVersion(TlsVersion.TLS1_2),
            'sigalgos',
            'ecc256.badssl.com',
            443,
            timeout=10
        )
        result = test.tls.test_sigalgos.TestTlsSigAlgos.get_result(**func_arguments)
        self.assertEqual(
            self._get_test_analyzer_result_json(**cli_arguments),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown(**cli_arguments),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_tls_simulations(self):
        func_arguments, cli_arguments = self._get_arguments(
            'tls',
            'simulations',
            'tls-v1-0.badssl.com',
            1010,
            timeout=10
        )
        result = test.tls.test_simulations.TestTlsSimulations.get_result(**func_arguments)
        self.assertEqual(
            self._get_test_analyzer_result_json(**cli_arguments),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown(**cli_arguments),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_tls_versions(self):
        func_arguments, cli_arguments = self._get_arguments(
            'tls',
            'versions',
            'tls-v1-0.badssl.com',
            1010,
            timeout=10
        )
        result = test.tls.test_versions.TestTlsVersions.get_result(**func_arguments)
        self.assertEqual(
            self._get_test_analyzer_result_json(**cli_arguments),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown(**cli_arguments),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_tls_all(self):
        result = test.tls.test_all.TestTlsAll.get_result('rc4-md5.badssl.com', 443, protocol_version=None, timeout=10)
        self.assertEqual(
            self._get_test_analyzer_result_json('tls', 'all', 'rc4-md5.badssl.com', timeout=10),
            result.as_json() + '\n',
        )

        self.assertEqual(
            self._get_test_analyzer_result_markdown('tls', 'all', 'rc4-md5.badssl.com', timeout=10),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_ja3_decode(self):
        result = test.ja3.test_decode.TestJA3Decode.get_result('771,7-6,5-4,3-2,1-0')
        self.assertEqual(
            self._get_test_analyzer_result_json('ja3', 'decode', '771,7-6,5-4,3-2,1-0'),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('ja3', 'decode', '771,7-6,5-4,3-2,1-0'),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_ja3_generate(self):
        hello_message = TlsHandshakeClientHello([TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5])

        self.assertEqual(
            test.ja3.test_generate.TestJA3Generate.get_result(hello_message).target,
            hello_message.ja3()
        )

    def test_arguments_ja3_generate(self):
        with patch.object(sys, 'argv', ['cryptolyzer', 'ja3', 'generate', 'localhost']), \
                patch.object(AnalyzerGenerate, 'analyze', return_value=None):
            parser = get_argument_parser()
            arguments = parser.parse_args()
            protocol_handler, analyzer, uris = get_protocol_handler_analyzer_and_uris(parser, arguments)
            self.assertEqual(list(map(lambda uri: uri.scheme, uris)), [analyzer.get_default_scheme()])
            protocol_handler.analyze(analyzer, uris[0])
