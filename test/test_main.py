# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import argparse
import io
import logging
import sys
import os

from test.common.classes import TestMainBase

import test.fingerprint.test_decode
import test.fingerprint.test_generate

import test.tls.test_versions
import test.tls.test_vulnerabilities
from test.common.markers import live_dns, live_server

import colorama
import urllib3

from cryptoparser.common.base import Serializable, SerializableTextEncoder

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello

from cryptolyzer.common.analyzer import AnalyzerIKEBase
from cryptolyzer.common.utils import LogSingleton, SerializableTextEncoderHighlighted
from cryptolyzer.__main__ import (
    get_argument_parser,
    get_protocol_handler_analyzer_and_uris,
    main,
    parse_arg_parallel,
    parse_arg_socket_timeout,
    parse_arg_throttle_delay,
    parse_arg_http_proxy,
)
from cryptolyzer.fingerprint.generate import AnalyzerGenerate
from cryptolyzer.tls.versions import AnalyzerVersions


class TestMain(TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return main

    def _test_runtime_error(self, argv, error_msg):
        with patch.object(sys, 'stdout', new_callable=io.StringIO) as stdout, \
                patch.object(sys, 'argv', argv):

            main()
            self.assertEqual(stdout.getvalue().split(os.linesep)[1], '* Error: ' + error_msg)

    def test_error_argument_parsing(self):
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
            ['cryptolyzer', '--http-proxy', 'https://proxy', 'tls', 'versions', 'unsupportedprotocol://localhost'],
            'cryptolyze: error: argument -p/--http-proxy: only HTTP proxy is supported'
        )
        self._test_argument_error(
            ['cryptolyzer', 'fingerprint', 'decode', 'unsupportedformat://tag'],
            'error: unsupported protocol: unsupportedformat'
        )

        with self.assertRaises(argparse.ArgumentTypeError) as context_manager:
            parse_arg_socket_timeout(-1)
        self.assertEqual(
            context_manager.exception.args,
            ('-1.0 socket timeout must be a positive integer value',)
        )

        with self.assertRaises(argparse.ArgumentTypeError) as context_manager:
            parse_arg_throttle_delay(-1)
        self.assertEqual(
            context_manager.exception.args,
            ('-1.0 throttle delay must be non-negative',)
        )

        with self.assertRaises(argparse.ArgumentTypeError) as context_manager:
            parse_arg_http_proxy('https://proxy')
        self.assertEqual(
            context_manager.exception.args,
            ('only HTTP proxy is supported',)
        )

    def test_argument_parsing(self):
        self.assertEqual(parse_arg_http_proxy('proxy'), urllib3.util.parse_url('http://proxy'))
        self.assertEqual(parse_arg_http_proxy('http://proxy'), urllib3.util.parse_url('http://proxy'))

        self.assertEqual(parse_arg_parallel('1'), 1)

        self.assertEqual(parse_arg_socket_timeout(1), 1.0)
        self.assertEqual(parse_arg_throttle_delay('0.5'), 0.5)

    def test_argument_parsing_parallel_error(self):
        with self.assertRaises(argparse.ArgumentTypeError) as context_manager:
            parse_arg_parallel(0)
        self.assertEqual(
            context_manager.exception.args,
            ('0 parallel must be a positive integer value',)
        )

    @live_dns
    def test_runtime_error(self):
        self._test_runtime_error(
            ['cryptolyzer', 'tls', 'versions', 'unresolvable.hostname'],
            'address of the target cannot be resolved'
        )

    @live_server
    def test_analyzer_uris_non_ip(self):
        self._get_test_analyzer_result_json('tls', 'versions', 'dns.google#non-ip-address')

    @live_server
    def test_analyzer_uris_ipv4(self):
        self.assertIn('8.8.8.8', self._get_test_analyzer_result_json('tls', 'versions', 'dns.google#8.8.8.8'))
        self.assertIn('8.8.8.8', self._get_test_analyzer_result_markdown('tls', 'versions', 'dns.google#8.8.8.8'))

    def _check_highlighted_output(self, func, func_arguments, cli_arguments):
        result = func(**func_arguments)

        colorama.init()
        Serializable.post_text_encoder = SerializableTextEncoderHighlighted()
        self.assertEqual(
            self._get_test_analyzer_result_highlighted(**cli_arguments),
            result.as_markdown() + '\n',
        )
        Serializable.post_text_encoder = SerializableTextEncoder()
        colorama.deinit()

    @live_server
    def test_analyzer_output_highlighted(self):
        func = test.tls.test_vulnerabilities.TestTlsVulnerabilities.get_result
        func_arguments, cli_arguments = self._get_arguments('tls', 'vulns', 'dh1024.badssl.com', 443, timeout=10,
                                                            scheme='https')
        self._check_highlighted_output(func, func_arguments, cli_arguments)

        func_arguments, cli_arguments = self._get_arguments('tls', 'vulns', 'null.badssl.com', 443, timeout=10,
                                                            scheme='https')
        self._check_highlighted_output(func, func_arguments, cli_arguments)

        func_arguments, cli_arguments = self._get_arguments('tls', 'vulns', 'rc4.badssl.com', 443, timeout=10,
                                                            scheme='https')
        self._check_highlighted_output(func, func_arguments, cli_arguments)

        func_arguments, cli_arguments = self._get_arguments('tls', 'vulns', 'novell.com', 443, timeout=10,
                                                            scheme='https')
        self._check_highlighted_output(func, func_arguments, cli_arguments)

        with patch.object(AnalyzerVersions, '_analyze_inappropriate_version_fallback', return_value=True):
            func = test.tls.test_versions.TestTlsVersions.get_result
            func_arguments, cli_arguments = self._get_arguments('tls', 'versions', 'badssl.com', 443, timeout=10,
                                                                scheme='https')
            self._check_highlighted_output(func, func_arguments, cli_arguments)

    def test_analyzer_output_fingerprint_decode(self):
        result = test.fingerprint.test_decode.TestFingerprintDecode.get_result('771,7-6,5-4,3-2,1-0')
        self.assertEqual(
            self._get_test_analyzer_result_json('fingerprint', 'decode', '771,7-6,5-4,3-2,1-0'),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('fingerprint', 'decode', '771,7-6,5-4,3-2,1-0'),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_fingerprint_decode_ja4(self):
        tag = 't13d0101h2_1301_002b_0403'
        result = test.fingerprint.test_decode.TestFingerprintDecodeJA4.get_result(tag)
        self.assertEqual(
            self._get_test_analyzer_result_json('fingerprint', 'decode', f'ja4://{tag}'),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('fingerprint', 'decode', f'ja4://{tag}'),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_fingerprint_generate(self):
        hello_message = TlsHandshakeClientHello([TlsCipherSuite.TLS_RSA_EXPORT_WITH_RC4_40_MD5])

        self.assertEqual(
            test.fingerprint.test_generate.TestFingerprintGenerateTls.get_result(hello_message).target.ja3.tag,
            hello_message.ja3()
        )

    def test_arguments_fingerprint_generate(self):
        with patch.object(sys, 'argv', ['cryptolyzer', 'fingerprint', 'generate', 'localhost']), \
                patch.object(AnalyzerGenerate, 'analyze', return_value=None):
            parser = get_argument_parser()
            arguments = parser.parse_args()
            protocol_handler, analyzer, uris = get_protocol_handler_analyzer_and_uris(parser, arguments)
            self.assertEqual(list(map(lambda uri: uri.scheme, uris)), [analyzer.get_default_scheme()])
            protocol_handler.analyze(analyzer, uris[0])

    def test_log_level(self):
        self.addCleanup(LogSingleton().setLevel, logging.INFO)
        with patch.object(sys, 'argv', ['cryptolyzer', '--log-level', 'debug', 'tls', 'versions', 'localhost']), \
                patch('cryptolyzer.__main__.get_protocol_handler_analyzer_and_uris', return_value=(None, None, [])):
            main()
        self.assertEqual(LogSingleton().level, logging.DEBUG)

    def test_strict_rfc_2409(self):
        self.addCleanup(AnalyzerIKEBase.set_strict_rfc_2409_compliance, False)
        with patch.object(sys, 'argv', ['cryptolyzer', 'ikev1', '--strict-rfc-2409', 'dhparams', 'localhost']), \
                patch('cryptolyzer.__main__.get_protocol_handler_analyzer_and_uris', return_value=(None, None, [])):
            main()
        self.assertEqual(AnalyzerIKEBase._MAX_PROPOSALS_PER_INIT_MESSAGE, 1)  # pylint: disable=protected-access
