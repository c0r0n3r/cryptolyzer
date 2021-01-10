# -*- coding: utf-8 -*-

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import unittest

import sys
import os

import test.ja3.test_decode
import test.ja3.test_generate

import test.tls.test_ciphers
import test.tls.test_curves
import test.tls.test_dhparams
import test.tls.test_pubkeys
import test.tls.test_pubkeyreq
import test.tls.test_sigalgos
import test.tls.test_versions

import six

from cryptoparser.tls.version import TlsProtocolVersionFinal, TlsVersion

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello

from cryptolyzer.__main__ import main, get_argument_parser, get_protocol_handler_analyzer_and_uris
from cryptolyzer.ja3.generate import AnalyzerGenerate


class TestMain(unittest.TestCase):
    def _test_argument_error(self, argv, stderr_regexp):
        with patch.object(sys, 'stderr', new_callable=six.StringIO) as stderr, \
                patch.object(sys, 'argv', argv):

            with self.assertRaises(SystemExit) as context_manager:
                main()
            self.assertEqual(context_manager.exception.args[0], 2)
            six.assertRegex(self, stderr.getvalue(), stderr_regexp)

    def test_argument_parsing(self):
        with open(os.devnull, 'w') as devnull, \
                patch.object(sys, 'stdout', devnull), \
                patch.object(sys, 'argv', ['cryptolyzer', '-h']):

            with self.assertRaises(SystemExit) as context_manager:
                main()
            self.assertEqual(context_manager.exception.args[0], 0)

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
            ['cryptolyzer', 'ja3', 'decode', 'unsupportedformat://tag'],
            'error: unsupported protocol: unsupportedformat'
        )

    @staticmethod
    def _get_test_analyzer_result(output_format, protocol, analyzer, address):
        with patch('sys.stdout', new_callable=six.StringIO) as stdout, \
                patch.object(
                    sys, 'argv', ['cryptolyzer', '--output-format', output_format, protocol, analyzer, address]
                ):
            main()
            return stdout.getvalue()

    @staticmethod
    def _get_test_analyzer_result_json(protocol, analyzer, address):
        return TestMain._get_test_analyzer_result('json', protocol, analyzer, address)

    @staticmethod
    def _get_test_analyzer_result_markdown(protocol, analyzer, address):
        return TestMain._get_test_analyzer_result('markdown', protocol, analyzer, address)

    def test_analyzer_uris_non_ip(self):
        self._get_test_analyzer_result_json('tls', 'versions', 'dns.google#non-ip-address')

    def test_analyzer_uris_ipv4(self):
        self.assertIn('8.8.8.8', self._get_test_analyzer_result_json('tls', 'versions', 'dns.google#8.8.8.8'))
        self.assertIn('8.8.8.8', self._get_test_analyzer_result_markdown('tls', 'versions', 'dns.google#8.8.8.8'))

    def test_analyzer_output_tls_ciphers(self):
        result = test.tls.test_ciphers.TestTlsCiphers.get_result(
            'rc4-md5.badssl.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_0)
        )
        self.assertEqual(
            self._get_test_analyzer_result_json('tls1', 'ciphers', 'rc4-md5.badssl.com'),
            result.as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('tls1', 'ciphers', 'rc4-md5.badssl.com'),
            result.as_markdown() + '\n'
        )
        simple_result = test.tls.test_ciphers.TestTlsCiphers.get_result('tls-v1-0.badssl.com', 1010)
        del simple_result.target
        self.assertTrue(
            simple_result.as_json() in
            self._get_test_analyzer_result_json('tls', 'ciphers', 'tls-v1-0.badssl.com:1010')
        )
        self.assertTrue(
            simple_result.as_markdown() in
            self._get_test_analyzer_result_markdown('tls1', 'ciphers', 'tls-v1-0.badssl.com:1010')
        )

    def test_analyzer_output_tls_pubkeyreq(self):
        result = test.tls.test_pubkeyreq.TestTlsPublicKeyRequest.get_result(
            'client.badssl.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        )
        self.assertEqual(
            self._get_test_analyzer_result_json('tls1_2', 'pubkeyreq', 'client.badssl.com:443'),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('tls1_2', 'pubkeyreq', 'client.badssl.com:443'),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_tls_curves(self):
        result = test.tls.test_curves.TestTlsCurves.get_result(
            'ecc256.badssl.com', 443, TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        )
        self.assertEqual(
            self._get_test_analyzer_result_json('tls1_2', 'curves', 'ecc256.badssl.com:443'),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('tls1_2', 'curves', 'ecc256.badssl.com:443'),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_tls_dhparams(self):
        result = test.tls.test_dhparams.TestTlsDHParams.get_result('dh2048.badssl.com', 443)
        self.assertEqual(
            self._get_test_analyzer_result_json('tls1_2', 'dhparams', 'dh2048.badssl.com'),
            result.as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('tls1_2', 'dhparams', 'dh2048.badssl.com'),
            result.as_markdown() + '\n'
        )

    def test_analyzer_output_tls_pubkeys(self):
        result = test.tls.test_pubkeys.TestTlsPubKeys.get_result('www.cloudflare.com', 443)
        self.assertEqual(
            self._get_test_analyzer_result_json(
                'tls1_2', 'pubkeys', '#'.join(['www.cloudflare.com', result.target.ip])
            ),
            result.as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown(
                'tls1_2', 'pubkeys', '#'.join(['www.cloudflare.com', result.target.ip])
            ),
            result.as_markdown() + '\n'
        )

    def test_analyzer_output_tls_sigalgos(self):
        result = test.tls.test_sigalgos.TestTlsSigAlgos.get_result('ecc256.badssl.com', 443)
        self.assertEqual(
            self._get_test_analyzer_result_json('tls1_2', 'sigalgos', 'ecc256.badssl.com:443'),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('tls1_2', 'sigalgos', 'ecc256.badssl.com:443'),
            result.as_markdown() + '\n',
        )

    def test_analyzer_output_tls_versions(self):
        result = test.tls.test_versions.TestTlsVersions.get_result('tls-v1-0.badssl.com', 1010)
        self.assertEqual(
            self._get_test_analyzer_result_json('tls', 'versions', 'tls-v1-0.badssl.com:1010'),
            result.as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result_markdown('tls', 'versions', 'tls-v1-0.badssl.com:1010'),
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
