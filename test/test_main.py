# -*- coding: utf-8 -*-

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import unittest

import sys
import os

import test.tls.test_ciphers
import test.tls.test_curves
import test.tls.test_dhparams
import test.tls.test_pubkeys
import test.tls.test_sigalgos
import test.tls.test_versions

import six

from cryptolyzer.__main__ import main


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

    @staticmethod
    def _get_test_analyzer_result(protocol, analyzer, address):
        with patch('sys.stdout', new_callable=six.StringIO) as stdout, \
                patch.object(sys, 'argv', ['cryptolyzer', protocol, analyzer, address]):
            main()
            return stdout.getvalue()

    def test_analyzer_uris_non_ip(self):
        self._get_test_analyzer_result('tls', 'versions', 'dns.google#non-ip-address')

    def test_analyzer_uris_ipv4(self):
        self.assertIn(
            '"ip": "8.8.8.8"',
            self._get_test_analyzer_result('tls', 'versions', 'dns.google#8.8.8.8')
        )

    def test_analyzer_output(self):
        self.assertEqual(
            self._get_test_analyzer_result('tls1', 'ciphers', 'rc4-md5.badssl.com'),
            test.tls.test_ciphers.TestTlsCiphers.get_result('rc4-md5.badssl.com', 443).as_json() + '\n'
        )
        simple_result = test.tls.test_ciphers.TestTlsCiphers.get_result('tls-v1-0.badssl.com', 1010)
        del simple_result.target
        self.assertTrue(
            simple_result.as_json() in
            self._get_test_analyzer_result('tls', 'ciphers', 'tls-v1-0.badssl.com:1010')
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'curves', 'ecc256.badssl.com:443'),
            test.tls.test_curves.TestTlsCurves.get_result('ecc256.badssl.com', 443).as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'dhparams', 'dh2048.badssl.com'),
            test.tls.test_dhparams.TestTlsDHParams.get_result('dh2048.badssl.com', 443).as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'pubkeys', 'badssl.com'),
            test.tls.test_pubkeys.TestTlsPubKeys.get_result('badssl.com', 443).as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'sigalgos', 'ecc256.badssl.com:443'),
            test.tls.test_sigalgos.TestTlsSigAlgos.get_result('ecc256.badssl.com', 443).as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls', 'versions', 'tls-v1-0.badssl.com:1010'),
            test.tls.test_versions.TestTlsVersions.get_result('tls-v1-0.badssl.com', 1010).as_json() + '\n',
        )
