#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

import sys
import os
import six

from cryptolyzer.__main__ import main

import tests.tls.test_ciphers
import tests.tls.test_curves
import tests.tls.test_dhparams
import tests.tls.test_pubkeys
import tests.tls.test_sigalgos
import tests.tls.test_versions


class TestMain(unittest.TestCase):
    def test_argument_parsing(self):
        with open(os.devnull, 'w') as devnull, \
                patch.object(sys, 'stdout', devnull), \
                patch.object(sys, 'argv', ['cryptolyzer', '-h']):

            with self.assertRaises(SystemExit) as context_manager:
                main()
            self.assertEqual(context_manager.exception.args[0], 0)

        with patch.object(sys, 'stderr', new_callable=six.StringIO) as stderr, \
                patch.object(sys, 'argv', ['cryptolyzer', 'tls', 'versions', 'unsupportedprotocol://localhost']):

            with self.assertRaises(SystemExit) as context_manager:
                main()
            self.assertEqual(context_manager.exception.args[0], 2)
            self.assertTrue(stderr.getvalue().endswith('error: unsupported protocol: unsupportedprotocol\n'))

    @staticmethod
    def _get_test_analyzer_result(protocol, analyzer, address):
        with patch('sys.stdout', new_callable=six.StringIO) as stdout, \
                patch.object(sys, 'argv', ['cryptolyzer', protocol, analyzer, address]):
            main()
            return stdout.getvalue()

    def test_analyzer_output(self):
        self.assertEqual(
            self._get_test_analyzer_result('tls1', 'ciphers', 'rc4-md5.badssl.com'),
            tests.tls.test_ciphers.TestTlsCiphers.get_result('rc4-md5.badssl.com', 443).as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'curves', 'ecc256.badssl.com:443'),
            tests.tls.test_curves.TestTlsCurves.get_result('ecc256.badssl.com', 443).as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'dhparams', 'dh2048.badssl.com'),
            tests.tls.test_dhparams.TestTlsDHParams.get_result('dh2048.badssl.com', 443).as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'pubkeys', 'badssl.com'),
            tests.tls.test_pubkeys.TestTlsPubKeys.get_result('badssl.com', 443).as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'sigalgos', 'ecc256.badssl.com:443'),
            tests.tls.test_sigalgos.TestTlsSigAlgos.get_result('ecc256.badssl.com', 443).as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls', 'versions', 'tls-v1-0.badssl.com:1010'),
            tests.tls.test_versions.TestTlsVersions.get_result('tls-v1-0.badssl.com', 1010).as_json() + '\n',
        )


if __name__ == '__main__':
    unittest.main()
