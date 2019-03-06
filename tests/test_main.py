#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest
import six
import sys
import os

from cryptolyzer.__main__ import main

import tests.tls.test_ciphers
import tests.tls.test_curves
import tests.tls.test_dhparams
import tests.tls.test_pubkeys
import tests.tls.test_sigalgos
import tests.tls.test_versions


try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

class TestMain(unittest.TestCase):
    def test_argument_parsing(self):
        with open(os.devnull, 'w') as devnull, \
            patch.object(sys, 'stdout', devnull), \
            patch.object(sys, 'argv', ['cryptolyzer', '-h']):

            with self.assertRaises(SystemExit) as context_manager:
                main()
            self.assertEqual(context_manager.exception.args[0], 0)

        with six.StringIO() as stderr, \
            patch.object(sys, 'stderr', stderr), \
            patch.object(sys, 'argv', ['cryptolyzer', 'tls', 'versions', 'unsupportedprotocol://localhost']):

            with self.assertRaises(SystemExit) as context_manager:
                main()
            self.assertEqual(context_manager.exception.args[0], 2)
            self.assertTrue(stderr.getvalue().endswith('error: unsupported protocol: unsupportedprotocol\n'))

    def _get_test_analyzer_result(self, protocol, analyzer, address):
        with six.StringIO() as stdout, \
            patch.object(sys, 'stdout', stdout), \
            patch.object(sys, 'argv', ['cryptolyzer', protocol, analyzer, address]):

            main()
            return stdout.getvalue()

    def test_analyzer_output(self):
        self.maxDiff = None
        self.assertEqual(
            self._get_test_analyzer_result('tls1', 'ciphers', 'rc4-md5.badssl.com'),
            tests.tls.test_ciphers.TestTlsCiphers._get_result('rc4-md5.badssl.com', 443).as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'curves', 'ecc256.badssl.com:443'),
            tests.tls.test_curves.TestTlsCurves._get_result('ecc256.badssl.com', 443).as_json() + '\n',
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'dhparams', 'dh2048.badssl.com'),
            tests.tls.test_dhparams.TestTlsDHParams._get_result('dh2048.badssl.com', 443).as_json() + '\n'
        )
        self.assertEqual(
            self._get_test_analyzer_result('tls1_2', 'pubkeys', 'badssl.com'),
            tests.tls.test_pubkeys.TestTlsPubKeys._get_result('badssl.com', 443).as_json() + '\n'
        )
        #self.assertEqual(
        #    self._get_test_analyzer_result('tls1', 'sigalgos', 'ecc256.badssl.com:443'),
        #    tests.tls.test_sigalgos.TestTlsSigAlgos._get_result('ecc256.badssl.com', 443).as_json() + '\n',
        #)
        self.assertEqual(
            self._get_test_analyzer_result('tls', 'versions', 'tls-v1-0.badssl.com:1010'),
            tests.tls.test_versions.TestTlsVersions._get_result('tls-v1-0.badssl.com', 1010).as_json() + '\n',
        )


if __name__ == '__main__':
    unittest.main()