# -*- coding: utf-8 -*-

import unittest

from cryptolyzer.common.analyzer import ProtocolHandlerBase

from cryptolyzer.ike.analyzer import ProtocolHandlerIKEVersionIndependent


class TestAnalyzer(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(KeyError):
            ProtocolHandlerBase.from_protocol('unsupportedprotocol')

    def test_protocol(self):
        self.assertEqual(ProtocolHandlerIKEVersionIndependent.get_protocol(), 'ike')
