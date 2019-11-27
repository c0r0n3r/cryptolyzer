# -*- coding: utf-8 -*-

import unittest

from cryptolyzer.common.analyzer import ProtocolHandlerBase


class TestAnalyzer(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(KeyError):
            ProtocolHandlerBase.from_protocol('unsupportedprotocol')
