#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7Client
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys


class TestTlsPubKeys(unittest.TestCase):
    @staticmethod
    def get_result(host, port):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7Client.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result
