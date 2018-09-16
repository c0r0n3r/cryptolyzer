#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from cryptoparser.tls.client import L7Client
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslProtocolVersion

from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys


class TestTlsPubKeys(unittest.TestCase):
    def _get_result(self, host, port):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7Client.from_scheme('tls', host, port)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result

    def test_no_common_name(self):
        result = self._get_result('no-common-name.badssl.com', 443)
        self.assertFalse('commonName' in result.certificate_chains[0][0]['subject'])
