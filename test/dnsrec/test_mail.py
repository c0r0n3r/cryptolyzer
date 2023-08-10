# -*- coding: utf-8 -*-

from test.common.classes import TestLoggerBase

import urllib3

from cryptoparser.dnsrec.record import DnsRecordMx

from cryptolyzer.dnsrec.analyzer import AnalyzerDnsMail
from cryptolyzer.dnsrec.client import L7ClientDns


class TestDnsRecordMail(TestLoggerBase):
    @classmethod
    def get_result(cls, uri, timeout=None):
        analyzer = AnalyzerDnsMail()
        client = L7ClientDns.from_uri(urllib3.util.parse_url(uri))
        if timeout:
            client.timeout = timeout
        return analyzer.analyze(client)

    def test_real(self):
        analyzer_result = self.get_result('dns://example.com')
        self.assertEqual(analyzer_result.mx, [DnsRecordMx(0, '')])

    def test_markdown(self):
        analyzer_result = self.get_result('dns://example.com')
        self.assertEqual(analyzer_result.as_markdown(), '\n'.join([
            '* Target:',
            '    * Scheme: dns',
            '    * Address: example.com',
            '    * Server: n/a',
            '* MX Records:',
            '    1.',
            '        * Priority: 0',
            '        * Exchange: ',
            '',
        ]))
