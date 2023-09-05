# -*- coding: utf-8 -*-

from test.common.classes import TestLoggerBase

import urllib3

from cryptoparser.dnsrec.record import DnsRecordMx
from cryptoparser.dnsrec.txt import DnsRecordTxtValueSpf, DnsRecordTxtValueSpfDirectiveAll, SpfQualifier

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
        self.assertEqual(
            analyzer_result.spf.value,
            DnsRecordTxtValueSpf([DnsRecordTxtValueSpfDirectiveAll(SpfQualifier.FAIL)])
        )
        self.assertIsNone(analyzer_result.dmarc.value)
        self.assertIsNone(analyzer_result.mta_sts.value)
        self.assertIsNone(analyzer_result.tls_rpt.value)

        analyzer_result = self.get_result('dns://gmail.com')
        self.assertEqual(len(analyzer_result.mx), 5)
        self.assertIsNotNone(analyzer_result.spf.value)
        self.assertIsNotNone(analyzer_result.dmarc.value)
        self.assertIsNotNone(analyzer_result.mta_sts.value)
        self.assertIsNotNone(analyzer_result.tls_rpt.value)

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
            '* Sender Policy Framework (SPF):',
            '    * Raw: v=spf1 -all',
            '    * Parsed:',
            '        * Version: SPF1',
            '        * Terms:',
            '            * All:',
            '                * Qualifier: Fail',
            '* Domain-based Message Authentication, Reporting, and Conformance (DMARC): n/a',
            '* SMTP MTA Strict Transport Security (MTA-STS): n/a',
            '* SMTP TLS Reporting: n/a',
            '',
        ]))
