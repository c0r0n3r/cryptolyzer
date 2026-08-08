# SPDX-License-Identifier: MPL-2.0

from test.common.classes import TestLoggerBase
from test.common.markers import live_dns
from test.dnsrec.classes import resolve_from_records

from unittest.mock import patch

import dns.resolver

import urllib3

from cryptodatahub.dnsrec.algorithm import DnsRrType

from cryptoparser.dnsrec.record import DnsRecordMx, DnsRecordTxt
from cryptoparser.dnsrec.txt import (
    DmarcAlignment,
    DmarcPolicyOption,
    DmarcPolicyVersion,
    DnsRecordTxtValueDmarc,
    DnsRecordTxtValueSpf,
    DnsRecordTxtValueSpfDirectiveAll,
    SpfQualifier,
)

from cryptolyzer.common.exception import NetworkError, NetworkErrorType

from cryptolyzer.dnsrec.analyzer import AnalyzerDnsMail
from cryptolyzer.dnsrec.client import L7ClientDns
from cryptolyzer.dnsrec.transfer import DnsHandshakeBase


class TestDnsRecordMail(TestLoggerBase):
    _RECORDS_BY_QUERY = {
        (None, DnsRrType.MX): [DnsRecordMx(0, '')],
        (None, DnsRrType.TXT): [DnsRecordTxt('v=spf1 -all')],
        ('_dmarc', DnsRrType.TXT): [
            DnsRecordTxt('v=DMARC1; p=reject; adkim=s; aspf=s; fo=0; pct=100; rf=afrf; ri=86400; sp=reject')
        ],
    }

    @classmethod
    def get_result(cls, uri, l4_socket_params=None):
        analyzer = AnalyzerDnsMail()
        client = L7ClientDns.from_uri(urllib3.util.parse_url(uri))
        if l4_socket_params:
            client.l4_socket_params = l4_socket_params.timeout
        return analyzer.analyze(client)

    def test_get_name(self):
        self.assertEqual(AnalyzerDnsMail.get_name(), 'mail')

    def test_get_help(self):
        self.assertIsInstance(AnalyzerDnsMail.get_help(), str)

    def test_records(self):
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=resolve_from_records('example.com', self._RECORDS_BY_QUERY)
        ):
            analyzer_result = self.get_result('dns://example.com')

        self.assertEqual(analyzer_result.mx, [DnsRecordMx(0, '')])
        self.assertEqual(
            analyzer_result.spf.value,
            DnsRecordTxtValueSpf([DnsRecordTxtValueSpfDirectiveAll(SpfQualifier.FAIL)])
        )
        self.assertEqual(
            analyzer_result.dmarc.value,
            DnsRecordTxtValueDmarc(
                version=DmarcPolicyVersion.DMARC1,
                policy=DmarcPolicyOption.REJECT,
                alignment_dkim=DmarcAlignment.STRICT,
                alignment_aspf=DmarcAlignment.STRICT,
                subdomain_policy=DmarcPolicyOption.REJECT,
            )
        )
        self.assertIsNone(analyzer_result.mta_sts.value)
        self.assertIsNone(analyzer_result.tls_rpt.value)

    def test_missing_records(self):
        with patch.object(DnsHandshakeBase, '_resolve', side_effect=dns.resolver.NoAnswer):
            analyzer_result = self.get_result('dns://example.com')

        self.assertEqual(analyzer_result.mx, [])
        self.assertIsNone(analyzer_result.spf.value)
        self.assertIsNone(analyzer_result.dmarc.value)
        self.assertIsNone(analyzer_result.mta_sts.value)
        self.assertIsNone(analyzer_result.tls_rpt.value)

    def test_unparsable_txt_record(self):
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=resolve_from_records('example.com', {
                (None, DnsRrType.MX): [DnsRecordMx(0, '')],
                (None, DnsRrType.TXT): [DnsRecordTxt('unrelated record value')],
            })
        ):
            analyzer_result = self.get_result('dns://example.com')

        self.assertIsNone(analyzer_result.spf.value)

    def test_error_multiple_txt_records(self):
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=resolve_from_records('example.com', {
                (None, DnsRrType.MX): [DnsRecordMx(0, '')],
                (None, DnsRrType.TXT): [DnsRecordTxt('v=spf1 -all'), DnsRecordTxt('v=spf1 +all')],
            })
        ):
            with self.assertRaises(NotImplementedError):
                self.get_result('dns://example.com')

    def test_error_non_existing_domain(self):
        with patch.object(DnsHandshakeBase, '_resolve', side_effect=dns.resolver.NXDOMAIN):
            with self.assertRaises(NetworkError) as context_manager:
                self.get_result('dns://example.com')
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    def test_error_txt_record_response(self):
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=resolve_from_records('example.com', {
                (None, DnsRrType.MX): [DnsRecordMx(0, '')],
            }, missing_error=dns.resolver.NXDOMAIN)
        ):
            analyzer_result = self.get_result('dns://example.com')

        self.assertEqual(analyzer_result.mx, [DnsRecordMx(0, '')])
        self.assertIsNone(analyzer_result.spf.value)
        self.assertIsNone(analyzer_result.dmarc.value)
        self.assertIsNone(analyzer_result.mta_sts.value)
        self.assertIsNone(analyzer_result.tls_rpt.value)

    def test_markdown(self):
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=resolve_from_records('example.com', self._RECORDS_BY_QUERY)
        ):
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
            '* Domain-based Message Authentication, Reporting, and Conformance (DMARC):',
            '    * Raw: v=DMARC1; p=reject; adkim=s; aspf=s; fo=0; pct=100; rf=afrf; ri=86400; sp=reject',
            '    * Parsed:',
            '        * Version: DMARC1',
            '        * Policy: reject',
            '        * DKIM Alignment: Strict',
            '        * ASPF Alignment: Strict',
            '        * Failure Option: All Failure',
            '        * Percent: 100',
            '        * Aggregated Reporting URL: n/a',
            '        * Failure Reporting URL: n/a',
            '        * Reporting Format: Authentication Failure Reporting Format (AFRF)',
            '        * Reporting Interval: 86400',
            '        * Subdomain Policy: reject',
            '* SMTP MTA Strict Transport Security (MTA-STS): n/a',
            '* SMTP TLS Reporting: n/a',
            '',
        ]))

    @live_dns
    def test_real(self):
        analyzer_result = self.get_result('dns://example.com')
        self.assertEqual(analyzer_result.mx, [DnsRecordMx(0, '')])
        self.assertEqual(
            analyzer_result.spf.value,
            DnsRecordTxtValueSpf([DnsRecordTxtValueSpfDirectiveAll(SpfQualifier.FAIL)])
        )
        self.assertEqual(
            analyzer_result.dmarc.value,
            DnsRecordTxtValueDmarc(
                version=DmarcPolicyVersion.DMARC1,
                policy=DmarcPolicyOption.REJECT,
                alignment_dkim=DmarcAlignment.STRICT,
                alignment_aspf=DmarcAlignment.STRICT,
                subdomain_policy=DmarcPolicyOption.REJECT,
            )
        )
        self.assertIsNone(analyzer_result.mta_sts.value)
        self.assertIsNone(analyzer_result.tls_rpt.value)

        analyzer_result = self.get_result('dns://gmail.com')
        self.assertEqual(len(analyzer_result.mx), 5)
        self.assertIsNotNone(analyzer_result.spf.value)
        self.assertIsNotNone(analyzer_result.dmarc.value)
        self.assertIsNotNone(analyzer_result.mta_sts.value)
        self.assertIsNotNone(analyzer_result.tls_rpt.value)
