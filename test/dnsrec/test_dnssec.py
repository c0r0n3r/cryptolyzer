# -*- coding: utf-8 -*-

from test.common.classes import TestLoggerBase

import urllib3

from cryptodatahub.dnsrec.algorithm import DnsSecAlgorithm, DnsSecDigestType

from cryptolyzer.dnsrec.analyzer import AnalyzerDnsSec
from cryptolyzer.dnsrec.client import L7ClientDns


class TestDnsRecordDnsSec(TestLoggerBase):
    @classmethod
    def get_result(cls, uri, timeout=None):
        analyzer = AnalyzerDnsSec()
        client = L7ClientDns.from_uri(urllib3.util.parse_url(uri))
        if timeout:
            client.timeout = timeout
        return analyzer.analyze(client)

    def test_real(self):
        analyzer_result = self.get_result('dns://google.com#1.1.1.1')
        self.assertEqual(analyzer_result.dns_keys, [])
        self.assertEqual(analyzer_result.delegation_signer, [])
        self.assertEqual(analyzer_result.resource_record_signatures, [])

        analyzer_result = self.get_result('dns://openssl.org#1.1.1.1')
        self.assertEqual(
            list(map(lambda dns_key: dns_key.algorithm, analyzer_result.dns_keys)),
            [DnsSecAlgorithm.RSASHA256, DnsSecAlgorithm.RSASHA256]
        )
        self.assertEqual(
            list(map(lambda digital_signature: digital_signature.algorithm, analyzer_result.delegation_signer)),
            [DnsSecAlgorithm.RSASHA256, DnsSecAlgorithm.RSASHA256]
        )
        self.assertEqual(
            list(map(lambda digital_signature: digital_signature.digest_type, analyzer_result.delegation_signer)),
            [DnsSecDigestType.SHA_256, DnsSecDigestType.SHA_256]
        )
        self.assertEqual(
            list(map(lambda rr_signature: rr_signature.algorithm, analyzer_result.resource_record_signatures)),
            10 * [DnsSecAlgorithm.RSASHA256]
        )
