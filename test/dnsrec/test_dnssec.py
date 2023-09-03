# -*- coding: utf-8 -*-

from test.common.classes import TestLoggerBase

import urllib3

from cryptodatahub.dnssec.algorithm import DnsSecAlgorithm, DnsSecDigestType

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
        self.assertEqual(analyzer_result.digital_signatures, [])
        self.assertEqual(analyzer_result.resource_record_signatures, [])

        analyzer_result = self.get_result('dns://cloudflare.com#1.1.1.1')
        self.assertEqual(
            list(map(lambda dns_key: dns_key.algorithm, analyzer_result.dns_keys)),
            [DnsSecAlgorithm.ECDSAP256SHA256, DnsSecAlgorithm.ECDSAP256SHA256]
        )
        self.assertEqual(
            list(map(lambda digital_signature: digital_signature.algorithm, analyzer_result.digital_signatures)),
            [DnsSecAlgorithm.ECDSAP256SHA256]
        )
        self.assertEqual(
            list(map(lambda digital_signature: digital_signature.digest_type, analyzer_result.digital_signatures)),
            [DnsSecDigestType.SHA_256]
        )
        dns_key_tags = set(map(lambda dns_key: dns_key.key_tag, analyzer_result.dns_keys))
        digital_signature_key_tags = set(map(
            lambda digital_signature: digital_signature.key_tag,
            analyzer_result.digital_signatures
        ))
        self.assertTrue(digital_signature_key_tags.issubset(dns_key_tags))
        self.assertEqual(analyzer_result.resource_record_signatures, [])
