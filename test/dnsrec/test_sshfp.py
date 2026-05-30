# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from test.common.classes import TestLoggerBase

import urllib3

from cryptodatahub.dnsrec.algorithm import SshFpAlgorithm, SshFpFingerprintType

from cryptoparser.dnsrec.record import DnsRecordSshfp

from cryptolyzer.dnsrec.analyzer import AnalyzerDnsSshfp
from cryptolyzer.dnsrec.client import L7ClientDns


class TestDnsRecordSshfp(TestLoggerBase):
    @classmethod
    def get_result(cls, uri):
        analyzer = AnalyzerDnsSshfp()
        client = L7ClientDns.from_uri(urllib3.util.parse_url(uri))
        return analyzer.analyze(client)

    def test_get_name(self):
        self.assertEqual(AnalyzerDnsSshfp.get_name(), 'sshfp')

    def test_get_help(self):
        self.assertIsInstance(AnalyzerDnsSshfp.get_help(), str)

    def test_missing(self):
        analyzer_result = self.get_result('dns://example.com')
        self.assertEqual(analyzer_result.sshfp_records, [])

    def test_real(self):
        analyzer_result = self.get_result('dns://sourceware.org')

        self.assertGreater(len(analyzer_result.sshfp_records), 0)
        for record in analyzer_result.sshfp_records:
            self.assertIsInstance(record, DnsRecordSshfp)
            self.assertIsInstance(record.algorithm, SshFpAlgorithm)
            self.assertIsInstance(record.fingerprint_type, SshFpFingerprintType)
            self.assertIsInstance(record.fingerprint, (bytes, bytearray))
            self.assertGreater(len(record.fingerprint), 0)

        algorithms = {record.algorithm for record in analyzer_result.sshfp_records}
        self.assertIn(SshFpAlgorithm.RSA, algorithms)
        self.assertIn(SshFpAlgorithm.ECDSA, algorithms)
        self.assertIn(SshFpAlgorithm.ED25519, algorithms)
