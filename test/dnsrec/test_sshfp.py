# SPDX-License-Identifier: MPL-2.0

from test.common.classes import TestLoggerBase
from test.common.markers import live_dns
from test.dnsrec.classes import resolve_from_records

from unittest.mock import patch

import dns.resolver

import urllib3

from cryptodatahub.dnsrec.algorithm import DnsRrType, SshFpAlgorithm, SshFpFingerprintType

from cryptoparser.dnsrec.record import DnsRecordSshfp

from cryptolyzer.dnsrec.analyzer import AnalyzerDnsSshfp
from cryptolyzer.dnsrec.client import L7ClientDns
from cryptolyzer.dnsrec.transfer import DnsHandshakeBase


class TestDnsRecordSshfp(TestLoggerBase):
    _SSHFP_RECORDS = [
        DnsRecordSshfp(
            algorithm=SshFpAlgorithm.RSA,
            fingerprint_type=SshFpFingerprintType.SHA2_256,
            fingerprint=bytes(range(32)),
        ),
        DnsRecordSshfp(
            algorithm=SshFpAlgorithm.ECDSA,
            fingerprint_type=SshFpFingerprintType.SHA2_256,
            fingerprint=bytes(range(32, 64)),
        ),
        DnsRecordSshfp(
            algorithm=SshFpAlgorithm.ED25519,
            fingerprint_type=SshFpFingerprintType.SHA2_256,
            fingerprint=bytes(range(64, 96)),
        ),
    ]

    @classmethod
    def get_result(cls, uri):
        analyzer = AnalyzerDnsSshfp()
        client = L7ClientDns.from_uri(urllib3.util.parse_url(uri))
        return analyzer.analyze(client)

    def test_get_name(self):
        self.assertEqual(AnalyzerDnsSshfp.get_name(), 'sshfp')

    def test_get_help(self):
        self.assertIsInstance(AnalyzerDnsSshfp.get_help(), str)

    def test_records(self):
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=resolve_from_records('example.com', {(None, DnsRrType.SSHFP): self._SSHFP_RECORDS})
        ):
            analyzer_result = self.get_result('dns://example.com')

        self.assertEqual(analyzer_result.sshfp_records, self._SSHFP_RECORDS)

    def test_missing(self):
        with patch.object(DnsHandshakeBase, '_resolve', side_effect=dns.resolver.NoAnswer):
            analyzer_result = self.get_result('dns://example.com')

        self.assertEqual(analyzer_result.sshfp_records, [])

    @live_dns
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
