# SPDX-License-Identifier: MPL-2.0

import base64
import datetime

from test.common.classes import TestLoggerBase
from test.common.markers import live_server

from unittest.mock import patch

import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.resolver
import dns.rrset

import urllib3

from cryptodatahub.dnsrec.algorithm import DnsSecAlgorithm, DnsSecDigestType, DnsRrType

from cryptoparser.dnsrec.record import (
    DnsRecordDnskey,
    DnsRecordDs,
    DnsRecordRrsig,
    DnsSecFlag,
    DnsSecProtocol,
)

from cryptolyzer.common.analyzer import ProtocolHandlerBase
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.dnsrec.analyzer import AnalyzerDnsSec
from cryptolyzer.dnsrec.client import L7ClientDns
from cryptolyzer.dnsrec.transfer import DnsHandshakeBase


class TestDnsRecordDnsSec(TestLoggerBase):
    # RFC 5702 Section 6.1 public key (RSASHA256, key tag 9033)
    _DNS_KEY_RECORD = DnsRecordDnskey(
        flags=[DnsSecFlag.DNS_ZONE_KEY],
        algorithm=DnsSecAlgorithm.RSASHA256,
        key=DnsRecordDnskey.parse_key(
            base64.b64decode(
                'AwEAAcFcGsaxxdgiuuGmCkVImy4h99CqT7jwY3pexPGcnUFtR2Fh36BponcwtkZ4cAgtvd4Qs8P'
                'kxUdp6p/DlUmObdk='
            ),
            DnsSecAlgorithm.RSASHA256,
        ),
        protocol=DnsSecProtocol.V3,
    )
    _DELEGATION_SIGNER_RECORD = DnsRecordDs(
        key_tag=_DNS_KEY_RECORD.key_tag,
        algorithm=DnsSecAlgorithm.RSASHA256,
        digest_type=DnsSecDigestType.SHA_256,
        digest=bytes(range(32)),
    )
    _RESOURCE_RECORD_SIGNATURE = DnsRecordRrsig(
        type_covered=DnsRrType.DNSKEY,
        algorithm=DnsSecAlgorithm.RSASHA256,
        labels=2,
        original_ttl=3600,
        signature_expiration=datetime.datetime(2024, 1, 1, tzinfo=datetime.timezone.utc),
        signature_inception=datetime.datetime(2023, 12, 1, tzinfo=datetime.timezone.utc),
        key_tag=_DNS_KEY_RECORD.key_tag,
        signers_name='example.com',
        signature=bytes(range(64)),
    )
    _RECORDS_BY_RR_TYPE = {
        DnsRrType.DNSKEY: [_DNS_KEY_RECORD],
        DnsRrType.DS: [_DELEGATION_SIGNER_RECORD],
        DnsRrType.RRSIG: [_RESOURCE_RECORD_SIGNATURE],
    }

    @staticmethod
    def _build_answer(domain, rr_type, dns_records):
        name = dns.name.from_text(domain)
        query = dns.message.make_query(name, rr_type.value.code)
        response = dns.message.make_response(query)
        rdata_list = [
            dns.rdata.GenericRdata(dns.rdataclass.IN, rr_type.value.code, dns_record.compose())
            for dns_record in dns_records
        ]
        response.answer.append(dns.rrset.from_rdata_list(name, 3600, rdata_list))

        return dns.resolver.Answer(name, rr_type.value.code, dns.rdataclass.IN, response)

    @classmethod
    def _resolve_from_records(cls, domain, records_by_rr_type):
        answers = {
            rr_type.value.name: cls._build_answer(domain, rr_type, dns_records)
            for rr_type, dns_records in records_by_rr_type.items()
        }

        def fake_resolve(_dns_resolver, **kwargs):
            return answers[kwargs['rdtype']]

        return fake_resolve

    @classmethod
    def get_result(cls, uri, timeout=None):
        analyzer = AnalyzerDnsSec()
        client = L7ClientDns.from_uri(urllib3.util.parse_url(uri))
        if timeout:
            client.timeout = timeout
        return analyzer.analyze(client)

    def test_get_name(self):
        self.assertEqual(AnalyzerDnsSec.get_name(), 'dnssec')

    def test_get_help(self):
        self.assertIsInstance(AnalyzerDnsSec.get_help(), str)

    def _assert_dnssec_result(self, analyzer_result):
        self.assertEqual(len(analyzer_result.dns_keys), 1)
        dns_key = analyzer_result.dns_keys[0]
        self.assertEqual(dns_key.algorithm, DnsSecAlgorithm.RSASHA256)
        self.assertEqual(dns_key.key_tag, self._DNS_KEY_RECORD.key_tag)
        self.assertEqual(dns_key.key, self._DNS_KEY_RECORD.key)

        self.assertEqual(len(analyzer_result.delegation_signer), 1)
        delegation_signer = analyzer_result.delegation_signer[0]
        self.assertEqual(delegation_signer.algorithm, DnsSecAlgorithm.RSASHA256)
        self.assertEqual(delegation_signer.digest_type, DnsSecDigestType.SHA_256)
        self.assertEqual(delegation_signer.key_tag, self._DELEGATION_SIGNER_RECORD.key_tag)
        self.assertEqual(delegation_signer.digest, self._DELEGATION_SIGNER_RECORD.digest)

        self.assertEqual(len(analyzer_result.resource_record_signatures), 1)
        rr_signature = analyzer_result.resource_record_signatures[0]
        self.assertEqual(rr_signature.algorithm, DnsSecAlgorithm.RSASHA256)
        self.assertEqual(rr_signature.type_covered, DnsRrType.DNSKEY)
        self.assertEqual(rr_signature.key_tag, self._RESOURCE_RECORD_SIGNATURE.key_tag)
        self.assertEqual(rr_signature.signature, self._RESOURCE_RECORD_SIGNATURE.signature)

    def test_records(self):
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=self._resolve_from_records('example.com', self._RECORDS_BY_RR_TYPE)
        ):
            analyzer_result = self.get_result('dns://example.com')

        self._assert_dnssec_result(analyzer_result)

    def test_missing(self):
        with patch.object(DnsHandshakeBase, '_resolve', side_effect=dns.resolver.NoAnswer):
            analyzer_result = self.get_result('dns://example.com')

        self.assertEqual(analyzer_result.dns_keys, [])
        self.assertEqual(analyzer_result.delegation_signer, [])
        self.assertEqual(analyzer_result.resource_record_signatures, [])

    def test_protocol_handler(self):
        handler = ProtocolHandlerBase.from_protocol('dns')
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=self._resolve_from_records('example.com', self._RECORDS_BY_RR_TYPE)
        ):
            analyzer_result = handler.analyze(
                AnalyzerDnsSec(),
                urllib3.util.parse_url('dns://example.com'),
                L4TransferSocketParams(),
            )

        self._assert_dnssec_result(analyzer_result)

    @live_server
    def test_real(self):
        analyzer_result = self.get_result('dns://google.com#1.1.1.1')
        self.assertEqual(analyzer_result.dns_keys, [])
        self.assertEqual(analyzer_result.delegation_signer, [])
        self.assertEqual(analyzer_result.resource_record_signatures, [])

        analyzer_result = self.get_result('dns://openssl.org#1.1.1.1')
        self.assertTrue(all(map(
            lambda dns_key: dns_key.algorithm == DnsSecAlgorithm.RSASHA256,
            analyzer_result.dns_keys
        )))
        self.assertTrue(all(map(
            lambda digital_signature: digital_signature.algorithm == DnsSecAlgorithm.RSASHA256,
            analyzer_result.delegation_signer
        )))
        self.assertTrue(all(map(
            lambda digital_signature: digital_signature.digest_type == DnsSecDigestType.SHA_256,
            analyzer_result.delegation_signer
        )))
        self.assertTrue(all(map(
            lambda rr_signature: rr_signature.algorithm == DnsSecAlgorithm.RSASHA256,
            analyzer_result.resource_record_signatures
        )))
