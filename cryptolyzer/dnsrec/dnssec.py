# -*- coding: utf-8 -*-

import attr

from cryptoparser.dnsrec.record import DnsRecordDnskey

from cryptolyzer.common.analyzer import AnalyzerDnsRecordBase
from cryptolyzer.common.result import AnalyzerResultDnsRecord, AnalyzerTargetDnsRecord


@attr.s
class AnalyzerResultDnsSec(AnalyzerResultDnsRecord):  # pylint: disable=too-few-public-methods
    dns_keys = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(DnsRecordDnskey),
        ),
        metadata={'human_readable_name': 'DNS Public Keys (DNSKEY)'},
    )


class AnalyzerDnsSec(AnalyzerDnsRecordBase):
    @classmethod
    def get_name(cls):
        return 'dnssec'

    @classmethod
    def get_help(cls):
        return 'Check DNSSEC records relates to a domain)'

    @staticmethod
    def _analyze_records(analyzable):
        dnskey_records = analyzable.get_dnskey_records()
        return dnskey_records

    def analyze(self, analyzable):
        dnskey_records = self._analyze_records(analyzable)

        return AnalyzerResultDnsSec(
            AnalyzerTargetDnsRecord.from_l7_client(analyzable),
            dnskey_records
        )
