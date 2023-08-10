# -*- coding: utf-8 -*-

import attr

from cryptoparser.dnsrec.record import DnsRecordMx

from cryptolyzer.common.analyzer import AnalyzerDnsRecordBase
from cryptolyzer.common.result import AnalyzerResultDnsRecord, AnalyzerTargetDnsRecord


@attr.s
class AnalyzerResultMail(AnalyzerResultDnsRecord):  # pylint: disable=too-few-public-methods
    mx = attr.ib(  # pylint: disable=invalid-name
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(DnsRecordMx)
        ),
        metadata={'human_readable_name': 'MX Records'},
    )


class AnalyzerDnsMail(AnalyzerDnsRecordBase):
    @classmethod
    def get_name(cls):
        return 'mail'

    @classmethod
    def get_help(cls):
        return 'Check mail-related DNS record(s)'

    def analyze(self, analyzable):
        mx_records = analyzable.get_mx_records()

        return AnalyzerResultMail(
            AnalyzerTargetDnsRecord.from_l7_client(analyzable),
            sorted(mx_records, key=lambda mx_record: mx_record.priority),
        )
