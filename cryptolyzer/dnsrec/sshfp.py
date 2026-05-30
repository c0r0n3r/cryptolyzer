# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import attr

from cryptoparser.dnsrec.record import DnsRecordSshfp

from cryptolyzer.common.analyzer import AnalyzerDnsRecordBase
from cryptolyzer.common.result import AnalyzerResultDnsRecord, AnalyzerTargetDnsRecord


@attr.s
class AnalyzerResultSshfp(AnalyzerResultDnsRecord):
    """
    :class: Analyzer result of SSHFP DNS resource records.

    :param sshfp_records: Parsed SSHFP resource records published for the target hostname.
    """

    sshfp_records = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(DnsRecordSshfp)
        ),
        metadata={'human_readable_name': 'SSHFP Records'},
    )


class AnalyzerDnsSshfp(AnalyzerDnsRecordBase):
    @classmethod
    def get_name(cls):
        return 'sshfp'

    @classmethod
    def get_help(cls):
        return 'Check SSH fingerprint (SSHFP) DNS record(s)'

    def analyze(self, analyzable):
        super().analyze(analyzable)

        sshfp_records = analyzable.get_sshfp_records()

        return AnalyzerResultSshfp(
            AnalyzerTargetDnsRecord.from_l7_client(analyzable),
            sshfp_records,
        )
