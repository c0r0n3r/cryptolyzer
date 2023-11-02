# -*- coding: utf-8 -*-

import collections

import attr

from cryptoparser.common.base import Serializable
from cryptoparser.common.parse import ParsableBase
from cryptoparser.dnsrec.record import DnsRecordMx


from cryptolyzer.common.analyzer import AnalyzerDnsRecordBase
from cryptolyzer.common.result import AnalyzerResultDnsRecord, AnalyzerTargetDnsRecord


@attr.s
class MailTxtRecordValue(Serializable):
    value = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(ParsableBase)))

    @property
    def raw(self):
        return self.value.compose().decode('ascii')

    def _as_markdown(self, level):
        if self.value is None:
            return self._markdown_result(self.value)

        return self._markdown_result(collections.OrderedDict([
            ('Raw', self.raw),
            ('Parsed', self.value),
        ]), level)


@attr.s
class AnalyzerResultMail(AnalyzerResultDnsRecord):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result of DNS TXT records relate to e-mail authentication and reporting.

    :param mx: Parsed value of `mail exchange <https://www.rfc-editor.org/rfc/rfc1035>`__ (MX) record.
    :param spf: Parsed value of
        `Sender Policy Framework <https://www.rfc-editor.org/rfc/rfc7208>`__ (SPF) record.
    :param dmarc: Parsed value of
        `Domain-based Message Authentication, Reporting, and Conformance <https://www.rfc-editor.org/rfc/rfc7489>`__
        (DMARC) record.
    :param mta_sts: Parsed value of
        `SMTP MTA Strict Transport Security <https://www.rfc-editor.org/rfc/rfc8461>`__ (MTA-STS) record.
    :param tls_rpt: Parsed value of `SMTP TLS Reporting <https://www.rfc-editor.org/rfc/rfc8460>`__ (TLSRPT) record.
    """

    mx = attr.ib(  # pylint: disable=invalid-name
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(DnsRecordMx)
        ),
        metadata={'human_readable_name': 'MX Records'},
    )
    spf = attr.ib(
        validator=attr.validators.instance_of(MailTxtRecordValue),
        metadata={'human_readable_name': 'Sender Policy Framework (SPF)'},
    )
    dmarc = attr.ib(
        validator=attr.validators.instance_of(MailTxtRecordValue),
        metadata={'human_readable_name': 'Domain-based Message Authentication, Reporting, and Conformance (DMARC)'},
    )
    mta_sts = attr.ib(
        validator=attr.validators.instance_of(MailTxtRecordValue),
        metadata={'human_readable_name': 'SMTP MTA Strict Transport Security (MTA-STS)'},
    )
    tls_rpt = attr.ib(
        validator=attr.validators.instance_of(MailTxtRecordValue),
        metadata={'human_readable_name': 'SMTP TLS Reporting'},
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

        spf = analyzable.get_txt_record_spf_values()
        dmarc = analyzable.get_txt_record_dmarc_values()
        tls_rpt = analyzable.get_txt_record_tls_rpt_values()
        mta_sts = analyzable.get_txt_record_mta_sts_values()

        return AnalyzerResultMail(
            AnalyzerTargetDnsRecord.from_l7_client(analyzable),
            sorted(mx_records, key=lambda mx_record: mx_record.priority),
            spf=MailTxtRecordValue(spf),
            dmarc=MailTxtRecordValue(dmarc),
            mta_sts=MailTxtRecordValue(mta_sts),
            tls_rpt=MailTxtRecordValue(tls_rpt),
        )
