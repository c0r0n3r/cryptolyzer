# -*- coding: utf-8 -*-

import attr

from cryptoparser.dnsrec.record import DnsRecordDnskey, DnsRecordDs, DnsRecordRrsig

from cryptolyzer.common.analyzer import AnalyzerDnsRecordBase
from cryptolyzer.common.result import AnalyzerResultDnsRecord, AnalyzerTargetDnsRecord


@attr.s
class AnalyzerResultDnsSec(AnalyzerResultDnsRecord):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to `DNSSEC <https://www.rfc-editor.org/rfc/rfc4034>`__ keys end signatures.

    :param dns_keys: List of the public keys that can be used to verify digital signatures
        (`DNSKEY <https://www.rfc-editor.org/rfc/rfc4034#section-2>`__).
    :param delegation_signer: List of the signatures relate to delegation signer
        (`DS <https://www.rfc-editor.org/rfc/rfc4034#section-5>`__).
    :param resource_record_signatures: List of the digital signatures for the record set
        (`RRSIG <https://www.rfc-editor.org/rfc/rfc4034#section-3>`__).
    """

    dns_keys = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(DnsRecordDnskey),
        ),
        metadata={'human_readable_name': 'DNS Public Keys (DNSKEY)'},
    )
    delegation_signer = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(DnsRecordDs),
        ),
        metadata={'human_readable_name': 'Delegation Signers (DS)'},
    )
    resource_record_signatures = attr.ib(
        validator=attr.validators.deep_iterable(
            member_validator=attr.validators.instance_of(DnsRecordRrsig),
        ),
        metadata={'human_readable_name': 'Resource Record Signature (RRSIG)'},
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
        ds_records = analyzable.get_ds_records()
        rrsig_records = analyzable.get_rrsig_records()

        return dnskey_records, ds_records, rrsig_records

    def analyze(self, analyzable):
        dnskey_records, ds_records, rrsig_records = self._analyze_records(analyzable)

        return AnalyzerResultDnsSec(
            AnalyzerTargetDnsRecord.from_l7_client(analyzable),
            dnskey_records,
            ds_records,
            rrsig_records,
        )
