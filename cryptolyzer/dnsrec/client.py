# -*- coding: utf-8 -*-

import abc

import attr
import urllib3


from cryptodatahub.common.types import convert_url
from cryptodatahub.dnsrec.algorithm import DnsRrType

from cryptoparser.common.exception import InvalidType
from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.dnsrec.record import (
    DnsRecordDnskey,
    DnsRecordDs,
    DnsRecordMx,
    DnsRecordRrsig,
    DnsRecordTxt,
)
from cryptoparser.dnsrec.txt import (
    DnsRecordTxtValueDmarc,
    DnsRecordTxtValueMtaSts,
    DnsRecordTxtValueTlsRpt,
    DnsRecordTxtValueSpf,
)

from cryptolyzer.common.exception import NetworkError
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.dnsrec.transfer import DnsHandshakeBase


@attr.s
class L7ClientDnsBase():
    domain = attr.ib(
        converter=convert_url(),
        validator=attr.validators.instance_of(urllib3.util.url.Url)
    )
    l4_socket_params = attr.ib(
        default=L4TransferSocketParams(),
        validator=attr.validators.instance_of(L4TransferSocketParams),
    )

    def __attrs_post_init__(self):
        if self.l4_socket_params.timeout is None:
            self.l4_socket_params = L4TransferSocketParams(
                self.get_default_timeout(), self.l4_socket_params.http_proxy
            )

    @classmethod
    def get_default_timeout(cls):
        return 5

    @classmethod
    def from_uri(cls, uri):
        try:
            transfer = next(iter(filter(
                lambda transfer_class: transfer_class.get_scheme() == uri.scheme,
                get_leaf_classes(cls)
            )))(uri)
        except StopIteration as e:
            raise ValueError(uri.scheme) from e

        return transfer

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_supported_schemes(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_client_handshake_class(cls):
        raise NotImplementedError()

    @classmethod
    def _log_records(cls, record_name, record_values):
        record_values = list(record_values)
        if not record_values:
            return

        record_value_list = ', '.join(record_values)
        LogSingleton().log(level=60, msg=f'Server responded ({record_name}) record(s) {record_value_list}')

    def _get_record_list(self, record_type, record_class, domain_prefix=None):
        dns_client = self.get_client_handshake_class()(self.l4_socket_params)

        dns_client.get_records(self, record_type, domain_prefix)

        return list(map(record_class.parse_exact_size, dns_client.raw_records))

    def get_mx_records(self, domain_prefix=None):
        mx_records = self._get_record_list(DnsRrType.MX, DnsRecordMx, domain_prefix)
        self._log_records(
            'MX',
            map(
                lambda mx_record: f'{str(mx_record.exchange)} ({mx_record.priority})',
                mx_records
            )
        )

        return mx_records

    def _get_txt_record_value(self, record_name, domain_prefix, record_value_type):
        try:
            txt_records = self._get_record_list(DnsRrType.TXT, DnsRecordTxt, domain_prefix)
        except NetworkError:
            return None

        self._log_records(record_name, map(lambda record: f'{record.value}', txt_records))

        record_values = []
        for txt_record in txt_records:
            try:
                record_values.append(record_value_type.parse_exact_size(txt_record.value.encode('ascii')))
            except InvalidType:
                pass

        if len(record_values) > 1:
            raise NotImplementedError(record_values)
        if not record_values:
            return None

        return record_values[0]

    def get_txt_record_spf_values(self):
        return self._get_txt_record_value('SPF', None, DnsRecordTxtValueSpf)

    def get_txt_record_dmarc_values(self):
        return self._get_txt_record_value('DMARC', '_dmarc', DnsRecordTxtValueDmarc)

    def get_txt_record_tls_rpt_values(self):
        return self._get_txt_record_value('TLS-RPT', '_smtp._tls', DnsRecordTxtValueTlsRpt)

    def get_txt_record_mta_sts_values(self):
        return self._get_txt_record_value('MTA-STS', '_mta-sts', DnsRecordTxtValueMtaSts)

    def get_dnskey_records(self, domain_prefix=None):
        dnskey_records = self._get_record_list(DnsRrType.DNSKEY, DnsRecordDnskey, domain_prefix)
        self._log_records(
            'DNSKEY',
            map(lambda dnskey_record: f'{dnskey_record.algorithm.value.name} ({dnskey_record.key_tag})', dnskey_records)
        )

        return dnskey_records

    def get_ds_records(self, domain_prefix=None):
        ds_records = self._get_record_list(DnsRrType.DS, DnsRecordDs, domain_prefix)
        self._log_records(
            'DS',
            map(lambda ds_record: f'{ds_record.algorithm.value.name} ({ds_record.key_tag})', ds_records)
        )

        return ds_records

    @staticmethod
    def _get_rrsig_record_log_value(rrsig_record):
        type_covered = rrsig_record.type_covered
        rrsig_record_value = type_covered.value.name if isinstance(rrsig_record, DnsRrType) else type_covered.value

        return f'{rrsig_record_value} ({rrsig_record.key_tag})'

    def get_rrsig_records(self, domain_prefix=None):
        rrsig_records = self._get_record_list(DnsRrType.RRSIG, DnsRecordRrsig, domain_prefix)
        self._log_records('RRSIG', map(self._get_rrsig_record_log_value, rrsig_records))

        return rrsig_records


class L7ClientDns(L7ClientDnsBase):
    @classmethod
    def get_scheme(cls):
        return 'dns'

    @classmethod
    def get_supported_schemes(cls):
        return {'dns': L7ClientDns}

    @classmethod
    def get_client_handshake_class(cls):
        return DnsClientHandshake


class DnsClientHandshake(DnsHandshakeBase):
    pass
