# -*- coding: utf-8 -*-

import abc

import attr
import urllib3

import six

from cryptodatahub.common.types import convert_url
from cryptodatahub.dnssec.algorithm import DnsRrType

from cryptoparser.common.utils import get_leaf_classes
from cryptoparser.dnsrec.record import DnsRecordDnskey, DnsRecordDs

from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.dnsrec.transfer import DnsHandshakeBase


@attr.s
class L7ClientDnsBase(object):
    domain = attr.ib(
        converter=convert_url(),
        validator=attr.validators.instance_of(urllib3.util.url.Url)
    )
    timeout = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of((float, int))))

    def __attrs_post_init__(self):
        if self.timeout is None:
            self.timeout = self.get_default_timeout()

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
            six.raise_from(ValueError(uri.scheme), e)

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

        LogSingleton().log(
            level=60,
            msg=six.u('Server responded (%s) record(s) %s') % (record_name, ', '.join(record_values))
        )

    def _get_record_list(self, record_type, record_class, domain_prefix=None):
        dns_client = self.get_client_handshake_class()(self.timeout)

        dns_client.get_records(self, record_type, domain_prefix)

        return list(map(record_class.parse_exact_size, dns_client.raw_records))

    def get_dnskey_records(self, domain_prefix=None):
        dnskey_records = self._get_record_list(DnsRrType.DNSKEY, DnsRecordDnskey, domain_prefix)
        self._log_records(
            'DNSKEY',
            map(
                lambda dnskey_record: '{} ({})'.format(dnskey_record.algorithm.value.name, dnskey_record.key_tag),
                dnskey_records
            )
        )

        return dnskey_records

    def get_ds_records(self, domain_prefix=None):
        ds_records = self._get_record_list(DnsRrType.DS, DnsRecordDs, domain_prefix)
        self._log_records(
            'DS',
            map(
                lambda ds_record: '{} ({})'.format(ds_record.algorithm.value.name, ds_record.key_tag),
                ds_records
            )
        )

        return ds_records


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
