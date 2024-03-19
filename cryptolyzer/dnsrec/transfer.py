# -*- coding: utf-8 -*-

import sys

import ipaddress

import six
import attr

from cryptodatahub.dnsrec.algorithm import DnsRrType

import dns.resolver

from cryptolyzer.common.exception import NetworkError, NetworkErrorType


@attr.s
class DnsHandshakeBase(object):
    timeout = attr.ib(validator=attr.validators.instance_of((float, int)))
    _answer = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(dns.resolver.Answer))
    )
    _record_type = attr.ib(
        init=False,
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(DnsRrType))
    )

    @property
    def raw_records(self):
        if self._answer is None:
            return []

        records = []
        for rrset in self._answer.response.answer:
            if rrset.rdtype == DnsRrType.CNAME.value.code:
                continue

            for record in list(rrset.items):
                out = six.BytesIO()
                record.to_wire(out)
                records.append(out.getvalue())

        return records

    def _create_resolver(self, nameservers):
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.lifetime = self.timeout

        if nameservers:
            nameserver_ips = []
            for nameserver in nameservers:
                try:
                    nameserver_ips.append(ipaddress.ip_address(nameserver))
                except ValueError:
                    pass
            if not nameserver_ips:
                raise NetworkError(NetworkErrorType.NO_RESPONSE)

            dns_resolver.nameservers = nameservers

        return dns_resolver

    @classmethod
    def _resolve(cls, dns_resolver, **kwargs):
        python_version_lt_3_6 = six.PY2 or (six.PY3 and sys.version_info.minor < 6)
        resolve_func = dns_resolver.query if python_version_lt_3_6 else dns_resolver.resolve
        return resolve_func(**kwargs)

    def _get_records_from_servers(self, domain, rr_type, nameservers, domain_prefix=None):
        if domain_prefix is not None:
            domain = '.'.join([domain_prefix, domain])

        dns_resolver = self._create_resolver(nameservers)

        records = None
        try:
            records = self._resolve(dns_resolver, qname=domain, rdtype=rr_type.value.name, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_ADDRESS), e)
        except dns.resolver.Timeout as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)
        except (dns.resolver.NoNameservers, dns.resolver.NoAnswer):
            pass

        return records

    def get_records(self, analyzable, record_type, domain_prefix=None):
        if analyzable.domain.fragment:
            nameservers = [analyzable.domain.fragment]
        else:
            nameservers = None

        self._answer = self._get_records_from_servers(analyzable.domain.host, record_type, nameservers, domain_prefix)
        self._record_type = record_type
