# -*- coding: utf-8 -*-

import io

import ipaddress

import attr

from cryptodatahub.dnsrec.algorithm import DnsRrType

import dns.resolver

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams


@attr.s
class DnsHandshakeBase():
    l4_socket_params = attr.ib(
        default=L4TransferSocketParams(),
        validator=attr.validators.instance_of(L4TransferSocketParams),
    )
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
                out = io.BytesIO()
                record.to_wire(out)
                records.append(out.getvalue())

        return records

    def _create_resolver(self, nameservers):
        dns_resolver = dns.resolver.Resolver()
        dns_resolver.lifetime = self.l4_socket_params.timeout

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
        return dns_resolver.resolve(**kwargs)

    def _get_records_from_servers(self, domain, rr_type, nameservers, domain_prefix=None):
        if domain_prefix is not None:
            domain = '.'.join([domain_prefix, domain])

        dns_resolver = self._create_resolver(nameservers)

        records = None
        try:
            records = self._resolve(dns_resolver, qname=domain, rdtype=rr_type.value.name, raise_on_no_answer=False)
        except dns.resolver.NXDOMAIN as e:
            raise NetworkError(NetworkErrorType.NO_ADDRESS) from e
        except dns.resolver.Timeout as e:
            raise NetworkError(NetworkErrorType.NO_RESPONSE) from e
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
