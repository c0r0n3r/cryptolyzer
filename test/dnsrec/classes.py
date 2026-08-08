# SPDX-License-Identifier: MPL-2.0

import dns.message
import dns.name
import dns.rdata
import dns.rdataclass
import dns.resolver
import dns.rrset

from cryptodatahub.dnsrec.algorithm import DnsRrType


def build_answer(domain, rr_type, dns_records, cname_domain=None):
    name = dns.name.from_text(domain)
    query = dns.message.make_query(name, rr_type.value.code)
    response = dns.message.make_response(query)

    if cname_domain is not None:
        cname_rdata = dns.rdata.GenericRdata(
            dns.rdataclass.IN, DnsRrType.CNAME.value.code, dns.name.from_text(cname_domain).to_wire()
        )
        response.answer.append(dns.rrset.from_rdata_list(name, 3600, [cname_rdata]))

    rdata_list = [
        dns.rdata.GenericRdata(
            dns.rdataclass.IN,
            rr_type.value.code,
            dns_record if isinstance(dns_record, (bytes, bytearray)) else dns_record.compose(),
        )
        for dns_record in dns_records
    ]
    response.answer.append(dns.rrset.from_rdata_list(name, 3600, rdata_list))

    return dns.resolver.Answer(name, rr_type.value.code, dns.rdataclass.IN, response)


def resolve_from_records(domain, records_by_query, missing_error=dns.resolver.NoAnswer, cname_domain=None):
    answers = {}
    for (domain_prefix, rr_type), dns_records in records_by_query.items():
        query_domain = domain if domain_prefix is None else '.'.join([domain_prefix, domain])
        answers[(query_domain, rr_type.value.name)] = build_answer(
            query_domain, rr_type, dns_records, cname_domain=cname_domain
        )

    def fake_resolve(_dns_resolver, **kwargs):
        try:
            return answers[(str(kwargs['qname']), kwargs['rdtype'])]
        except KeyError as e:
            raise missing_error from e

    return fake_resolve
