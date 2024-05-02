# -*- coding: utf-8 -*-

import unittest

from cryptodatahub.dnsrec.algorithm import DnsRrType

from cryptolyzer.common.exception import NetworkError, NetworkErrorType

from cryptolyzer.dnsrec.client import L7ClientDns
from cryptolyzer.dnsrec.transfer import DnsHandshakeBase


class TestDnsHandshakeBase(unittest.TestCase):
    def test_record_query(self):
        dns_handshake = DnsHandshakeBase(5)
        self.assertEqual(len(list(dns_handshake.raw_records)), 0)

        dns_handshake = DnsHandshakeBase(5)
        l7_client = L7ClientDns('one.one.one.one')
        dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(len(list(dns_handshake.raw_records)), 2)

        dns_handshake = DnsHandshakeBase(5)
        l7_client = L7ClientDns('one.one.one.one')
        dns_handshake.get_records(l7_client, DnsRrType.AAAA)
        self.assertEqual(len(list(dns_handshake.raw_records)), 2)

    def test_domain_prefix(self):
        dns_handshake = DnsHandshakeBase(5)
        l7_client = L7ClientDns('one.one.one.one')
        dns_handshake.get_records(l7_client, DnsRrType.A)
        raw_records_without_domain_prefix = dns_handshake.raw_records

        dns_handshake = DnsHandshakeBase(5)
        l7_client = L7ClientDns('one.one.one')
        dns_handshake.get_records(l7_client, DnsRrType.A, domain_prefix='one')
        raw_records_with_domain_prefix = dns_handshake.raw_records

        self.assertEqual(set(raw_records_with_domain_prefix), set(raw_records_without_domain_prefix))

    def test_cname_record(self):
        dns_handshake = DnsHandshakeBase(5)
        l7_client = L7ClientDns('searchsecurity.techtarget.com')
        dns_handshake.get_records(l7_client, DnsRrType.A)

        self.assertEqual(len(list(dns_handshake.raw_records)), 2)

        dns_handshake = DnsHandshakeBase(5)
        l7_client = L7ClientDns('searchsecurity.techtarget.com')

        dns_handshake.get_records(l7_client, DnsRrType.CNAME)
        self.assertEqual(len(list(dns_handshake.raw_records)), 0)

        dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(len(list(dns_handshake.raw_records)), 2)

    def test_error_non_existing_domain(self):
        with self.assertRaises(NetworkError) as context_manager:
            dns_handshake = DnsHandshakeBase(5)
            l7_client = L7ClientDns('non.existing.domain')
            dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    def test_error_invalid_nameserver(self):
        with self.assertRaises(NetworkError) as context_manager:
            dns_handshake = DnsHandshakeBase(1)
            l7_client = L7ClientDns('one.one.one.one#256.256.256.256')
            dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)

    def test_error_nameserver_timeout(self):
        with self.assertRaises(NetworkError) as context_manager:
            dns_handshake = DnsHandshakeBase(0.001)
            l7_client = L7ClientDns('one.one.one.one#1.1.1.1', 0.001)
            dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)
