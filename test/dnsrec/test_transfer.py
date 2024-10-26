# -*- coding: utf-8 -*-

import unittest

import dns.resolver

try:
    from unittest.mock import patch
except ImportError:
    from mock import patch

from cryptodatahub.dnsrec.algorithm import DnsRrType

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.dnsrec.client import L7ClientDns
from cryptolyzer.dnsrec.transfer import DnsHandshakeBase


class TestDnsHandshakeBase(unittest.TestCase):
    def test_record_query(self):
        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        self.assertEqual(len(list(dns_handshake.raw_records)), 0)

        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        l7_client = L7ClientDns('one.one.one.one')
        dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(len(list(dns_handshake.raw_records)), 2)

        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        l7_client = L7ClientDns('one.one.one.one')
        dns_handshake.get_records(l7_client, DnsRrType.AAAA)
        self.assertEqual(len(list(dns_handshake.raw_records)), 2)

    def test_domain_prefix(self):
        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        l7_client = L7ClientDns('one.one.one.one')
        dns_handshake.get_records(l7_client, DnsRrType.A)
        raw_records_without_domain_prefix = dns_handshake.raw_records

        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        l7_client = L7ClientDns('one.one.one')
        dns_handshake.get_records(l7_client, DnsRrType.A, domain_prefix='one')
        raw_records_with_domain_prefix = dns_handshake.raw_records

        self.assertEqual(set(raw_records_with_domain_prefix), set(raw_records_without_domain_prefix))

    def test_cname_record(self):
        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        l7_client = L7ClientDns('searchsecurity.techtarget.com')
        dns_handshake.get_records(l7_client, DnsRrType.A)

        self.assertEqual(len(list(dns_handshake.raw_records)), 2)

        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        l7_client = L7ClientDns('searchsecurity.techtarget.com')

        dns_handshake.get_records(l7_client, DnsRrType.CNAME)
        self.assertEqual(len(list(dns_handshake.raw_records)), 0)

        dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(len(list(dns_handshake.raw_records)), 2)

    def test_error_non_existing_domain(self):
        with self.assertRaises(NetworkError) as context_manager:
            dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
            l7_client = L7ClientDns('non.existing.domain')
            dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    def test_error_invalid_nameserver(self):
        with self.assertRaises(NetworkError) as context_manager:
            dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=1))
            l7_client = L7ClientDns('one.one.one.one#256.256.256.256')
            dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)

    @patch.object(DnsHandshakeBase, '_resolve', side_effect=dns.resolver.Timeout)
    def test_error_nameserver_timeout(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=1000))
            l7_client = L7ClientDns('one.one.one.one#1.1.1.1', L4TransferSocketParams(timeout=1000))
            dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_RESPONSE)
