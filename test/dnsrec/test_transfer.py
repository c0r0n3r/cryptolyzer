# SPDX-License-Identifier: MPL-2.0

import unittest

from test.common.markers import live_dns
from test.dnsrec.classes import resolve_from_records

from unittest.mock import Mock, patch

import dns.resolver

from cryptodatahub.dnsrec.algorithm import DnsRrType

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.dnsrec.client import L7ClientDns
from cryptolyzer.dnsrec.transfer import DnsHandshakeBase


class TestDnsHandshakeBase(unittest.TestCase):
    _A_RECORDS = [bytes([1, 0, 0, 1]), bytes([1, 1, 1, 1])]

    def test_record_query(self):
        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        self.assertEqual(len(list(dns_handshake.raw_records)), 0)

        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=resolve_from_records('one.one.one.one', {(None, DnsRrType.A): self._A_RECORDS})
        ):
            dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
            l7_client = L7ClientDns('one.one.one.one')
            dns_handshake.get_records(l7_client, DnsRrType.A)
            self.assertEqual(len(list(dns_handshake.raw_records)), 2)

    def test_resolve(self):
        dns_resolver = Mock()
        answer = DnsHandshakeBase._resolve(  # pylint: disable=protected-access
            dns_resolver, qname='one.one.one.one', rdtype='A'
        )
        self.assertEqual(answer, dns_resolver.resolve.return_value)
        dns_resolver.resolve.assert_called_once_with(qname='one.one.one.one', rdtype='A')

    def test_domain_prefix(self):
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=resolve_from_records('one.one.one', {('one', DnsRrType.A): self._A_RECORDS})
        ):
            dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
            l7_client = L7ClientDns('one.one.one')
            dns_handshake.get_records(l7_client, DnsRrType.A, domain_prefix='one')
            self.assertEqual(len(list(dns_handshake.raw_records)), 2)

    def test_cname_record(self):
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=resolve_from_records(
                'searchsecurity.techtarget.com',
                {(None, DnsRrType.A): self._A_RECORDS},
                cname_domain='techtarget.com',
            )
        ):
            dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
            l7_client = L7ClientDns('searchsecurity.techtarget.com')
            dns_handshake.get_records(l7_client, DnsRrType.A)
            self.assertEqual(len(list(dns_handshake.raw_records)), 2)

    def test_error_non_existing_domain(self):
        with patch.object(DnsHandshakeBase, '_resolve', side_effect=dns.resolver.NXDOMAIN):
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

    @live_dns
    def test_real(self):
        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        l7_client = L7ClientDns('one.one.one.one')
        dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(len(list(dns_handshake.raw_records)), 2)

        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        l7_client = L7ClientDns('one.one.one.one')
        dns_handshake.get_records(l7_client, DnsRrType.AAAA)
        self.assertEqual(len(list(dns_handshake.raw_records)), 2)
