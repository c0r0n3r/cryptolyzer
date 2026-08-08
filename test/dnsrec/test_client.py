# SPDX-License-Identifier: MPL-2.0

import unittest

from test.dnsrec.classes import resolve_from_records

from unittest.mock import patch

import urllib3

from cryptodatahub.dnsrec.algorithm import DnsRrType

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.dnsrec.client import L7ClientDns
from cryptolyzer.dnsrec.transfer import DnsHandshakeBase


class TestDnsClient(unittest.TestCase):
    def test_error_unknown_scheme(self):
        with self.assertRaises(ValueError) as context_manager:
            L7ClientDns.from_uri(urllib3.util.parse_url('unknown://mock.site'))
        self.assertEqual(context_manager.exception.args, ('unknown', ))

    def test_supported_schemes(self):
        self.assertEqual(L7ClientDns.get_supported_schemes(), {'dns': L7ClientDns})

    def test_client_dns(self):
        with patch.object(
            DnsHandshakeBase, '_resolve',
            side_effect=resolve_from_records(
                'one.one.one.one',
                {(None, DnsRrType.A): [bytes([1, 0, 0, 1]), bytes([1, 1, 1, 1])]},
            )
        ):
            dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
            l7_client = L7ClientDns.from_uri(urllib3.util.parse_url('dns://one.one.one.one'))
            dns_handshake.get_records(l7_client, DnsRrType.A)
            self.assertEqual(len(list(dns_handshake.raw_records)), 2)
