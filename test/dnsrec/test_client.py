# -*- coding: utf-8 -*-

import unittest

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

    def test_client_dns(self):
        dns_handshake = DnsHandshakeBase(L4TransferSocketParams(timeout=5))
        l7_client = L7ClientDns.from_uri(urllib3.util.parse_url('dns://one.one.one.one'))
        dns_handshake.get_records(l7_client, DnsRrType.A)
        self.assertEqual(len(list(dns_handshake.raw_records)), 2)
