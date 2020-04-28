# -*- coding: utf-8 -*-

import unittest
import socket

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.utils import resolve_address


class TestResolveAddress(unittest.TestCase):
    def test_error_wrong_ip(self):
        with self.assertRaises(NetworkError) as context_manager:
            resolve_address('one.one.one.one', 0, 'not.an.ip')
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    def test_error_unresolvable_address(self):
        with self.assertRaises(NetworkError) as context_manager:
            resolve_address('unresolvable.address', 0)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    def test_resolve(self):
        family, ip = resolve_address('one.one.one.one', 0, '1.1.1.1')
        self.assertEqual(family, socket.AF_INET)
        self.assertEqual(ip, '1.1.1.1')

        family, ip = resolve_address('one.one.one.one', 0, '2606:4700:4700::1111')
        self.assertEqual(family, socket.AF_INET6)
        self.assertEqual(ip, '2606:4700:4700::1111')
