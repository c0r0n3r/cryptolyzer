#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import six

from crypton.common.exception import NotEnoughData, InvalidValue

from crypton.tls.subprotocol import TlsChangeCipherSpecMessage, TlsChangeCipherSpecType


class TestRecord(unittest.TestCase):
    def test_error(self):
        with six.assertRaisesRegex(self, InvalidValue, '0xff is not a valid TlsChangeCipherSpecType'):
            # pylint: disable=expression-not-assigned
            TlsChangeCipherSpecMessage.parse_exact_bytes(b'\xff'),

        with self.assertRaises(NotEnoughData) as context_manager:
            # pylint: disable=expression-not-assigned
            TlsChangeCipherSpecMessage.parse_exact_bytes(b''),
        self.assertEqual(context_manager.exception.bytes_needed, 1)

    def test_parse(self):
        self.assertEqual(
            TlsChangeCipherSpecMessage.parse_exact_bytes(b'\x01'),
            TlsChangeCipherSpecMessage(TlsChangeCipherSpecType.CHANGE_CIPHER_SPEC)
        )

    def test_compose(self):
        self.assertEqual(
            b'\x01',
            TlsChangeCipherSpecMessage(TlsChangeCipherSpecType.CHANGE_CIPHER_SPEC).compose()
        )
