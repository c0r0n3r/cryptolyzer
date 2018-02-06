#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import six

from crypton.common.exception import NotEnoughData, InvalidValue

from crypton.tls.subprotocol import TlsAlertMessage, TlsAlertLevel, TlsAlertDescription


class TestRecord(unittest.TestCase):
    def test_error(self):
        with six.assertRaisesRegex(self, InvalidValue, '0xff is not a valid TlsAlertLevel'):
            # pylint: disable=expression-not-assigned
            TlsAlertMessage.parse_exact_bytes(b'\xff\x00'),

        with six.assertRaisesRegex(self, InvalidValue, '0xff is not a valid TlsAlertDescription'):
            # pylint: disable=expression-not-assigned
            TlsAlertMessage.parse_exact_bytes(b'\x01\xff'),

        with self.assertRaises(NotEnoughData) as context_manager:
            # pylint: disable=expression-not-assigned
            TlsAlertMessage.parse_exact_bytes(b'\xff'),
        self.assertGreater(context_manager.exception.bytes_needed, 1)

    def test_parse(self):
        self.assertEqual(
            TlsAlertMessage.parse_exact_bytes(b'\x02\x28'),
            TlsAlertMessage(TlsAlertLevel.FATAL, TlsAlertDescription.HANDSHAKE_FAILURE)
        )

    def test_compose(self):
        self.assertEqual(
            b'\x02\x28',
            TlsAlertMessage(TlsAlertLevel.FATAL, TlsAlertDescription.HANDSHAKE_FAILURE).compose()
        )
