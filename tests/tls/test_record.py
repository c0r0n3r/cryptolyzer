#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

import six

from crypton.common.exception import NotEnoughData, InvalidValue

from crypton.tls.record import TlsRecord
from crypton.tls.subprotocol import TlsSubprotocolMessageBase
from crypton.tls.version import TlsVersion, TlsProtocolVersionFinal

from crypton.tls.subprotocol import TlsAlertMessage, TlsAlertLevel, TlsAlertDescription


class TestSubprotocolMessageBase(unittest.TestCase):
    def test_error(self):
        with self.assertRaises(NotImplementedError):
            TlsSubprotocolMessageBase.get_content_type()


class TestRecord(unittest.TestCase):
    def setUp(self):
        self.test_message = TlsAlertMessage(
            level=TlsAlertLevel.FATAL,
            description=TlsAlertDescription.HANDSHAKE_FAILURE
        )
        self.test_record = TlsRecord(
            messages=[self.test_message, ],
            protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0)
        )
        self.test_record_bytes = b'\x15\x03\x01\x00\x02\x02\x28'

    def test_error(self):
        with six.assertRaisesRegex(self, InvalidValue, '0xff is not a valid TlsContentType'):
            record = TlsRecord.parse_exact_bytes(
                b'\xff' +      # type = INVALID
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x00' +  # length = 0
                b''
            )

        with self.assertRaises(NotEnoughData) as context_manager:
            record = TlsRecord.parse_exact_bytes(
                b'\x15' +      # type = alert
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x01' +  # length = 1
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 1)

        record = TlsRecord.parse_exact_bytes(
            b'\x15' +      # type = alert
            b'\x03\x03' +  # version = TLS 1.2
            b'\x00\x02' +  # length = 2
            b'\x02\x28'
        )
        with self.assertRaises(ValueError):
            record.protocol_version = 'invalid version'
        with self.assertRaises(ValueError):
            record.messages = ['invalid message', ]

        with self.assertRaises(NotEnoughData) as context_manager:
            record = TlsRecord.parse_exact_bytes(
                b'\x16' +      # type = handshake
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x02' +  # length = 4
                b''
            )
        self.assertEqual(context_manager.exception.bytes_needed, 2)

        with self.assertRaises(InvalidValue) as context_manager:
            record = TlsRecord.parse_exact_bytes(
                b'\x16' +          # type = handshake
                b'\x03\x01' +      # version = TLS 1.0
                b'\x00\x06' +      # length = 10
                b'\xff'            # handshake_type: INVALID
                b'\x00\x00\x02' +  # handshake_length = 0
                b'\x03\x03' +      # version = TLS 1.2
                b''
            )

        with self.assertRaises(InvalidValue) as context_manager:
            record = TlsRecord.parse_exact_bytes(
                b'\x18' +      # type = heartbeat
                b'\x03\x03' +  # version = TLS 1.2
                b'\x00\x01' +  # length = 4
                b'\x00'
            )

    def test_parse(self):
        record = TlsRecord.parse_exact_bytes(self.test_record_bytes)

        self.assertEqual(len(record.messages), 1)
        self.assertEqual(
            record.messages[0],
            self.test_message
        )

    def test_compose(self):
        self.assertEqual(
            self.test_record.compose(),
            self.test_record_bytes
        )
