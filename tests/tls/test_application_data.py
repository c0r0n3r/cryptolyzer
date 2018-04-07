#!/usr/bin/env python
# -*- coding: utf-8 -*-

import unittest

from crypton.tls.record import TlsContentType
from crypton.tls.subprotocol import TlsApplicationDataMessage


class TestRecord(unittest.TestCase):
    _APPLICATION_DATA_MESSAGE_BYTES = b'\x01\x02\x03\x04'

    def test_error(self):
        pass

    def test_parse(self):
        self.assertEqual(
            TlsApplicationDataMessage.parse_exact_bytes(self._APPLICATION_DATA_MESSAGE_BYTES),
            TlsApplicationDataMessage(data=self._APPLICATION_DATA_MESSAGE_BYTES)
        )

    def test_compose(self):
        self.assertEqual(
            self._APPLICATION_DATA_MESSAGE_BYTES,
            TlsApplicationDataMessage(data=self._APPLICATION_DATA_MESSAGE_BYTES).compose()
        )

    def test_content_type(self):
        self.assertEqual(TlsApplicationDataMessage.get_content_type(), TlsContentType.APPLICATION_DATA)
