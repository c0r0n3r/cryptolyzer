#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum

from crypton.common.exception import NotEnoughData, InvalidValue
from crypton.common.parse import ParsableBase, Parser, Composer


class TlsContentType(enum.IntEnum):
    CHANGE_CIPHER_SPEC = 0x14
    ALERT = 0x15
    HANDSHAKE = 0x16
    APPLICATION_DATA = 0x17
    HEARTBEAT = 0x18


class TlsSubprotocolMessageBase(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def get_content_type(cls):
        raise NotImplementedError()


class TlsAlertLevel(enum.IntEnum):
    WARNING = 0x01
    FATAL = 0x02


class TlsAlertDescription(enum.IntEnum):
    CLOSE_NOTIFY = 0x00
    UNEXPECTED_MESSAGE = 0x0a
    BAD_RECORD_MAC = 0x14
    RECORD_OVERFLOW = 0x16
    HANDSHAKE_FAILURE = 0x28
    BAD_CERTIFICATE = 0x2a
    UNSUPPORTED_CERTIFICATE = 0x2b
    CERTIFICATE_REVOKED = 0x2c
    CERTIFICATE_EXPIRED = 0x2d
    CERTIFICATE_UNKNOWN = 0x2e
    ILLEGAL_PARAMETER = 0x2f
    UNKNOWN_CA = 0x30
    ACCESS_DENIED = 0x30
    DECODE_ERROR = 0x32
    DECRYPT_ERROR = 0x33
    PROTOCOL_VERSION = 0x46
    INSUFFICIENT_SECURITY = 0x47
    INTERNAL_ERROR = 0x50
    INAPPROPRIATE_FALLBACK = 0x56
    USER_CANCELED = 0x5a
    MISSING_EXTENSION = 0x6d
    UNSUPPORTED_EXTENSION = 0x6e
    CERTIFICATE_UNOBTAINABLE = 0x6f
    UNRECOGNIZED_NAME = 0x70
    BAD_CERTIFICATE_STATUS_RESPONSE = 0x71
    BAD_CERTIFICATE_HASH_VALUE = 0x72
    UNKNOWN_PSK_IDENTITY = 0x73
    CERTIFICATE_REQUIRED = 0x74
    NO_APPLICATION_PROTOCOL = 0x78


class TlsAlertMessage(TlsSubprotocolMessageBase):
    __SIZE = 2

    def __init__(self, level, description):
        self.level = level
        self.description = description

    @classmethod
    def get_content_type(cls):
        return TlsContentType.ALERT

    @classmethod
    def _parse(cls, parsable_bytes):
        if len(parsable_bytes) < cls.__SIZE:
            raise NotEnoughData(cls.__SIZE)

        parser = Parser(parsable_bytes)

        parser.parse_numeric('level', 1)
        parser.parse_numeric('description', 1)

        return TlsAlertMessage(parser['level'], parser['description']), parser.parsed_byte_num

    def compose(self):
        composer = Composer()

        composer.compose_numeric(self.level, 1)
        composer.compose_numeric(self.description, 1)

        return composer.composed_bytes

    @property
    def level(self):
        return self._level

    @level.setter
    def level(self, value):
        try:
            # pylint: disable=attribute-defined-outside-init
            self._level = TlsAlertLevel(value)
        except ValueError:
            raise InvalidValue(value, TlsAlertLevel)

    @property
    def description(self):
        return self._description

    @description.setter
    def description(self, value):
        try:
            # pylint: disable=attribute-defined-outside-init
            self._description = TlsAlertDescription(value)
        except ValueError:
            raise InvalidValue(value, TlsAlertDescription)

    def __eq__(self, other):
        return self.level == other.level and self.description == other.description


class TlsChangeCipherSpecType(enum.IntEnum):
    CHANGE_CIPHER_SPEC = 0x01


class TlsChangeCipherSpecMessage(TlsSubprotocolMessageBase):
    def __init__(self, change_cipher_spec_type=TlsChangeCipherSpecType.CHANGE_CIPHER_SPEC):
        super(TlsChangeCipherSpecMessage, self).__init__()

        self._change_cipher_spec_type = change_cipher_spec_type

    @classmethod
    def get_content_type(cls):
        return TlsContentType.CHANGE_CIPHER_SPEC

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        parser.parse_numeric('change_cipher_spec_type', 1, TlsChangeCipherSpecType)

        return TlsChangeCipherSpecMessage(parser['change_cipher_spec_type']), parser.parsed_byte_num

    def compose(self):
        composer = Composer()

        composer.compose_numeric(self._change_cipher_spec_type, 1)

        return composer.composed_bytes

    def __eq__(self, other):
        return self._change_cipher_spec_type == other._change_cipher_spec_type


class TlsApplicationDataMessage(TlsSubprotocolMessageBase):
    def __init__(self, data):
        super(TlsApplicationDataMessage, self).__init__()

        self.data = data

    @classmethod
    def get_content_type(cls):
        return TlsContentType.APPLICATION_DATA

    @classmethod
    def _parse(cls, parsable_bytes):
        return TlsApplicationDataMessage(parsable_bytes), len(parsable_bytes)

    def compose(self):
        return self.data

    def __eq__(self, other):
        return self.data == other.data
