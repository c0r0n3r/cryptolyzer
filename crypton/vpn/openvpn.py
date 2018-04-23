#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc
import enum

from crypton.common.exception import InvalidValue, NotEnoughData
from crypton.common.parse import ParsableBase, Parser, Composer


class OpenVpnOpCode(enum.IntEnum):
    CONTROL_V1 = 0x04
    ACK_V1 = 0x05
    HARD_RESET_CLIENT_V2 = 0x07
    HARD_RESET_SERVER_V2 = 0x08


class OpenVPNPacketBase(ParsableBase):
    IS_TCP = True

    def __init__(self, session_id, packet_id_array=[], remote_session_id=None):
        self.session_id = session_id
        self.packet_id_array = packet_id_array
        self.remote_session_id = remote_session_id

    @classmethod
    @abc.abstractmethod
    def get_op_code(cls):
        return NotImplementedError()

    @classmethod
    def _parse_header(cls, parsable_bytes):
        parser = Parser(parsable_bytes)

        #FIXME
        if cls.IS_TCP:
            parser.parse_numeric('packet_len', 2)
            if parser['packet_len'] > parser.unparsed_byte_num:
                raise NotEnoughData(parser['packet_len']- parser.unparsed_byte_num)

        parser.parse_numeric('packet_type', 1)
        if parser['packet_type'] >> 3 != cls.get_op_code():
            raise InvalidValue(parser['packet_type'], OpenVPNPacketBase, 'opcode')

        parser.parse_numeric('session_id', 8)
        parser.parse_numeric('packet_id_array_length', 1)
        if parser['packet_id_array_length']:
            parser.parse_numeric_array('packet_id_array', parser['packet_id_array_length'], 4)
            parser.parse_numeric('remote_session_id', 8)

        return parser


    def _compose_header(self, payload_length=0):
        composer = Composer()

        composer.compose_numeric(self.get_op_code() << 3, 1)
        composer.compose_numeric(self.session_id, 8)
        composer.compose_numeric(len(self.packet_id_array), 1)
        if self.packet_id_array:
            composer.compose_numeric_array(self.packet_id_array, 4)
            composer.compose_numeric(self.remote_session_id, 8)

        #FIXME
        if self.IS_TCP:
            composer_payload_length = Composer()
            composer_payload_length.compose_numeric(composer.composed_byte_num + payload_length, 2)
            return composer_payload_length.composed_bytes + composer.composed_bytes
        else:
            return composer.composed_bytes


class OpenVPNPacketControlV1(OpenVPNPacketBase):
    def __init__(self, session_id, packet_ids, remote_session_id, packet_id, payload):
        super(OpenVPNPacketControlV1, self).__init__(session_id, packet_ids, remote_session_id)

        self.packet_id = packet_id
        self.data = payload

    @classmethod
    @abc.abstractmethod
    def get_op_code(cls):
        return OpenVpnOpCode.CONTROL_V1

    def compose(self):
        composer = Composer()

        composer.compose_numeric(self.packet_id, 4)
        composer.compose_bytes(self.data)

        return self._compose_header(composer.composed_byte_num) + composer.composed_bytes

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = cls._parse_header(parsable_bytes)

        parser.parse_numeric('packet_id', 4)
        parser.parse_bytes('payload', parser.unparsed_byte_num)

        return OpenVPNPacketControlV1(
            parser['session_id'],
            getattr(parser, 'packet_id_array', []),
            getattr(parser, 'remote_session_id', None),
            parser['packet_id'],
            parser['payload']
        ), parser.parsed_byte_num


class OpenVPNPacketAckV1(OpenVPNPacketBase):
    def __init__(self, session_id, remote_session_id, packet_ids):
        super(OpenVPNPacketAckV1, self).__init__(session_id, packet_ids, remote_session_id)

    @classmethod
    @abc.abstractmethod
    def get_op_code(cls):
        return OpenVpnOpCode.ACK_V1

    def compose(self):
        return self._compose_header()

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = cls._parse_header(parsable_bytes)

        return OpenVPNPacketAckV1(
            parser['session_id'],
            parser['remote_session_id'],
            parser['packet_id_array']
        ), parser.parsed_byte_num


class OpenVPNPacketHardResetClientV2(OpenVPNPacketBase):
    def __init__(self, session_id, packet_id):
        super(OpenVPNPacketHardResetClientV2, self).__init__(session_id)

        self.packet_id = packet_id

    @classmethod
    @abc.abstractmethod
    def get_op_code(cls):
        return OpenVpnOpCode.HARD_RESET_CLIENT_V2

    def compose(self):
        composer = Composer()

        composer.compose_numeric(self.packet_id, 4)

        return self._compose_header(composer.composed_byte_num) + composer.composed_bytes


class OpenVPNPacketHardResetServerV2(OpenVPNPacketBase):
    def __init__(self, session_id, remote_session_id, packet_id_array, packet_id):
        super(OpenVPNPacketHardResetServerV2, self).__init__(session_id, packet_id_array, remote_session_id)

        self.packet_id = packet_id

    @classmethod
    @abc.abstractmethod
    def get_op_code(cls):
        return OpenVpnOpCode.HARD_RESET_SERVER_V2

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = cls._parse_header(parsable_bytes)

        parser.parse_numeric('packet_id', 2)

        return OpenVPNPacketHardResetServerV2(
            parser['session_id'],
            getattr(parser, 'remote_session_id', None),
            getattr(parser, 'packet_id_array', []),
            parser['packet_id']
        ), parser.parsed_byte_num

    def compose(self):
        composer = Composer()

        composer.compose_numeric(self.packet_id, 2)

        return self._compose_header(composer.composed_byte_num) + composer.composed_bytes
