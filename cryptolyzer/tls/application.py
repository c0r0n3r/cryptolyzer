# -*- coding: utf-8 -*-

import abc

import six

import attr

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.parse import ParserBinary
from cryptoparser.common.exception import NotEnoughData, InvalidType

from cryptoparser.tls.openvpn import (
    OpenVpnPacketAckV1,
    OpenVpnPacketControlV1,
    OpenVpnPacketVariant,
    OpenVpnPacketWrapperTcp,
    OpenVpnOpCode,
)

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType


@attr.s(init=False)
class L7OpenVpnBase(object):
    _FRAGMENT_LENGHT = 100

    session_id = attr.ib(
        init=False, default=None,
        validator=attr.validators.optional(attr.validators.instance_of(six.integer_types))
    )
    client_packet_id = attr.ib(
        init=False, default=0x00000000,
        validator=attr.validators.instance_of(six.integer_types)
    )
    remote_session_id = attr.ib(
        init=False, default=None,
        validator=attr.validators.optional(attr.validators.instance_of(six.integer_types))
    )
    _buffer = attr.ib(init=False)

    @classmethod
    @abc.abstractmethod
    def _is_tcp(cls):
        raise NotImplementedError()

    def _parse_packet(self, parsable):
        if self._is_tcp():
            parser = ParserBinary(parsable)
            parser.parse_parsable('packet', OpenVpnPacketWrapperTcp)
            parsable = parser['packet'].payload
            parsed_length = parser.parsed_length
        else:
            parsed_length = None

        parser = ParserBinary(parsable)
        parser.parse_parsable('packet', OpenVpnPacketVariant)

        if parsed_length is None:
            parsed_length = parser.parsed_length

        return parser['packet'], parsed_length

    def _send_packet(self, l4_transfer, packet):
        sendable_bytes = packet.compose()
        if self._is_tcp():
            sendable_bytes = OpenVpnPacketWrapperTcp(sendable_bytes).compose()

        l4_transfer.send(sendable_bytes)

        if packet.get_op_code() != OpenVpnOpCode.ACK_V1:
            self.client_packet_id += 1

    def _receive_packets(self, l4_transfer):
        packets = []
        receivable_byte_num = 0

        while True:
            try:
                packet, parsed_length = self._parse_packet(l4_transfer.buffer)
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            else:
                l4_transfer.flush_buffer(parsed_length)
                packets.append(packet)

                if not l4_transfer.buffer:
                    break

            try:
                l4_transfer.receive(receivable_byte_num)
            except NotEnoughData as e:
                if l4_transfer.buffer:
                    six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

                six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)

        return packets

    def _send_bytes(self, l4_transfer, sendable_bytes):
        fragment_count = int(len(sendable_bytes) / self._FRAGMENT_LENGHT) + 1
        for fragment_num in range(fragment_count):
            fragment_start = fragment_num * self._FRAGMENT_LENGHT
            fragment_end = (fragment_num + 1) * self._FRAGMENT_LENGHT
            fragment_bytes = sendable_bytes[fragment_start:fragment_end]

            fragment_packet = OpenVpnPacketControlV1(
                self.session_id,
                [self.client_packet_id],
                self.remote_session_id,
                self.client_packet_id,
                fragment_bytes
            )
            self._send_packet(l4_transfer, fragment_packet)

        return len(sendable_bytes)

    def _receive_packet_bytes(self, l4_transfer, receivable_byte_num):
        try:
            packets = self._receive_packets(l4_transfer)
        except (InvalidType, InvalidValue, NotEnoughData) as e:
            six.raise_from(SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY), e)

        received_bytes = bytearray()
        for packet in packets:
            if packet.get_op_code() == OpenVpnOpCode.ACK_V1:
                continue
            if packet.get_op_code() == OpenVpnOpCode.CONTROL_V1:
                received_bytes += packet.payload

                packet_ack = OpenVpnPacketAckV1(
                    self.session_id,
                    self.remote_session_id,
                    [packet.packet_id, ]
                )
                self._send_packet(l4_transfer, packet_ack)
            elif packet.get_op_code() == OpenVpnOpCode.HARD_RESET_SERVER_V2:
                raise NotEnoughData(receivable_byte_num - len(received_bytes))
            else:
                raise InvalidType()

        return received_bytes
