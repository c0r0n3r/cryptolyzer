# -*- coding: utf-8 -*-

import attr

from cryptoparser.common.parse import ParserText

from cryptoparser.ssh.record import SshRecordInit

from cryptoparser.ssh.subprotocol import SshProtocolMessage


class SshHandshakeBase(object):
    _last_processed_message_type = attr.ib(init=False, default=None)
    server_messages = attr.ib(init=False, default={})

    @staticmethod
    def exchange_version(transfer, protocol_message):
        transfer.send(protocol_message.compose())

        transfer.receive_line(256)
        parser = ParserText(transfer.buffer)
        parser.parse_parsable('protocol_message', SshProtocolMessage)

        return parser

    def do_key_exchange_init(self, transfer, protocol_message, key_exchange_init_message, last_handshake_message_type):
        parser = self.exchange_version(transfer, protocol_message)
        received_messages = {SshProtocolMessage: parser['protocol_message']}
        if last_handshake_message_type == SshProtocolMessage:
            return received_messages

        transfer.flush_buffer(parser.parsed_length)
        transfer.send(SshRecordInit(key_exchange_init_message).compose())

        return received_messages
