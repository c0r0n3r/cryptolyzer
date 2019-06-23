# -*- coding: utf-8 -*-

import six

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.ssh.record import SshRecord
from cryptoparser.ssh.subprotocol import SshProtocolMessage, SshKeyExchangeInit, SshMessageCode
from cryptoparser.ssh.ciphersuite import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4ClientTCP, L7TransferBase

from cryptolyzer.ssh.exception import SshDisconnect
from cryptolyzer.ssh.transfer import SshHandshakeBase


class SshProtocolMessageDefault(SshProtocolMessage):
    def __init__(self):
        super(SshProtocolMessageDefault, self).__init__(
            protocol_version=SshProtocolVersion(SshVersion.SSH2, 0),
            software_version='CryptoLyzer',
            comment='https://gitlab.com/coroner/cyrptolyzer'
        )


class SshKeyExchangeInitAnyAlgorithm(SshKeyExchangeInit):
    def __init__(self):
        super(SshKeyExchangeInitAnyAlgorithm, self).__init__(
            kex_algorithms=list(SshKexAlgorithm),
            host_key_algorithms=list(SshHostKeyAlgorithm),
            encryption_algorithms_client_to_server=list(SshEncryptionAlgorithm),
            encryption_algorithms_server_to_client=list(SshEncryptionAlgorithm),
            mac_algorithms_client_to_server=list(SshMacAlgorithm),
            mac_algorithms_server_to_client=list(SshMacAlgorithm),
            compression_algorithms_client_to_server=list(SshCompressionAlgorithm),
            compression_algorithms_server_to_client=list(SshCompressionAlgorithm),
        )


class L7ClientSsh(L7TransferBase):
    @classmethod
    def get_scheme(cls):
        return 'ssh'

    @classmethod
    def get_default_port(cls):
        return 22

    @classmethod
    def get_supported_schemes(cls):
        return {'ssh': L7ClientSsh}

    def _init_connection(self):
        self.l4_transfer = L4ClientTCP(self.address, self.port, self.timeout, self.ip)
        self.l4_transfer.init_connection()

    def do_handshake(
            self,
            protocol_message=SshProtocolMessageDefault(),
            key_exchange_init_message=SshKeyExchangeInitAnyAlgorithm(),
            last_message_type=SshKeyExchangeInit
    ):
        self.init_connection()

        try:
            ssh_client = SshClientHandshake()
            ssh_client.do_handshake(
                self.l4_transfer,
                protocol_message,
                key_exchange_init_message,
                last_message_type
            )
        finally:
            self._close_connection()

        return ssh_client.server_messages


class SshClientHandshake(SshHandshakeBase):
    def do_handshake(
            self,
            transfer,
            protocol_message,
            key_exchange_init_message,
            last_message_type
    ):
        self.server_messages = self.do_key_exchange_init(
            transfer, protocol_message, key_exchange_init_message, last_message_type
        )
        if last_message_type in self.server_messages:
            return

        while True:
            try:
                record, parsed_length = SshRecord.parse_immutable(transfer.buffer)
                transfer.flush_buffer(parsed_length)

                if record.packet.get_message_code() == SshMessageCode.DISCONNECT:
                    raise SshDisconnect(record.packet.reason, record.packet.description)

                self._last_processed_message_type = type(record.packet)
                self.server_messages[self._last_processed_message_type] = record.packet
                if self._last_processed_message_type.get_message_code() == last_message_type:
                    break

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed

            try:
                transfer.receive(receivable_byte_num)
            except NotEnoughData as e:
                six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)
