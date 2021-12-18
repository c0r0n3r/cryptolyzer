# -*- coding: utf-8 -*-

import attr
import six

from cryptoparser.common.algorithm import KeyExchange
from cryptoparser.common.exception import NotEnoughData

from cryptoparser.ssh.record import SshRecordInit, SshRecordKexDH, SshRecordKexDHGroup
from cryptoparser.ssh.ciphersuite import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)
from cryptoparser.ssh.subprotocol import (
    SshKeyExchangeInit,
    SshDHGroupExchangeGroup,
    SshDHGroupExchangeInit,
    SshDHGroupExchangeRequest,
    SshDisconnectMessage,
    SshProtocolMessage,
)
from cryptoparser.ssh.version import SshProtocolVersion, SshSoftwareVersionUnparsed, SshVersion

from cryptolyzer import __setup__

from cryptolyzer.common.dhparam import get_dh_ephemeral_key_forged, bytes_to_int, int_to_bytes
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4ClientTCP, L7TransferBase

from cryptolyzer.ssh.exception import SshDisconnect
from cryptolyzer.ssh.transfer import SshHandshakeBase


class SshProtocolMessageDefault(SshProtocolMessage):
    def __init__(self):
        super(SshProtocolMessageDefault, self).__init__(
            protocol_version=SshProtocolVersion(SshVersion.SSH2, 0),
            software_version=SshSoftwareVersionUnparsed('{}_{}'.format(__setup__.__title__, __setup__.__version__)),
            comment=__setup__.__url__
        )


class SshKeyExchangeInitAnyAlgorithm(SshKeyExchangeInit):
    def __init__(
            self,
            kex_algorithms=tuple(SshKexAlgorithm),
            host_key_algorithms=tuple(SshHostKeyAlgorithm),
            encryption_algorithms_client_to_server=tuple(SshEncryptionAlgorithm),
            encryption_algorithms_server_to_client=tuple(SshEncryptionAlgorithm),
            mac_algorithms_client_to_server=tuple(SshMacAlgorithm),
            mac_algorithms_server_to_client=tuple(SshMacAlgorithm),
            compression_algorithms_client_to_server=tuple(SshCompressionAlgorithm),
            compression_algorithms_server_to_client=tuple(SshCompressionAlgorithm),
    ):  # pylint: disable=too-many-arguments

        super(SshKeyExchangeInitAnyAlgorithm, self).__init__(
            kex_algorithms=kex_algorithms,
            host_key_algorithms=host_key_algorithms,
            encryption_algorithms_client_to_server=encryption_algorithms_client_to_server,
            encryption_algorithms_server_to_client=encryption_algorithms_server_to_client,
            mac_algorithms_client_to_server=mac_algorithms_client_to_server,
            mac_algorithms_server_to_client=mac_algorithms_server_to_client,
            compression_algorithms_client_to_server=compression_algorithms_client_to_server,
            compression_algorithms_server_to_client=compression_algorithms_server_to_client,
        )


class SshKeyExchangeInitKeyExchangeDHE(SshKeyExchangeInitAnyAlgorithm):
    def __init__(self):
        super(SshKeyExchangeInitKeyExchangeDHE, self).__init__(
            kex_algorithms=[
                kex_algorithm
                for kex_algorithm in SshKexAlgorithm
                if kex_algorithm.value.kex == KeyExchange.DHE
            ]
        )


@attr.s(frozen=True)
class L7ServerSshGexParams(object):
    gex_min = attr.ib(default=768, validator=attr.validators.instance_of(six.integer_types))
    gex_max = attr.ib(default=8192, validator=attr.validators.instance_of(six.integer_types))
    gex_number = attr.ib(default=2048, validator=attr.validators.instance_of(six.integer_types))


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
            gex_params=L7ServerSshGexParams(),
            last_message_type=SshKeyExchangeInit,
    ):
        self.init_connection()

        try:
            ssh_client = SshClientHandshake()
            ssh_client.do_handshake(
                transfer=self.l4_transfer,
                protocol_message=protocol_message,
                key_exchange_init_message=key_exchange_init_message,
                gex_params=gex_params,
                last_message_type=last_message_type,
            )
        finally:
            self._close_connection()

        return ssh_client.server_messages


class SshClientHandshake(SshHandshakeBase):
    @classmethod
    def _process_kex_init(cls, transfer, record, key_exchange_init_message, gex_params):
        agreed_kex = list(filter(
            record.packet.kex_algorithms.__contains__,
            key_exchange_init_message.kex_algorithms
        ))
        if not agreed_kex:
            raise NotImplementedError()

        agreed_kex_type = agreed_kex[0]
        if agreed_kex_type.value.kex == KeyExchange.DHE:
            if agreed_kex_type.value.key_size is None:
                record_class = SshRecordKexDHGroup
                transfer.send(record_class(SshDHGroupExchangeRequest(
                    gex_min=gex_params.gex_min,
                    gex_max=gex_params.gex_max,
                    gex_number=gex_params.gex_number,
                )).compose())
                raise IndexError(record_class)

            record_class = SshRecordKexDH
        else:
            raise NotImplementedError()

        return record_class

    @classmethod
    def _process_dh_group_exchange_group(cls, record, transfer, record_class):
        ephemeral_public_key = get_dh_ephemeral_key_forged(bytes_to_int(record.packet.p))
        ephemeral_public_key_bytes = int_to_bytes(ephemeral_public_key, 1024).lstrip(b'\x00')
        transfer.send(record_class(SshDHGroupExchangeInit(ephemeral_public_key_bytes)).compose())

        return SshRecordKexDHGroup

    def do_handshake(
            self,
            transfer,
            protocol_message,
            key_exchange_init_message,
            gex_params,
            last_message_type,
    ):  # pylint: disable=too-many-arguments
        self.server_messages = self.do_key_exchange_init(
            transfer, protocol_message, key_exchange_init_message, last_message_type
        )
        if last_message_type in self.server_messages:
            return

        record_class = SshRecordInit

        while True:
            try:
                record, parsed_length = record_class.parse_immutable(transfer.buffer)
                transfer.flush_buffer(parsed_length)

                if isinstance(record.packet, SshDisconnectMessage):
                    raise SshDisconnect(record.packet.reason, record.packet.description)

                self._last_processed_message_type = type(record.packet)
                self.server_messages[self._last_processed_message_type] = record.packet
                if self._last_processed_message_type.get_message_code() == last_message_type:
                    break

                if isinstance(record.packet, SshKeyExchangeInit):
                    record_class = self._process_kex_init(transfer, record, key_exchange_init_message, gex_params)
                elif isinstance(record.packet, SshDHGroupExchangeGroup):
                    record_class = self._process_dh_group_exchange_group(record, transfer, record_class)

                receivable_byte_num = record_class.HEADER_SIZE
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            except IndexError as e:
                record_class = e.args[0]
                continue

            try:
                transfer.receive(receivable_byte_num)
            except NotEnoughData as e:
                six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)
