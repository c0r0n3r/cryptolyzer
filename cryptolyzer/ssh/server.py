# -*- coding: utf-8 -*-

import abc
import attr

from cryptodatahub.ssh.algorithm import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)

from cryptoparser.common.classes import LanguageTag

from cryptoparser.ssh.record import SshRecordInit
from cryptoparser.ssh.subprotocol import SshMessageCode, SshReasonCode, SshKeyExchangeInit, SshDisconnectMessage
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.application import L7ServerBase, L7ServerHandshakeBase, L7ServerConfigurationBase

from cryptolyzer.ssh.client import SshProtocolMessageDefault
from cryptolyzer.ssh.transfer import SshHandshakeBase


@attr.s
class SshServerConfiguration(L7ServerConfigurationBase):  # pylint: disable=too-many-instance-attributes
    protocol_version = attr.ib(
        validator=attr.validators.instance_of(SshProtocolVersion),
        default=SshProtocolVersion(SshVersion.SSH2)
    )
    kex_algorithms = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SshKexAlgorithm)),
        default=list(SshKexAlgorithm)
    )
    server_host_key_algorithms = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SshHostKeyAlgorithm)),
        default=list(SshHostKeyAlgorithm)
    )
    encryption_algorithms_client_to_server = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SshEncryptionAlgorithm)),
        default=list(SshEncryptionAlgorithm)
    )
    encryption_algorithms_server_to_client = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SshEncryptionAlgorithm)),
        default=list(SshEncryptionAlgorithm)
    )
    mac_algorithms_client_to_server = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SshMacAlgorithm)),
        default=list(SshMacAlgorithm)
    )
    mac_algorithms_server_to_client = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SshMacAlgorithm)),
        default=list(SshMacAlgorithm)
    )
    compression_algorithms_client_to_server = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SshCompressionAlgorithm)),
        default=list(SshCompressionAlgorithm)
    )
    compression_algorithms_server_to_client = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SshCompressionAlgorithm)),
        default=list(SshCompressionAlgorithm)
    )
    languages_client_to_server = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(LanguageTag)),
        default=()
    )
    languages_server_to_client = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.instance_of(LanguageTag)),
        default=()
    )


@attr.s
class L7ServerSshBase(L7ServerBase):
    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    def _get_handshake_class(self):
        return SshServerHandshake

    def _do_handshake(self, last_handshake_message_type):
        try:
            handshake_class = self._get_handshake_class()
            handshake_object = handshake_class(self, self.configuration)
            handshake_object.do_handshake(last_handshake_message_type)
        finally:
            self.l4_transfer.close()

        return handshake_object.client_messages

    def do_ssh_handshake(self, last_handshake_message_type=SshMessageCode.KEXINIT):
        return self._do_handshakes(last_handshake_message_type)


@attr.s
class SshServerHandshake(L7ServerHandshakeBase, SshHandshakeBase):
    def _init_connection(self, last_handshake_message_type):
        protocol_message = SshProtocolMessageDefault()
        protocol_message.protocol_version = self.configuration.protocol_version

        key_exchange_init_message = SshKeyExchangeInit(
            self.configuration.kex_algorithms,
            self.configuration.server_host_key_algorithms,
            self.configuration.encryption_algorithms_client_to_server,
            self.configuration.encryption_algorithms_server_to_client,
            self.configuration.mac_algorithms_client_to_server,
            self.configuration.mac_algorithms_server_to_client,
            self.configuration.compression_algorithms_client_to_server,
            self.configuration.compression_algorithms_server_to_client,
            self.configuration.languages_client_to_server,
            self.configuration.languages_server_to_client,
        )

        return self.do_key_exchange_init(
            transfer=self.l7_transfer,
            protocol_message=protocol_message,
            key_exchange_init_message=key_exchange_init_message,
            last_handshake_message_type=last_handshake_message_type
        )

    def _parse_record(self):
        record = SshRecordInit.parse_exact_size(self.l7_transfer.buffer)
        is_handshake = record.packet.get_message_code() == SshMessageCode.KEXINIT

        return record, len(self.l7_transfer.buffer), is_handshake

    def _parse_message(self, record):
        return record.packet

    def _process_handshake_message(self, message, last_handshake_message_type):
        self._last_processed_message_type = message.get_message_code()
        self.client_messages[self._last_processed_message_type] = message

        if self._last_processed_message_type == last_handshake_message_type:
            self._send_disconnect(SshReasonCode.HOST_NOT_ALLOWED_TO_CONNECT, 'not allowed to connect')
            raise StopIteration()

    def _process_non_handshake_message(self, message):
        self._send_disconnect(SshReasonCode.PROTOCOL_ERROR, 'protocol error', 'en')
        raise StopIteration()

    def _process_invalid_message(self):
        self._send_disconnect(SshReasonCode.PROTOCOL_ERROR, 'protocol error', 'en')
        raise StopIteration()

    def _send_disconnect(self, reason, description, language=None):
        kwargs = {
            'reason': reason,
            'description': description,
        }
        if language is not None:
            kwargs['language'] = language

        self.l7_transfer.send(SshRecordInit(SshDisconnectMessage(**kwargs)).compose())


class L7ServerSsh(L7ServerSshBase):
    def __attrs_post_init__(self):
        if self.configuration is None:
            self.configuration = SshServerConfiguration()

    @classmethod
    def get_scheme(cls):
        return 'ssh'

    @classmethod
    def get_default_port(cls):
        return 2222
