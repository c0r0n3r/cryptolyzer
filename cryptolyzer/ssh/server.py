# SPDX-License-Identifier: MPL-2.0

import abc
import attr

from cryptodatahub.common.key import PublicKey, PublicKeyParamsRsa
from cryptodatahub.common.parameter import DHParamWellKnown

from cryptodatahub.ssh.algorithm import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshKexAlgorithm,
    SshMacAlgorithm,
)

from cryptoparser.common.classes import LanguageTag
from cryptoparser.common.exception import NotEnoughData

from cryptoparser.ssh.key import SshHostKeyRSA, SshPublicKeyBase
from cryptoparser.ssh.record import SshRecordInit, SshRecordKexDH, SshRecordKexDHGroup
from cryptoparser.ssh.subprotocol import (
    SshDHGroupExchangeGroup,
    SshDHGroupExchangeReply,
    SshDHKeyExchangeReply,
    SshDisconnectMessage,
    SshKeyExchangeInit,
    SshMessageCode,
    SshNewKeys,
    SshReasonCode,
)
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion

from cryptolyzer.common.application import L7ServerBase, L7ServerHandshakeBase, L7ServerConfigurationBase
from cryptolyzer.common.dhparam import get_dh_ephemeral_key_forged, int_to_bytes

from cryptolyzer.ssh.client import SshProtocolMessageDefault
from cryptolyzer.ssh.transfer import SshHandshakeBase


# Public RSA host-key material only: a fixed ~2048-bit odd modulus (public data, never a private key) paired
# with the standard public exponent. It lets the offline mock server present a parseable host key during key
# exchange; the client verifies no signature, so no private key is ever needed.
DEFAULT_SSH_SERVER_HOST_PUBLIC_KEY = SshHostKeyRSA(
    SshHostKeyAlgorithm.SSH_RSA,
    PublicKey.from_params(PublicKeyParamsRsa(
        modulus=int('c0ffee' + 'a5' * 252 + '01', 16),
        public_exponent=65537,
    )),
)
DEFAULT_SSH_SERVER_DH_GROUP_EXCHANGE_GROUPS = (
    DHParamWellKnown.RFC3526_2048_BIT_MODP_GROUP,
    DHParamWellKnown.RFC3526_3072_BIT_MODP_GROUP,
    DHParamWellKnown.RFC3526_4096_BIT_MODP_GROUP,
    DHParamWellKnown.RFC3526_6144_BIT_MODP_GROUP,
    DHParamWellKnown.RFC3526_8192_BIT_MODP_GROUP,
)


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
    max_remote_algorithm_count = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(int)),
        default=None,
        metadata={'description': 'Maximum number of algorithms allowed per list from remote side (None = unlimited)'}
    )
    key_exchange_reply = attr.ib(
        validator=attr.validators.instance_of(bool),
        default=False,
        metadata={'description': 'Whether to complete the key exchange instead of disconnecting after KEXINIT'}
    )
    host_public_key = attr.ib(
        validator=attr.validators.instance_of(SshPublicKeyBase),
        default=DEFAULT_SSH_SERVER_HOST_PUBLIC_KEY
    )
    dh_group_exchange_groups = attr.ib(
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(DHParamWellKnown)),
        default=DEFAULT_SSH_SERVER_DH_GROUP_EXCHANGE_GROUPS
    )
    dh_group_exchange_bounds_tolerated = attr.ib(
        validator=attr.validators.instance_of(bool),
        default=True
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
        if self.configuration is not None and self.configuration.key_exchange_reply:
            return SshServerHandshakeKeyExchange

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

    def _disconnect_if_too_many_algorithms(self, message):
        if (self.configuration.max_remote_algorithm_count is None or
                message.get_message_code() != SshMessageCode.KEXINIT):
            return

        for attribute in message._get_cipher_attributes():  # pylint: disable=protected-access
            if 'algorithms' not in attribute.name:
                continue

            algorithm_list = getattr(message, attribute.name)
            if len(algorithm_list) > self.configuration.max_remote_algorithm_count:
                self._send_disconnect(
                    SshReasonCode.PROTOCOL_ERROR,
                    (
                        f'Too many {attribute.name} '
                        f'({len(algorithm_list)} > {self.configuration.max_remote_algorithm_count})'
                    )
                )
                raise StopIteration()

    def _process_handshake_message(self, message, last_handshake_message_type):
        self._last_processed_message_type = message.get_message_code()
        self.client_messages[self._last_processed_message_type] = message

        self._disconnect_if_too_many_algorithms(message)

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


@attr.s
class SshServerHandshakeKeyExchange(SshServerHandshake):
    _RECORD_CLASS_BY_MESSAGE_CODE = {
        SshMessageCode.DH_KEX_INIT: SshRecordKexDH,
        SshMessageCode.DH_GEX_REQUEST: SshRecordKexDHGroup,
        SshMessageCode.DH_GEX_INIT: SshRecordKexDHGroup,
    }
    _FORGED_SIGNATURE = b'\x00' * 4

    _group_exchange_group = attr.ib(init=False, default=None)

    def _parse_record(self):
        if len(self.l7_transfer.buffer) < SshRecordInit.HEADER_SIZE:
            raise NotEnoughData(SshRecordInit.HEADER_SIZE - len(self.l7_transfer.buffer))

        message_code = self.l7_transfer.buffer[5]
        record_class = self._RECORD_CLASS_BY_MESSAGE_CODE.get(message_code, SshRecordInit)
        record = record_class.parse_exact_size(self.l7_transfer.buffer)
        is_handshake = record.packet.get_message_code() != SshMessageCode.DISCONNECT

        return record, len(self.l7_transfer.buffer), is_handshake

    def _process_handshake_message(self, message, last_handshake_message_type):
        message_code = message.get_message_code()
        self._last_processed_message_type = message_code
        self.client_messages[message_code] = message

        if message_code == SshMessageCode.DH_KEX_INIT:
            self._send_key_exchange_reply(SshRecordKexDH, SshDHKeyExchangeReply, self._sorted_groups()[0])
        elif message_code == SshMessageCode.DH_GEX_REQUEST:
            self._send_group_exchange_group(message)
        elif message_code == SshMessageCode.DH_GEX_INIT:
            if self._group_exchange_group is None:
                raise StopIteration()
            self._send_key_exchange_reply(SshRecordKexDHGroup, SshDHGroupExchangeReply, self._group_exchange_group)
        else:
            self._disconnect_if_too_many_algorithms(message)

    def _sorted_groups(self):
        return sorted(self.configuration.dh_group_exchange_groups, key=lambda well_known: well_known.value.key_size)

    def _get_group_exchange_group(self, message):
        sorted_groups = self._sorted_groups()
        if not self.configuration.dh_group_exchange_bounds_tolerated:
            return sorted_groups[0]

        for well_known in sorted_groups:
            if message.gex_min <= well_known.value.key_size <= message.gex_max:
                return well_known

        return None

    def _send_group_exchange_group(self, message):
        well_known = self._get_group_exchange_group(message)
        if well_known is None:
            raise StopIteration()

        self._group_exchange_group = well_known
        parameter_numbers = well_known.value.parameter_numbers
        self.l7_transfer.send(SshRecordKexDHGroup(SshDHGroupExchangeGroup(
            int_to_bytes(parameter_numbers.p, well_known.value.key_size // 8),
            int_to_bytes(parameter_numbers.g, (parameter_numbers.g.bit_length() + 7) // 8),
        )).compose())

    def _send_key_exchange_reply(self, record_class, reply_class, well_known):
        ephemeral_public_key = int_to_bytes(
            get_dh_ephemeral_key_forged(well_known.value.parameter_numbers.p), well_known.value.key_size // 8
        ).lstrip(b'\x00')
        reply = reply_class(
            host_public_key=self.configuration.host_public_key,
            ephemeral_public_key=ephemeral_public_key,
            signature=self._FORGED_SIGNATURE,
        )
        self.l7_transfer.send(record_class(reply).compose() + record_class(SshNewKeys()).compose())


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
