# -*- coding: utf-8 -*-

import attr
import six

from cryptodatahub.common.algorithm import Authentication, KeyExchange, NamedGroup

from cryptodatahub.ssh.algorithm import (
    SshCompressionAlgorithm,
    SshEncryptionAlgorithm,
    SshHostKeyAlgorithm,
    SshHostKeyType,
    SshKexAlgorithm,
    SshMacAlgorithm,
)

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.ssh.key import SshX509Certificate, SshX509CertificateChain
from cryptoparser.ssh.record import SshRecordInit, SshRecordKexDH, SshRecordKexDHGroup
from cryptoparser.ssh.subprotocol import (
    SshDHGroupExchangeGroup,
    SshDHGroupExchangeInit,
    SshDHGroupExchangeRequest,
    SshDHKeyExchangeInit,
    SshDisconnectMessage,
    SshKeyExchangeInit,
    SshNewKeys,
    SshProtocolMessage,
)
from cryptoparser.ssh.version import SshProtocolVersion, SshSoftwareVersionUnparsed, SshVersion

from cryptolyzer import __setup__

from cryptolyzer.common.dhparam import (
    DHParamWellKnown,
    bytes_to_int,
    get_dh_ephemeral_key_forged,
    get_ecdh_ephemeral_key_forged,
    int_to_bytes,
)
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4ClientTCP, L7TransferBase

from cryptolyzer.ssh.exception import SshDisconnect
from cryptolyzer.ssh.transfer import SshHandshakeBase


SSH_KEX_ALGORITHMS_TO_NAMED_GROUP = {
    SshKexAlgorithm.CURVE25519_SHA256: NamedGroup.CURVE25519,
    SshKexAlgorithm.CURVE25519_SHA256_LIBSSH_ORG: NamedGroup.CURVE25519,
    SshKexAlgorithm.CURVE448_SHA512_LIBSSH_ORG: NamedGroup.CURVE25519,
    SshKexAlgorithm.ECDH_SHA2_SECP256K1_OID: NamedGroup.SECP256K1,
    SshKexAlgorithm.ECDH_SHA2_BRAINPOOLP256R1_GENUA_DE: NamedGroup.BRAINPOOLP256R1,
    SshKexAlgorithm.ECDH_SHA2_BRAINPOOLP384R1_GENUA_DE: NamedGroup.BRAINPOOLP384R1,
    SshKexAlgorithm.ECDH_SHA2_BRAINPOOLP521R1_GENUA_DE: NamedGroup.BRAINPOOLP512R1,
    SshKexAlgorithm.ECDH_SHA2_CURVE25519: NamedGroup.CURVE25519,
    SshKexAlgorithm.ECDH_SHA2_NISTB233: NamedGroup.SECT233R1,
    SshKexAlgorithm.ECDH_SHA2_NISTB409: NamedGroup.SECT409R1,
    SshKexAlgorithm.ECDH_SHA2_NISTK163: NamedGroup.SECT163K1,
    SshKexAlgorithm.ECDH_SHA2_NISTK233: NamedGroup.SECT233K1,
    SshKexAlgorithm.ECDH_SHA2_NISTK283: NamedGroup.SECT283K1,
    SshKexAlgorithm.ECDH_SHA2_NISTK409: NamedGroup.SECT409K1,
    SshKexAlgorithm.ECDH_SHA2_NISTP192: NamedGroup.PRIME192V1,
    SshKexAlgorithm.ECDH_SHA2_NISTP224: NamedGroup.SECP224R1,
    SshKexAlgorithm.ECDH_SHA2_NISTP256: NamedGroup.PRIME256V1,
    SshKexAlgorithm.ECDH_SHA2_NISTP256_WIN7_MICROSOFT_COM: NamedGroup.PRIME256V1,
    SshKexAlgorithm.ECDH_SHA2_NISTP384: NamedGroup.SECP384R1,
    SshKexAlgorithm.ECDH_SHA2_NISTP384_WIN7_MICROSOFT_COM: NamedGroup.SECP384R1,
    SshKexAlgorithm.ECDH_SHA2_NISTP521: NamedGroup.SECP521R1,
    SshKexAlgorithm.ECDH_SHA2_NISTP521_WIN7_MICROSOFT_COM: NamedGroup.SECP521R1,
    SshKexAlgorithm.ECDH_SHA2_NISTT571: NamedGroup.SECT571R1,
}


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


class SshKeyExchangeInitKeyExchangeBase(SshKeyExchangeInitAnyAlgorithm):
    def __init__(self, key_exchange):
        super(SshKeyExchangeInitKeyExchangeBase, self).__init__(
            kex_algorithms=[
                kex_algorithm
                for kex_algorithm in SshKexAlgorithm
                if kex_algorithm.value.kex == key_exchange
            ]
        )


class SshKeyExchangeInitKeyExchangeDHE(SshKeyExchangeInitKeyExchangeBase):
    def __init__(self):
        super(SshKeyExchangeInitKeyExchangeDHE, self).__init__(KeyExchange.DHE)


class SshKeyExchangeInitKeyExchangeECDHE(SshKeyExchangeInitKeyExchangeBase):
    def __init__(self):
        super(SshKeyExchangeInitKeyExchangeECDHE, self).__init__(KeyExchange.ECDHE)


class SshKeyExchangeInitHostKeyBase(SshKeyExchangeInitAnyAlgorithm):
    def __init__(self, host_key_type, authentication):
        super(SshKeyExchangeInitHostKeyBase, self).__init__(
            kex_algorithms=list(filter(
                lambda algorithm: algorithm.value.kex in [KeyExchange.DHE, KeyExchange.ECDHE],
                SshKexAlgorithm
            )),
            host_key_algorithms=list(filter(
                lambda algorithm: (
                    algorithm.value.signature.value.key_type == authentication and
                    algorithm.value.key_type == host_key_type
                ),
                SshHostKeyAlgorithm
            ))
        )


class SshKeyExchangeInitHostKeyDSS(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostKeyDSS, self).__init__(
            SshHostKeyType.HOST_KEY, Authentication.DSS
        )


class SshKeyExchangeInitHostKeyRSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostKeyRSA, self).__init__(
            SshHostKeyType.HOST_KEY, Authentication.RSA
        )


class SshKeyExchangeInitHostKeyECDSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostKeyECDSA, self).__init__(
            SshHostKeyType.HOST_KEY, Authentication.ECDSA
        )


class SshKeyExchangeInitHostKeyED25519(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostKeyED25519, self).__init__(
            SshHostKeyType.HOST_KEY, Authentication.EDDSA
        )


class SshKeyExchangeInitHostCertificateV00DSS(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostCertificateV00DSS, self).__init__(
            SshHostKeyType.HOST_CERTIFICATE, Authentication.DSS
        )


class SshKeyExchangeInitHostCertificateV00RSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostCertificateV00RSA, self).__init__(
            SshHostKeyType.HOST_CERTIFICATE, Authentication.RSA
        )


class SshKeyExchangeInitHostCertificateV01DSS(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostCertificateV01DSS, self).__init__(
            SshHostKeyType.HOST_CERTIFICATE, Authentication.DSS
        )


class SshKeyExchangeInitHostCertificateV01RSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostCertificateV01RSA, self).__init__(
            SshHostKeyType.HOST_CERTIFICATE, Authentication.RSA
        )


class SshKeyExchangeInitHostCertificateV01ECDSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostCertificateV01ECDSA, self).__init__(
            SshHostKeyType.HOST_CERTIFICATE, Authentication.ECDSA
        )


class SshKeyExchangeInitHostCertificateV01ED25519(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostCertificateV01ED25519, self).__init__(
            SshHostKeyType.HOST_CERTIFICATE, Authentication.EDDSA
        )


class SshKeyExchangeInitX509CertificateBase(SshKeyExchangeInitAnyAlgorithm):
    def __init__(self, ssh_x509_certificate_class, authentication):
        super(SshKeyExchangeInitX509CertificateBase, self).__init__(
            kex_algorithms=list(filter(
                lambda algorithm: algorithm.value.kex in [KeyExchange.ECDHE],
                SshKexAlgorithm
            )),
            host_key_algorithms=list(filter(
                lambda algorithm: algorithm.value.signature.value.key_type == authentication,
                ssh_x509_certificate_class.get_host_key_algorithms()
            ))
        )


class SshKeyExchangeInitX509CertificateDSS(SshKeyExchangeInitX509CertificateBase):
    def __init__(self):
        super(SshKeyExchangeInitX509CertificateDSS, self).__init__(
            SshX509Certificate, Authentication.DSS
        )


class SshKeyExchangeInitX509CertificateRSA(SshKeyExchangeInitX509CertificateBase):
    def __init__(self):
        super(SshKeyExchangeInitX509CertificateRSA, self).__init__(
            SshX509Certificate, Authentication.RSA
        )


class SshKeyExchangeInitX509CertificateChainDSA(SshKeyExchangeInitX509CertificateBase):
    def __init__(self):
        super(SshKeyExchangeInitX509CertificateChainDSA, self).__init__(
            SshX509CertificateChain, Authentication.DSS
        )


class SshKeyExchangeInitX509CertificateChainECDSA(SshKeyExchangeInitX509CertificateBase):
    def __init__(self):
        super(SshKeyExchangeInitX509CertificateChainECDSA, self).__init__(
            SshX509CertificateChain, Authentication.ECDSA
        )


class SshKeyExchangeInitX509CertificateChainRSA(SshKeyExchangeInitX509CertificateBase):
    def __init__(self):
        super(SshKeyExchangeInitX509CertificateChainRSA, self).__init__(
            SshX509CertificateChain, Authentication.RSA
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
            last_message_type=SshKeyExchangeInit.get_message_code(),
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
    def _process_kex_init_dhe(cls, transfer, agreed_kex_type, gex_params):
        if agreed_kex_type.value.key_size is None:
            record_class = SshRecordKexDHGroup
            transfer.send(record_class(SshDHGroupExchangeRequest(
                gex_min=gex_params.gex_min,
                gex_max=gex_params.gex_max,
                gex_number=gex_params.gex_number,
            )).compose())
            raise IndexError(record_class)

        record_class = SshRecordKexDH
        key_size = agreed_kex_type.value.key_size
        for dh_param in DHParamWellKnown:
            if dh_param.value.key_size == key_size:
                ephemeral_public_key = get_dh_ephemeral_key_forged(dh_param.value.parameter_numbers.p)
                ephemeral_public_key_bytes = int_to_bytes(ephemeral_public_key, key_size).lstrip(b'\x00')
                break
        else:
            raise NotImplementedError()

        transfer.send(record_class(SshDHKeyExchangeInit(ephemeral_public_key_bytes)).compose())

        return record_class

    @classmethod
    def _process_kex_init_ecdhe(cls, transfer, agreed_kex_type):
        record_class = SshRecordKexDH
        try:
            named_group = SSH_KEX_ALGORITHMS_TO_NAMED_GROUP[agreed_kex_type]
        except KeyError as e:
            six.raise_from(NotImplementedError(), e)

        ephemeral_public_key_bytes = get_ecdh_ephemeral_key_forged(named_group)
        transfer.send(record_class(SshDHKeyExchangeInit(ephemeral_public_key_bytes)).compose())

        return record_class

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
            record_class = cls._process_kex_init_dhe(transfer, agreed_kex_type, gex_params)
        elif agreed_kex_type.value.kex == KeyExchange.ECDHE:
            record_class = cls._process_kex_init_ecdhe(transfer, agreed_kex_type)
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
                elif isinstance(record.packet, SshNewKeys):
                    raise NotImplementedError(SshNewKeys)

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
