#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptography.hazmat.backends import default_backend as cryptography_default_backend
from cryptography.hazmat.primitives.asymmetric import dh as cryptography_dh
from cryptography.hazmat.primitives.asymmetric import ec as cryptography_ec
from cryptoparser.ssh.subprotocol import SshKexDHGexRequest

from cryptoparser.common.algorithm import Authentication, KeyExchange
from cryptoparser.common.client import L7ClientTcp
from cryptoparser.common.exception import NotEnoughData
from cryptoparser.common.parse import ParserText

from cryptolyzer.common.exception import NetworkError, NetworkErrorType

from cryptoparser.ssh.record import SshRecord
from cryptoparser.ssh.subprotocol import SshMessageCode, SshProtocolMessage, SshKeyExchangeInit
from cryptoparser.ssh.subprotocol import SshKexAlgorithmVector, SshHostKeyAlgorithmVector
from cryptoparser.ssh.ciphersuite import SshHostKeyAlgorithms, SshKexAlgorithms, SshEncryptionAlgorithms
from cryptoparser.ssh.ciphersuite import SshMacAlgorithms, SshCompressionAlgorithms, SshHostKeyType
from cryptoparser.ssh.version import SshProtocolVersion, SshVersion


class SshKeyExchangeInitAnyAlgorithm(SshKeyExchangeInit):
    def __init__(self):
        super(SshKeyExchangeInitAnyAlgorithm, self).__init__(
            kex_algorithms=list(SshKexAlgorithms),
            server_host_key_algorithms=list(SshHostKeyAlgorithms),
            encryption_algorithms_client_to_server=list(SshEncryptionAlgorithms),
            encryption_algorithms_server_to_client=list(SshEncryptionAlgorithms),
            mac_algorithms_client_to_server=list(SshMacAlgorithms),
            mac_algorithms_server_to_client=list(SshMacAlgorithms),
            compression_algorithms_client_to_server=list(SshCompressionAlgorithms),
            compression_algorithms_server_to_client=list(SshCompressionAlgorithms),
        )


class SshKeyExchangeInitHostKeyBase(SshKeyExchangeInitAnyAlgorithm):
    def __init__(self, host_key_type, authentication):
        super(SshKeyExchangeInitHostKeyBase, self).__init__()

        self.server_host_key_algorithms = SshHostKeyAlgorithmVector(list(filter(
            lambda algorithm: algorithm.value.authentication == authentication and algorithm.value.key_type == host_key_type,
            self.server_host_key_algorithms
        )))


class SshKeyExchangeInitHostKeyDSS(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostKeyDSS, self).__init__(SshHostKeyType.KEY, Authentication.DSS)


class SshKeyExchangeInitHostKeyRSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostKeyRSA, self).__init__(SshHostKeyType.KEY, Authentication.RSA)


class SshKeyExchangeInitHostKeyECDSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostKeyECDSA, self).__init__(SshHostKeyType.KEY, Authentication.ECDSA)


class SshKeyExchangeInitHostKeyEDDSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostKeyEDDSA, self).__init__(SshHostKeyType.KEY, Authentication.EDDSA)


class SshKeyExchangeInitHostCertificateDSS(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostCertificateDSS, self).__init__(SshHostKeyType.CERTIFICATE, Authentication.DSS)


class SshKeyExchangeInitHostCertificateRSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostCertificateRSA, self).__init__(SshHostKeyType.CERTIFICATE, Authentication.RSA)


class SshKeyExchangeInitHostCertificateECDSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostCertificateECDSA, self).__init__(SshHostKeyType.CERTIFICATE, Authentication.ECDSA)


class SshKeyExchangeInitHostCertificateEDDSA(SshKeyExchangeInitHostKeyBase):
    def __init__(self):
        super(SshKeyExchangeInitHostCertificateEDDSA, self).__init__(SshHostKeyType.CERTIFICATE, Authentication.EDDSA)

        self.server_host_key_algorithms = SshHostKeyAlgorithmVector(list(filter(
            lambda algorithm: algorithm.value.authentication == authentication and algorithm.value.key_type == host_key_type,
            self.server_host_key_algorithms
        )))


class SshKeyExchangeInitKexDHGroup(SshKeyExchangeInitAnyAlgorithm):
    def __init__(self):
        super(SshKeyExchangeInitKexDHGroup, self).__init__()

        self.kex_algorithms = SshKexAlgorithmVector(list(filter(
            lambda algorithm: algorithm.value.kex == KeyExchange.DHE and algorithm.value.key_size is None,
            self.kex_algorithms
        )))


class ClientSsh(L7ClientTcp):
    @classmethod
    def get_scheme(cls):
        return 'ssh'

    @classmethod
    def get_default_port(cls):
        return 22

    def do_handshake(
            self,
            protocol_message=SshProtocolMessage(
                protocol_version=SshProtocolVersion(SshVersion.SSH2, 0),
                product='Cryptolyter_0.1',
                comment='https://github.com/c0r0n3r/cyrptolyze'
            ),
            key_exchange_init_message=SshKeyExchangeInitAnyAlgorithm(),
            last_message_type=SshKeyExchangeInit,
            dh_key_size=None
    ):
        self._socket = self._connect()
        tls_client = SshClientHandshake(self)
        server_messages = tls_client.do_handshake(
            protocol_message,
            key_exchange_init_message,
            last_message_type,
            dh_key_size
        )
        self._close()

        return server_messages


L7ClientTcp.register(ClientSsh)


def get_ecdh_public_key():
    # Generate a private key for use in the exchange.
    private_key = cryptography_ec.generate_private_key(
        cryptography_ec.SECP521R1(), cryptography_default_backend()
    )
    return private_key.public_key().public_numbers().encode_point()


def get_dh_public_key():
    return int((
        'B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6' +
        '9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0' +
        '13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70' +
        '98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0' +
        'A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708' +
        'DF1FB2BC 2E4A4371'
    ).replace(' ', ''), 16).to_bytes(1024, byteorder='big')



class SshDisconnect(ValueError):
    def __init__(self, reason):
        super(SshDisconnect, self).__init__()

        self.reason = reason


class SshUnimplemented(ValueError):
    def __init__(self, sequence_number):
        super(SshUnimplemented, self).__init__()

        self.sequence_number = sequence_number


class SshClientHandshake(object):
    def __init__(self, l4_client):
        self._l4_client = l4_client

    def exchange_version(self, protocol_message):
        self._l4_client.send(protocol_message.compose())

        try:
            self._l4_client.receive_at_most(256)
        except NotEnoughData:
            if self._l4_client.buffer:
                raise NetworkError(NetworkErrorType.NO_CONNECTION)
            else:
                raise NetworkError(NetworkErrorType.NO_RESPONSE)
        index = self._l4_client.buffer.find(b'\r\n')
        parser = ParserText(self._l4_client.buffer if index == -1 else self._l4_client.buffer[0:index + 2])
        parser.parse_parsable('protocol_message', SshProtocolMessage)
        self._l4_client.flush_buffer(parser.parsed_length if index == -1 else index + 2)

        return parser

    def do_handshake(
            self,
            protocol_message,
            key_exchange_init_message,
            last_message_type,
            dh_key_size=None,
    ):
        if dh_key_size is None:
            dh_key_size = 2048

        parser = self.exchange_version(protocol_message)
        #server_messages = {SshProtocolMessage.get_message_code(): parser['protocol_message']}
        server_messages = {}
        if last_message_type == SshProtocolMessage:
            return server_messages

        self._l4_client.send(SshRecord(key_exchange_init_message).compose())
        while True:
            try:
                record = SshRecord.parse_exact_size(self._l4_client.buffer)
                self._l4_client.flush_buffer()
                if record.packet.get_message_code() == SshMessageCode.DISCONNECT:
                    raise SshDisconnect(record.packet.reason)
                elif record.packet.get_message_code() == SshMessageCode.UNIMPLEMENTED:
                    raise SshUnimplemented(record.packet.sequence_number)

                if record.packet.get_message_code() == SshMessageCode.KEXINIT:
                    agreed_kex = list(filter(
                        record.packet.kex_algorithms.__contains__,
                        key_exchange_init_message.kex_algorithms
                    ))
                    if len(agreed_kex) == 0:
                        raise NotImplementedError

                    agreed_key_type = agreed_kex[0].value.kex
                    if agreed_key_type == KeyExchange.ECDHE:
                        ephemeral_public_key = get_ecdh_public_key()
                    elif agreed_key_type == KeyExchange.DHE:
                        ephemeral_public_key = get_dh_public_key()
                        kex_dh_gex_request_message = SshKexDHGexRequest(dh_key_size - 1, dh_key_size, dh_key_size + 1)
                        self._l4_client.send(SshRecord(kex_dh_gex_request_message).compose())
                    else:
                        raise NotImplementedError
                elif record.packet.get_message_code() == SshMessageCode.KEX_DH_GEX_GROUP:
                    pass

                server_messages[record.packet.get_message_code()] = record.packet
                if record.packet.get_message_code() == last_message_type.get_message_code():
                    return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            try:
                self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if self._l4_client.buffer:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION)
                else:
                    raise NetworkError(NetworkErrorType.NO_RESPONSE)
