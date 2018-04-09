#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc

from crypton.common.algorithm import Authentication, KeyExchange
from crypton.common.exception import NotEnoughData
from crypton.common.utils import get_leaf_classes

from crypton.tls.ciphersuite import TlsCipherSuite
from crypton.tls.subprotocol import TlsHandshakeClientHello, TlsCipherSuiteVector, TlsContentType, TlsHandshakeType
from crypton.tls.extension import TlsExtensionSupportedVersions, TlsExtensionServerName, TlsExtensionECPointFormats, TlsECPointFormat, TlsExtensionEllipticCurves, TlsNamedCurve, TlsExtensionSignatureAlgorithms, TlsSignatureAndHashAlgorithm

from crypton.tls.record import TlsRecord
from crypton.tls.version import TlsVersion, TlsProtocolVersionFinal

import socket as socket_module


class TlsHandshakeClientHelloAnyAlgorithm(TlsHandshakeClientHello):
    def __init__(self, hostname):
        super(TlsHandshakeClientHelloAnyAlgorithm, self).__init__(
            cipher_suites=TlsCipherSuiteVector(list(TlsCipherSuite)),
            extensions=[
                TlsExtensionServerName(hostname),
                TlsExtensionECPointFormats(list(TlsECPointFormat)),
                TlsExtensionEllipticCurves(list(TlsNamedCurve)),
                TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            ]
        )


class TlsHandshakeClientHelloAuthenticationRSA(TlsHandshakeClientHello):
    _CIPHER_SUITES = TlsCipherSuiteVector([
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.authentication and
            cipher_suite.value.authentication in [Authentication.RSA, Authentication.RSA_EXPORT])
    ])

    def __init__(self, hostname):
        super(TlsHandshakeClientHelloAuthenticationRSA, self).__init__(
            cipher_suites=TlsCipherSuiteVector(self._CIPHER_SUITES),
            extensions=[
                TlsExtensionServerName(hostname),
                TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            ]
        )


class TlsHandshakeClientHelloAuthenticationDSS(TlsHandshakeClientHello):
    _CIPHER_SUITES = TlsCipherSuiteVector([
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.authentication and
            cipher_suite.value.authentication in [Authentication.DSS, Authentication.DSS_EXPORT])
    ])

    def __init__(self, hostname):
        super(TlsHandshakeClientHelloAuthenticationDSS, self).__init__(
            cipher_suites=TlsCipherSuiteVector(self._CIPHER_SUITES),
            extensions=[
                TlsExtensionServerName(hostname),
            ]
        )


class TlsHandshakeClientHelloAuthenticationECDSA(TlsHandshakeClientHello):
    _CIPHER_SUITES = TlsCipherSuiteVector([
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.authentication and
            cipher_suite.value.authentication in [Authentication.ECDSA, ])
    ])


    def __init__(self, hostname):
        super(TlsHandshakeClientHelloAuthenticationECDSA, self).__init__(
            cipher_suites=TlsCipherSuiteVector(self._CIPHER_SUITES),
            extensions=[
                TlsExtensionServerName(hostname),
                TlsExtensionECPointFormats(list(TlsECPointFormat)),
                TlsExtensionEllipticCurves(list(TlsNamedCurve)),
                TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            ]
        )

class TlsHandshakeClientHelloKeyExchangeECDHx(TlsHandshakeClientHello):
    _CIPHER_SUITES = TlsCipherSuiteVector([
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if (cipher_suite.value.key_exchange and
            cipher_suite.value.key_exchange in [KeyExchange.ECDH, KeyExchange.ECDHE])
    ])


    def __init__(self, hostname):
        super(TlsHandshakeClientHelloKeyExchangeECDHx, self).__init__(
            cipher_suites=TlsCipherSuiteVector(self._CIPHER_SUITES),
            extensions=[
                TlsExtensionServerName(hostname),
                TlsExtensionECPointFormats(list(TlsECPointFormat)),
                TlsExtensionEllipticCurves(list(TlsNamedCurve)),
                TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            ]
        )


class TlsHandshakeClientHelloBasic(TlsHandshakeClientHello):
    def __init__(self):
        super(TlsHandshakeClientHelloBasic, self).__init__(
            cipher_suites=TlsCipherSuiteVector(list(TlsCipherSuite)),
            extensions=[]
        )


class Client(object):
    def __init__(self, host, port):
        self._host = host
        self._port = port
        self._socket = None

    def connect(self):
        self._socket = socket_module.socket(socket_module.AF_INET, socket_module.SOCK_STREAM)
        self._socket.connect((self._host, self._port))

    def close(self):
        if self._socket:
            self._socket.close()

    def send(self, sendable_bytes):
        total_sent_byte_num = 0
        while total_sent_byte_num < len(sendable_bytes):
            actual_sent_byte_num = self._socket.send(sendable_bytes[total_sent_byte_num:])
            if actual_sent_byte_num == 0:
                raise IOError()
            total_sent_byte_num = total_sent_byte_num + actual_sent_byte_num

    def receive(self, receivable_byte_num):
        total_received_bytes = bytearray()

        while len(total_received_bytes) < receivable_byte_num:
            try:
                actual_received_bytes = self._socket.recv(min(receivable_byte_num - len(total_received_bytes), 1024))
            except socket_module.error:
                actual_received_bytes = None

            if not actual_received_bytes:
                raise NotEnoughData(receivable_byte_num - len(total_received_bytes))

            total_received_bytes += actual_received_bytes

        return total_received_bytes

    @classmethod
    def from_scheme(cls, scheme):
        for client_class in get_leaf_classes(Client):
            if client_class.get_scheme() == scheme:
                return client_class
        else:
            raise ValueError()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        return NotImplementedError()


class ClientTls(Client):
    @classmethod
    def get_scheme(cls):
        return 'tls'


class ClientHTTPS(Client):
    @classmethod
    def get_scheme(cls):
        return 'https'


import poplib


class ClientPOP3(Client):
    def __init__(self, host, port):
        #self.client = poplib.POP3(host, port)

        super(ClientPOP3, self).__init__(host, port)

    @classmethod
    def get_scheme(cls):
        return 'pop'

    def connect(self):
        self.client = poplib.POP3(self._host, self._port)
        if 'STLS' not in self.capa():
            raise ValueError
        response = self.stls()
        if response != b'+OK':
            raise ValueError
        self._socket = self.client.sock

    def close(self):
        if self._socket:
            self.client.quit()


import smtplib


class ClientSMTP(Client):
    def __init__(self, host, port):
        #self.client = smtplib.SMTP(host, port)

        super(ClientSMTP, self).__init__(host, port)

    @classmethod
    def get_scheme(cls):
        return 'smtp'

    def connect(self):
        self.client = smtplib.SMTP()
        self.client.connect(self._host, self._port)
        self.client.ehlo()
        if not self.client.has_extn('STARTTLS'):
            raise ValueError
        response, message = self.client.docmd('STARTTLS')
        if response != 220:
            raise ValueError
        self._socket = self.client.sock

    def close(self):
        if self._socket:
            self.client.quit()

import imaplib


class ClientIMAP(Client):
    def __init__(self, host, port):
        #self.client = imaplib.IMAP(host, port)

        super(ClientIMAP, self).__init__(host, port)

    @classmethod
    def get_scheme(cls):
        return 'imap'

    def connect(self):
        self.client = imaplib.IMAP4(self._host, self._port)
        if 'STARTTLS' not in self.client.capabilities:
            raise ValueError
        response, message = self.client.xatom('STARTTLS')
        if response != 'OK':
            raise ValueError
        self._socket = self.client.socket()

    def close(self):
        if self._socket:
            self.client.quit()


class InvalidState(ValueError):
    def __init__(self, description):
        super(InvalidState, self).__init__()

        self.description = description


class TlsAlert(ValueError):
    def __init__(self, description):
        super(TlsAlert, self).__init__()

        self.description = description


class TlsClientHandshake(object):
    def __init__(self, host, port, client_class=Client):
        self._client = client_class(host, port)
        self._host = host

    def do(self, hello_message=None, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0), last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE):
        if hello_message is None:
            hello_message = TlsHandshakeClientHelloAnyAlgorithm(self._host)

        self._client.connect()

        tls_record = TlsRecord([hello_message, ], protocol_version)
        self._client.send(tls_record.compose())

        server_messages = {}
        parsable_bytes = bytearray()
        while True:
            try:
                record = TlsRecord.parse_mutable_bytes(parsable_bytes)
                if record.content_type == TlsContentType.ALERT:
                    raise TlsAlert(record.messages[0].description)
                elif record.content_type != TlsContentType.HANDSHAKE:
                    raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

                for handshake_message in record.messages:
                    if handshake_message.get_handshake_type() in server_messages:
                        raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

                    server_messages[handshake_message.get_handshake_type()] = handshake_message
                    if handshake_message.get_handshake_type() == last_handshake_message_type:
                        return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed

            parsable_bytes += self._client.receive(receivable_byte_num)


import enum
import random

from crypton.common.base import ParsableBase, Composer, Vector, VectorParamNumeric

class SslVersion(enum.IntEnum):
    SSL2 = 0x0002


class SslHandshakeType(enum.IntEnum):
    ERROR = 0x00
    CLIENT_HELLO = 0x01
    CLIENT_MASTER_KEY = 0x02
    CLIENT_FINISHED = 0x03
    SERVER_HELLO = 0x04
    SERVER_VERIFY = 0x05
    SERVER_FINISHED = 0x06
    REQUEST_CERTIFICATE = 0x07
    CLIENT_CERTIFICATE = 0x08


class SslCipherKind(enum.IntEnum):
    RC4_128_WITH_MD5 = 0x010080
    RC4_128_EXPORT40_WITH_MD5 = 0x020080
    RC2_128_CBC_WITH_MD5 = 0x030080
    RC2_128_CBC_EXPORT40_WITH_MD5 = 0x040080
    IDEA_128_CBC_WITH_MD5 = 0x050080
    DES_64_CBC_WITH_MD5 = 0x060040
    DES_192_EDE3_CBC_WITH_MD5 = 0x0700C0


class SslCertificateType(enum.IntEnum):
    X509_CERTIFICATE = 0x01


class SslAuthenticationType(enum.IntEnum):
    MD5_WITH_RSA_ENCRYPTION = 0x01


class SslErrorType(enum.IntEnum):
    NO_CIPHER_ERROR = 0x0001
    NO_CERTIFICATE_ERROR = 0x0002
    BAD_CERTIFICATE_ERROR = 0x0003
    UNSUPPORTED_CERTIFICATE_TYPE_ERROR  = 0x0004


class SslError(ValueError):
    def __init__(self, error):
        super(SslError, self).__init__()

        self.error = error


class SslHandshake(ParsableBase):
    @classmethod
    @abc.abstractmethod
    def get_handshake_type(cls):
        return NotImplementedError()


class SslSessionIdVector(Vector):
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=0, max_byte_num=16)


class SslHandshakeClientHello(SslHandshake):
    def __init__(
        self,
        cipher_kinds,
        session_id=SslSessionIdVector([]),
        challenge=bytearray.fromhex('{:16x}'.format(random.getrandbits(128)).zfill(32)),
    ):
        self.cipher_kinds = cipher_kinds
        self.session_id = session_id
        self.challenge = challenge

    @classmethod
    def get_handshake_type(cls):
        return SslHandshakeType.CLIENT_HELLO

    def compose(self):
        body_composer = Composer()

        body_composer.compose_numeric(self.get_handshake_type(), 1)
        body_composer.compose_numeric(SslVersion.SSL2, 2)

        body_composer.compose_numeric(len(self.cipher_kinds) * 3, 2)
        body_composer.compose_numeric(0, 2)
        body_composer.compose_numeric(len(self.challenge), 2)

        body_composer.compose_numeric_array(self.cipher_kinds, 3)
        body_composer.compose_bytes(self.challenge)

        header_composer = Composer()
        if body_composer.composed_bytes >= 2 ** 16:
            header_composer.compose_numeric(body_composer.composed_byte_num | (2 ** 15), 2)
        else:
            header_composer.compose_numeric(body_composer.composed_byte_num | (2 ** 23), 2)

        return header_composer.composed_bytes + body_composer.composed_bytes


class SslHandshakeClientHelloAnyAlgorithm(SslHandshakeClientHello):
    def __init__(self):
        super(SslHandshakeClientHelloAnyAlgorithm, self).__init__(cipher_kinds=list(SslCipherKind))


class SslClientHandshake(object):
    def __init__(self, host, port, client_class=Client):
        self._client = client_class(host, port)
        self._host = host

    def do(self, hello_message=None, last_handshake_message_type=SslHandshakeType.SERVER_HELLO):
        if hello_message is None:
            hello_message = SslHandshakeClientHelloAnyAlgorithm(self._host)

        self._client.connect()

        self._client.send(hello_message.compose())

        server_messages = {}
        parsable_bytes = bytearray()
        while True:
            try:
                record = TlsRecord.parse_mutable_bytes(parsable_bytes)
                if record.content_type == TlsContentType.ALERT:
                    raise TlsAlert(record.messages[0].description)
                elif record.content_type != TlsContentType.HANDSHAKE:
                    raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

                for handshake_message in record.messages:
                    if handshake_message.get_handshake_type() in server_messages:
                        raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

                    server_messages[handshake_message.get_handshake_type()] = handshake_message
                    if handshake_message.get_handshake_type() == last_handshake_message_type:
                        return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed

            parsable_bytes += self._client.receive(receivable_byte_num)
