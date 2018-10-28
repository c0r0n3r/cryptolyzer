#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc

import imaplib
import poplib
import smtplib

import socket as socket_module

from cryptoparser.common.algorithm import Authentication, KeyExchange
from cryptoparser.common.exception import NotEnoughData
from cryptoparser.common.utils import get_leaf_classes

from cryptoparser.tls.ciphersuite import TlsCipherSuite
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello, TlsCipherSuiteVector, TlsContentType, TlsHandshakeType
from cryptoparser.tls.subprotocol import TlsAlertLevel, TlsAlertDescription
from cryptoparser.tls.extension import TlsExtensionServerName
from cryptoparser.tls.extension import TlsExtensionSignatureAlgorithms, TlsSignatureAndHashAlgorithm
from cryptoparser.tls.extension import TlsExtensionECPointFormats, TlsECPointFormat
from cryptoparser.tls.extension import TlsExtensionEllipticCurves, TlsNamedCurve

from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal


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


class ClientPOP3(Client):
    def __init__(self, host, port):
        super(ClientPOP3, self).__init__(host, port)

    @classmethod
    def get_scheme(cls):
        return 'pop'

    def connect(self):
        self.client = poplib.POP3(self._host, self._port)
        if 'STLS' not in self.client.capa():
            raise ValueError
        response = self.client.stls()
        if response != b'+OK':
            raise ValueError
        self._socket = self.client.sock

    def close(self):
        if self._socket:
            self.client.quit()


class ClientSMTP(Client):
    def __init__(self, host, port):
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
        response, _ = self.client.docmd('STARTTLS')
        if response != 220:
            raise ValueError
        self._socket = self.client.sock

    def close(self):
        if self._socket:
            self.client.quit()


class ClientIMAP(Client):
    def __init__(self, host, port):
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

    def do(
            self,
            hello_message,
            protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0),
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
    ):
        self._client.connect()

        tls_record = TlsRecord([hello_message, ], protocol_version)
        self._client.send(tls_record.compose())

        server_messages = {}
        parsable = bytearray()
        while True:
            try:
                record = TlsRecord.parse_mutable(parsable)
                if record.content_type == TlsContentType.ALERT:
                    if record.messages[0].level == TlsAlertLevel.FATAL:
                        raise TlsAlert(record.messages[0].description)
                    else:
                        continue
                elif record.content_type != TlsContentType.HANDSHAKE:
                    raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

                for handshake_message in record.messages:
                    handshake_type = handshake_message.get_handshake_type()
                    if handshake_type in server_messages:
                        raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)
                    if (handshake_type == TlsHandshakeType.SERVER_HELLO and
                            handshake_message.protocol_version != protocol_version):
                        raise TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)

                    server_messages[handshake_message.get_handshake_type()] = handshake_message

                    if handshake_message.get_handshake_type() == last_handshake_message_type:
                        return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed

            parsable += self._client.receive(receivable_byte_num)
