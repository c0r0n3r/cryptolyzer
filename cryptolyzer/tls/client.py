#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc

import imaplib
import poplib
import smtplib

import socket

from cryptoparser.common.algorithm import Authentication, KeyExchange
from cryptoparser.common.exception import NotEnoughData
from cryptoparser.common.utils import get_leaf_classes

from cryptoparser.tls.ciphersuite import TlsCipherSuite, SslCipherKind
from cryptoparser.tls.subprotocol import SslMessageType, SslHandshakeClientHello
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello
from cryptoparser.tls.subprotocol import TlsCipherSuiteVector, TlsContentType, TlsHandshakeType
from cryptoparser.tls.subprotocol import TlsAlertLevel, TlsAlertDescription
from cryptoparser.tls.extension import TlsExtensionServerName
from cryptoparser.tls.extension import TlsExtensionSignatureAlgorithms, TlsSignatureAndHashAlgorithm
from cryptoparser.tls.extension import TlsExtensionECPointFormats, TlsECPointFormat
from cryptoparser.tls.extension import TlsExtensionEllipticCurves, TlsNamedCurve

from cryptoparser.tls.record import TlsRecord, SslRecord
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal, SslVersion

from cryptolyzer.common.exception import NetworkError, NetworkErrorType


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
                TlsExtensionEllipticCurves(list(TlsNamedCurve)),
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


class TlsHandshakeClientHelloKeyExchangeDHE(TlsHandshakeClientHello):
    _CIPHER_SUITES = TlsCipherSuiteVector([
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if cipher_suite.value.key_exchange == KeyExchange.DHE
    ])

    def __init__(self, hostname):
        super(TlsHandshakeClientHelloKeyExchangeDHE, self).__init__(
            cipher_suites=TlsCipherSuiteVector(self._CIPHER_SUITES),
            extensions=[
                TlsExtensionServerName(hostname),
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


class L7Client(object):
    _DEFAULT_TIMEOUT = 5

    def __init__(self, host, port, timeout=None):
        self._host = host
        self._port = port
        self._socket = None
        self._timeout = self._DEFAULT_TIMEOUT if timeout is None else timeout
        self._buffer = bytearray()

    def _do_handshake(
            self,
            tls_client,
            hello_message,
            protocol_version,
            last_handshake_message_type
    ):
        try:
            self._socket = self._connect()
        except ConnectionRefusedError:
            raise NetworkError(NetworkErrorType.NO_CONNECTION)

        try:
            server_messages = tls_client.do_handshake(hello_message, protocol_version, last_handshake_message_type)
        finally:
            self._close()

        return server_messages

    def do_ssl_handshake(self, hello_message, last_handshake_message_type=SslMessageType.SERVER_HELLO):
        return self._do_handshake(
            SslClientHandshake(self),
            hello_message,
            SslVersion.SSL2,
            last_handshake_message_type
        )

    def do_tls_handshake(
            self,
            hello_message,
            protocol_version,
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO
    ):
        return self._do_handshake(
            TlsClientHandshake(self),
            hello_message,
            protocol_version,
            last_handshake_message_type
        )

    def _close(self):
        self._socket.close()
        self._socket = None

    def send(self, sendable_bytes):
        total_sent_byte_num = 0
        while total_sent_byte_num < len(sendable_bytes):
            actual_sent_byte_num = self._socket.send(sendable_bytes[total_sent_byte_num:])
            if actual_sent_byte_num == 0:
                raise IOError()
            total_sent_byte_num = total_sent_byte_num + actual_sent_byte_num

    def receive(self, receivable_byte_num):
        total_received_byte_num = 0
        while total_received_byte_num < receivable_byte_num:
            try:
                actual_received_bytes = self._socket.recv(min(receivable_byte_num - total_received_byte_num, 1024))
                self._buffer += actual_received_bytes
                total_received_byte_num += len(actual_received_bytes)
            except socket.error:
                actual_received_bytes = None

            if not actual_received_bytes:
                raise NotEnoughData(receivable_byte_num - total_received_byte_num)

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @property
    def buffer(self):
        return bytearray(self._buffer)

    def flush_buffer(self, byte_num=None):
        if byte_num is None:
            byte_num = len(self._buffer)

        self._buffer = self._buffer[byte_num:]

    @classmethod
    def from_scheme(cls, scheme, host, port=None, timeout=None):
        for client_class in get_leaf_classes(L7Client):
            if client_class.get_scheme() == scheme:
                port = client_class.get_default_port() if port is None else port
                return client_class(host, port, timeout)

        raise ValueError()

    @classmethod
    def get_supported_schemes(cls):
        return {leaf_cls.get_scheme() for leaf_cls in get_leaf_classes(cls)}

    @abc.abstractmethod
    def _connect(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()


class L7ClientTls(L7Client):
    @classmethod
    def get_scheme(cls):
        return 'tls'

    @classmethod
    def get_default_port(cls):
        return 443

    def _connect(self):
        return socket.create_connection((self._host, self._port), self._timeout)


class L7ClientHTTPS(L7Client):
    @classmethod
    def get_scheme(cls):
        return 'https'

    @classmethod
    def get_default_port(cls):
        return 443

    def _connect(self):
        return socket.create_connection((self._host, self._port), self._timeout)


class ClientPOP3(L7Client):
    def __init__(self, host, port):
        super(ClientPOP3, self).__init__(host, port)

        self.client = None

    @classmethod
    def get_scheme(cls):
        return 'pop'

    @classmethod
    def get_default_port(cls):
        return 110

    def _connect(self):
        self.client = poplib.POP3(self._host, self._port)
        if 'STLS' not in self.client.capa():
            raise ValueError
        response = self.client.stls()
        if response != b'+OK':
            raise ValueError
        return self.client.sock

    def close(self):
        if self.client:
            self.client.quit()


class ClientSMTP(L7Client):
    def __init__(self, host, port):
        super(ClientSMTP, self).__init__(host, port)

        self.client = None

    @classmethod
    def get_scheme(cls):
        return 'smtp'

    @classmethod
    def get_default_port(cls):
        return 587

    def _connect(self):
        self.client = smtplib.SMTP()
        self.client.connect(self._host, self._port)
        self.client.ehlo()
        if not self.client.has_extn('STARTTLS'):
            raise ValueError
        response, _ = self.client.docmd('STARTTLS')
        if response != 220:
            raise ValueError
        return self.client.sock

    def close(self):
        if self.client:
            self.client.quit()


class ClientIMAP(L7Client):
    def __init__(self, host, port):
        super(ClientIMAP, self).__init__(host, port)

        self.client = None

    @classmethod
    def get_scheme(cls):
        return 'imap'

    @classmethod
    def get_default_port(cls):
        return 143

    def _connect(self):
        self.client = imaplib.IMAP4(self._host, self._port)
        if 'STARTTLS' not in self.client.capabilities:
            raise ValueError
        response, _ = self.client.xatom('STARTTLS')
        if response != 'OK':
            raise ValueError
        return self.client.socket()

    def close(self):
        if self.client:
            self.client.quit()


class InvalidState(ValueError):
    def __init__(self, description):
        super(InvalidState, self).__init__()

        self.description = description


class TlsAlert(ValueError):
    def __init__(self, description):
        super(TlsAlert, self).__init__()

        self.description = description


class TlsClient(object):
    def __init__(self, l4_client):
        self._l4_client = l4_client

    @abc.abstractmethod
    def do_handshake(self, hello_message, protocol_version, last_handshake_message_type):
        raise NotImplementedError()


class TlsClientHandshake(TlsClient):
    def do_handshake(
            self,
            hello_message,
            protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0),
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
    ):
        tls_record = TlsRecord([hello_message, ], protocol_version)
        self._l4_client.send(tls_record.compose())

        server_messages = {}
        while True:
            try:
                record = TlsRecord.parse_exact_size(self._l4_client.buffer)
                self._l4_client.flush_buffer()
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

            try:
                self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if self._l4_client.buffer:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION)
                else:
                    raise NetworkError(NetworkErrorType.NO_RESPONSE)


class SslError(ValueError):
    def __init__(self, error):
        super(SslError, self).__init__()

        self.error = error


class SslHandshakeClientHelloAnyAlgorithm(SslHandshakeClientHello):
    def __init__(self):
        super(SslHandshakeClientHelloAnyAlgorithm, self).__init__(
            cipher_kinds=list(SslCipherKind)
        )


class SslClientHandshake(TlsClient):
    def do_handshake(
            self,
            hello_message=None,
            protocol_version=SslVersion.SSL2,
            last_handshake_message_type=SslMessageType.SERVER_HELLO
    ):
        ssl_record = SslRecord(hello_message)
        self._l4_client.send(ssl_record.compose())

        server_messages = {}
        while True:
            try:
                record = SslRecord.parse_exact_size(self._l4_client.buffer)
                self._l4_client.flush_buffer()
                message = record.messages[0]
                # FIXME: error message is not parsed
                if message.get_message_type() == SslMessageType.ERROR:
                    raise SslError(message.get_message_type())

                server_messages[message.get_message_type()] = message
                if message.get_message_type() == last_handshake_message_type:
                    return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed

            try:
                self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if self._l4_client.buffer:
                    try:
                        tls_record = TlsRecord.parse_exact_size(self._l4_client.buffer)
                        self._l4_client.flush_buffer()
                    except ValueError:
                        raise NetworkError(NetworkErrorType.NO_CONNECTION)
                    else:
                        if (tls_record.content_type == TlsContentType.ALERT and
                                tls_record.messages[0].description == TlsAlertDescription.PROTOCOL_VERSION):
                            raise NetworkError(NetworkErrorType.NO_RESPONSE)
                        else:
                            raise NetworkError(NetworkErrorType.NO_CONNECTION)
                else:
                    raise NetworkError(NetworkErrorType.NO_RESPONSE)
