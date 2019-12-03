# -*- coding: utf-8 -*-

import abc

import ipaddress

import ftplib
import imaplib
import poplib
import smtplib

import socket
import string

from cryptoparser.common.algorithm import Authentication, KeyExchange
from cryptoparser.common.exception import NotEnoughData, InvalidType, InvalidValue
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

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, ResponseError, ResponseErrorType


class TlsHandshakeClientHelloAnyAlgorithm(TlsHandshakeClientHello):
    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloAnyAlgorithm, self).__init__(
            protocol_version=protocol_version,
            cipher_suites=TlsCipherSuiteVector(list(TlsCipherSuite)),
            extensions=[
                TlsExtensionServerName(hostname),
                TlsExtensionECPointFormats(list(TlsECPointFormat)),
                TlsExtensionEllipticCurves(list(TlsNamedCurve)),
                TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            ]
        )


class TlsHandshakeClientHelloAuthenticationBase(TlsHandshakeClientHello):
    def __init__(self, protocol_version, hostname, authentication):
        _cipher_suites = TlsCipherSuiteVector([
            cipher_suite
            for cipher_suite in TlsCipherSuite
            if (cipher_suite.value.authentication and
                cipher_suite.value.authentication == authentication)
        ])

        super(TlsHandshakeClientHelloAuthenticationBase, self).__init__(
            protocol_version=protocol_version,
            cipher_suites=TlsCipherSuiteVector(_cipher_suites),
            extensions=[
                TlsExtensionServerName(hostname),
            ]
        )


class TlsHandshakeClientHelloAuthenticationRSA(TlsHandshakeClientHelloAuthenticationBase):
    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloAuthenticationRSA, self).__init__(
            protocol_version=protocol_version,
            hostname=hostname,
            authentication=Authentication.RSA
        )

        self.extensions.extend([
            TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            TlsExtensionEllipticCurves(list(TlsNamedCurve)),
        ])


class TlsHandshakeClientHelloAuthenticationDSS(TlsHandshakeClientHelloAuthenticationBase):
    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloAuthenticationDSS, self).__init__(
            protocol_version=protocol_version,
            hostname=hostname,
            authentication=Authentication.DSS
        )


class TlsHandshakeClientHelloAuthenticationECDSA(TlsHandshakeClientHelloAuthenticationBase):
    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloAuthenticationECDSA, self).__init__(
            protocol_version=protocol_version,
            hostname=hostname,
            authentication=Authentication.ECDSA
        )

        self.extensions.extend([
            TlsExtensionECPointFormats(list(TlsECPointFormat)),
            TlsExtensionEllipticCurves(list(TlsNamedCurve)),
            TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
        ])


class TlsHandshakeClientHelloAuthenticationRarelyUsed(TlsHandshakeClientHello):
    def __init__(self, protocol_version, hostname):
        _cipher_suites = TlsCipherSuiteVector([
            cipher_suite
            for cipher_suite in TlsCipherSuite
            if (cipher_suite.value.authentication and
                cipher_suite.value.authentication in [
                    Authentication.DSS,
                    Authentication.KRB5,
                    Authentication.PSK,
                    Authentication.SRP,
                    Authentication.anon,
                ])
        ])

        super(TlsHandshakeClientHelloAuthenticationRarelyUsed, self).__init__(
            protocol_version=protocol_version,
            cipher_suites=TlsCipherSuiteVector(_cipher_suites),
            extensions=[
                TlsExtensionServerName(hostname),
            ]
        )


class TlsHandshakeClientHelloKeyExchangeDHE(TlsHandshakeClientHello):
    _CIPHER_SUITES = TlsCipherSuiteVector([
        cipher_suite
        for cipher_suite in TlsCipherSuite
        if cipher_suite.value.key_exchange == KeyExchange.DHE
    ])

    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloKeyExchangeDHE, self).__init__(
            protocol_version=protocol_version,
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

    def __init__(self, protocol_version, hostname):
        super(TlsHandshakeClientHelloKeyExchangeECDHx, self).__init__(
            protocol_version=protocol_version,
            cipher_suites=TlsCipherSuiteVector(self._CIPHER_SUITES),
            extensions=[
                TlsExtensionServerName(hostname),
                TlsExtensionECPointFormats(list(TlsECPointFormat)),
                TlsExtensionEllipticCurves(list(TlsNamedCurve)),
                TlsExtensionSignatureAlgorithms(list(TlsSignatureAndHashAlgorithm)),
            ]
        )


class TlsHandshakeClientHelloBasic(TlsHandshakeClientHello):
    def __init__(self, protocol_version):
        super(TlsHandshakeClientHelloBasic, self).__init__(
            protocol_version=protocol_version,
            cipher_suites=TlsCipherSuiteVector(list(TlsCipherSuite)),
            extensions=[]
        )


class L7ClientTlsBase(object):
    _DEFAULT_TIMEOUT = 5

    def __init__(self, address, port, timeout=None, ip=None):
        self._address = address
        self._port = port
        self._socket = None
        self._timeout = self._DEFAULT_TIMEOUT if timeout is None else timeout
        self._buffer = bytearray()

        if ip:
            try:
                ipaddress.ip_address(ip)
            except ValueError:
                raise NetworkError(NetworkErrorType.NO_ADDRESS)
        else:
            try:
                ip_addresses = [
                    addrinfo[4][0]
                    for addrinfo in socket.getaddrinfo(self._address, self._port, 0, socket.SOCK_STREAM)
                ]
            except socket.gaierror:
                raise NetworkError(NetworkErrorType.NO_ADDRESS)
            if not ip_addresses:
                raise NetworkError(NetworkErrorType.NO_ADDRESS)
            ip = ip_addresses[0]
        self._ip = ip

    def _do_handshake(
            self,
            tls_client,
            hello_message,
            record_version,
            last_handshake_message_type
    ):
        try:
            self._setup_connection()
        except BaseException as e:  # pylint: disable=broad-except
            if e.__class__.__name__ == 'ConnectionRefusedError' or isinstance(e, (socket.error, socket.timeout)):
                raise NetworkError(NetworkErrorType.NO_CONNECTION)

            if self._socket:
                self.close()

            raise e

        try:
            tls_client.do_handshake(hello_message, record_version, last_handshake_message_type)
        finally:
            try:
                self.close()
            except (socket.error, socket.timeout):
                pass

        return tls_client.server_messages

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
            record_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0),
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO
    ):
        return self._do_handshake(
            TlsClientHandshake(self),
            hello_message,
            record_version,
            last_handshake_message_type
        )

    def _close(self):
        self._socket.close()

    def close(self):
        if self._socket is not None:
            self._close()
        self._socket = None

    def _send(self, sendable_bytes):
        return self._socket.send(sendable_bytes)

    def send(self, sendable_bytes):
        total_sent_byte_num = 0
        while total_sent_byte_num < len(sendable_bytes):
            actual_sent_byte_num = self._send(sendable_bytes[total_sent_byte_num:])
            if actual_sent_byte_num == 0:
                raise NetworkError(NetworkErrorType.NO_CONNECTION)
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
    def address(self):
        return self._address

    @property
    def ip(self):
        return self._ip

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
    def from_scheme(cls, scheme, address, port=None, timeout=None, ip=None):  # pylint: disable=too-many-arguments
        for client_class in get_leaf_classes(L7ClientTlsBase):
            if client_class.get_scheme() == scheme:
                port = client_class.get_default_port() if port is None else port
                return client_class(address, port, timeout, ip)

        raise ValueError()

    @classmethod
    def get_supported_schemes(cls):
        return {leaf_cls.get_scheme() for leaf_cls in get_leaf_classes(L7ClientTlsBase)}

    def _setup_connection(self):
        self._socket = socket.create_connection((self._ip, self._port), self._timeout)

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()


class L7ClientTls(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'tls'

    @classmethod
    def get_default_port(cls):
        return 443


class L7ClientHTTPS(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'https'

    @classmethod
    def get_default_port(cls):
        return 443


class L7ClientDoH(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'doh'

    @classmethod
    def get_default_port(cls):
        return 443


class L7ClientPOP3S(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'pop3s'

    @classmethod
    def get_default_port(cls):
        return 995


class ClientPOP3(L7ClientTlsBase):
    def __init__(self, address, port, timeout=None, ip=None):
        super(ClientPOP3, self).__init__(address, port, timeout, ip)

        self.client = None

    @classmethod
    def get_scheme(cls):
        return 'pop3'

    @classmethod
    def get_default_port(cls):
        return 110

    def _setup_connection(self):
        try:
            self.client = poplib.POP3(self._ip, self._port, self._timeout)
            self._socket = self.client.sock

            response = self.client._shortcmd('STLS')  # pylint: disable=protected-access
            if len(response) < 3 or response[:3] != b'+OK':
                raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)
        except poplib.error_proto:
            raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)

    def _close(self):
        if self.client is not None:
            try:
                self.client.quit()
            except poplib.error_proto:
                self._socket.close()


class L7ClientSMTPS(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'smtps'

    @classmethod
    def get_default_port(cls):
        return 465


class ClientSMTP(L7ClientTlsBase):
    def __init__(self, address, port, timeout=None, ip=None):
        super(ClientSMTP, self).__init__(address, port, timeout, ip)

        self.client = None

    @classmethod
    def get_scheme(cls):
        return 'smtp'

    @classmethod
    def get_default_port(cls):
        return 587

    def _setup_connection(self):
        try:
            self.client = smtplib.SMTP(timeout=self._timeout)
            self.client.connect(self._ip, self._port)
            self._socket = self.client.sock

            self.client.ehlo()
            if not self.client.has_extn('STARTTLS'):
                raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)
            response, _ = self.client.docmd('STARTTLS')
            if response != 220:
                raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)
        except smtplib.SMTPException:
            raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)

    def _close(self):
        if self.client is not None:
            try:
                self.client.quit()
            except smtplib.SMTPServerDisconnected:
                self._socket.close()


class L7ClientIMAPS(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'imaps'

    @classmethod
    def get_default_port(cls):
        return 993


class IMAP4(imaplib.IMAP4, object):
    def __init__(self, host, port, timeout):
        self._timeout = timeout
        super(IMAP4, self).__init__(host, port)

    def open(self, host='', port=imaplib.IMAP4_PORT):
        self.host = host
        self.port = port
        self.sock = socket.create_connection((host, port), self._timeout)
        self.file = self.sock.makefile('rb')


class ClientIMAP(L7ClientTlsBase):
    def __init__(self, address, port, timeout=None, ip=None):
        super(ClientIMAP, self).__init__(address, port, timeout, ip)

        self.client = None

    @classmethod
    def get_scheme(cls):
        return 'imap'

    @classmethod
    def get_default_port(cls):
        return 143

    @property
    def _capabilities(self):
        return self.client.capabilities

    def _setup_connection(self):
        try:
            self.client = IMAP4(self._ip, self._port, self._timeout)
            self._socket = self.client.socket()

            if 'STARTTLS' not in self._capabilities:
                raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)
            response, _ = self.client.xatom('STARTTLS')
            if response != 'OK':
                raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)
        except imaplib.IMAP4.error:
            raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)

    def _close(self):
        if self.client:
            self.client.shutdown()


class L7ClientFTPS(L7ClientTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'ftps'

    @classmethod
    def get_default_port(cls):
        return 990


class ClientFTP(L7ClientTlsBase):
    def __init__(self, address, port, timeout=None, ip=None):
        super(ClientFTP, self).__init__(address, port, timeout, ip)

        self.client = None

    @classmethod
    def get_scheme(cls):
        return 'ftp'

    @classmethod
    def get_default_port(cls):
        return 21

    def _setup_connection(self):
        try:
            self.client = ftplib.FTP()
            response = self.client.connect(self._ip, self._port, self._timeout)
            if not response.startswith('220'):
                raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)
            self._socket = self.client.sock

            response = self.client.sendcmd('AUTH TLS')
            if not response.startswith('234'):
                raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)
        except ftplib.all_errors:
            raise ResponseError(ResponseErrorType.UNSUPPORTED_SECURITY)

    def _close(self):
        if self.client is not None:
            try:
                self.client.quit()
            except ftplib.all_errors:
                self._socket.close()


class TlsAlert(ValueError):
    def __init__(self, description):
        super(TlsAlert, self).__init__()

        self.description = description

    def __str__(self):
        return self.__repr__()

    def __repr__(self):
        return 'TlsAlert(TlsAlertDescription.{})'.format(self.description.name)


class TlsClient(object):
    def __init__(self, l4_client):
        self._l4_client = l4_client
        self._last_processed_message_type = None
        self.server_messages = {}

    @property
    def _buffer_is_plain_text(self):
        try:
            return all([c in string.printable for c in self._l4_client.buffer.decode('utf-8')])
        except UnicodeDecodeError:
            return False

    def raise_response_error(self):
        response_is_plain_text = self._l4_client.buffer and self._buffer_is_plain_text
        self._l4_client.flush_buffer()

        if response_is_plain_text:
            raise ResponseError(ResponseErrorType.PLAIN_TEXT_RESPONSE)

        raise ResponseError(ResponseErrorType.UNPARSABLE_RESPONSE)

    @abc.abstractmethod
    def do_handshake(self, hello_message, record_version, last_handshake_message_type):
        raise NotImplementedError()


class TlsClientHandshake(TlsClient):
    def _process_message(self, handshake_message, protocol_version):
        handshake_type = handshake_message.get_handshake_type()
        if handshake_type in self.server_messages:
            raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)
        if (handshake_type == TlsHandshakeType.SERVER_HELLO and
                not handshake_message.protocol_version == protocol_version):
            raise TlsAlert(TlsAlertDescription.PROTOCOL_VERSION)

    def do_handshake(
            self,
            hello_message,
            record_version=TlsProtocolVersionFinal(TlsVersion.SSL3),
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
    ):
        self.server_messages = {}
        self._last_processed_message_type = None

        tls_record = TlsRecord([hello_message, ], record_version)
        self._l4_client.send(tls_record.compose())

        while True:
            try:
                record = TlsRecord.parse_exact_size(self._l4_client.buffer)
                self._l4_client.flush_buffer()

                if record.content_type == TlsContentType.ALERT:
                    if record.messages[0].level == TlsAlertLevel.FATAL:
                        raise TlsAlert(record.messages[0].description)

                    continue

                if record.content_type != TlsContentType.HANDSHAKE:
                    raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

                for handshake_message in record.messages:
                    self._process_message(handshake_message, hello_message.protocol_version)
                    self._last_processed_message_type = handshake_message.get_handshake_type()
                    self.server_messages[self._last_processed_message_type] = handshake_message

                    if self._last_processed_message_type == last_handshake_message_type:
                        return

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            except (InvalidType, InvalidValue):
                self.raise_response_error()

            try:
                self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if self._l4_client.buffer:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION)

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
            record_version=SslVersion.SSL2,
            last_handshake_message_type=SslMessageType.SERVER_HELLO
    ):
        ssl_record = SslRecord(hello_message)
        self._l4_client.send(ssl_record.compose())

        self.server_messages = {}
        while True:
            try:
                record = SslRecord.parse_exact_size(self._l4_client.buffer)
                self._l4_client.flush_buffer()
                if record.message.get_message_type() == SslMessageType.ERROR:
                    raise SslError(record.message.error_type)

                self._last_processed_message_type = record.message.get_message_type()
                self.server_messages[self._last_processed_message_type] = record.message
                if self._last_processed_message_type == last_handshake_message_type:
                    break

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed
            except (InvalidType, InvalidValue):
                self.raise_response_error()

            try:
                self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if self._l4_client.buffer:
                    try:
                        tls_record = TlsRecord.parse_exact_size(self._l4_client.buffer)
                        self._l4_client.flush_buffer()
                    except (InvalidType, InvalidValue):
                        self.raise_response_error()
                    else:
                        if (tls_record.content_type == TlsContentType.ALERT and
                                (tls_record.messages[0].description in [
                                    TlsAlertDescription.PROTOCOL_VERSION,
                                    TlsAlertDescription.HANDSHAKE_FAILURE,
                                    TlsAlertDescription.INTERNAL_ERROR,
                                ])):
                            raise NetworkError(NetworkErrorType.NO_RESPONSE)

                        raise NetworkError(NetworkErrorType.NO_CONNECTION)
                else:
                    raise NetworkError(NetworkErrorType.NO_RESPONSE)
