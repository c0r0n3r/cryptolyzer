# -*- coding: utf-8 -*-

import abc

import ftplib
import imaplib
import poplib
import smtplib

import socket

from cryptoparser.common.algorithm import Authentication, KeyExchange
from cryptoparser.common.exception import NotEnoughData, InvalidType, InvalidValue

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

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.common.transfer import L4ClientTCP, L7TransferBase


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


class L7ClientTlsBase(L7TransferBase):
    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    def _init_connection(self):
        self._l4_transfer = L4ClientTCP(self._address, self._port, self._timeout, self._ip)
        self._l4_transfer.init_connection()

    def _do_handshake(
            self,
            tls_client,
            hello_message,
            record_version,
            last_handshake_message_type
    ):
        self.init_connection()

        try:
            tls_client.do_handshake(self, hello_message, record_version, last_handshake_message_type)
        finally:
            self._close_connection()

        return tls_client.server_messages

    def do_ssl_handshake(self, hello_message, last_handshake_message_type=SslMessageType.SERVER_HELLO):
        return self._do_handshake(
            SslClientHandshake(),
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
            TlsClientHandshake(),
            hello_message,
            record_version,
            last_handshake_message_type
        )


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

        self._l7_client = None

    @classmethod
    def get_scheme(cls):
        return 'pop3'

    @classmethod
    def get_default_port(cls):
        return 110

    def _init_connection(self):
        self._l4_transfer = L4ClientTCP(self._address, self._port, self._timeout, self._ip)
        try:
            self._l7_client = poplib.POP3(self._ip, self._port, self._timeout)
            self._l4_transfer.init_connection(self._l7_client.sock)

            response = self._l7_client._shortcmd('STLS')  # pylint: disable=protected-access
            if len(response) < 3 or response[:3] != b'+OK':
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        except poplib.error_proto:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

    def _close_connection(self):
        if self._l7_client is not None:
            try:
                self._l7_client.quit()
            except poplib.error_proto:
                self._l4_transfer.close()


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

        self._l7_client = None

    @classmethod
    def get_scheme(cls):
        return 'smtp'

    @classmethod
    def get_default_port(cls):
        return 587

    def _init_connection(self):
        self._l4_transfer = L4ClientTCP(self._address, self._port, self._timeout, self._ip)
        try:
            self._l7_client = smtplib.SMTP(timeout=self._timeout)
            self._l7_client.connect(self._ip, self._port)
            self._l4_transfer.init_connection(self._l7_client.sock)

            self._l7_client.ehlo()
            if not self._l7_client.has_extn('STARTTLS'):
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
            response, _ = self._l7_client.docmd('STARTTLS')
            if response != 220:
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        except smtplib.SMTPException:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

    def _close_connection(self):
        if self._l7_client is not None:
            try:
                self._l7_client.quit()
            except smtplib.SMTPServerDisconnected:
                self._l4_transfer.close()


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

        self._l7_client = None

    @classmethod
    def get_scheme(cls):
        return 'imap'

    @classmethod
    def get_default_port(cls):
        return 143

    @property
    def _capabilities(self):
        return self._l7_client.capabilities

    def _init_connection(self):
        self._l4_transfer = L4ClientTCP(self._address, self._port, self._timeout, self._ip)
        try:
            self._l7_client = IMAP4(self._ip, self._port, self._timeout)
            self._l4_transfer.init_connection(self._l7_client.socket())

            if 'STARTTLS' not in self._capabilities:
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
            response, _ = self._l7_client.xatom('STARTTLS')
            if response != 'OK':
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        except imaplib.IMAP4.error:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

    def _close_connection(self):
        if self._l7_client is not None:
            try:
                self._l7_client.shutdown()
            except IMAP4.error:
                self._l4_transfer.close()


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

        self._l7_client = None

    @classmethod
    def get_scheme(cls):
        return 'ftp'

    @classmethod
    def get_default_port(cls):
        return 21

    def _init_connection(self):
        self._l4_transfer = L4ClientTCP(self._address, self._port, self._timeout, self._ip)
        try:
            self._l7_client = ftplib.FTP()
            response = self._l7_client.connect(self._address, self._port, self._timeout)
            self._l4_transfer.init_connection(self._l7_client.sock)
            if not response.startswith('220'):
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

            response = self._l7_client.sendcmd('AUTH TLS')
            if not response.startswith('234'):
                raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        except ftplib.all_errors:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

    def _close_connection(self):
        if self._l7_client is not None:
            try:
                self._l7_client.quit()
            except ftplib.all_errors:
                self._l4_transfer.close()


class TlsClient(object):
    def __init__(self):
        self._last_processed_message_type = None
        self.server_messages = {}

    @staticmethod
    def raise_response_error(transfer):
        response_is_plain_text = transfer.buffer and transfer.buffer_is_plain_text
        transfer.flush_buffer()

        if response_is_plain_text:
            raise SecurityError(SecurityErrorType.PLAIN_TEXT_MESSAGE)

        raise SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE)

    @abc.abstractmethod
    def do_handshake(self, transfer, hello_message, record_version, last_handshake_message_type):
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
            transfer,
            hello_message,
            record_version=TlsProtocolVersionFinal(TlsVersion.SSL3),
            last_handshake_message_type=TlsHandshakeType.SERVER_HELLO_DONE
    ):
        self.server_messages = {}
        self._last_processed_message_type = None

        tls_record = TlsRecord([hello_message, ], record_version)
        transfer.send(tls_record.compose())

        while True:
            try:
                record = TlsRecord.parse_exact_size(transfer.buffer)
                transfer.flush_buffer()

                if record.content_type == TlsContentType.ALERT:
                    if (record.messages[0].level == TlsAlertLevel.FATAL or
                            record.messages[0].description == TlsAlertDescription.CLOSE_NOTIFY):
                        raise TlsAlert(record.messages[0].description)

                    transfer.flush_buffer()
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
                self.raise_response_error(transfer)

            try:
                transfer.receive(receivable_byte_num)
            except NotEnoughData:
                if transfer.buffer:
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
            transfer,
            hello_message=None,
            record_version=SslVersion.SSL2,
            last_handshake_message_type=SslMessageType.SERVER_HELLO
    ):
        ssl_record = SslRecord(hello_message)
        transfer.send(ssl_record.compose())

        self.server_messages = {}
        while True:
            try:
                record = SslRecord.parse_exact_size(transfer.buffer)
                transfer.flush_buffer()
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
                self.raise_response_error(transfer)

            try:
                transfer.receive(receivable_byte_num)
            except NotEnoughData:
                if transfer.buffer:
                    try:
                        tls_record = TlsRecord.parse_exact_size(transfer.buffer)
                        transfer.flush_buffer()
                    except (InvalidType, InvalidValue):
                        self.raise_response_error(transfer)
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
