#!/usr/bin/env python
# -*- coding: utf-8 -*-

import abc

from crypton.common.algorithm import Authentication, KeyExchange
from crypton.common.exception import NotEnoughData, NetworkError, NetworkErrorType
from crypton.common.parse import Parser
from crypton.common.utils import get_leaf_classes

from crypton.tls.ciphersuite import TlsCipherSuite
from crypton.tls.subprotocol import TlsHandshakeClientHello, TlsCipherSuiteVector, TlsContentType, TlsHandshakeType
from crypton.tls.subprotocol import SslMessageBase, SslMessageType, SslHandshakeClientHello, SslCipherKind
from crypton.tls.extension import TlsExtensionSupportedVersions, TlsExtensionServerName, TlsExtensionECPointFormats, TlsECPointFormat, TlsExtensionEllipticCurves, TlsNamedCurve, TlsExtensionSignatureAlgorithms, TlsSignatureAndHashAlgorithm

from crypton.tls.record import TlsRecord, SslRecord
from crypton.tls.version import TlsVersion, TlsProtocolVersionFinal, SslVersion

import socket


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


class L7Client(object):
    def __init__(self, host, port, tls_client=None, ssl_client=None):
        self._host = host
        self._port = port
        self._socket = None
        self._tls_client = tls_client if tls_client else TlsClientHandshake(self)
        self._ssl_client = ssl_client if ssl_client else SslClientHandshake(self)

    def do_ssl_handshake(self, hello_message, last_handshake_message_type=SslMessageType.SERVER_HELLO):
        self._socket = self._connect()
        server_messages = self._ssl_client.do_handshake(hello_message, SslVersion.SSL2, last_handshake_message_type)
        self._close()

        return server_messages

    def do_tls_handshake(self, hello_message, protocol_version, last_handshake_message_type=TlsHandshakeType.SERVER_HELLO):
        self._socket = self._connect()
        server_messages = self._tls_client.do_handshake(hello_message, protocol_version, last_handshake_message_type)
        self._close()

        return server_messages

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
        total_received_bytes = bytearray()

        while len(total_received_bytes) < receivable_byte_num:
            try:
                actual_received_bytes = self._socket.recv(min(receivable_byte_num - len(total_received_bytes), 1024))
            except socket.error as e:
                actual_received_bytes = None

            if not actual_received_bytes:
                raise NotEnoughData(receivable_byte_num - len(total_received_bytes))

            total_received_bytes += actual_received_bytes

        return total_received_bytes

    @property
    def host(self):
        return self._host

    @property
    def port(self):
        return self._port

    @classmethod
    def from_scheme(cls, scheme, host, port):
        for client_class in get_leaf_classes(L7Client):
            if client_class.get_scheme() == scheme:
                return client_class(host, port)
        else:
            raise ValueError()

    @classmethod
    def get_supported_schemes(cls):
        return set([leaf_cls.get_scheme() for leaf_cls in get_leaf_classes(cls)])

    @abc.abstractmethod
    def _connect(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        return NotImplementedError()


class L7ClientTls(L7Client):
    @classmethod
    def get_scheme(cls):
        return 'tls'

    def _connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self._host, self._port))
        return sock


class L7ClientHTTPS(L7Client):
    @classmethod
    def get_scheme(cls):
        return 'https'

    def _connect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self._host, self._port))
        return sock


import poplib


class L7ClientPOP3(L7Client):
    def __init__(self, host, port):
        #self.client = poplib.POP3(host, port)

        super(L7ClientPOP3, self).__init__(host, port)

    @classmethod
    def get_scheme(cls):
        return 'pop'

    def _connect(self):
        #FIXME: self
        self.client = poplib.POP3(self._host, self._port)
        if 'STLS' not in self.capa():
            raise ValueError
        response = self.stls()
        if response != b'+OK':
            raise ValueError
        return self.client.sock

    def close(self):
        if self._socket:
            self.client.quit()


import smtplib


class L7ClientSMTP(L7Client):
    def __init__(self, host, port):
        #self.client = smtplib.SMTP(host, port)

        super(L7ClientSMTP, self).__init__(host, port)

    @classmethod
    def get_scheme(cls):
        return 'smtp'

    def _connect(self):
        #FIXME: self
        self.client = smtplib.SMTP()
        self.client.connect(self._host, self._port)
        self.client.ehlo()
        if not self.client.has_extn('STARTTLS'):
            raise ValueError
        response, message = self.client.docmd('STARTTLS')
        if response != 220:
            raise ValueError
        return self.client.sock

    def close(self):
        if self._socket:
            self.client.quit()

import imaplib


class L7ClientIMAP(L7Client):
    def __init__(self, host, port):
        #self.client = imaplib.IMAP(host, port)

        super(L7ClientIMAP, self).__init__(host, port)

    @classmethod
    def get_scheme(cls):
        return 'imap'

    def _connect(self):
        #FIXME: self
        self.client = imaplib.IMAP4(self._host, self._port)
        if 'STARTTLS' not in self.client.capabilities:
            raise ValueError
        response, message = self.client.xatom('STARTTLS')
        if response != 'OK':
            raise ValueError
        return self.client.socket()

    def close(self):
        if self._socket:
            self.client.quit()

from crypton.vpn.openvpn import OpenVpnOpCode, OpenVPNPacketBase, OpenVPNPacketControlV1, OpenVPNPacketHardResetClientV2, OpenVPNPacketHardResetServerV2, OpenVPNPacketAckV1

class L7ClientOpenVPNBase(L7Client):
    _FRAGMENT_LENGHT = 100

    def __init__(self, host, port):
        super(L7ClientOpenVPNBase, self).__init__(host, port, TlsClientOpenVPN(self))

        self.client_packet_id = 0x00000000
        self.session_id = 0xdeadbabedeadbabe
        self.remote_session_id = None

    def _send_packet(self, sock, packet):
        super(L7ClientOpenVPNBase, self).send(packet.compose())
        #print('send:', packet.get_op_code())
        if packet.get_op_code() != OpenVpnOpCode.ACK_V1:
            self.client_packet_id += 1

    def _reset_session(self, sock, is_udp=True):
        self.client_packet_id = 0x00000000
        self.session_id += 1

        packet_client_hard_reset = OpenVPNPacketHardResetClientV2(
            self.session_id,
            self.client_packet_id
        )
        self._send_packet(sock, packet_client_hard_reset)

        hard_reset_server_bytes = sock.recv(64)
        #print(len(hard_reset_server_bytes))
        packet_hard_reset_server, unparsed_bytes = OpenVPNPacketHardResetServerV2.parse_immutable_bytes(hard_reset_server_bytes)
        if packet_hard_reset_server.remote_session_id is not None and packet_hard_reset_server.remote_session_id != self.session_id:
            raise ValueError('Invalid session id; expected_session_id={} actual_session_id={}'.format(hex(self.session_id), hex(packet_hard_reset_server.remote_session_id)))

        self.remote_session_id = packet_hard_reset_server.session_id
        packet_ack_server_hard_reset = OpenVPNPacketAckV1(
            self.session_id,
            self.remote_session_id,
            [packet_hard_reset_server.packet_id, ]
        )
        self._send_packet(sock, packet_ack_server_hard_reset)

        return sock


    def send(self, sendable_bytes):
        fragment_count = int(len(sendable_bytes) / self._FRAGMENT_LENGHT) + 1
        for fragment_num in range(fragment_count):
            fragment_bytes = sendable_bytes[fragment_num * self._FRAGMENT_LENGHT:(fragment_num + 1) * self._FRAGMENT_LENGHT]

            fragment_packet = OpenVPNPacketControlV1(
                self.session_id,
                [self.client_packet_id],
                self.remote_session_id,
                self.client_packet_id,
                fragment_bytes
            )
            self._send_packet(self._socket, fragment_packet)

    def receive(self, receivable_byte_num):
        parser = None

        while True:
            try:
                received_bytes = self._socket.recv(1024)
            except socket.timeout:
                break
            parser = Parser(received_bytes)
            #print('received_bytes:', len(received_bytes))
            parser.parse_derived('packet', OpenVPNPacketBase)
            #print('receive:', parser['packet'].get_op_code())
            if parser['packet'].get_op_code() != OpenVpnOpCode.ACK_V1:
                #print('break')
                break

        total_received_bytes = bytearray()
        while parser and parser['packet'].get_op_code() == OpenVpnOpCode.CONTROL_V1:
            #print('receive:', parser['packet'].get_op_code())
            #print('packet_id', hex(parser['packet'].packet_id))
            total_received_bytes += parser['packet'].data

            packet_ack = OpenVPNPacketAckV1(
                self.session_id,
                self.remote_session_id,
                [parser['packet'].packet_id, ]
            )
            self._send_packet(self._socket, packet_ack)

            try:
                received_bytes = self._socket.recv(1024)
            except socket.timeout:
                break

            parser = Parser(received_bytes)
            parser.parse_derived('packet', OpenVPNPacketBase)

        if not total_received_bytes:
            raise NotEnoughData(receivable_byte_num - len(total_received_bytes))

        return total_received_bytes

    def close(self):
        if self._socket:
            self._socket.close()


class L7ClientOpenVPN(L7ClientOpenVPNBase):
    @classmethod
    def get_scheme(cls):
        return 'openvpn'

    def _connect(self):
        #print('connect')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect((self._host, self._port))
        #FIXME
        self._socket = sock
        self._reset_session(sock)
        return sock


class L7ClientOpenVPN(L7ClientOpenVPNBase):
    @classmethod
    def get_scheme(cls):
        return 'openvpntcp'

    def _connect(self):
        #print('connect')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self._host, self._port))
        #FIXME
        self._socket = sock
        self._reset_session(sock)
        return sock


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
    def do_handshake(self, hello_message=None, protocol_version=TlsProtocolVersionFinal(TlsVersion.TLS1_0), last_handshake_message_type=TlsHandshakeType.CERTIFICATE):
        if hello_message is None:
            hello_message = TlsHandshakeClientHelloAnyAlgorithm(self._host)

        tls_record = TlsRecord([hello_message, ], protocol_version)
        self._l4_client.send(tls_record.compose())

        server_messages = {}
        received_bytes = bytearray()
        while True:
            try:
                record = TlsRecord.parse_mutable_bytes(received_bytes)
                if record.content_type == TlsContentType.ALERT:
                    raise TlsAlert(record.messages[0].description)
                elif record.content_type != TlsContentType.HANDSHAKE:
                    raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

                for handshake_message in record.messages:
                    if handshake_message.get_handshake_type() in server_messages:
                        raise TlsAlert(TlsAlertDescription.UNEXPECTED_MESSAGE)

                    handshake_type = handshake_message.get_handshake_type()
                    server_messages[handshake_type] = handshake_message
                    if handshake_type == last_handshake_message_type:
                        return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed

            try:
                actual_received_bytes = self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if received_bytes:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION)
                else:
                    raise NetworkError(NetworkErrorType.NO_RESPONSE)
            received_bytes += actual_received_bytes


class SslError(ValueError):
    def __init__(self, error):
        super(SslError, self).__init__()

        self.error = error


class SslHandshakeClientHelloAnyAlgorithm(SslHandshakeClientHello):
    def __init__(self):
        super(SslHandshakeClientHelloAnyAlgorithm, self).__init__(cipher_kinds=list(SslCipherKind))


class SslClientHandshake(TlsClient):
    def do_handshake(self, hello_message=None, protocol_version=SslVersion.SSL2, last_handshake_message_type=SslMessageType.SERVER_HELLO):
        if hello_message is None:
            hello_message = SslHandshakeClientHelloAnyAlgorithm(self._host)

        ssl_record = SslRecord(hello_message)
        self._l4_client.send(ssl_record.compose())

        server_messages = {}
        received_bytes = bytearray()
        while True:
            try:
                record = SslRecord.parse_mutable_bytes(received_bytes)
                message = record.messages[0]
                #FIXME: error message is not parsed
                if message.get_message_type() == SslMessageType.ERROR:
                    raise SslError(message.get_message_type())

                server_messages[message.get_message_type()] = message
                if message.get_message_type() == last_handshake_message_type:
                    return server_messages

                receivable_byte_num = 0
            except NotEnoughData as e:
                receivable_byte_num = e.bytes_needed

            try:
                actual_received_bytes = self._l4_client.receive(receivable_byte_num)
            except NotEnoughData:
                if received_bytes:
                    raise NetworkError(NetworkErrorType.NO_CONNECTION)
                else:
                    raise NetworkError(NetworkErrorType.NO_RESPONSE)
            received_bytes += actual_received_bytes


class TlsClientOpenVPN(TlsClientHandshake):
    pass
