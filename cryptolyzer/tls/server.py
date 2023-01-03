# -*- coding: utf-8 -*-

import abc
import attr

import six

from cryptodatahub.common.algorithm import BlockCipher
from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.tls.extension import TlsExtensionType, TlsExtensionSupportedVersionsServer
from cryptoparser.tls.ldap import (
    LDAPResultCode,
    LDAPExtendedRequestStartTLS,
    LDAPExtendedResponseStartTLS,
)
from cryptoparser.tls.mysql import (
    MySQLCapability,
    MySQLHandshakeSslRequest,
    MySQLHandshakeV10,
    MySQLRecord,
    MySQLVersion,
)
from cryptoparser.tls.postgresql import SslRequest, Sync
from cryptoparser.tls.rdp import (
    TPKT,
    COTPConnectionConfirm,
    COTPConnectionRequest,
    RDPProtocol,
    RDPNegotiationRequest,
    RDPNegotiationResponse,
)

from cryptoparser.tls.record import TlsRecord, SslRecord
from cryptoparser.tls.subprotocol import (
    SslErrorMessage,
    SslErrorType,
    SslHandshakeServerHello,
    SslMessageBase,
    SslMessageType,
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsCipherSuite,
    TlsContentType,
    TlsHandshakeHelloRetryRequest,
    TlsHandshakeServerHello,
    TlsHandshakeType,
    TlsSubprotocolMessageParser,
)
from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.__setup__ import __title__, __version__
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError, SecurityErrorType
from cryptolyzer.common.application import L7ServerBase, L7ServerHandshakeBase, L7ServerConfigurationBase


@attr.s
class TlsServerConfiguration(L7ServerConfigurationBase):
    protocol_versions = attr.ib(
        converter=sorted,
        default=[TlsProtocolVersion(version) for version in TlsVersion],
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsProtocolVersion))
    )
    cipher_suites = attr.ib(
        default=list(filter(lambda cipher_suite: cipher_suite.value.bulk_cipher == BlockCipher.RC2, TlsCipherSuite)),
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsCipherSuite))
    )
    fallback_to_ssl = attr.ib(default=False, validator=attr.validators.instance_of(bool))
    close_on_error = attr.ib(default=False, validator=attr.validators.instance_of(bool))


@attr.s
class L7ServerTlsBase(L7ServerBase):
    def __attrs_post_init__(self):
        if self.configuration is None:
            self.configuration = TlsServerConfiguration()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    def _init_l7(self):
        pass

    def _deinit_l7(self):
        pass

    def _get_handshake_class(self, l4_transfer):
        if self.configuration.fallback_to_ssl:
            try:
                l4_transfer.receive(TlsRecord.HEADER_SIZE)
            except NotEnoughData as e:
                six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

            try:
                TlsRecord.parse_header(l4_transfer.buffer)
                handshake_class = TlsServerHandshake
            except InvalidValue:
                handshake_class = SslServerHandshake
        else:
            handshake_class = TlsServerHandshake

        return handshake_class

    def _do_handshake(self, last_handshake_message_type):
        try:
            self._init_l7()
        except (NotEnoughData, InvalidValue, NetworkError, SecurityError):
            self.l4_transfer.close()
            return {}

        try:
            handshake_class = self._get_handshake_class(self.l4_transfer)
            handshake_object = handshake_class(self.l4_transfer, self.configuration)
        except NetworkError:
            self.l4_transfer.close()
            return {}

        try:
            handshake_object.do_handshake(last_handshake_message_type)
        finally:
            self._deinit_l7()
            self.l4_transfer.close()

        return handshake_object.client_messages

    def do_handshake(self, last_handshake_message_type=TlsHandshakeType.CLIENT_HELLO):
        return self._do_handshakes(last_handshake_message_type)


@attr.s
class L7ServerStartTlsBase(L7ServerTlsBase):
    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()


@attr.s
class TlsServer(L7ServerHandshakeBase):
    @staticmethod
    def _is_message_plain_text(transfer):
        return transfer.buffer and transfer.buffer_is_plain_text

    @abc.abstractmethod
    def _parse_record(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _parse_message(self, record):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_handshake_message(self, message, last_handshake_message_type):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_non_handshake_message(self, message):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_invalid_message(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_plain_text_message(self):
        raise NotImplementedError()


class TlsServerHandshake(TlsServer):
    def _check_protocol_version(self, message):
        try:
            supported_versions = message.extensions.get_item_by_type(
                TlsExtensionType.SUPPORTED_VERSIONS
            ).supported_versions
        except KeyError:
            supported_versions = [message.protocol_version, ]

        for supported_version in supported_versions:
            if supported_version in self.configuration.protocol_versions:
                return supported_version

        self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.PROTOCOL_VERSION)
        raise StopIteration()

    def _prepare_server_hello(self, message, protocol_version):
        extensions = []
        if protocol_version > TlsProtocolVersion(TlsVersion.TLS1_2):
            extensions.append(TlsExtensionSupportedVersionsServer(protocol_version))

        if protocol_version > TlsProtocolVersion(TlsVersion.TLS1_2):
            server_hello = TlsHandshakeHelloRetryRequest(
                protocol_version=protocol_version,
                cipher_suite=message.cipher_suites[0],
                extensions=extensions,
            )
        else:
            preferred_cipher_suite_list = self.configuration.cipher_suites
            selectable_cipher_suite_set = set(message.cipher_suites)
            for cipher_suite in preferred_cipher_suite_list:
                if cipher_suite in selectable_cipher_suite_set:
                    choosen_cipher_suite = cipher_suite
                    break
            else:
                self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.HANDSHAKE_FAILURE)
                raise StopIteration()

            server_hello = TlsHandshakeServerHello(
                protocol_version=protocol_version,
                cipher_suite=choosen_cipher_suite,
                random=message.random,
                extensions=extensions,
            )

        return server_hello

    def _process_handshake_message(self, message, last_handshake_message_type):
        self._last_processed_message_type = message.get_handshake_type()
        self.client_messages[self._last_processed_message_type] = message

        if len(self.client_messages) == 1:
            if TlsHandshakeType.CLIENT_HELLO not in self.client_messages:
                self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.UNEXPECTED_MESSAGE)
                raise StopIteration()

        if message.get_handshake_type() == TlsHandshakeType.CLIENT_HELLO:
            protocol_version = self._check_protocol_version(message)
            server_hello = self._prepare_server_hello(message, protocol_version)
            self.l4_transfer.send(TlsRecord(server_hello.compose()).compose())

        if self._last_processed_message_type == last_handshake_message_type:
            self._handle_error(TlsAlertLevel.WARNING, TlsAlertDescription.CLOSE_NOTIFY)
            raise StopIteration()

    def _process_non_handshake_message(self, message):
        self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.UNEXPECTED_MESSAGE)
        raise StopIteration()

    def _process_plain_text_message(self):
        if self._is_message_plain_text(self.l4_transfer):
            self._handle_error(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR)
            raise StopIteration()

    def _process_invalid_message(self):
        self._process_plain_text_message()

        self._handle_error(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR)
        raise StopIteration()

    def _handle_error(self, alert_level, alert_description):
        if self.configuration.close_on_error:
            self.l4_transfer.close()
        else:
            self.l4_transfer.send(TlsRecord(
                TlsAlertMessage(alert_level, alert_description).compose(),
                content_type=TlsContentType.ALERT,
            ).compose())

    def _parse_record(self):
        record = TlsRecord.parse_exact_size(self.l4_transfer.buffer)
        is_handshake = record.content_type == TlsContentType.HANDSHAKE

        return record, is_handshake

    def _parse_message(self, record):
        subprotocol_parser = TlsSubprotocolMessageParser(record.content_type)
        message, _ = subprotocol_parser.parse(record.fragment)

        return message


class SslServerHandshake(TlsServer):
    client_messages = attr.ib(
        init=False,
        default={},
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SslMessageBase))
    )

    def _process_handshake_message(self, message, last_handshake_message_type):
        self._last_processed_message_type = message.get_message_type()
        self.client_messages[self._last_processed_message_type] = message

        server_hello = SslHandshakeServerHello(
            certificate=b'fake certificate',
            cipher_kinds=message.cipher_kinds,
            connection_id=b'fake connection id',
        )
        self.l4_transfer.send(SslRecord(server_hello).compose())

        if self._last_processed_message_type == last_handshake_message_type:
            self._handle_error(SslErrorType.NO_CIPHER_ERROR)
            raise StopIteration()

    def _process_non_handshake_message(self, message):
        self._handle_error(SslErrorType.NO_CIPHER_ERROR)
        raise StopIteration()

    def _process_plain_text_message(self):
        if self._is_message_plain_text(self.l4_transfer):
            self._handle_error(SslErrorType.NO_CIPHER_ERROR)
            raise StopIteration()

    def _process_invalid_message(self):
        self._process_plain_text_message()

        self._handle_error(SslErrorType.NO_CIPHER_ERROR)
        raise StopIteration()

    def _handle_error(self, error_type):
        self.l4_transfer.send(SslRecord(SslErrorMessage(error_type)).compose())

    def _parse_record(self):
        record = SslRecord.parse_exact_size(self.l4_transfer.buffer)
        is_handshake = record.message.get_message_type() != SslMessageType.ERROR

        return record, is_handshake

    def _parse_message(self, record):
        return record.message


class L7ServerTls(L7ServerTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'tls'

    @classmethod
    def get_default_port(cls):
        return 4433


class L7ServerTlsRDP(L7ServerStartTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'rdp'

    @classmethod
    def get_default_port(cls):
        return 3389

    def _init_l7(self):
        self.l4_transfer.receive(TPKT.HEADER_SIZE)
        try:
            TPKT.parse_exact_size(self.l4_transfer.buffer)
        except NotEnoughData as e:
            self.l4_transfer.receive(e.bytes_needed)

        tpkt = TPKT.parse_exact_size(self.l4_transfer.buffer)
        cotp = COTPConnectionRequest.parse_exact_size(tpkt.message)
        neg_req = RDPNegotiationRequest.parse_exact_size(cotp.user_data)
        if RDPProtocol.SSL not in neg_req.protocol:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

        self.l4_transfer.flush_buffer()

        neg_resp = RDPNegotiationResponse([], [RDPProtocol.SSL, ])
        cotp = COTPConnectionConfirm(src_ref=cotp.src_ref, user_data=neg_resp.compose())
        tpkt = TPKT(version=3, message=cotp.compose())
        request_bytes = tpkt.compose()
        self.l4_transfer.send(request_bytes)

    def _deinit_l7(self):
        pass


class L7ServerTlsLDAP(L7ServerStartTlsBase):
    _EXTENDED_RESPONSE_STARTLS_BYTES = LDAPExtendedResponseStartTLS(LDAPResultCode.SUCCESS).compose()

    @classmethod
    def get_scheme(cls):
        return 'ldap'

    @classmethod
    def get_default_port(cls):
        return 3389

    def _init_l7(self):
        self.l4_transfer.receive(LDAPExtendedRequestStartTLS.HEADER_SIZE)
        try:
            LDAPExtendedRequestStartTLS.parse_exact_size(self.l4_transfer.buffer)
        except NotEnoughData as e:
            self.l4_transfer.receive(e.bytes_needed)

        LDAPExtendedRequestStartTLS.parse_exact_size(self.l4_transfer.buffer)
        self.l4_transfer.flush_buffer()

        self.l4_transfer.send(self._EXTENDED_RESPONSE_STARTLS_BYTES)

    def _deinit_l7(self):
        pass


class L7ServerTlsPostgreSQL(L7ServerStartTlsBase):
    _SSL_REQUEST_BYTES = SslRequest().compose()
    _SYNC_BYTES = Sync().compose()

    @classmethod
    def get_scheme(cls):
        return 'postgresql'

    @classmethod
    def get_default_port(cls):
        return 5432

    def _init_l7(self):
        self.l4_transfer.receive(len(self._SSL_REQUEST_BYTES))
        if self.l4_transfer.buffer != self._SSL_REQUEST_BYTES:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        self.l4_transfer.flush_buffer()

        self.l4_transfer.send(self._SYNC_BYTES)

    def _deinit_l7(self):
        pass


class L7ServerTlsMySQL(L7ServerStartTlsBase):
    _SERVER_HANDSHAKE_RECORD_BYTES = MySQLRecord(0, MySQLHandshakeV10(
        protocol_version=MySQLVersion.MYSQL_10,
        server_version='1.2.3.4',
        connection_id=0x01020304,
        auth_plugin_data=b'12345678',
        capabilities=[MySQLCapability.CLIENT_SSL, ],
    ).compose()).compose()

    @classmethod
    def get_scheme(cls):
        return 'mysql'

    @classmethod
    def get_default_port(cls):
        return 3306

    def _init_l7(self):
        self.l4_transfer.send(self._SERVER_HANDSHAKE_RECORD_BYTES)

        self.l4_transfer.receive(MySQLRecord.HEADER_SIZE)
        try:
            MySQLRecord.parse_exact_size(self.l4_transfer.buffer)
        except NotEnoughData as e:
            self.l4_transfer.receive(e.bytes_needed)

        record, parsed_length = MySQLRecord.parse_immutable(self.l4_transfer.buffer)
        self.l4_transfer.flush_buffer(parsed_length)

        ssl_request = MySQLHandshakeSslRequest.parse_exact_size(record.packet_bytes)
        if not set([MySQLCapability.CLIENT_SSL, MySQLCapability.CLIENT_SECURE_CONNECTION]) & ssl_request.capabilities:
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)

    def _deinit_l7(self):
        pass


@attr.s
class L7ServerStartTlsTextBase(L7ServerStartTlsBase):
    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def _get_greeting(cls):
        raise NotImplementedError()

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return None

    @classmethod
    def _get_capabilities_response(cls):
        return None  # pragma: no cover

    @classmethod
    def _get_starttls_request_prefix(cls):
        return b'STARTTLS'

    @classmethod
    @abc.abstractmethod
    def _get_starttls_response(cls):
        raise NotImplementedError()

    @classmethod
    def _get_software_name(cls):
        return '{} {}'.format(__title__, __version__).encode('ascii')

    def _init_l7(self):
        greeting = self._get_greeting()
        if greeting:
            self.l4_transfer.send(greeting)

        self.l4_transfer.receive_line()
        capabilities_request_prefix = self._get_capabilities_request_prefix()
        if capabilities_request_prefix and self.l4_transfer.buffer.startswith(capabilities_request_prefix):
            self.l4_transfer.flush_buffer()
            self.l4_transfer.send(self._get_capabilities_response())
            self.l4_transfer.receive_line()

        starttls_request_prefix = self._get_starttls_request_prefix()
        if not self.l4_transfer.buffer.startswith(starttls_request_prefix):
            raise SecurityError(SecurityErrorType.UNSUPPORTED_SECURITY)
        self.l4_transfer.flush_buffer()

        self.l4_transfer.send(self._get_starttls_response())


class L7ServerTlsSieve(L7ServerStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'sieve'

    @classmethod
    def get_default_port(cls):
        return 4190

    @classmethod
    def _get_greeting(cls):
        return b'\r\n'.join([
            b'"STARTTLS"',
            b'OK "' + cls._get_software_name() + b'" ready,',
            b'',
        ])

    @classmethod
    def _get_starttls_response(cls):
        return b'OK "Begin TLS negotiation now."\r\n'


class L7ServerTlsFTP(L7ServerStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'ftp'

    @classmethod
    def get_default_port(cls):
        return 2121

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'FEAT'

    @classmethod
    def _get_capabilities_response(cls):
        return b'\r\n'.join([
            b'211-Extensions supported:',
            b' AUTH TLS',
            b'211 End.',
            b'',
        ])

    @classmethod
    def _get_greeting(cls):
        return b'\r\n'.join([
            b'220 Welcome to ' + cls._get_software_name() + b'.',
            b'',
        ])

    @classmethod
    def _get_starttls_request_prefix(cls):
        return b'AUTH TLS'

    @classmethod
    def _get_starttls_response(cls):
        return b'234 AUTH TLS OK.\r\n'


class L7ServerTlsPOP3(L7ServerStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'pop3'

    @classmethod
    def get_default_port(cls):
        return 1110

    @classmethod
    def _get_greeting(cls):
        return b'\r\n'.join([
            b'+OK ' + cls._get_software_name() + b' ready.',
            b'',
        ])

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'CAPA'

    @classmethod
    def _get_capabilities_response(cls):
        return b'\r\n'.join([
            b'+OK',
            b'CAPA',
            b'STLS',
            b'.',
            b'',
        ])

    @classmethod
    def _get_starttls_request_prefix(cls):
        return b'STLS'

    @classmethod
    def _get_starttls_response(cls):
        return b'+OK Begin TLS negotiation now.\r\n'


class L7ServerStartTlsMailBase(L7ServerStartTlsTextBase):
    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    @classmethod
    def _get_greeting(cls):
        return b'\r\n'.join([
            b'220 localhost ' + cls._get_software_name() + b' ready.',
            b'',
        ])

    @classmethod
    @abc.abstractmethod
    def _get_capabilities_request_prefix(cls):
        raise NotImplementedError()

    @classmethod
    def _get_capabilities_response(cls):
        return b'\r\n'.join([
            b'250 localhost at your service',
            b'250 STARTTLS',
            b'',
        ])

    @classmethod
    def _get_starttls_request_prefix(cls):
        return b'STARTTLS'

    @classmethod
    def _get_starttls_response(cls):
        return b'220 Ready to start TLS\r\n'


class L7ServerTlsSMTP(L7ServerStartTlsMailBase):
    @classmethod
    def get_scheme(cls):
        return 'smtp'

    @classmethod
    def get_default_port(cls):
        return 5587

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'EHLO'


class L7ServerTlsLMTP(L7ServerStartTlsMailBase):
    @classmethod
    def get_scheme(cls):
        return 'lmtp'

    @classmethod
    def get_default_port(cls):
        return 2424

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'LHLO'


class L7ServerTlsNNTP(L7ServerStartTlsTextBase):
    @classmethod
    def get_scheme(cls):
        return 'nntp'

    @classmethod
    def get_default_port(cls):
        return 1119

    @classmethod
    def _get_capabilities_request_prefix(cls):
        return b'CAPABILITIES'

    @classmethod
    def _get_capabilities_response(cls):
        return b'\r\n'.join([
            b'101 Capability list:',
            b'STARTTLS',
            b'.',
            b'',
        ])

    @classmethod
    def _get_greeting(cls):
        return b'\r\n'.join([
            b'200 ' + cls._get_software_name() + b' Welcome!',
            b'',
        ])

    @classmethod
    def _get_starttls_response(cls):
        return b'382 Continue with TLS negotiation\r\n'
