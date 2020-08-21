# -*- coding: utf-8 -*-

import abc
import socket
import attr

import six

from cryptoparser.common.exception import NotEnoughData, InvalidType, InvalidValue

from cryptoparser.tls.record import TlsRecord, SslRecord
from cryptoparser.tls.subprotocol import (
    SslErrorMessage,
    SslErrorType,
    SslMessageBase,
    SslMessageType,
    TlsAlertDescription,
    TlsAlertLevel,
    TlsAlertMessage,
    TlsContentType,
    TlsHandshakeType,
    TlsSubprotocolMessageBase,
)

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L7TransferBase, L4TransferBase, L4ServerTCP


@attr.s
class L7ServerTlsBase(L7TransferBase):
    max_handshake_count = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(int)))
    l4_transfer = attr.ib(
        init=False, default=None, validator=attr.validators.optional(attr.validators.instance_of(L4TransferBase))
    )

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    def _init_connection(self):
        self.l4_transfer = L4ServerTCP(self.address, self.port, self.timeout, self.ip)
        self.l4_transfer.init_connection()

    @staticmethod
    def _get_handshake_class(l4_transfer, fallback_to_ssl):
        if fallback_to_ssl is None:
            handshake_class = SslServerHandshake
        elif fallback_to_ssl:
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

    def _do_handshake(self, last_handshake_message_type, fallback_to_ssl):
        try:
            handshake_class = self._get_handshake_class(self.l4_transfer, fallback_to_ssl)
            handshake_object = handshake_class(self.l4_transfer)
        except NetworkError:
            self.l4_transfer.close()
            return {}

        try:
            handshake_object.do_handshake(last_handshake_message_type)
        finally:
            self.l4_transfer.close()

        return handshake_object.client_messages

    def _do_handshakes(self, last_handshake_message_type, fallback_to_ssl):
        clients_messages = []
        actual_handshake_count = 0
        while True:
            self.l4_transfer.close()

            if self.max_handshake_count is not None and actual_handshake_count >= self.max_handshake_count:
                break

            try:
                self.l4_transfer.accept()
            except socket.timeout:
                break

            actual_handshake_count += 1
            clients_messages.append(self._do_handshake(last_handshake_message_type, fallback_to_ssl))

        self._close_connection()

        return clients_messages

    def do_ssl_handshake(self, last_handshake_message_type=SslMessageType.CLIENT_HELLO):
        return self._do_handshakes(
            last_handshake_message_type,
            fallback_to_ssl=None
        )

    def do_tls_handshake(self, last_handshake_message_type=TlsHandshakeType.CLIENT_HELLO, fallback_to_ssl=False):
        return self._do_handshakes(
            last_handshake_message_type,
            fallback_to_ssl
        )


@attr.s
class TlsServer(object):
    l4_transfer = attr.ib(validator=attr.validators.instance_of(L4TransferBase))
    _last_processed_message_type = attr.ib(init=False, default=None)
    clients_messages = attr.ib(init=False, default={})

    def _is_message_plain_text(self):
        return self.l4_transfer.buffer and self.l4_transfer.buffer_is_plain_text

    @abc.abstractmethod
    def _process_plain_text_message(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_handshake_message(self, record, last_handshake_message_type):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_non_handshake_message(self, record):
        raise NotImplementedError()

    @abc.abstractmethod
    def _process_invalid_message(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def do_handshake(self, last_handshake_message_type):
        raise NotImplementedError()


class TlsServerHandshake(TlsServer):
    client_messages = attr.ib(
        init=False,
        default={},
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(TlsSubprotocolMessageBase))
    )
    _last_processed_message_type = attr.ib(
        init=False, default=None, validator=attr.validators.optional(attr.validators.instance_of(TlsHandshakeType))
    )

    def _process_handshake_message(self, record, last_handshake_message_type):
        for handshake_message in record.messages:
            self._last_processed_message_type = handshake_message.get_handshake_type()
            self.client_messages[self._last_processed_message_type] = handshake_message

            if self._last_processed_message_type == last_handshake_message_type:
                self._send_alert(TlsAlertLevel.WARNING, TlsAlertDescription.CLOSE_NOTIFY)
                raise StopIteration()

    def _process_non_handshake_message(self, record):
        self._send_alert(TlsAlertLevel.FATAL, TlsAlertDescription.UNEXPECTED_MESSAGE)
        raise StopIteration()

    def _process_plain_text_message(self):
        if self._is_message_plain_text():
            self._send_alert(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR)
            raise StopIteration()

    def _process_invalid_message(self):
        self._process_plain_text_message()

        self._send_alert(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR)
        raise StopIteration()

    def _send_alert(self, alert_level, alert_description):
        self.l4_transfer.send(TlsRecord([
            TlsAlertMessage(alert_level, alert_description),
        ]).compose())

    def do_handshake(self, last_handshake_message_type=TlsHandshakeType.CLIENT_HELLO):
        self.client_messages = {}
        self._last_processed_message_type = None

        while True:
            try:
                try:
                    record = TlsRecord.parse_exact_size(self.l4_transfer.buffer)
                    self.l4_transfer.flush_buffer()
                    receivable_byte_num = 0
                except NotEnoughData as e:
                    receivable_byte_num = e.bytes_needed
                except (InvalidType, InvalidValue):
                    self._process_invalid_message()
                else:
                    if record.content_type == TlsContentType.HANDSHAKE:
                        self._process_handshake_message(record, last_handshake_message_type)
                    else:
                        self._process_non_handshake_message(record)

                try:
                    self.l4_transfer.receive(receivable_byte_num)
                except NotEnoughData:
                    self._process_plain_text_message()
                    raise StopIteration()

                continue
            except StopIteration:
                break


class SslServerHandshake(TlsServer):
    client_messages = attr.ib(
        init=False,
        default={},
        validator=attr.validators.deep_iterable(member_validator=attr.validators.in_(SslMessageBase))
    )

    def _process_handshake_message(self, record, last_handshake_message_type):
        self._last_processed_message_type = record.message.get_message_type()
        self.client_messages[self._last_processed_message_type] = record.message

        if self._last_processed_message_type == last_handshake_message_type:
            self._send_alert(SslErrorType.NO_CIPHER_ERROR)
            raise StopIteration()

    def _process_non_handshake_message(self, record):
        self._send_alert(SslErrorType.NO_CIPHER_ERROR)
        raise StopIteration()

    def _process_plain_text_message(self):
        if self._is_message_plain_text():
            self._send_alert(SslErrorType.NO_CIPHER_ERROR)
            raise StopIteration()

    def _process_invalid_message(self):
        self._process_plain_text_message()

        self._send_alert(SslErrorType.NO_CIPHER_ERROR)
        raise StopIteration()

    def _send_alert(self, error_type):
        self.l4_transfer.send(SslRecord(SslErrorMessage(error_type)).compose())

    def do_handshake(self, last_handshake_message_type=SslMessageType.CLIENT_HELLO):
        self.client_messages = {}
        self._last_processed_message_type = None

        while True:
            try:
                try:
                    record = SslRecord.parse_exact_size(self.l4_transfer.buffer)
                    self.l4_transfer.flush_buffer()
                    receivable_byte_num = 0
                except NotEnoughData as e:
                    receivable_byte_num = e.bytes_needed
                except (InvalidType, InvalidValue):
                    self._process_plain_text_message()
                    self._process_invalid_message()
                else:
                    if record.message.get_message_type() == SslMessageType.ERROR:
                        self._process_non_handshake_message(record)
                    else:
                        self._process_handshake_message(record, last_handshake_message_type)

                try:
                    self.l4_transfer.receive(receivable_byte_num)
                except NotEnoughData:
                    self._process_plain_text_message()
                    raise StopIteration()

                continue
            except StopIteration:
                break


class L7ServerTls(L7ServerTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'tls'

    @classmethod
    def get_default_port(cls):
        return 4433
