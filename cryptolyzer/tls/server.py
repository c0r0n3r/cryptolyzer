# -*- coding: utf-8 -*-

import abc
import attr

import six

from cryptoparser.common.exception import NotEnoughData, InvalidValue

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
)

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.application import L7ServerBase, L7ServerHandshakeBase


@attr.s
class L7ServerTlsBase(L7ServerBase):

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

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
class TlsServer(L7ServerHandshakeBase):
    def _is_message_plain_text(self):
        return self.l4_transfer.buffer and self.l4_transfer.buffer_is_plain_text

    @abc.abstractmethod
    def _parse_record(self):
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
    def _process_plain_text_message(self):
        raise NotImplementedError()


class TlsServerHandshake(TlsServer):
    def _process_handshake_message(self, record, last_handshake_message_type):
        for handshake_message in record.messages:
            self._last_processed_message_type = handshake_message.get_handshake_type()
            self.client_messages[self._last_processed_message_type] = handshake_message

            if self._last_processed_message_type == last_handshake_message_type:
                self._handle_error(TlsAlertLevel.WARNING, TlsAlertDescription.CLOSE_NOTIFY)
                raise StopIteration()

    def _process_non_handshake_message(self, record):
        self._handle_error(TlsAlertLevel.FATAL, TlsAlertDescription.UNEXPECTED_MESSAGE)
        raise StopIteration()

    def _process_plain_text_message(self):
        if self._is_message_plain_text():
            self._handle_error(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR)
            raise StopIteration()

    def _process_invalid_message(self):
        self._process_plain_text_message()

        self._handle_error(TlsAlertLevel.WARNING, TlsAlertDescription.DECRYPT_ERROR)
        raise StopIteration()

    def _handle_error(self, alert_level, alert_description):
        self.l4_transfer.send(TlsRecord([
            TlsAlertMessage(alert_level, alert_description),
        ]).compose())

    def _parse_record(self):
        record = TlsRecord.parse_exact_size(self.l4_transfer.buffer)
        is_handshake = record.content_type == TlsContentType.HANDSHAKE

        return record, is_handshake


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
            self._handle_error(SslErrorType.NO_CIPHER_ERROR)
            raise StopIteration()

    def _process_non_handshake_message(self, record):
        self._handle_error(SslErrorType.NO_CIPHER_ERROR)
        raise StopIteration()

    def _process_plain_text_message(self):
        if self._is_message_plain_text():
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


class L7ServerTls(L7ServerTlsBase):
    @classmethod
    def get_scheme(cls):
        return 'tls'

    @classmethod
    def get_default_port(cls):
        return 4433
