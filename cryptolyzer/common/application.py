# -*- coding: utf-8 -*-

import abc

import attr

from cryptodatahub.common.exception import InvalidValue

from cryptoparser.common.exception import NotEnoughData, InvalidType

from cryptolyzer.common.exception import NetworkError
from cryptolyzer.common.transfer import L4TransferBase, L7TransferBase, L4ServerTCP


class L7ServerConfigurationBase(object):
    pass


@attr.s
class L7ServerBase(L7TransferBase):
    configuration = attr.ib(
        default=None,
        validator=attr.validators.optional(attr.validators.instance_of(L7ServerConfigurationBase))
    )
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
        l4_transfer_class = self._get_transfer_class()
        self.l4_transfer = l4_transfer_class(self.address, self.port, self.timeout, self.ip)
        self.l4_transfer.init_connection()

    @classmethod
    def _get_transfer_class(cls):
        return L4ServerTCP

    @abc.abstractmethod
    def _get_handshake_class(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _do_handshake(self, last_handshake_message_type):
        raise NotImplementedError()

    def _do_handshakes(self, last_handshake_message_type):
        client_messages = []
        actual_handshake_count = 0
        while True:
            self.l4_transfer.close_client()

            if self.max_handshake_count is not None and actual_handshake_count >= self.max_handshake_count:
                break

            try:
                self.l4_transfer.accept()
            except NetworkError:
                break

            actual_handshake_count += 1
            client_messages.append(self._do_handshake(last_handshake_message_type))

        self._close_connection()

        return client_messages


@attr.s
class L7ServerHandshakeBase(object):
    l7_transfer = attr.ib(validator=attr.validators.instance_of(L7TransferBase))
    configuration = attr.ib(validator=attr.validators.instance_of(L7ServerConfigurationBase))
    _last_processed_message_type = attr.ib(init=False, default=None)
    client_messages = attr.ib(init=False, default={})

    def _init_connection(self, last_handshake_message_type):
        pass

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

    def _process_not_enough_data(self):  # pylint: disable=no-self-use
        raise StopIteration()

    def do_handshake(self, last_handshake_message_type):
        self.client_messages = {}
        self._last_processed_message_type = None

        self._init_connection(last_handshake_message_type)

        while True:
            try:
                try:
                    record, parsed_length, is_handshake = self._parse_record()
                    message = self._parse_message(record)
                except NotEnoughData as e:
                    receivable_byte_num = e.bytes_needed
                except (InvalidType, InvalidValue):
                    self._process_invalid_message()
                else:
                    self.l7_transfer.flush_buffer(parsed_length)
                    receivable_byte_num = 0

                    if is_handshake:
                        self._process_handshake_message(message, last_handshake_message_type)
                    else:
                        self._process_non_handshake_message(message)

                try:
                    self.l7_transfer.receive(receivable_byte_num)
                except NotEnoughData:
                    self._process_not_enough_data()

                continue
            except StopIteration:
                break
