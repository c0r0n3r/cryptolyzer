# -*- coding: utf-8 -*-

import abc
import socket
import string
import six
import attr

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.common.utils import get_leaf_classes

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.utils import resolve_address


@attr.s
class L4TransferBase(object):
    address = attr.ib(validator=attr.validators.instance_of(six.string_types))
    port = attr.ib(validator=attr.validators.instance_of(int))
    timeout = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of((int, float))))
    ip = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    _socket = attr.ib(
        init=False, default=None, validator=attr.validators.optional(attr.validators.instance_of(socket.socket))
    )
    _buffer = attr.ib(init=False, default=bytearray(), validator=attr.validators.instance_of(bytearray))
    _family = attr.ib(init=False)

    def __attrs_post_init__(self):
        if self.timeout is None:
            self.timeout = self.get_default_timeout()
        self._socket = None
        self._buffer = bytearray()
        self._family, self.ip = resolve_address(self.address, self.port, self.ip)

    def _close(self):
        try:
            self._socket.close()
        except (socket.error, socket.timeout):
            pass

    def close(self):
        if self._socket is not None:
            self._close()
            self._socket = None

    def _send(self, sendable_bytes):
        return self._socket.send(sendable_bytes)

    @property
    def buffer(self):
        return bytearray(self._buffer)

    def flush_buffer(self, byte_num=None):
        if byte_num is None:
            byte_num = len(self._buffer)

        self._buffer = self._buffer[byte_num:]

    @property
    def buffer_is_plain_text(self):
        try:
            return all(c in string.printable for c in self._buffer.decode('utf-8'))
        except UnicodeDecodeError:
            return False

    def init_connection(self, _socket=None):
        self.close()

        if _socket:
            self._socket = _socket
            self.ip, self.port = _socket.getsockname()[0:2]
        else:
            self._init_connection()

    @abc.abstractmethod
    def _init_connection(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_timeout(cls):
        raise NotImplementedError()


@attr.s
class L4TransferTCP(L4TransferBase):
    def send(self, sendable_bytes):
        total_sent_byte_num = 0
        while total_sent_byte_num < len(sendable_bytes):
            actual_sent_byte_num = self._send(sendable_bytes[total_sent_byte_num:])
            if actual_sent_byte_num == 0:
                raise NetworkError(NetworkErrorType.NO_CONNECTION)
            total_sent_byte_num += actual_sent_byte_num

        return total_sent_byte_num

    def receive(self, receivable_byte_num, flags=0):
        total_received_byte_num = 0
        while total_received_byte_num < receivable_byte_num:
            try:
                actual_received_bytes = self._socket.recv(
                    min(receivable_byte_num - total_received_byte_num, 1024), flags
                )
                self._buffer += actual_received_bytes
                total_received_byte_num += len(actual_received_bytes)
            except socket.error:
                actual_received_bytes = None

            if not actual_received_bytes:
                raise NotEnoughData(receivable_byte_num - total_received_byte_num)

        return total_received_byte_num

    def receive_until(self, terminator, max_line_length=None):
        terminator_len = len(terminator)
        total_received_byte_num = self.receive(terminator_len)

        while True:
            if self._buffer[-terminator_len:] == terminator:
                break

            total_received_byte_num += self.receive(1)
            if max_line_length is not None and total_received_byte_num == max_line_length:
                raise StopIteration

        return total_received_byte_num

    def receive_line(self, max_line_length=None):
        return self.receive_until(b'\n', max_line_length - 1 if max_line_length is not None else None)

    @abc.abstractmethod
    def _init_connection(self):
        raise NotImplementedError()


class L4ClientTCP(L4TransferTCP):
    def _init_connection(self):
        try:
            self._socket = socket.create_connection((self.ip, self.port), self.timeout)
        except BaseException as e:  # pylint: disable=broad-except
            if e.__class__.__name__ == 'ConnectionRefusedError' or isinstance(e, (socket.error, socket.timeout)):
                six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

            raise e

    @classmethod
    def get_default_timeout(cls):
        return 5


@attr.s
class L4ServerTCP(L4TransferTCP):
    backlog = attr.ib(default=1, validator=attr.validators.instance_of(int))
    _server_socket = attr.ib(init=False, default=None)
    bind_port = attr.ib(init=False, default=None)

    def __del__(self):
        if self._server_socket is not None:
            self._server_socket.close()

    def _init_connection(self):
        try:
            self._server_socket = socket.socket(self._family, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.settimeout(self.timeout)
            self._server_socket.bind((self.ip, self.port))
            self._server_socket.listen(self.backlog)
        except KeyboardInterrupt as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)
        except OverflowError as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_ADDRESS), e)
        except (OSError, socket.error) as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

        self.bind_port = self._server_socket.getsockname()[1]

    def accept(self):
        self._socket, _ = self._server_socket.accept()
        self._socket.settimeout(self.get_default_timeout())
        self.flush_buffer()

    @classmethod
    def get_default_timeout(cls):
        return 1


@attr.s
class L7TransferBase(object):
    address = attr.ib(validator=attr.validators.instance_of(six.string_types))
    port = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(int)))
    timeout = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of((float, int))))
    ip = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(six.string_types)))
    _family = attr.ib(init=False)
    l4_transfer = attr.ib(
        init=False, default=None, validator=attr.validators.optional(attr.validators.instance_of(L4TransferBase))
    )

    def __attrs_post_init__(self):
        if self.port is None:
            self.port = self.get_default_port()
        if self.timeout is None:
            self.timeout = self.get_default_timeout()

        self._family, self.ip = resolve_address(self.address, self.port, self.ip)
        self.l4_transfer = None

    def send(self, sendable_bytes):
        return self.l4_transfer.send(sendable_bytes)

    def receive(self, receivable_byte_num):
        return self.l4_transfer.receive(receivable_byte_num)

    def flush_buffer(self, byte_num=None):
        self.l4_transfer.flush_buffer(byte_num)

    @property
    def buffer(self):
        return self.l4_transfer.buffer

    @property
    def buffer_is_plain_text(self):
        return self.l4_transfer.buffer_is_plain_text

    @classmethod
    def get_supported_schemes(cls):
        return {leaf_cls.get_scheme() for leaf_cls in get_leaf_classes(cls)}

    @classmethod
    def from_scheme(cls, scheme, address, port=None, timeout=None, ip=None):  # pylint: disable=too-many-arguments
        for transfer_class in get_leaf_classes(cls):
            if transfer_class.get_scheme() == scheme:
                port = transfer_class.get_default_port() if port is None else port
                return transfer_class(address=address, port=port, timeout=timeout, ip=ip)

        raise ValueError(scheme)

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    @classmethod
    def get_default_timeout(cls):
        return None

    @abc.abstractmethod
    def _init_connection(self):
        raise NotImplementedError()

    def init_connection(self):
        try:
            self._init_connection()
        except (SecurityError, NetworkError):
            self._close_connection()
            raise

    def _close_connection(self):
        if self.l4_transfer:
            self.l4_transfer.close()
            self.l4_transfer = None
