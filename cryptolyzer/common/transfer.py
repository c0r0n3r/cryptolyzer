# -*- coding: utf-8 -*-

import abc
import socket

import ipaddress
import attr
import six

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.common.utils import get_leaf_classes

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.utils import buffer_flush, buffer_is_plain_text, resolve_address


@attr.s
class L4TransferBase(object):
    address = attr.ib(validator=attr.validators.instance_of(six.string_types))
    port = attr.ib(validator=attr.validators.instance_of(int))
    timeout = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of((int, float))))
    ip = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of((
        six.string_types, ipaddress.IPv4Address, ipaddress.IPv6Address
    ))))
    _family = attr.ib(init=False)
    _buffer = attr.ib(init=False)
    _socket = attr.ib(
        init=False, default=None,
        validator=attr.validators.optional(attr.validators.instance_of(socket.socket))
    )

    def __attrs_post_init__(self):
        if self.timeout is None:
            self.timeout = self.get_default_timeout()
        self._family, self.ip = resolve_address(self.address, self.port, self.ip)
        self._buffer = bytearray()

    def __del__(self):
        self.close()

    @staticmethod
    def _close_socket(sock):
        try:
            sock.close()
        except BaseException as e:  # pylint: disable=broad-except
            if e.__class__.__name__ != 'TimeoutError' and not isinstance(e, (socket.error, socket.timeout)):
                raise e

    def close(self):
        if self._socket is not None:
            self._close_socket(self._socket)
            self._socket = None

    @abc.abstractmethod
    def _send(self, sendable_bytes):
        raise NotImplementedError()

    @property
    def buffer(self):
        return bytearray(self._buffer)

    def flush_buffer(self, byte_num=None):
        self._buffer = buffer_flush(self._buffer, byte_num)

    @property
    def buffer_is_plain_text(self):
        return buffer_is_plain_text(self._buffer)

    def init_connection(self, _socket=None):
        self.close()

        if _socket:
            self._socket = _socket
            self.ip, self.port = _socket.getsockname()[0:2]
        else:
            self._init_connection()

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
                actual_received_bytes = self._receive_bytes(
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

    @staticmethod
    def _receive_bytes_from_tcp_socket(sock, receivable_byte_num, flags):
        if sock is None:
            raise NotEnoughData(receivable_byte_num)

        return sock.recv(receivable_byte_num, flags)

    @abc.abstractmethod
    def _receive_bytes(self, receivable_byte_num, flags):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_timeout(cls):
        raise NotImplementedError()


@attr.s
class L4ClientBase(L4TransferBase):
    @abc.abstractmethod
    def _init_connection(self):
        raise NotImplementedError()

    @abc.abstractmethod
    def _receive_bytes(self, receivable_byte_num, flags):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_timeout(cls):
        raise NotImplementedError()

    def _send(self, sendable_bytes):
        return self._socket.send(sendable_bytes)


class L4ClientTCP(L4ClientBase):
    def _init_connection(self):
        self._buffer = bytearray()
        try:
            self._socket = socket.create_connection((str(self.ip), self.port), self.timeout)
        except BaseException as e:  # pylint: disable=broad-except
            if e.__class__.__name__ == 'ConnectionRefusedError' or isinstance(e, (socket.error, socket.timeout)):
                six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

            raise e

    def _receive_bytes(self, receivable_byte_num, flags):
        return self._receive_bytes_from_tcp_socket(self._socket, receivable_byte_num, flags)

    @classmethod
    def get_default_timeout(cls):
        return 5


class L4ClientUDP(L4ClientBase):
    def _init_connection(self):
        self._buffer = bytearray()
        self._socket = socket.socket(self._family, socket.SOCK_DGRAM)
        self._socket.settimeout(self.timeout)
        self._socket.connect((str(self.ip), self.port))

    def _receive_bytes(self, receivable_byte_num, flags):
        msg_bytes = bytearray(1)
        msg_byte_num = self._socket.recv_into(msg_bytes, 1, flags=socket.MSG_PEEK | socket.MSG_TRUNC)

        msg_bytes = bytearray(msg_byte_num)
        self._socket.recv_into(msg_bytes, msg_byte_num, flags=flags)

        return msg_bytes

    @classmethod
    def get_default_timeout(cls):
        return 5


@attr.s
class L4ServerBase(L4TransferBase):
    backlog = attr.ib(default=1, validator=attr.validators.instance_of(int))

    @classmethod
    @abc.abstractmethod
    def _get_socket_type(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def close_client(self):
        raise NotImplementedError()

    def __del__(self):
        super(L4ServerBase, self).__del__()

        if self._socket is not None:
            self._close_socket(self._socket)

    def close(self):
        self.close_client()

    def _init_connection(self):
        socket_type = self._get_socket_type()
        try:
            self._socket = socket.socket(self._family, socket_type)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.settimeout(self.timeout)
            self._socket.bind((str(self.address), self.port))
            if socket_type == socket.SOCK_STREAM:
                self._socket.listen(self.backlog)
        except KeyboardInterrupt as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_RESPONSE), e)
        except OverflowError as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_ADDRESS), e)
        except (OSError, socket.error) as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

    @property
    def bind_address(self):
        return self._socket.getsockname()[0]

    @property
    def bind_port(self):
        return self._socket.getsockname()[1]

    @classmethod
    def get_default_timeout(cls):
        return 1


@attr.s
class L4ServerTCP(L4ServerBase):
    _client_socket = attr.ib(
        init=False, default=None, validator=attr.validators.optional(attr.validators.instance_of(socket.socket))
    )

    @classmethod
    def _get_socket_type(cls):
        return socket.SOCK_STREAM

    def accept(self):
        try:
            self._client_socket, _ = self._socket.accept()
        except BaseException as e:  # pylint: disable=broad-except
            six.raise_from(NetworkError(NetworkErrorType.NO_CONNECTION), e)

        self._client_socket.settimeout(self.get_default_timeout())
        self.flush_buffer()

    def _receive_bytes(self, receivable_byte_num, flags):
        return self._receive_bytes_from_tcp_socket(self._client_socket, receivable_byte_num, flags)

    def _send(self, sendable_bytes):
        return self._client_socket.send(sendable_bytes)

    def close_client(self):
        if self._client_socket is not None:
            self._client_socket.close()
            self._client_socket = None


@attr.s
class L4ServerUDP(L4ServerBase):
    _client_address = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of((
        ipaddress.IPv4Address, ipaddress.IPv6Address
    ))))
    _client_port = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(int)))

    @classmethod
    def _get_socket_type(cls):
        return socket.SOCK_DGRAM

    def accept(self):
        pass

    def _send(self, sendable_bytes):
        return self._socket.sendto(sendable_bytes, (self._client_address, self._client_port))

    def _receive_bytes(self, receivable_byte_num, flags):
        msg_bytes = bytearray(1)
        msg_byte_num = self._socket.recv_into(msg_bytes, 1, flags=socket.MSG_PEEK | socket.MSG_TRUNC)

        msg_bytes, client_address = self._socket.recvfrom(msg_byte_num, flags)

        if self._client_address is None:
            self._client_address, self._client_port = client_address[0:2]
        elif client_address[0:2] != (self._client_address, self._client_port):
            raise NotImplementedError()

        return msg_bytes

    def close(self):
        super(L4ServerUDP, self).close()

        self._client_address = None

    def close_client(self):
        pass


@attr.s
class L7TransferBase(object):
    address = attr.ib(validator=attr.validators.instance_of(six.string_types))
    port = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of(int)))
    timeout = attr.ib(
        default=None,
        converter=attr.converters.optional(float),
        validator=attr.validators.optional(attr.validators.instance_of(float))
    )
    ip = attr.ib(default=None, validator=attr.validators.optional(attr.validators.instance_of((
        six.string_types, ipaddress.IPv4Address, ipaddress.IPv6Address
    ))))
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

    def receive_line(self, max_line_length=None):
        return self.l4_transfer.receive_line(max_line_length)

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
