# -*- coding: utf-8 -*-

import abc
import socket
import string
import six

from cryptoparser.common.exception import NotEnoughData
from cryptoparser.common.utils import get_leaf_classes

from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.utils import resolve_address


@six.add_metaclass(abc.ABCMeta)
class L4TransferBase(object):
    def __init__(self, address, port, timeout=None, ip=None):
        self._address = address
        self._port = port
        self._socket = None
        self._timeout = self.get_default_timeout() if timeout is None else timeout
        self._buffer = bytearray()

        self._family, self._ip = resolve_address(address, port, ip)

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
            return all([c in string.printable for c in self._buffer.decode('utf-8')])
        except UnicodeDecodeError:
            return False

    def init_connection(self, _socket=None):
        self.close()

        if _socket:
            self._socket = _socket
            self._ip, self._port = _socket.getsockname()[0:2]
        else:
            self._init_connection()

    @abc.abstractmethod
    def _init_connection(self):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_timeout(cls):
        raise NotImplementedError()


class L4TransferTCP(L4TransferBase):
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

    @abc.abstractmethod
    def _init_connection(self):
        raise NotImplementedError()


class L4ClientTCP(L4TransferTCP):
    def _init_connection(self):
        try:
            self._socket = socket.create_connection((self._ip, self._port), self._timeout)
        except BaseException as e:  # pylint: disable=broad-except
            if e.__class__.__name__ == 'ConnectionRefusedError' or isinstance(e, (socket.error, socket.timeout)):
                raise NetworkError(NetworkErrorType.NO_CONNECTION)

            raise e

    @classmethod
    def get_default_timeout(cls):
        return 5


class L4ServerTCP(L4TransferTCP):
    def __init__(self, address, port, timeout=None, ip=None, backlog=1):  # pylint: disable=too-many-arguments
        super(L4ServerTCP, self).__init__(address, port, timeout, ip)

        self._server_socket = None
        self.backlog = backlog

    def __del__(self):
        if self._server_socket is not None:
            self._server_socket.close()

    def _init_connection(self):
        try:
            self._server_socket = socket.socket(self._family, socket.SOCK_STREAM)
            self._server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._server_socket.settimeout(self._timeout)
            self._server_socket.bind((self._ip, self._port))
            self._server_socket.listen(self.backlog)
        except KeyboardInterrupt:
            raise NetworkError(NetworkErrorType.NO_RESPONSE)
        except OverflowError:
            raise NetworkError(NetworkErrorType.NO_ADDRESS)
        except (OSError, socket.error):
            raise NetworkError(NetworkErrorType.NO_CONNECTION)

    def accept(self):
        self._socket, _ = self._server_socket.accept()

    @property
    def port(self):
        if self._port:
            return self._port

        if not self._server_socket:
            raise NotImplementedError()

        return self._server_socket.getsockname()[1]

    @classmethod
    def get_default_timeout(cls):
        return None


class L7TransferBase(object):
    def __init__(self, address, port=None, timeout=None, ip=None):
        self._address = address
        self._port = self.get_default_port() if port is None else port
        self._family, self._ip = resolve_address(address, self._port, ip)
        self._timeout = timeout

        self._l4_transfer = None

    @property
    def address(self):
        return self._address

    @property
    def ip(self):
        return self._ip

    @property
    def port(self):
        if self._port == 0:
            return self._l4_transfer.port

        return self._port

    def send(self, sendable_bytes):
        return self._l4_transfer.send(sendable_bytes)

    def receive(self, receivable_byte_num):
        self._l4_transfer.receive(receivable_byte_num)

    def flush_buffer(self, byte_num=None):
        self._l4_transfer.flush_buffer(byte_num)

    @property
    def buffer(self):
        return self._l4_transfer.buffer

    @property
    def buffer_is_plain_text(self):
        return self._l4_transfer.buffer_is_plain_text

    @classmethod
    def get_supported_schemes(cls):
        return {leaf_cls.get_scheme() for leaf_cls in get_leaf_classes(cls)}

    @classmethod
    def from_scheme(cls, scheme, address, port=None, timeout=None, ip=None):  # pylint: disable=too-many-arguments
        for transfer_class in get_leaf_classes(cls):
            if transfer_class.get_scheme() == scheme:
                port = transfer_class.get_default_port() if port is None else port
                return transfer_class(address, port, timeout, ip)

        raise ValueError()

    @classmethod
    @abc.abstractmethod
    def get_scheme(cls):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_default_port(cls):
        raise NotImplementedError()

    @abc.abstractmethod
    def _init_connection(self):
        raise NotImplementedError()

    def init_connection(self):
        try:
            self._init_connection()
        except SecurityError:
            self._close_connection()
            raise

    def _close_connection(self):
        if self._l4_transfer:
            self._l4_transfer.close()
            self._l4_transfer = None
