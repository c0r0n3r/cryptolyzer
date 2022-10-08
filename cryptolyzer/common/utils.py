# -*- coding: utf-8 -*-

import ipaddress
import logging
import socket
import string
import sys

import six

from cryptolyzer import __setup__
from cryptolyzer.common.exception import NetworkError, NetworkErrorType


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


@six.add_metaclass(Singleton)
class LogSingleton(logging.Logger):
    def __init__(self):
        super(LogSingleton, self).__init__(__setup__.__name__)

        formatter = logging.Formatter(fmt='%(asctime)s %(message)s', datefmt='%Y-%m-%dT%H:%M:%S%z')

        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(60)
        handler.setFormatter(formatter)

        self.addHandler(handler)


def resolve_address(address, port, ip=None):
    if ip:
        try:
            family = socket.AF_INET if ipaddress.ip_address(six.text_type(ip)).version == 4 else socket.AF_INET6
        except ValueError as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_ADDRESS), e)

    try:
        addresses = [
            (addrinfo[0], addrinfo[4][0])
            for addrinfo in socket.getaddrinfo(address, port, 0, socket.SOCK_STREAM)
        ]
    except socket.gaierror as e:
        six.raise_from(NetworkError(NetworkErrorType.NO_ADDRESS), e)
    if not addresses:
        raise NetworkError(NetworkErrorType.NO_ADDRESS)

    if not ip:
        family = addresses[0][0]
        ip = addresses[0][1]

    return family, ip


def buffer_is_plain_text(buffer):
    try:
        return all(c in string.printable for c in buffer.decode('utf-8'))
    except UnicodeDecodeError:
        return False


def buffer_flush(buffer, byte_num):
    if byte_num is None:
        byte_num = len(buffer)

    return buffer[byte_num:]
