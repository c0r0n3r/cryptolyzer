# -*- coding: utf-8 -*-

import ipaddress
import socket
import six

from cryptolyzer.common.exception import NetworkError, NetworkErrorType


def bytes_to_colon_separated_hex(byte_array):
    return ':'.join(['{:02X}'.format(x) for x in six.iterbytes(byte_array)])


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
