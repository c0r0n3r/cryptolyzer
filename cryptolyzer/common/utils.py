# -*- coding: utf-8 -*-

import struct


def bytes_to_colon_separated_hex(byte_array):
    return ':'.join(['{:02X}'.format(x) for x in struct.unpack(len(byte_array) * 'B', byte_array)])
