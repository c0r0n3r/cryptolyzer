#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64

from cryptography.hazmat.backends import default_backend as cryptography_default_backend
from cryptography.hazmat.primitives import hashes as cryptography_hashes


def base64_encode(byte_array):
    return str(base64.b64encode(byte_array), 'ascii')


def bytes_to_colon_separated_hex(byte_array):
    return ':'.join(['{:02X}'.format(x) for x in byte_array])


def get_hash(data, hash_algo):
    digest = cryptography_hashes.Hash(hash_algo(), backend=cryptography_default_backend())
    digest.update(data)

    return digest.finalize()
