# SPDX-License-Identifier: MPL-2.0

import math
import secrets

import codecs
import collections
import attr

from Crypto.Math.Primality import PROBABLY_PRIME, test_probable_prime

from cryptodatahub.common.algorithm import KeyExchange
from cryptodatahub.common.grade import AttackNamed
from cryptodatahub.common.key import convert_public_key_size, PublicKeySize
from cryptodatahub.common.parameter import (
    DHParameterNumbers,
    DHParamWellKnown,
    ECParameterForm,
    ECParamWellKnown,
)

from cryptoparser.common.base import Vector, VectorParamNumeric, Serializable
from cryptoparser.common.parse import ParserBinary
from cryptoparser.tls.extension import TlsNamedCurveFactory
from cryptoparser.tls.subprotocol import TlsECCurveType


@attr.s
class DHPublicNumbers:
    y = attr.ib(  # pylint: disable=invalid-name
        validator=attr.validators.instance_of(int),
        metadata={'human_readable_name': 'y'},
    )
    parameter_numbers = attr.ib(validator=attr.validators.instance_of(DHParameterNumbers))


@attr.s
class DHPublicKey:
    public_numbers = attr.ib(validator=attr.validators.instance_of(DHPublicNumbers))
    key_size = attr.ib(validator=attr.validators.instance_of(int))


class TlsDHParamVector(Vector):  # pylint: disable=too-many-ancestors
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=1, max_byte_num=2 ** 16 - 1)


def bytes_to_int(bytes_value):
    return int.from_bytes(bytes_value, byteorder='big')


def int_to_bytes(int_value, size):
    hex_value = f'{int_value:x}'
    str_value = ('0' * ((size * 2) - len(hex_value))) + hex_value

    return bytearray(codecs.decode(str_value, 'hex'))


def get_dh_public_key_from_bytes(p_bytes, g_bytes, y_bytes):
    parameter_numbers = DHParameterNumbers(bytes_to_int(p_bytes), bytes_to_int(g_bytes))
    public_numbers = DHPublicNumbers(bytes_to_int(y_bytes), parameter_numbers)

    return DHPublicKey(public_numbers, len(bytearray(p_bytes).lstrip(b'\x00')) * 8)


def get_dh_ephemeral_key_forged(prime):
    return secrets.randbelow(prime - 3) + 2


def get_ecdh_ephemeral_key_forged(key_parameter, add_point_format_octet=True):
    """Return a forged ECDH ephemeral public key for ``key_parameter``.

    Only the uncompressed point format (SEC1 / X9.62) is supported for
    Weierstrass curves; a Montgomery curve always uses raw key bytes, as X25519
    and X448 do (RFC 7748), because only the u coordinate is transmitted.

    :param add_point_format_octet: When True, the returned bytes for a
        Weierstrass curve include the leading 0x04 point-format octet that
        marks an uncompressed point. A Montgomery curve is unaffected.
    """
    if not isinstance(key_parameter, ECParamWellKnown):
        raise NotImplementedError(key_parameter)

    key_size_in_bytes = int(math.ceil(key_parameter.value.field_size / 8))

    if key_parameter.value.parameter_form == ECParameterForm.MONTGOMERY:
        return key_size_in_bytes * b'\xff'

    parts = []
    if add_point_format_octet:
        parts.append(b'\x04')
    parts.extend([
        int_to_bytes(key_parameter.value.parameter_numbers.x, key_size_in_bytes),
        int_to_bytes(key_parameter.value.parameter_numbers.y, key_size_in_bytes),
    ])
    return bytearray().join(parts)


def parse_tls_dh_params(param_bytes):
    parser = ParserBinary(param_bytes)

    parser.parse_parsable('p', TlsDHParamVector)
    parser.parse_parsable('g', TlsDHParamVector)
    parser.parse_parsable('y', TlsDHParamVector)

    return get_dh_public_key_from_bytes(parser['p'], parser['g'], parser['y'])


def parse_ecdh_params(param_bytes):
    parser = ParserBinary(param_bytes)

    parser.parse_numeric('curve_type', 1, TlsECCurveType)

    if parser['curve_type'] != TlsECCurveType.NAMED_CURVE:
        raise NotImplementedError(parser['curve_type'])

    parser.parse_parsable('named_curve', TlsNamedCurveFactory)

    parser.parse_numeric('public_key_length', 1)
    parser.parse_raw('public_key', parser['public_key_length'])

    return parser['named_curve'], parser['public_key']


@attr.s
class DHParameter(Serializable):
    parameter_numbers: DHParameterNumbers = attr.ib(
        validator=attr.validators.instance_of(DHParameterNumbers),
        metadata={'human_friendly': False},
    )
    key_size: PublicKeySize = attr.ib(
        converter=convert_public_key_size(KeyExchange.DHE),
        validator=attr.validators.instance_of(PublicKeySize)
    )
    well_known = attr.ib(init=False, validator=attr.validators.in_(DHParamWellKnown))
    prime = attr.ib(init=False, validator=attr.validators.instance_of(bool))
    safe_prime = attr.ib(init=False, validator=attr.validators.instance_of(bool))

    @staticmethod
    def _is_probable_prime(candidate):
        return test_probable_prime(candidate) == PROBABLY_PRIME

    def _is_prime(self):
        return self._is_probable_prime(self.parameter_numbers.p)

    def _is_safe_prime(self):
        return self._is_probable_prime((self.parameter_numbers.p - 1) // 2)

    def _check_prime(self):
        self.prime = self._is_prime()
        self.safe_prime = self.prime and self._is_safe_prime()

    def __attrs_post_init__(self):
        for well_know_public_number in DHParamWellKnown:
            if self.parameter_numbers == well_know_public_number.value.parameter_numbers:
                self.well_known = well_know_public_number
                self.prime = True
                self.safe_prime = not any(
                    vulnerability.named == AttackNamed.NON_SAFE_PRIME
                    for vulnerability in well_know_public_number.value.vulnerabilities
                )
                break
        else:
            self.well_known = None
            self._check_prime()

    def _asdict(self):
        result = attr.asdict(self, recurse=False, dict_factory=collections.OrderedDict)
        if self.well_known:
            result['parameter_numbers'] = None

        return result
