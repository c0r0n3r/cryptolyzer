# -*- coding: utf-8 -*-

import math

import codecs
import collections
import six
import attr

from cryptodatahub.common.algorithm import KeyExchange, NamedGroup
from cryptodatahub.common.key import convert_public_key_size, PublicKeySize
from cryptodatahub.common.parameter import DHParameterNumbers, DHParamWellKnown

from cryptoparser.common.base import Vector, VectorParamNumeric, Serializable
from cryptoparser.common.parse import ParserBinary
from cryptoparser.tls.extension import TlsNamedCurveFactory
from cryptoparser.tls.subprotocol import TlsECCurveType

from cryptolyzer.common.curves import WellKnownECParams

from .prime import is_prime, prime_precheck


@attr.s
class DHPublicNumbers(object):
    y = attr.ib(  # pylint: disable=invalid-name
        validator=attr.validators.instance_of(six.integer_types),
        metadata={'human_readable_name': 'y'},
    )
    parameter_numbers = attr.ib(validator=attr.validators.instance_of(DHParameterNumbers))


@attr.s
class DHPublicKey(object):
    public_numbers = attr.ib(validator=attr.validators.instance_of(DHPublicNumbers))
    key_size = attr.ib(validator=attr.validators.instance_of(six.integer_types))


class TlsDHParamVector(Vector):  # pylint: disable=too-many-ancestors
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=1, max_byte_num=2 ** 16 - 1)


def bytes_to_int(bytes_value):
    return int(''.join(map('{:02x}'.format, bytes_value)), 16)


def int_to_bytes(int_value, size):
    hex_value = '%x' % int_value
    str_value = ('0' * ((size * 2) - len(hex_value))) + hex_value

    return bytearray(codecs.decode(str_value, 'hex'))


def get_dh_public_key_from_bytes(p_bytes, g_bytes, y_bytes):
    parameter_numbers = DHParameterNumbers(bytes_to_int(p_bytes), bytes_to_int(g_bytes))
    public_numbers = DHPublicNumbers(bytes_to_int(y_bytes), parameter_numbers)

    return DHPublicKey(public_numbers, len(bytearray(p_bytes).lstrip(b'\x00')) * 8)


def get_dh_ephemeral_key_forged(prime):
    return prime // 2 + 1


def get_ecdh_ephemeral_key_forged(named_group):
    key_size_in_bytes = int(math.ceil(named_group.value.size / 8))

    if named_group in [NamedGroup.CURVE25519, NamedGroup.CURVE448]:
        ephemeral_public_key_bytes = key_size_in_bytes * b'\xff'
    else:
        try:
            well_know_ec_param = WellKnownECParams.from_named_group(named_group)
        except AttributeError as e:
            six.raise_from(NotImplementedError(named_group), e)

        ephemeral_public_key_bytes = bytearray().join([
            b'\x04',  # uncompressed point format
            int_to_bytes(well_know_ec_param.value.parameter_numbers.x, key_size_in_bytes),
            int_to_bytes(well_know_ec_param.value.parameter_numbers.y, key_size_in_bytes),
        ])

    return ephemeral_public_key_bytes


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
    parameter_numbers = attr.ib(
        validator=attr.validators.instance_of(DHParameterNumbers),
        metadata={'human_friendly': False},
    )
    key_size = attr.ib(
        converter=convert_public_key_size(KeyExchange.DHE),
        validator=attr.validators.instance_of(PublicKeySize)
    )
    well_known = attr.ib(init=False, validator=attr.validators.in_(DHParamWellKnown))
    prime = attr.ib(init=False, validator=attr.validators.instance_of(bool))
    safe_prime = attr.ib(init=False, validator=attr.validators.instance_of(bool))

    def _check_prime(self):
        param_num_p = self.parameter_numbers.p
        param_num_g = self.parameter_numbers.g

        self.prime, self.safe_prime = prime_precheck(param_num_p, param_num_g)

        # If the number is not divisible by any of the small primes, then
        # move on to the full Miller-Rabin test.
        self.prime = is_prime(self.key_size.value, param_num_p)
        if self.prime:
            self.safe_prime = is_prime(self.key_size.value, param_num_p // 2)

    def __attrs_post_init__(self):
        for well_know_public_number in DHParamWellKnown:
            if self.parameter_numbers == well_know_public_number.value.parameter_numbers:
                self.well_known = well_know_public_number
                self.prime = True
                self.safe_prime = well_know_public_number.value.safe_prime
                break
        else:
            self.well_known = None
            self._check_prime()

    def _asdict(self):
        result = attr.asdict(self, recurse=False, dict_factory=collections.OrderedDict)
        if self.well_known:
            result['parameter_numbers'] = None

        return result
