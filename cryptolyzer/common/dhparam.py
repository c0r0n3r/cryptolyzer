#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptography.hazmat.backends import default_backend as cryptography_default_backend
import cryptography.exceptions
import cryptography.hazmat.primitives.asymmetric.ec as cryptography_ec
import cryptography.hazmat.primitives.asymmetric.dh as cryptography_dh
import cryptography.hazmat.primitives.asymmetric.x25519 as cryptography_x25519

from cryptoparser.common.base import Vector, VectorParamNumeric, Serializable
from cryptoparser.common.parse import ParserBinary
from cryptoparser.tls.extension import TlsNamedCurve, TlsNamedCurveFactory
from cryptoparser.tls.subprotocol import TlsECCurveType


class TlsDHParamVector(Vector):  # pylint: disable=too-many-ancestors
    @classmethod
    def get_param(cls):
        return VectorParamNumeric(item_size=1, min_byte_num=1, max_byte_num=2 ** 16 - 1)


def parse_dh_params(param_bytes):
    parser = ParserBinary(param_bytes)

    parser.parse_parsable('p', TlsDHParamVector)
    parser.parse_parsable('g', TlsDHParamVector)
    parser.parse_parsable('y', TlsDHParamVector)

    p = int(''.join(map('{:02x}'.format, parser['p'])), 16)  # pylint: disable=invalid-name
    g = int(''.join(map('{:02x}'.format, parser['g'])), 16)  # pylint: disable=invalid-name
    y = int(''.join(map('{:02x}'.format, parser['y'])), 16)  # pylint: disable=invalid-name

    parameter_numbers = cryptography_dh.DHParameterNumbers(p, g)
    public_numbers = cryptography_dh.DHPublicNumbers(y, parameter_numbers)

    return public_numbers.public_key(cryptography_default_backend())


def parse_ecdh_params(param_bytes):
    parser = ParserBinary(param_bytes)

    parser.parse_numeric('curve_type', 1, TlsECCurveType)

    if parser['curve_type'] != TlsECCurveType.NAMED_CURVE:
        raise NotImplementedError(parser['curve_type'])

    parser.parse_parsable('named_curve', TlsNamedCurveFactory)
    named_curve = parser['named_curve']

    parser.parse_numeric('point_length', 1)
    parser.parse_bytes('point', parser['point_length'])

    if named_curve == TlsNamedCurve.X25519:
        try:
            public_key = cryptography_x25519.X25519PublicKey.from_public_bytes(bytes(parser['point']))
        except cryptography.exceptions.UnsupportedAlgorithm:
            raise NotImplementedError(named_curve)
    else:
        try:
            cryptography_curve = getattr(cryptography_ec, named_curve.name)()
        except AttributeError:
            raise NotImplementedError(named_curve)

        public_key = cryptography_ec.EllipticCurvePublicKey.from_encoded_point(
            cryptography_curve,
            bytes(parser['point'])
        )

    return parser['named_curve'], public_key


class DHParameter(Serializable):
    def __init__(self, public_key, reused):
        self.public_key = public_key
        self.reused = reused

        codes = cryptography_default_backend()._ffi.new("int[]", 1)  # pylint: disable=protected-access
        dh_check_func = cryptography_default_backend()._lib.Cryptography_DH_check  # pylint: disable=protected-access
        if dh_check_func(public_key._dh_cdata, codes) == 1:  # pylint: disable=protected-access
            self.prime = (codes[0] & 0x01) == 0  # DH_CHECK_P_NOT_PRIME
            if self.prime:
                self.safe_prime = (codes[0] & 0x02) == 0  # DH_CHECK_P_NOT_SAFE_PRIME
            else:
                self.safe_prime = False
        else:  # pragma: no cover
            self.prime = None
            self.safe_prime = None

    @property
    def key_size(self):
        return self.public_key.key_size

    def _asdict(self):
        result = {'key_size': self.key_size}
        result.update({
            key: value
            for key, value in self.__dict__.items()
            if key != 'public_key'
        })
        return result
