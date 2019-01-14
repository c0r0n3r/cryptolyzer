#!/usr/bin/env python
# -*- coding: utf-8 -*-

import cryptography.exceptions  # pylint: disable=import-error
import cryptography.hazmat.primitives.asymmetric.ec as cryptography_ec  # pylint: disable=import-error
import cryptography.hazmat.primitives.asymmetric.x25519 as cryptography_x25519  # pylint: disable=import-error

from cryptoparser.common.parse import ParserBinary
from cryptoparser.tls.extension import TlsNamedCurve, TlsNamedCurveFactory
from cryptoparser.tls.subprotocol import TlsECCurveType


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

    return public_key
