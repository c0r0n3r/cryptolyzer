# -*- coding: utf-8 -*-

import unittest
import attr

import cryptography.hazmat.primitives.asymmetric.dh as cryptography_dh
from cryptography.hazmat.backends import default_backend as cryptography_default_backend
from cryptography.hazmat.primitives import serialization as cryptography_serialization

from cryptoparser.tls.extension import TlsNamedCurve

from cryptolyzer.common.dhparam import parse_ecdh_params, DHParameter, WellKnownDHParams
from cryptolyzer.common.exception import SecurityError, SecurityErrorType


class TestParse(unittest.TestCase):
    @staticmethod
    def _generate_dh_param(parameter_numbers, reused):
        public_numbers = cryptography_dh.DHPublicNumbers(
            0x012345678abcdef,
            cryptography_dh.DHParameterNumbers(parameter_numbers.p, parameter_numbers.g, parameter_numbers.q),
        )
        public_key = public_numbers.public_key(cryptography_default_backend())

        return DHParameter(public_key, reused)

    def test_parse_dh_param(self):
        dh_parameter = self._generate_dh_param(
            WellKnownDHParams.RFC3526_2048_BIT_MODP_GROUP.value.dh_param_numbers, False
        )
        self.assertEqual(dh_parameter.key_size, 2048)
        self.assertEqual(dh_parameter.well_known, WellKnownDHParams.RFC3526_2048_BIT_MODP_GROUP)
        self.assertEqual(
            attr.asdict(
                dh_parameter.well_known.value,
                filter=lambda attribute, value: attribute.name != 'dh_param_numbers'
            ),
            {"name": "2048-bit MODP Group", "source": "RFC3526"}
        )

    def test_all_well_known_dhparam(self):
        dh_params = [
            self._generate_dh_param(well_known_dh_param.value.dh_param_numbers, False)
            for well_known_dh_param in WellKnownDHParams
        ]
        self.assertTrue(all([dh_param.well_known for dh_param in dh_params]))

    def test_parse_ecdh_param_x25519(self):
        point_data = bytes(
            b'\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f' +
            b'\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f' +
            b''
        )
        param_bytes = bytes(
            b'\x03' +      # curve type: TlsECCurveType.NAMED_CURVE
            b'\x00\x1d' +  # named curve: TlsNamedCurve.X25519
            b'\x20' +      # point length: 32
            point_data +   # point data
            b''
        )

        try:
            supported_curve, public_key = parse_ecdh_params(param_bytes)
        except NotImplementedError as e:
            if (hasattr(cryptography_default_backend, 'x25519_supported') and
                    cryptography_default_backend.x25519_supported()):  # pylint: disable=no-member
                raise e
        else:
            self.assertEqual(supported_curve, TlsNamedCurve.X25519)
            public_key_in_der_format = public_key.public_bytes(
                encoding=cryptography_serialization.Encoding.Raw,
                format=cryptography_serialization.PublicFormat.Raw
            )
            self.assertEqual(public_key_in_der_format, point_data)

    def test_parse_ecdh_param_secp256r1(self):
        point_data = bytes(
            b'\x04\x85\xa2\x90\xb7\x4f\x33\xe7\xae\xae\x7a\x34\xf7\xa0\x40\xf8' +
            b'\xcb\x1b\x69\xac\x3f\x3f\xa7\x77\x25\xb4\x43\xc3\x90\x95\x56\x7c' +
            b'\x9a\x2d\xdb\x6e\x45\x83\x3a\x45\xe9\xb7\x3b\x80\xf5\xad\x8a\x3e' +
            b'\xa3\xae\xe2\x29\x9f\x0c\x4e\x10\xb9\x53\x59\xbe\xb1\xcd\x42\x96' +
            b'\xfb'
        )
        param_bytes = bytes(
            b'\x03' +      # curve type: TlsECCurveType.NAMED_CURVE
            b'\x00\x17' +  # named curve: TlsNamedCurve.SECP256R1
            b'\x41' +      # point length: 65
            point_data +   # point data
            b''
        )

        supported_curve, public_key = parse_ecdh_params(param_bytes)
        self.assertEqual(supported_curve, TlsNamedCurve.SECP256R1)
        public_key_in_der_format = public_key.public_bytes(
            encoding=cryptography_serialization.Encoding.X962,
            format=cryptography_serialization.PublicFormat.UncompressedPoint,
        )
        self.assertEqual(public_key_in_der_format, point_data)

    def test_parse_ecdh_param_invalid(self):
        param_bytes = bytes(
            b'\x03' +      # curve type: TlsECCurveType.NAMED_CURVE
            b'\x00\x17' +  # named curve: TlsNamedCurve.SECP256R1
            b'\x00' +      # point length: 0
            b''
        )

        with self.assertRaises(SecurityError) as context_manager:
            parse_ecdh_params(param_bytes)
        self.assertEqual(context_manager.exception.error, SecurityErrorType.UNPARSABLE_MESSAGE)
