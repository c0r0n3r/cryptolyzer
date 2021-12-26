# -*- coding: utf-8 -*-

import unittest
import attr

from cryptoparser.tls.extension import TlsNamedCurve

from cryptolyzer.common.dhparam import (
    DHParameter,
    DHParameterNumbers,
    DHPublicKey,
    DHPublicNumbers,
    WellKnownDHParams,
    parse_ecdh_params,
)


class TestParse(unittest.TestCase):
    @staticmethod
    def _generate_dh_param(parameter_numbers, reused, key_size):
        public_numbers = DHPublicNumbers(
            0x012345678abcdef,
            DHParameterNumbers(parameter_numbers.p, parameter_numbers.g, parameter_numbers.q),
        )
        public_key = DHPublicKey(public_numbers, key_size)

        return DHParameter(public_key, reused)

    def test_parse_dh_param(self):
        dh_parameter = self._generate_dh_param(
            WellKnownDHParams.RFC3526_2048_BIT_MODP_GROUP.value.dh_param_numbers, False, 2048
        )
        self.assertEqual(dh_parameter.well_known, WellKnownDHParams.RFC3526_2048_BIT_MODP_GROUP)
        self.assertEqual(
            attr.asdict(
                dh_parameter.well_known.value,
                filter=lambda attribute, value: attribute.name != 'dh_param_numbers'
            ),
            {'key_size': 2048, 'name': '2048-bit MODP Group', 'safe_prime': True, 'source': 'RFC3526'}
        )

    def test_all_well_known_dhparam(self):
        dh_params = [
            self._generate_dh_param(
                well_known_dh_param.value.dh_param_numbers, False, well_known_dh_param.value.key_size
            )
            for well_known_dh_param in WellKnownDHParams
        ]
        self.assertTrue(all(dh_param.well_known for dh_param in dh_params))

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
        self.assertEqual(public_key, point_data)
