#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections
import unittest
import six

from crypton.common.exception import NotEnoughData, InvalidValue
from crypton.tls.extension import TlsExtensionUnparsed, TlsExtensionParsed
from crypton.tls.version import TlsVersion, TlsProtocolVersionFinal, TlsProtocolVersionDraft

from crypton.tls.extension import TlsExtensionServerName
from crypton.tls.extension import TlsExtensionECPointFormats, TlsECPointFormat
from crypton.tls.extension import TlsExtensionEllipticCurves, TlsNamedCurve
from crypton.tls.extension import TlsExtensionSupportedVersions


class TestExtensionUnparsed(unittest.TestCase):

    def test_error(self):
        extension_missing_data_dict = collections.OrderedDict([
            ('extension_type', b'\xff\x01'),
            ('extension_length', b'\x00\x01'),
        ])
        extension_missing_data_bytes = b''.join(extension_missing_data_dict.values())
        with self.assertRaises(NotEnoughData) as context_manager:
            # pylint: disable=expression-not-assigned
            TlsExtensionUnparsed.parse_exact_bytes(extension_missing_data_bytes)
        self.assertEqual(context_manager.exception.bytes_needed, 5)

    def test_parse_and_compose(self):
        extension_minimal_dict = collections.OrderedDict([
            ('extension_type', b'\xff\x01'),
            ('extension_length', b'\x00\x00'),
        ])
        extension_minimal_bytes = b''.join(extension_minimal_dict.values())

        extension_minimal = TlsExtensionUnparsed.parse_exact_bytes(extension_minimal_bytes)
        self.assertEqual(extension_minimal.compose(), extension_minimal_bytes)


        extension_with_data_dict = collections.OrderedDict([
            ('extension_type', b'\xff\x01'),
            ('extension_length', b'\x00\x04'),
            ('extension_data', b'\xde\xad\xbe\xaf'),
        ])
        extension_with_data_bytes = b''.join(extension_with_data_dict.values())

        extension_with_data = TlsExtensionUnparsed.parse_exact_bytes(extension_with_data_bytes)
        self.assertEqual(extension_with_data.compose(), extension_with_data_bytes)


class ExtensionInvalidType(TlsExtensionParsed):
    @classmethod
    def get_extension_type(cls):
        return 0xffff

    @classmethod
    def _parse(cls, parsable_bytes):
        parser = super(ExtensionInvalidType, cls)._parse_header(parsable_bytes)

        return ExtensionInvalidType(), parser.parsed_byte_num


class TestExtensionParsed(unittest.TestCase):
    def test_error(self):
        extension_invalid_type_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x00'),
            ('extension_length', b'\x00\x00'),
        ])
        extension_invalid_type_bytes = b''.join(extension_invalid_type_dict.values())

        with self.assertRaises(InvalidValue) as context_manager:
            # pylint: disable=expression-not-assigned
            ExtensionInvalidType.parse_exact_bytes(extension_invalid_type_bytes)
        self.assertEqual(context_manager.exception.value, 0x0000)


class TestExtensionHostname(unittest.TestCase):
    def test_parse(self):
        extension_hostname_empty_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x00'),
            ('extension_length', b'\x00\x00'),
        ])
        extension_hostname_empty_bytes = b''.join(extension_hostname_empty_dict.values())

        extension_hostname_empty = TlsExtensionServerName.parse_exact_bytes(extension_hostname_empty_bytes)
        self.assertEqual(extension_hostname_empty.host_name, '')
        self.assertEqual(extension_hostname_empty.compose(), extension_hostname_empty_bytes)

        extension_hostname_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x00'),
            ('extension_length', b'\x00\x14'),
            ('name_list_length', b'\x00\x12'),
            ('name_type', b'\x00'),
            ('name_length', b'\x00\x0f'),
            ('name', b'\x77\x77\x77\x2e\x65\x78\x61\x6d\x70\x6c\x65\x2e\x63\x6f\x6d')
        ])
        extension_hostname_bytes = b''.join(extension_hostname_dict.values())

        extension_hostname = TlsExtensionServerName.parse_exact_bytes(extension_hostname_bytes)
        self.assertEqual(extension_hostname.host_name, 'www.example.com')
        self.assertEqual(extension_hostname.compose(), extension_hostname_bytes)

        extension_hostname_internationalized_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x00'),
            ('extension_length', b'\x00\x1e'),
            ('name_list_length', b'\x00\x1c'),
            ('name_type', b'\x00'),
            ('name_length', b'\x00\x19'),
            ('name', b'\x78\x6e\x2d\x2d\x73\x6c\x61\x6e\x64\x2d\x79\x73\x61\x2e\x69\x63\x6f\x6d\x2e\x6d\x75\x73\x65\x75\x6d')
        ])
        extension_hostname_internationalized_bytes = b''.join(extension_hostname_internationalized_dict.values())

        extension_hostname_internationalized = TlsExtensionServerName.parse_exact_bytes(extension_hostname_internationalized_bytes)
        self.assertEqual(extension_hostname_internationalized.host_name, 'ísland.icom.museum')
        self.assertEqual(extension_hostname_internationalized.compose(), extension_hostname_internationalized_bytes)


class TestExtensionECPointFormat(unittest.TestCase):
    def test_parse(self):
        extension_ec_point_formats_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x0b'),
            ('extension_length', b'\x00\x02'),
            ('ec_point_format_list_length', b'\x01'),
            ('ec_point_format_list', b'\x00'),
        ])
        extension_ec_point_formats_bytes = b''.join(extension_ec_point_formats_dict.values())

        extension_point_formats = TlsExtensionECPointFormats.parse_exact_bytes(extension_ec_point_formats_bytes)
        self.assertEqual(list(extension_point_formats.point_formats), [TlsECPointFormat.UNCOMPRESSED, ])
        self.assertEqual(extension_point_formats.compose(), extension_ec_point_formats_bytes)


class TestExtensionEllipticCurves(unittest.TestCase):
    def test_parse(self):
        extension_elliptic_curves_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x0a'),
            ('extension_length', b'\x00\x08'),
            ('elliptic_curve_list_length', b'\x00\x06'),
            ('elliptic_curve_list', b'\x00\x1d\x00\x17\x00\x18'),
        ])
        extension_elliptic_curves_bytes = b''.join(extension_elliptic_curves_dict.values())

        extension_elliptic_curves = TlsExtensionEllipticCurves.parse_exact_bytes(extension_elliptic_curves_bytes)
        self.assertEqual(
            list(extension_elliptic_curves.elliptic_curves),
            [
                TlsNamedCurve.X25519,
                TlsNamedCurve.SECP256R1,
                TlsNamedCurve.SECP384R1,
            ]
        )
        self.assertEqual(extension_elliptic_curves.compose(), extension_elliptic_curves_bytes)

class TestExtensionSupportedVersions(unittest.TestCase):
    def test_parse(self):
        extension_supported_versions_dict = collections.OrderedDict([
            ('extension_type', b'\x00\x2b'),
            ('extension_length', b'\x00\x07'),
            ('supported_version_list_length', b'\x06'),
            ('supported_version_list', b'\x03\x02\x03\x03\x7f\x18'),
        ])
        extension_supported_versions_bytes = b''.join(extension_supported_versions_dict.values())

        extension_supported_versions = TlsExtensionSupportedVersions.parse_exact_bytes(extension_supported_versions_bytes)
        self.assertEqual(
            list(extension_supported_versions.supported_versions),
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
                TlsProtocolVersionDraft(24),
            ]
        )
        self.assertEqual(extension_supported_versions.compose(), extension_supported_versions_bytes)

