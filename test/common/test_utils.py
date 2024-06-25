# -*- coding: utf-8 -*-

import os

import unittest
import socket

from test.common.classes import (
    TestGradeableComplex,
    TestGradeableSimple,
    TestGradeableVulnerabilities,
    TestGradeableVulnerabilitiesName,
    TestGradeableVulnerabilitiesLongName,
)

import colorama

from cryptodatahub.common.grade import AttackNamed, AttackType, Grade, Vulnerability

from cryptodatahub.tls.algorithm import (
    TlsCipherSuite,
    TlsNamedCurve,
    TlsSignatureAndHashAlgorithm,
    TlsTokenBindingParamater,
    TlsVersion,
)

from cryptoparser.common.utils import bytes_to_hex_string

from cryptoparser.tls.extension import (
    TlsExtensionRecordSizeLimit,
    TlsExtensionTokenBinding,
    TlsExtensionType,
    TlsExtensionUnparsed,
    TlsTokenBindingProtocolVersion,
)
from cryptoparser.tls.grease import TlsInvalidTypeTwoByte
from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.version import TlsProtocolVersion

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.utils import HandshakeToCapabilitiesTls, SerializableTextEncoderHighlighted, resolve_address

from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloKeyExchangeECDHx,
    TlsHandshakeClientHelloSpecalization,
)


class TestSerializableTextEncoderHighlighted(unittest.TestCase):
    _VULNERABILITY_DEPRECATED = Vulnerability(None, Grade.DEPRECATED, None)
    _VULNERABILITY_WEAK = Vulnerability(AttackType.MITM, Grade.WEAK, None)
    _VULNERABILITY_INSECURE = Vulnerability(AttackType.MITM, Grade.INSECURE, None)
    _VULNERABILITY_SECURE = Vulnerability(AttackType.MITM, Grade.SECURE, None)
    _VULNERABILITY_NAMED = Vulnerability(AttackType.DOS_ATTACK, Grade.WEAK, AttackNamed.DHEAT_ATTACK)

    @staticmethod
    def _colorize(text, color):
        foreground_color = colorama.Style.RESET_ALL if color is None else getattr(colorama.Fore, color.upper())
        return foreground_color + text + colorama.Style.RESET_ALL

    @staticmethod
    def _highlight(text):
        return colorama.Style.BRIGHT + text + colorama.Style.RESET_ALL

    def test_non_greadable(self):
        self.assertEqual(SerializableTextEncoderHighlighted()('value', 0), (False, 'value'))

    def test_not_greaded(self):
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableComplex.from_gradeables(None), 0),
            (False, self._colorize('TestGradeableComplex', None))
        )

        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableComplex.from_gradeables([None]), 0),
            (False, self._colorize('TestGradeableComplex', None))
        )

        self.assertEqual(
            SerializableTextEncoderHighlighted()(
                TestGradeableComplex.from_gradeables([
                    TestGradeableComplex.from_gradeables(None)
                ]), 0
            ),
            (False, self._colorize('TestGradeableComplex', None))
        )

    def test_greadable_simple(self):
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableSimple(Grade.SECURE), 0),
            (False, self._colorize('TestGradeableSimple', 'green'))
        )
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableSimple(Grade.DEPRECATED), 0),
            (False, self._colorize('TestGradeableSimple', 'yellow') + ' (deprecated)')
        )
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableSimple(Grade.WEAK), 0),
            (False, self._colorize('TestGradeableSimple', 'yellow') + ' (weak)')
        )
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableSimple(Grade.INSECURE), 0),
            (False, self._colorize('TestGradeableSimple', 'red'))
        )

    def test_greadable_vulnerabilities(self):
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableVulnerabilities([]), 0),
            (False, self._colorize('TestGradeable', 'green'))
        )
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableVulnerabilities([
                self._VULNERABILITY_WEAK
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeable', 'yellow'),
                ('* TestGradeableName is ' + self._colorize('weak', 'yellow') + ', due to MITM attack'),
            ]))
        )
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableVulnerabilities([
                self._VULNERABILITY_INSECURE
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeable', 'red'),
                ('* TestGradeableName is ' + self._colorize('insecure', 'red') + ', due to MITM attack'),
            ]))
        )

    def test_greadable_vulnerabilities_sorted_by_grade(self):
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableVulnerabilities([
                self._VULNERABILITY_WEAK,
                self._VULNERABILITY_INSECURE,
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeable', 'red'),
                '* TestGradeableName is',
                ('    ' + self._colorize('insecure', 'red') + ', due to MITM attack'),
                ('    ' + self._colorize('weak', 'yellow') + ', due to MITM attack'),
            ]))
        )

    def test_greadable_vulnerabilities_named_vulnerability(self):
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableVulnerabilities([
                self._VULNERABILITY_NAMED
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeable', 'yellow'),
                (
                    '* TestGradeableName is ' +
                    self._colorize('weak', 'yellow') +
                    ', due to (D)DoS attack, called D(HE)at attack'
                ),
            ]))
        )

    def test_greadable_vulnerabilities_no_name(self):
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableVulnerabilitiesName([
                self._VULNERABILITY_DEPRECATED
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeableName', 'yellow'),
                (
                    '* TestGradeableName ' +
                    self._highlight('name') +
                    ' is ' +
                    self._colorize('deprecated', 'yellow')
                ),
            ]))
        )

    def test_greadable_vulnerabilities_name(self):
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableVulnerabilitiesName([
                self._VULNERABILITY_WEAK
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeableName', 'yellow'),
                (
                    '* TestGradeableName ' +
                    self._highlight('name') +
                    ' is ' +
                    self._colorize('weak', 'yellow') +
                    ', due to MITM attack'
                ),
            ]))
        )

    def test_greadable_vulnerabilities_long_name(self):
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableVulnerabilitiesLongName([
                self._VULNERABILITY_WEAK
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeableLongName', 'yellow'),
                (
                    '* TestGradeableLongName ' +
                    self._highlight('long name (name)') +
                    ' is ' +
                    self._colorize('weak', 'yellow') +
                    ', due to MITM attack'
                ),
            ]))
        )

    def test_greadable_multiple(self):
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableComplex.from_gradeables([]), 0),
            (False, self._colorize('TestGradeableComplex', 'green'))
        )

        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableComplex.from_gradeables([
                TestGradeableVulnerabilities([self._VULNERABILITY_WEAK]),
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeableComplex', 'yellow'),
                (
                    '* TestGradeableName is ' +
                    self._colorize('weak', 'yellow') +
                    ', due to MITM attack'
                ),
            ]))

        )

        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableComplex.from_gradeables([
                TestGradeableVulnerabilities([]),
                TestGradeableVulnerabilities([self._VULNERABILITY_WEAK]),
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeableComplex', 'yellow'),
                (
                    '* TestGradeableName is ' +
                    self._colorize('weak', 'yellow') +
                    ', due to MITM attack'
                ),
            ]))

        )

        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableComplex.from_gradeables([
                TestGradeableComplex.from_gradeables([TestGradeableVulnerabilities([self._VULNERABILITY_WEAK])]),
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeableComplex', 'yellow'),
                (
                    '* TestGradeableName is ' +
                    self._colorize('weak', 'yellow') +
                    ', due to MITM attack'
                ),
            ]))

        )

    def test_greadable_multiple_sorted_by_grade(self):
        self.assertEqual(
            SerializableTextEncoderHighlighted()(TestGradeableComplex.from_gradeables([
                TestGradeableVulnerabilities([self._VULNERABILITY_WEAK]),
                TestGradeableVulnerabilities([self._VULNERABILITY_INSECURE]),
            ]), 0),
            (False, os.linesep.join([
                self._colorize('TestGradeableComplex', 'red'),
                (
                    '* TestGradeableName is ' +
                    self._colorize('insecure', 'red') +
                    ', due to MITM attack'
                ),
                (
                    '* TestGradeableName is ' +
                    self._colorize('weak', 'yellow') +
                    ', due to MITM attack'
                ),
            ]))

        )


class TestResolveAddress(unittest.TestCase):
    def test_error_wrong_ip(self):
        with self.assertRaises(NetworkError) as context_manager:
            resolve_address('one.one.one.one', 0, 'not.an.ip')
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    def test_error_unresolvable_address(self):
        with self.assertRaises(NetworkError) as context_manager:
            resolve_address('unresolvable.address', 0)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_ADDRESS)

    def test_resolve(self):
        family, ip = resolve_address('one.one.one.one', 0, '1.1.1.1')
        self.assertEqual(family, socket.AF_INET)
        self.assertEqual(ip, '1.1.1.1')

        family, ip = resolve_address('one.one.one.one', 0, '2606:4700:4700::1111')
        self.assertEqual(family, socket.AF_INET6)


class TestHandshakeToCapabilitiesTls(unittest.TestCase):
    @staticmethod
    def _get_tshark_json_bytes(parsable):
        json_string = ''.join([
            '[{"_source": {"layers": {"tcp": {"tcp.payload": "',
            bytes_to_hex_string(parsable.compose()),
            '"}}}}]'
        ])

        return json_string

    def test_tls1_2(self):
        client_hello = TlsHandshakeClientHelloAnyAlgorithm([TlsProtocolVersion(TlsVersion.TLS1_2), ], 'hostname')
        tshark_json = self._get_tshark_json_bytes(TlsRecord(client_hello.compose()))
        tls_json_object = HandshakeToCapabilitiesTls.from_tshark(tshark_json).to_capabilities()

        self.assertEqual(list(client_hello.cipher_suites), tls_json_object.cipher_suites)
        self.assertEqual(
            list(map(lambda extension: extension.extension_type, client_hello.extensions)),
            tls_json_object.extension_types
        )
        self.assertFalse(tls_json_object.grease.cipher_suites)
        self.assertFalse(tls_json_object.grease.extension_types)
        self.assertEqual(tls_json_object.grease.extensions, [])

    def test_tls1_3(self):
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(TlsProtocolVersion(TlsVersion.TLS1_3), 'hostname')
        tshark_json = self._get_tshark_json_bytes(TlsRecord(client_hello.compose()))
        tls_json_object = HandshakeToCapabilitiesTls.from_tshark(tshark_json).to_capabilities()

        self.assertEqual(list(client_hello.cipher_suites), tls_json_object.cipher_suites)
        self.assertEqual(
            list(map(lambda extension: extension.extension_type, client_hello.extensions)),
            tls_json_object.extension_types
        )
        self.assertFalse(tls_json_object.grease.cipher_suites)
        self.assertFalse(tls_json_object.grease.extension_types)
        self.assertEqual(tls_json_object.grease.extensions, [])

    def test_tls_extensions(self):
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(TlsProtocolVersion(TlsVersion.TLS1_2), 'hostname')
        client_hello.extensions.append(TlsExtensionRecordSizeLimit(5))
        client_hello.extensions.append(TlsExtensionTokenBinding(
            TlsTokenBindingProtocolVersion(1, 2), [TlsTokenBindingParamater.RSA2048_PSS, ]
        ))

        tshark_json = self._get_tshark_json_bytes(TlsRecord(client_hello.compose()))
        tls_json_object = HandshakeToCapabilitiesTls.from_tshark(tshark_json).to_capabilities()

        self.assertEqual(list(client_hello.cipher_suites), tls_json_object.cipher_suites)
        self.assertEqual(
            list(map(lambda extension: extension.extension_type, client_hello.extensions)),
            tls_json_object.extension_types
        )
        self.assertFalse(tls_json_object.grease.cipher_suites)
        self.assertFalse(tls_json_object.grease.extension_types)
        self.assertEqual(tls_json_object.grease.extensions, [])

    def test_tls_grease(self):
        client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(TlsProtocolVersion(TlsVersion.TLS1_2), 'hostname')
        client_hello.cipher_suites.append(TlsInvalidTypeTwoByte.from_random())
        client_hello.extensions.append(TlsExtensionUnparsed(TlsInvalidTypeTwoByte.from_random(), b''))

        tshark_json = self._get_tshark_json_bytes(TlsRecord(client_hello.compose()))
        tls_json_object = HandshakeToCapabilitiesTls.from_tshark(tshark_json).to_capabilities()

        self.assertTrue(tls_json_object.grease.cipher_suites)
        self.assertTrue(tls_json_object.grease.extension_types)
        self.assertEqual(tls_json_object.grease.extensions, [])

        grease_value = TlsInvalidTypeTwoByte.from_random()
        client_hello = TlsHandshakeClientHelloSpecalization(
            hostname='hostname',
            protocol_versions=[TlsProtocolVersion(TlsVersion.TLS1_2), ],
            cipher_suites=[TlsCipherSuite.TLS_RSA_WITH_AES_128_CBC_SHA, ],
            named_curves=[TlsNamedCurve.X25519, grease_value, ],
            signature_algorithms=[TlsSignatureAndHashAlgorithm.RSA_SHA1, grease_value],
            extensions=[
            ]
        )

        tshark_json = self._get_tshark_json_bytes(TlsRecord(client_hello.compose()))
        tls_json_object = HandshakeToCapabilitiesTls.from_tshark(tshark_json).to_capabilities()

        self.assertFalse(tls_json_object.grease.cipher_suites)
        self.assertFalse(tls_json_object.grease.extension_types)
        self.assertEqual(tls_json_object.grease.extensions, [
            TlsExtensionType.SIGNATURE_ALGORITHMS,
            TlsExtensionType.SUPPORTED_GROUPS,
        ])
