# -*- coding: utf-8 -*-

import json
import pathlib

from test.common.classes import TestMainBase

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

from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloAnyAlgorithm,
    TlsHandshakeClientHelloKeyExchangeECDHx,
    TlsHandshakeClientHelloSpecalization,
    TlsHandshakeClientHelloStreamCipherRC4,
)

from tools.handshake_to_capabilities import main, HandshakeToCapabilitiesTls


class TestTlsClientBase(TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return main

    def setUp(self):
        self.script_path = pathlib.Path() / 'tools' / 'handshake_to_capabilities.py'


class TestMain(TestTlsClientBase):
    def test_argument_parsing(self):
        self._test_argument_help(self.script_path)

        self._test_argument_error(
            [self.script_path, '--protocol', 'unsupportedprotocol', '--format', 'tshark'],
            'usage: handshake_to_capabilities \\[-h\\] \\[--protocol {tls}\\] \\[--format \\{tshark\\}\\]'
        )

        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'unsuportedformat'],
            'usage: handshake_to_capabilities \\[-h\\] \\[--protocol {tls}\\] \\[--format \\{tshark\\}\\]'
        )

    def test_error_no_input_data(self):
        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'No input data',
            b''
        )

    def test_error_not_a_json(self):
        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Invalid JSON data',
            b'not a JSON'
        )

    def test_error_empty_json(self):
        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Empty JSON data',
            b'{}'
        )


class TestTShark(TestTlsClientBase):
    @staticmethod
    def _get_tshark_json_bytes(parsable):
        json_string = ''.join([
            '[{"_source": {"layers": {"tcp": {"tcp.payload": "',
            bytes_to_hex_string(parsable.compose()),
            '"}}}}]'
        ])

        return json_string

    def test_error_not_tshark_json_structure(self):
        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Not a TShark JSON structure',
            b'{"invalid-json-data": null}'
        )

        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Not a TShark JSON structure',
            b'[{"_source": {}}]'
        )

        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Not a TShark JSON structure',
            b'{"_source": {"layers": {}}}'
        )

    def test_error_missing_payload_in_tshark_json_data(self):
        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Missing TCP payload in TShark JSON data',
            b'[{"_source": {"layers": {"tcp.segments": null}}}]'
        )

        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Missing TCP payload in TShark JSON data',
            b'[{"_source": {"layers": {"tcp": null}}}]'
        )

        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Missing TCP payload in TShark JSON data',
            b'[{"_source": {"layers": {}}}]'
        )

    def test_error_invalid_tcp_payload_in_tshark_json_data(self):
        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Invalid TCP payload in TShark JSON data',
            b'[{"_source": {"layers": {"tcp.segments": {"tcp.reassembled.data": null}}}}]'
        )

        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Invalid TCP payload in TShark JSON data',
            b'[{"_source": {"layers": {"tcp": {"tcp.payload": null}}}}]'
        )

        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Invalid TCP payload in TShark JSON data',
            b'[{"_source": {"layers": {"tcp": {"tcp.payload": "not-a-hex-string"}}}}]'
        )

    def test_error_invalid_handshake_in_tshark_json_data(self):
        self._test_argument_error(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            'Invalid handshake bytes in TShark JSON data',
            b'[{"_source": {"layers": {"tcp": {"tcp.payload": "de:ad:be:af"}}}}]'
        )

    def test_output(self):
        tls_record_bytes = TlsRecord(TlsHandshakeClientHelloStreamCipherRC4(
            TlsProtocolVersion(TlsVersion.TLS1_2), 'hostname'
        ).compose()).compose()
        tshark_json = ''.join([
            '[{"_source": {"layers": {"tcp": {"tcp.payload": "',
            bytes_to_hex_string(tls_record_bytes),
            '"}}}}]',
        ])
        capability_json = json.dumps(HandshakeToCapabilitiesTls.from_binary(tls_record_bytes).to_capabilities())

        stdout, stderr = self._get_command_result(
            [self.script_path, '--protocol', 'tls', '--format', 'tshark'],
            tshark_json.encode('ascii')
        )
        self.assertEqual(stdout, capability_json + '\n')
        self.assertEqual(stderr, '')

    def test_tls1_2(self):
        client_hello = TlsHandshakeClientHelloAnyAlgorithm([TlsProtocolVersion(TlsVersion.TLS1_2), ], 'hostname')
        tshark_json = self._get_tshark_json_bytes(TlsRecord(client_hello.compose()))
        tls_json_object = HandshakeToCapabilitiesTls.from_tshark(tshark_json).to_capabilities()

        self.assertEqual(list(client_hello.cipher_suites), tls_json_object.cipher_suites)
        self.assertEqual(
            set(map(lambda extension: extension.extension_type, client_hello.extensions)),
            set(tls_json_object.extension_types)
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
            set(map(lambda extension: extension.extension_type, client_hello.extensions)),
            set(tls_json_object.extension_types)
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
            set(map(lambda extension: extension.extension_type, client_hello.extensions)),
            set(tls_json_object.extension_types)
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
