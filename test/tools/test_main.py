# -*- coding: utf-8 -*-

import json

try:
    import pathlib
except ImportError:  # pragma: no cover
    import pathlib2 as pathlib  # pragma: no cover

from test.common.classes import TestMainBase

from cryptodatahub.tls.algorithm import TlsVersion

from cryptoparser.common.utils import bytes_to_hex_string

from cryptoparser.tls.record import TlsRecord
from cryptoparser.tls.version import TlsProtocolVersion

from cryptolyzer.common.utils import HandshakeToCapabilitiesTls

from cryptolyzer.tls.client import TlsHandshakeClientHelloStreamCipherRC4

from tools.handshake_to_capabilities import main


class TestTlsClientBase(TestMainBase):
    def setUp(self):
        self.main_func = main
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
