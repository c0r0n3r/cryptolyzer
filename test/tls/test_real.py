# SPDX-License-Identifier: MPL-2.0

import collections
import concurrent.futures
import json
import pathlib
import typing
import unittest

from test.common.markers import live_server

import test.tls.test_curves

from cryptodatahub.common.pqc import HybridNamedGroup, KeyEncapsulationMechanism, KeyParameter

from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.tls.curves import AnalyzerResultCurves


class TestReal(unittest.TestCase):
    OQS_TEST_SERVER_ADDRESS = 'test.openquantumsafe.org'
    OQS_TEST_SERVER_ASSIGNMENTS_FILE_PATH = (
        pathlib.Path(__file__).parent / 'data' / 'openquantumsafe_assignments.json'
    )
    OQS_TEST_SERVER_ASSIGNMENTS_WILDCARD = '*'
    OQS_TEST_SERVER_L4_SOCKET_PARAMS = L4TransferSocketParams(timeout=10, throttle_delay=1)
    OQS_MAX_WORKER_COUNT = 8

    @classmethod
    def _get_assignments(cls) -> dict[str, dict[str, int]]:
        with open(cls.OQS_TEST_SERVER_ASSIGNMENTS_FILE_PATH, encoding='ascii') as json_file:
            return json.load(json_file, object_pairs_hook=collections.OrderedDict)

    @classmethod
    def _get_oqs_names_by_port(cls) -> dict[int, tuple[str, str]]:
        names_by_port = collections.OrderedDict()
        for oqs_name, ports_by_name in cls._get_assignments().items():
            for key_encapsulation_mechanism_name, port in ports_by_name.items():
                if key_encapsulation_mechanism_name == cls.OQS_TEST_SERVER_ASSIGNMENTS_WILDCARD:
                    continue

                names_by_port[port] = (oqs_name, key_encapsulation_mechanism_name)

        return names_by_port

    @classmethod
    def _get_key_parameters_by_port(cls) -> dict[int, tuple[str, KeyParameter]]:
        key_parameters_by_oqs_name = cls._get_key_parameters_by_oqs_name()

        return collections.OrderedDict([
            (port, (oqs_name, key_parameters_by_oqs_name[key_encapsulation_mechanism_name]))
            for port, (oqs_name, key_encapsulation_mechanism_name)
            in cls._get_oqs_names_by_port().items()
        ])

    @classmethod
    def _get_wildcard_ports_by_oqs_name(cls) -> dict[str, int]:
        return collections.OrderedDict([
            (oqs_name, ports_by_name[cls.OQS_TEST_SERVER_ASSIGNMENTS_WILDCARD])
            for oqs_name, ports_by_name in cls._get_assignments().items()
            if cls.OQS_TEST_SERVER_ASSIGNMENTS_WILDCARD in ports_by_name
        ])

    @staticmethod
    def _get_key_parameters_by_oqs_name() -> dict[str, KeyParameter]:
        return collections.OrderedDict([
            (key_parameter.value.oqs_name, key_parameter)
            for registry in (KeyEncapsulationMechanism, HybridNamedGroup)
            for key_parameter in registry
            if key_parameter.value.oqs_name is not None
        ])

    @classmethod
    def _get_result(cls, port: int) -> AnalyzerResultCurves:
        return test.tls.test_curves.TestTlsCurves.get_result(
            cls.OQS_TEST_SERVER_ADDRESS,
            port,
            TlsProtocolVersion(TlsVersion.TLS1_3),
            cls.OQS_TEST_SERVER_L4_SOCKET_PARAMS,
        )

    @classmethod
    def _get_analyses_by_port(
            cls,
            ports: typing.Iterable[int],
    ) -> dict[int, concurrent.futures.Future]:
        with concurrent.futures.ThreadPoolExecutor(
                max_workers=cls.OQS_MAX_WORKER_COUNT
        ) as executor:
            return collections.OrderedDict([(port, executor.submit(cls._get_result, port)) for port in ports])

    def test_key_parameter_names_are_known(self) -> None:
        key_parameters_by_oqs_name = self._get_key_parameters_by_oqs_name()
        unknown_names = [
            key_encapsulation_mechanism_name
            for _, key_encapsulation_mechanism_name in self._get_oqs_names_by_port().values()
            if key_encapsulation_mechanism_name not in key_parameters_by_oqs_name
        ]
        self.assertEqual(unknown_names, [])

    @live_server
    def test_key_encapsulation_mechanisms(self) -> None:
        key_parameters_by_port = self._get_key_parameters_by_port()
        analyses_by_port = self._get_analyses_by_port(key_parameters_by_port)

        for port, (oqs_name, key_parameter) in key_parameters_by_port.items():
            with self.subTest(
                    oqs_name=oqs_name,
                    key_encapsulation_mechanism=key_parameter,
                    port=port,
            ):
                self.assertEqual(
                    [
                        named_curve.value.key_parameter
                        for named_curve in analyses_by_port[port].result().curves
                    ],
                    [key_parameter],
                )

    @live_server
    def test_wildcard_ports(self) -> None:
        ports_by_oqs_name = self._get_wildcard_ports_by_oqs_name()
        analyses_by_port = self._get_analyses_by_port(ports_by_oqs_name.values())

        reported_key_parameters_by_oqs_name = collections.OrderedDict([
            (
                oqs_name,
                tuple(
                    named_curve.value.key_parameter
                    for named_curve in analyses_by_port[port].result().curves
                ),
            )
            for oqs_name, port in ports_by_oqs_name.items()
        ])

        reference_key_parameters = next(iter(reported_key_parameters_by_oqs_name.values()))
        for oqs_name, key_parameters in reported_key_parameters_by_oqs_name.items():
            with self.subTest(
                    oqs_name=oqs_name,
                    port=ports_by_oqs_name[oqs_name],
            ):
                self.assertEqual(key_parameters, reference_key_parameters)

        self.assertTrue([
            key_parameter
            for key_parameter in reference_key_parameters
            if isinstance(key_parameter, HybridNamedGroup)
        ])
