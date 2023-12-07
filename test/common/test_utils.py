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

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.utils import SerializableTextEncoderHighlighted, resolve_address


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
        self.assertEqual(ip, '2606:4700:4700::1111')
