# -*- coding: utf-8 -*-

import ipaddress
import logging
import os
import socket
import string
import sys


import colorama
import attr

from cryptodatahub.common.grade import Grade, Gradeable, GradeableComplex, GradeableSimple, GradeableVulnerabilities

from cryptoparser.common.base import Serializable

from cryptolyzer import __setup__
from cryptolyzer.common.exception import NetworkError, NetworkErrorType


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


class LogSingleton(logging.Logger, metaclass=Singleton):
    def __init__(self):
        super().__init__(__setup__.__name__)

        formatter = logging.Formatter(fmt='%(asctime)s %(message)s', datefmt='%Y-%m-%dT%H:%M:%S%z')

        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(60)
        handler.setFormatter(formatter)

        self.addHandler(handler)


@attr.s
class SerializableTextEncoderHighlighted():
    _COLOR_SCHEMES = {
        None: colorama.Style.RESET_ALL,
        Grade.INSECURE: colorama.Fore.RED,
        Grade.DEPRECATED: colorama.Fore.YELLOW,
        Grade.WEAK: colorama.Fore.YELLOW,
        Grade.SECURE: colorama.Fore.GREEN,
    }

    old_serializable_text_encoder = attr.ib(init=False, validator=attr.validators.instance_of(callable))

    def __attrs_post_init__(self):
        self.old_serializable_text_encoder = Serializable.post_text_encoder

    @staticmethod
    def _key_vulneravility(vulnerability):
        return (vulnerability.grade.value, vulnerability.attack_type.value.name if vulnerability.attack_type else None)

    @staticmethod
    def _get_attack_result_string(vulnerability):
        if vulnerability.attack_type is None:
            attack_name = ''
        else:
            attack_name = f', due to {vulnerability.attack_type.value.name}'
            if vulnerability.named is not None:
                attack_name += f', called {vulnerability.named.value.name}'

        return attack_name

    @classmethod
    def _get_highlighted_text(cls, text):
        return colorama.Style.BRIGHT + text + colorama.Style.RESET_ALL

    def _get_colorized_text(self, grade, text):
        return self._COLOR_SCHEMES[grade] + text + colorama.Style.RESET_ALL

    @classmethod
    def _get_gradeable_simple_result(cls, gradeable_simple):
        if gradeable_simple.grade in (Grade.SECURE, Grade.INSECURE):
            return ''

        return f' ({gradeable_simple.grade.value.name})'

    def _get_gradeable_vulnerabilities_result(self, gradeable_vulnerabilities, level):
        if not gradeable_vulnerabilities.vulnerabilities:
            return ''

        indent = level * '    '

        if hasattr(gradeable_vulnerabilities, 'long_name') and gradeable_vulnerabilities.long_name is not None:
            name = f'{gradeable_vulnerabilities.long_name} ({gradeable_vulnerabilities.name})'
        elif hasattr(gradeable_vulnerabilities, 'name'):
            name = gradeable_vulnerabilities.name
        else:
            name = ''

        if name:
            name = ' ' + self._get_highlighted_text(name)

        result = os.linesep
        result += f'{indent}* {gradeable_vulnerabilities.get_gradeable_name()}{name} is'

        if len(gradeable_vulnerabilities.vulnerabilities) > 1:
            indent += '    '
            result += os.linesep
        else:
            indent = ' '

        result += os.linesep.join([
            f'{indent}'
            f'{self._get_colorized_text(vulnerability.grade, vulnerability.grade.value.name)}'
            f'{self._get_attack_result_string(vulnerability)}'
            for vulnerability in sorted(gradeable_vulnerabilities.vulnerabilities, key=self._key_vulneravility)
        ])

        return result

    def _get_gradeable_complex_result(self, gradeable_complex, level):
        result = ''

        if gradeable_complex.gradeables is None:
            return result

        graded_gradeabes = filter(
            lambda gradeable: gradeable is not None and gradeable.min_grade is not None,
            gradeable_complex.gradeables
        )

        for gradeable in sorted(graded_gradeabes, key=lambda gradeable: gradeable.min_grade.value):
            if isinstance(gradeable, GradeableVulnerabilities):
                result += self._get_gradeable_vulnerabilities_result(gradeable, level)
            elif isinstance(gradeable, GradeableComplex):
                result += self._get_gradeable_complex_result(gradeable, level)

        return result

    def __call__(self, obj, level):
        if isinstance(obj, Gradeable):
            min_grade = obj.min_grade

            result = self._get_colorized_text(min_grade, str(obj))
            if min_grade != Grade.SECURE:
                if isinstance(obj, GradeableSimple):
                    result += self._get_gradeable_simple_result(obj)
                elif isinstance(obj, GradeableVulnerabilities):
                    result += self._get_gradeable_vulnerabilities_result(obj, level)
                elif isinstance(obj, GradeableComplex):
                    result += self._get_gradeable_complex_result(obj, level)
                else:
                    raise NotImplementedError(type(obj))

            result = False, result
        else:
            result = self.old_serializable_text_encoder(obj, level)

        return result


def resolve_address(address, port, ip=None):
    try:
        addresses = [
            (addrinfo[0], addrinfo[4][0])
            for addrinfo in socket.getaddrinfo(address, port, 0, socket.SOCK_STREAM)
        ]
    except socket.gaierror as e:
        raise NetworkError(NetworkErrorType.NO_ADDRESS) from e
    if not addresses:
        raise NetworkError(NetworkErrorType.NO_ADDRESS)

    if not ip:
        family = addresses[0][0]
        ip = addresses[0][1]
    else:
        try:
            family = socket.AF_INET if ipaddress.ip_address(str(ip)).version == 4 else socket.AF_INET6
        except ValueError as e:
            raise NetworkError(NetworkErrorType.NO_ADDRESS) from e

    return family, ip  # pylint: disable=possibly-used-before-assignment


def buffer_is_plain_text(buffer):
    try:
        return all(c in string.printable for c in buffer.decode('utf-8'))
    except UnicodeDecodeError:
        return False


def buffer_flush(buffer, byte_num):
    if byte_num is None:
        byte_num = len(buffer)

    return buffer[byte_num:]
