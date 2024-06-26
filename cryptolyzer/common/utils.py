# -*- coding: utf-8 -*-

import abc
import collections
import json
import ipaddress
import logging
import os
import socket
import string
import sys

import six

import colorama
import attr

from cryptodatahub.common.grade import Grade, Gradeable, GradeableComplex, GradeableSimple, GradeableVulnerabilities
from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.tls.algorithm import TlsExtensionType
from cryptodatahub.tls.client import ClientCapabilities, ClientExtensionParams, ClientGreaseParams

from cryptoparser.common.base import Serializable
from cryptoparser.common.exception import InvalidType, NotEnoughData, TooMuchData
from cryptoparser.common.utils import bytes_from_hex_string

from cryptoparser.tls.grease import TlsInvalidTypeBase, TlsInvalidType
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello
from cryptoparser.tls.record import TlsRecord

from cryptolyzer import __setup__
from cryptolyzer.common.exception import NetworkError, NetworkErrorType


class Singleton(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super(Singleton, cls).__call__(*args, **kwargs)
        return cls._instances[cls]


@six.add_metaclass(Singleton)
class LogSingleton(logging.Logger):
    def __init__(self):
        super(LogSingleton, self).__init__(__setup__.__name__)

        formatter = logging.Formatter(fmt='%(asctime)s %(message)s', datefmt='%Y-%m-%dT%H:%M:%S%z')

        handler = logging.StreamHandler(sys.stderr)
        handler.setLevel(60)
        handler.setFormatter(formatter)

        self.addHandler(handler)


@attr.s
class SerializableTextEncoderHighlighted(object):
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
            attack_name = ', due to {}'.format(vulnerability.attack_type.value.name)
            if vulnerability.named is not None:
                attack_name += ', called {}'.format(vulnerability.named.value.name)

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

        return ' ({})'.format(gradeable_simple.grade.value.name)

    def _get_gradeable_vulnerabilities_result(self, gradeable_vulnerabilities, level):
        if not gradeable_vulnerabilities.vulnerabilities:
            return ''

        indent = level * '    '

        if hasattr(gradeable_vulnerabilities, 'long_name') and gradeable_vulnerabilities.long_name is not None:
            name = '{} ({})'.format(gradeable_vulnerabilities.long_name, gradeable_vulnerabilities.name)
        elif hasattr(gradeable_vulnerabilities, 'name'):
            name = gradeable_vulnerabilities.name
        else:
            name = ''

        if name:
            name = ' ' + self._get_highlighted_text(name)

        result = os.linesep
        result += '{}* {}{} is'.format(indent, gradeable_vulnerabilities.get_gradeable_name(), name)

        if len(gradeable_vulnerabilities.vulnerabilities) > 1:
            indent += '    '
            result += os.linesep
        else:
            indent = ' '

        result += os.linesep.join([
            '{}{}{}'.format(
                indent,
                self._get_colorized_text(vulnerability.grade, vulnerability.grade.value.name),
                self._get_attack_result_string(vulnerability),
            )
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
        six.raise_from(NetworkError(NetworkErrorType.NO_ADDRESS), e)
    if not addresses:
        raise NetworkError(NetworkErrorType.NO_ADDRESS)

    if not ip:
        family = addresses[0][0]
        ip = addresses[0][1]
    else:
        try:
            family = socket.AF_INET if ipaddress.ip_address(six.text_type(ip)).version == 4 else socket.AF_INET6
        except ValueError as e:
            six.raise_from(NetworkError(NetworkErrorType.NO_ADDRESS), e)

    return family, ip


def buffer_is_plain_text(buffer):
    try:
        return all(c in string.printable for c in buffer.decode('utf-8'))
    except UnicodeDecodeError:
        return False


def buffer_flush(buffer, byte_num):
    if byte_num is None:
        byte_num = len(buffer)

    return buffer[byte_num:]


@attr.s
class HandshakeToCapabilitiesBase(object):
    handshake_data = attr.ib(validator=attr.validators.instance_of((bytes, bytearray)))

    @abc.abstractmethod
    def _parse_handshake(self, handshake_data):
        raise NotImplementedError()

    @abc.abstractmethod
    def _handshake_to_capabilities(self, handshake):
        raise NotImplementedError()

    @classmethod
    @abc.abstractmethod
    def get_protocol(cls):
        raise NotImplementedError()

    @staticmethod
    def _parse_parsable(parsable_class, handshake_data):
        try:
            parsable = parsable_class.parse_exact_size(handshake_data)
        except (InvalidType, InvalidValue, NotEnoughData, TooMuchData) as e:
            six.raise_from(ValueError('Invalid handshake bytes in TShark JSON data'), e)

        return parsable

    @classmethod
    def from_binary(cls, handshake_data):
        return cls(handshake_data)

    @classmethod
    def from_tshark(cls, handshake_data):
        try:
            tshark_json = json.loads(handshake_data)
        except ValueError as e:  # json.decoder.JSONDecodeError is derived from ValueError
            six.raise_from(ValueError('Invalid JSON data'), e)

        if not tshark_json:
            raise ValueError('Empty JSON data')

        for packet in tshark_json:
            try:
                layers = packet['_source']['layers']
            except (KeyError, TypeError) as e:
                six.raise_from(ValueError('Not a TShark JSON structure'), e)

            try:
                if 'tcp.segments' in layers:
                    payload = layers['tcp.segments']['tcp.reassembled.data']
                elif 'tcp' in layers:
                    payload = layers['tcp']['tcp.payload']
                else:
                    raise KeyError()
            except (KeyError, TypeError) as e:
                six.raise_from(ValueError('Missing TCP payload in TShark JSON data'), e)

            if not isinstance(payload, six.string_types):
                raise ValueError('Invalid TCP payload in TShark JSON data')
            try:
                payload_bytes = bytes_from_hex_string(payload, separator=':')
            except ValueError as e:
                six.raise_from(ValueError('Invalid TCP payload in TShark JSON data'), e)

            return cls(payload_bytes)

    def to_capabilities(self):
        handshake = self._parse_handshake(self.handshake_data)
        return self._handshake_to_capabilities(handshake)


@attr.s
class HandshakeToCapabilitiesTls(HandshakeToCapabilitiesBase):
    client_hello = attr.ib(init=False, default=None)
    grease = attr.ib(init=False, default=collections.OrderedDict())
    extensions = attr.ib(init=False, default=collections.OrderedDict())

    _GREASE_EXTENSIONS = [
        TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION,
        TlsExtensionType.KEY_SHARE,
        TlsExtensionType.PSK_KEY_EXCHANGE_MODES,
        TlsExtensionType.SIGNATURE_ALGORITHMS,
        TlsExtensionType.SIGNATURE_ALGORITHMS_CERT,
        TlsExtensionType.SUPPORTED_GROUPS,
        TlsExtensionType.SUPPORTED_VERSIONS,
    ]

    def _parse_handshake(self, handshake_data):
        tls_record = self._parse_parsable(TlsRecord, handshake_data)

        self.client_hello = TlsHandshakeClientHello.parse_exact_size(tls_record.fragment)

    @classmethod
    def _is_grease(cls, value):
        return (isinstance(value, TlsInvalidTypeBase) and value.value.value_type == TlsInvalidType.GREASE)

    @classmethod
    def _get_non_grease_vaules(cls, values):
        non_grease_values = [value for value in values if not cls._is_grease(value)]
        has_grease = len(non_grease_values) < len(values)

        return non_grease_values, has_grease

    def _update_extensions_simple(self, extension_type, parameter_name, parameter_converter=None, sub_item=False):
        try:
            extension = self.client_hello.extensions.get_item_by_type(extension_type)
        except KeyError:
            return

        extension_name = extension_type.name.lower()
        parameter = getattr(extension, parameter_name)
        if parameter_converter:
            parameter = parameter_converter(parameter)

        if sub_item:
            extension_params = self.extensions.get(extension_name, collections.OrderedDict())
            extension_params.update(collections.OrderedDict([(parameter_name, parameter)]))
            self.extensions[extension_name] = extension_params
        else:
            self.extensions.update(collections.OrderedDict([(extension_name, parameter)]))

    def _update_extensions_iterable(self, extension_type, parameter_name, parameter_converter=None):
        try:
            extension = self.client_hello.extensions.get_item_by_type(extension_type)
        except KeyError:
            return

        extension_name = extension_type.name.lower()
        if parameter_name is not None:
            parameters, has_grease = self._get_non_grease_vaules(getattr(extension, parameter_name))
            if parameter_converter:
                converted_parameters = []
                for parameter in parameters:
                    converted_parameter = parameter_converter(parameter)
                    if converted_parameter:
                        converted_parameters.append(converted_parameter)
                parameters = converted_parameters
        else:
            parameters = []
            has_grease = False

        self.extensions.update(collections.OrderedDict([(extension_name, parameters)]))

        if has_grease and extension_type in self._GREASE_EXTENSIONS:
            self.grease['extensions'].append(extension_type)

    def _handshake_to_capabilities(self, handshake):
        self.grease.update(collections.OrderedDict([('extensions', [])]))

        cipher_suites, has_grease = self._get_non_grease_vaules(self.client_hello.cipher_suites)
        self.grease.update(collections.OrderedDict([('cipher_suites', has_grease)]))

        extension_types, has_grease = self._get_non_grease_vaules(list(map(
            lambda extension: extension.extension_type, self.client_hello.extensions
        )))
        self.grease.update(collections.OrderedDict([('extension_types', has_grease)]))

        self._update_extensions_iterable(TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION, "protocol_names")
        self._update_extensions_iterable(TlsExtensionType.APPLICATION_LAYER_PROTOCOL_SETTINGS, "protocol_names")
        self._update_extensions_iterable(TlsExtensionType.COMPRESS_CERTIFICATE, "compression_algorithms")
        self._update_extensions_iterable(TlsExtensionType.DELEGATED_CREDENTIALS, "hash_and_signature_algorithms")
        self._update_extensions_iterable(TlsExtensionType.EC_POINT_FORMATS, "point_formats")
        self._update_extensions_iterable(
            TlsExtensionType.KEY_SHARE, "key_share_entries",
            lambda key_share_entry: None if self._is_grease(key_share_entry.group) else key_share_entry.group.name
        )
        self._update_extensions_iterable(
            TlsExtensionType.KEY_SHARE_RESERVED, "key_share_entries",
            lambda key_share_entry: None if self._is_grease(key_share_entry.group) else key_share_entry.group.name
        )
        self._update_extensions_iterable(TlsExtensionType.POST_HANDSHAKE_AUTH, None)
        self._update_extensions_iterable(TlsExtensionType.PSK_KEY_EXCHANGE_MODES, "key_exchange_modes")
        self._update_extensions_simple(TlsExtensionType.RECORD_SIZE_LIMIT, "record_size_limit")
        self._update_extensions_iterable(TlsExtensionType.SIGNATURE_ALGORITHMS, "hash_and_signature_algorithms")
        self._update_extensions_iterable(TlsExtensionType.SUPPORTED_GROUPS, "elliptic_curves")
        self._update_extensions_iterable(
            TlsExtensionType.SUPPORTED_VERSIONS, "supported_versions",
            lambda supported_version: supported_version.version
        )
        self._update_extensions_simple(
            TlsExtensionType.TOKEN_BINDING, "parameters",
            lambda parameters: [parameter.name for parameter in parameters], True
        )
        self._update_extensions_simple(TlsExtensionType.TOKEN_BINDING, "protocol_version", str, True)

        return ClientCapabilities(
            tls_versions=[],
            cipher_suites=cipher_suites,
            compression_methods=list(self.client_hello.compression_methods),
            fallback_scsv=self.client_hello.fallback_scsv,
            empty_renegotiation_info_scsv=self.client_hello.empty_renegotiation_info_scsv,
            grease=ClientGreaseParams(**self.grease),
            extension_types=extension_types,
            extension_params=ClientExtensionParams(**self.extensions),
        )

    @classmethod
    def get_protocol(cls):
        return 'tls'
