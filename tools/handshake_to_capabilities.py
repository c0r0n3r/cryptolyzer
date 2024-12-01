# -*- coding: utf-8 -*-

import abc
import argparse
import collections
import json
import sys


import attr

from cryptodatahub.common.exception import InvalidValue
from cryptodatahub.tls.algorithm import TlsExtensionType
from cryptodatahub.tls.client import ClientCapabilities, ClientExtensionParams, ClientGreaseParams

from cryptoparser.common.exception import InvalidType, NotEnoughData, TooMuchData
from cryptoparser.common.utils import bytes_from_hex_string, get_leaf_classes

from cryptoparser.tls.grease import TlsInvalidTypeBase, TlsInvalidType
from cryptoparser.tls.subprotocol import TlsHandshakeClientHello
from cryptoparser.tls.record import TlsRecord


@attr.s
class HandshakeToCapabilitiesBase():
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
            raise ValueError('Invalid handshake bytes in TShark JSON data') from e

        return parsable

    @classmethod
    def from_binary(cls, handshake_data):
        return cls(handshake_data)

    @classmethod
    def from_tshark(cls, handshake_data):
        try:
            tshark_json = json.loads(handshake_data)
        except ValueError as e:  # json.decoder.JSONDecodeError is derived from ValueError
            raise ValueError('Invalid JSON data') from e

        if not tshark_json:
            raise ValueError('Empty JSON data')

        for packet in tshark_json:
            try:
                layers = packet['_source']['layers']
            except (KeyError, TypeError) as e:
                raise ValueError('Not a TShark JSON structure') from e

            try:
                if 'tcp.segments' in layers:
                    payload = layers['tcp.segments']['tcp.reassembled.data']
                elif 'tcp' in layers:
                    payload = layers['tcp']['tcp.payload']
                else:
                    raise KeyError()
            except (KeyError, TypeError) as e:
                raise ValueError('Missing TCP payload in TShark JSON data') from e

            if not isinstance(payload, str):
                raise ValueError('Invalid TCP payload in TShark JSON data')
            try:
                payload_bytes = bytes_from_hex_string(payload, separator=':')
            except ValueError as e:
                raise ValueError('Invalid TCP payload in TShark JSON data') from e

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
        parameters, has_grease = self._get_non_grease_vaules(getattr(extension, parameter_name))
        if parameter_converter:
            converted_parameters = []
            for parameter in parameters:
                converted_parameter = parameter_converter(parameter)
                if converted_parameter:
                    converted_parameters.append(converted_parameter)
            parameters = converted_parameters

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
        extension_types = list(sorted(extension_types, key=lambda extension_type: extension_type.name))
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


def main():
    handshake_to_capabilities_classes = {
        handshake_to_capabilities_class.get_protocol(): handshake_to_capabilities_class
        for handshake_to_capabilities_class in get_leaf_classes(HandshakeToCapabilitiesBase)
    }
    parser = argparse.ArgumentParser(prog='handshake_to_capabilities')
    parser.add_argument(
        '--protocol', choices=sorted(handshake_to_capabilities_classes.keys()), help='name of the parsable protocol'
    )
    parser.add_argument(
        '--format', choices=['tshark', ], help='format of the parsable data'
    )
    arguments = parser.parse_args()

    handshake_data = sys.stdin.read()
    if not handshake_data:
        print('No input data', file=sys.stderr)
        sys.exit(2)

    handshake_class = handshake_to_capabilities_classes[arguments.protocol]
    parser_func = getattr(handshake_class, 'from_' + arguments.format)

    try:
        handshake_to_capabilities_object = parser_func(handshake_data)
        client_capabilities = handshake_to_capabilities_object.to_capabilities()
    except (TypeError, ValueError) as e:
        print(e.args[0], file=sys.stderr)
        sys.exit(2)

    print(json.dumps(client_capabilities))


if __name__ == '__main__':
    main()  # pragma: no cover
