# -*- coding: utf-8 -*-

import collections

import attr

import six

from cryptodatahub.common.algorithm import KeyExchange, NamedGroupType
from cryptodatahub.common.key import PublicKeySize

from cryptodatahub.tls.algorithm import TlsNamedCurve
from cryptodatahub.tls.client import ClientVersionedParamsBase, TlsClient

from cryptoparser.tls.ciphersuite import SslCipherKind, TlsCipherSuite
from cryptoparser.tls.extension import (
    TlsExtensionCertificateStatusRequestClient,
    TlsExtensionKeyShareClient,
    TlsExtensionKeyShareReservedClient,
    TlsExtensionKeyShareServer,
    TlsExtensionPadding,
    TlsExtensionRecordSizeLimit,
    TlsExtensionRenegotiationInfo,
    TlsExtensionServerNameClient,
    TlsExtensionSessionTicket,
    TlsExtensionSupportedVersionsClient,
    TlsExtensionTokenBinding,
    TlsExtensionType,
    TlsExtensionUnparsed,
    TlsExtensionUnusedData,
    TlsExtensionVariantClient,
    TlsNextProtocolName,
    TlsProtocolName,
    TlsTokenBindingProtocolVersion,
)
from cryptoparser.tls.grease import TlsInvalidTypeTwoByte
from cryptoparser.tls.subprotocol import (
    TlsAlertDescription,
    TlsCompressionMethod,
    TlsHandshakeType,
    TlsHandshakeClientHello,
)
from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.dhparam import (
    DHParameter,
    DHParamWellKnown,
    parse_tls_dh_params,
)
from cryptolyzer.common.exception import ErrorParams, NetworkError, SecurityError, SecurityErrorType
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.common.utils import LogSingleton

from cryptolyzer.tls.client import TlsAlert, key_share_entry_from_named_curve

from cryptolyzer.tls.curves import AnalyzerCurves


@attr.s
class AnalyzerResultSimulationsSsl(object):
    """
    :class: Analyzer result relates to the parameters of the SSL connection initiated between the server and the
        simulated client application.

    :param cipher_kind: cipher kind.
    """

    cipher_kind = attr.ib(validator=attr.validators.instance_of(SslCipherKind))


@attr.s
class AnalyzerResultSimulationsTlsBase(object):
    """
    :class: Analyzer result relates to the parameters of the TLS connection initiated between the server and the
        simulated client application.

    :param version: protocol version.
    :param cipher_suite: cipher suite.
    :param compression_method: compression method.
    :param application_layer_protocol: application layer protocol.
    """

    version = attr.ib(validator=attr.validators.instance_of(TlsProtocolVersion))
    cipher_suite = attr.ib(validator=attr.validators.instance_of(TlsCipherSuite))
    compression_method = attr.ib(validator=attr.validators.instance_of(TlsCompressionMethod))
    encrypt_then_mac = attr.ib(validator=attr.validators.instance_of(bool))
    application_layer_protocol = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of((TlsProtocolName, TlsNextProtocolName)))
    )


@attr.s
class AnalyzerResultSimulationsTlsPfs(AnalyzerResultSimulationsTlsBase):
    """
    :class: Analyzer result relates to the parameters of a TLS connection -- used a forward secret key-exchange --
        initiated between the server and the simulated client application.

    :param key_size: Key size of used during the key exchange.
    """

    key_size = attr.ib(validator=attr.validators.instance_of(PublicKeySize))


@attr.s
class AnalyzerResultSimulationsTlsPfsNamedGroup(AnalyzerResultSimulationsTlsPfs):
    """
    :class: Analyzer result relates to the parameters of a TLS connection -- used a named group during the key
        exchange -- initiated between the server and the simulated client application.

    :param named_group: Named group used during the key exchange.
    """

    named_group = attr.ib(validator=attr.validators.instance_of(TlsNamedCurve))


@attr.s
class AnalyzerResultSimulationsTlsPfsDhWellKnown(AnalyzerResultSimulationsTlsPfs):
    """
    :class: Analyzer result relates to the parameters of a TLS connection -- used a Diffie-Hellman parameter during the
        key exchange -- initiated between the server and the simulated client application.

    :param well_known: the well-known Diffie-Hellman parameter used during the key exchange.
    """

    well_known = attr.ib(validator=attr.validators.in_(DHParamWellKnown))


@attr.s
class AnalyzerResultSimulations(AnalyzerResultTls):
    """
    :class: Analyzer result relates to the simulated client applications.

    :param succeeded_clients: the list of client applications where the connection initiation was successful,
    :param failed_clients: the list of client applications where the connection initiation was failed.
    """

    succeeded_clients = attr.ib(validator=attr.validators.deep_mapping(
        key_validator=attr.validators.instance_of(ClientVersionedParamsBase),
        value_validator=attr.validators.instance_of((AnalyzerResultSimulationsTlsBase, AnalyzerResultSimulationsSsl)),
    ))
    failed_clients = attr.ib(validator=attr.validators.deep_mapping(
        key_validator=attr.validators.instance_of(ClientVersionedParamsBase),
        value_validator=attr.validators.instance_of(ErrorParams),
    ))


class AnalyzerSimulations(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'simulations'

    @classmethod
    def get_help(cls):
        return 'Check which parameters are negotiated using different clients with the server(s)'

    @staticmethod
    def _get_extension(server_name, extension_type, extension_params, grease):
        extension_types_with_no_attrs = [
            TlsExtensionRenegotiationInfo, TlsExtensionSessionTicket, TlsExtensionCertificateStatusRequestClient
        ]

        extension_classes = TlsExtensionVariantClient.get_parsed_extensions()
        extension_class = extension_classes[extension_type][0]
        extension_params = getattr(extension_params, extension_type.name.lower(), None)

        if issubclass(extension_class, TlsExtensionUnusedData) or extension_class in extension_types_with_no_attrs:
            extension = extension_class()
        elif extension_class is TlsExtensionServerNameClient:
            extension = extension_class(server_name)
        elif extension_class in [TlsExtensionKeyShareClient, TlsExtensionKeyShareReservedClient]:
            key_share_entries = [
                key_share_entry_from_named_curve(tls_named_curve)
                for tls_named_curve in extension_params
            ]
            extension = extension_class(key_share_entries)
        elif extension_class is TlsExtensionPadding:
            extension = extension_class(1)
        elif extension_class is TlsExtensionSupportedVersionsClient:
            supported_versions = [
                TlsProtocolVersion(tls_version)
                for tls_version in extension_params
            ]
            if TlsExtensionType.SUPPORTED_VERSIONS in grease.extensions:
                supported_versions.append(TlsInvalidTypeTwoByte.from_random())

            extension = extension_class(supported_versions)
        elif extension_class is TlsExtensionRecordSizeLimit:
            extension = extension_class(extension_params)
        elif extension_class is TlsExtensionTokenBinding:
            major, minor = extension_params.protocol_version.split('.')
            extension = extension_class(
                TlsTokenBindingProtocolVersion(int(major), int(minor)),
                extension_params.parameters
            )
        else:
            if extension_type in grease.extensions:
                if extension_type == TlsExtensionType.PSK_KEY_EXCHANGE_MODES:
                    raise NotImplementedError(extension_type)

                grease = TlsInvalidTypeTwoByte.from_random()
                extension_params.append(grease)

            extension = extension_class(extension_params)

        return extension

    @staticmethod
    def _get_client_hello_from_client_params(client_params, server_name):
        cipher_suites = list(client_params.capabilities.cipher_suites)
        if client_params.capabilities.grease.cipher_suites:
            cipher_suites.append(TlsInvalidTypeTwoByte.from_random())

        extensions = [
            AnalyzerSimulations._get_extension(
                server_name,
                extension_type,
                client_params.capabilities.extension_params,
                client_params.capabilities.grease,
            )
            for extension_type in client_params.capabilities.extension_types
        ]

        if client_params.capabilities.grease.extensions:
            extensions.append(TlsExtensionUnparsed(TlsInvalidTypeTwoByte.from_random(), b''))

        return TlsHandshakeClientHello(
            cipher_suites=cipher_suites,
            compression_methods=client_params.capabilities.compression_methods,
            extensions=extensions,
            fallback_scsv=client_params.capabilities.fallback_scsv,
            empty_renegotiation_info_scsv=client_params.capabilities.empty_renegotiation_info_scsv,
        )

    @staticmethod
    def _get_result_base_params(protocol_version, server_hello):
        result_params = {
            'version': protocol_version,
            'cipher_suite': server_hello.cipher_suite,
            'compression_method': server_hello.compression_method,
        }

        try:
            server_hello.extensions.get_item_by_type(TlsExtensionType.ENCRYPT_THEN_MAC)
            result_params['encrypt_then_mac'] = True  # pragma: no cover
        except KeyError:
            result_params['encrypt_then_mac'] = False

        try:
            extension = server_hello.extensions.get_item_by_type(
                TlsExtensionType.APPLICATION_LAYER_PROTOCOL_NEGOTIATION
            )
            result_params['application_layer_protocol'] = extension.protocol_names[0]
        except KeyError:
            result_params['application_layer_protocol'] = None

        if result_params['application_layer_protocol'] is None:
            try:
                extension = server_hello.extensions.get_item_by_type(
                    TlsExtensionType.NEXT_PROTOCOL_NEGOTIATION
                )
                result_params['application_layer_protocol'] = extension.protocol_names[0]
            except KeyError:
                result_params['application_layer_protocol'] = None

        return result_params

    @staticmethod
    def _get_simulation_result_version_1_3(protocol_version, server_hello):
        result_params = AnalyzerSimulations._get_result_base_params(protocol_version, server_hello)

        key_share_extension = server_hello.extensions.get_item_by_type(TlsExtensionType.KEY_SHARE)
        result_params['named_group'] = (
            key_share_extension.key_share_entry.group
            if isinstance(key_share_extension, TlsExtensionKeyShareServer)
            else key_share_extension.selected_group
        )
        result_params['key_size'] = PublicKeySize(
            KeyExchange.DHE
            if result_params['named_group'].value.named_group.value.group_type == NamedGroupType.FINITE_FIELD
            else KeyExchange.ECDHE,
            result_params['named_group'].value.named_group.value.size
        )

        return AnalyzerResultSimulationsTlsPfsNamedGroup(**result_params)

    @staticmethod
    def _get_simulation_result_version_1_2(protocol_version, server_messages):
        server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
        cipher_suite = server_hello.cipher_suite
        result_params = AnalyzerSimulations._get_result_base_params(protocol_version, server_hello)

        if not cipher_suite.value.key_exchange.value.forward_secret:
            return AnalyzerResultSimulationsTlsBase(**result_params)

        if cipher_suite.value.key_exchange in [KeyExchange.DHE, KeyExchange.ADH]:
            server_key_exchange = server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE]
            dh_public_key = parse_tls_dh_params(server_key_exchange.param_bytes)
            key_size = dh_public_key.key_size
            result_params['key_size'] = PublicKeySize(cipher_suite.value.key_exchange, key_size)
            dh_parameter = DHParameter(dh_public_key.public_numbers.parameter_numbers, key_size)
            well_known = dh_parameter.well_known
            if well_known is None:
                result = AnalyzerResultSimulationsTlsPfs(**result_params)
            else:
                result_params['well_known'] = well_known
                result = AnalyzerResultSimulationsTlsPfsDhWellKnown(**result_params)
        elif cipher_suite.value.key_exchange in [KeyExchange.ECDHE, KeyExchange.AECDH]:
            server_key_exchange = server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE]
            tls_named_curve = AnalyzerCurves.get_supported_curve(protocol_version, server_key_exchange)
            result_params['named_group'] = tls_named_curve
            result_params['key_size'] = PublicKeySize(
                cipher_suite.value.key_exchange,
                tls_named_curve.value.named_group.value.size
            )
            result = AnalyzerResultSimulationsTlsPfsNamedGroup(**result_params)

        return result

    def _get_simulation_result(self, server_messages):
        server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
        try:
            supported_versions_extension = server_hello.extensions.get_item_by_type(TlsExtensionType.SUPPORTED_VERSIONS)
        except KeyError:
            protocol_version = server_hello.protocol_version
        else:
            protocol_version = supported_versions_extension.selected_version

        is_tls1_3 = protocol_version > TlsProtocolVersion(TlsVersion.TLS1_2)
        if is_tls1_3:
            result = self._get_simulation_result_version_1_3(protocol_version, server_hello)
        else:
            result = self._get_simulation_result_version_1_2(protocol_version, server_messages)

        return result

    def _simulate_tls_client(self, analyzable, tls_client, address):
        client_hello = self._get_client_hello_from_client_params(tls_client, address)

        try:
            server_messages = analyzable.do_tls_handshake(hello_message=client_hello, last_handshake_message_type=None)
        except TlsAlert as e:
            if e.description == TlsAlertDescription.PROTOCOL_VERSION:
                six.raise_from(SecurityError(SecurityErrorType.NO_SHARED_VERSION), e)
            elif e.description == TlsAlertDescription.HANDSHAKE_FAILURE:
                six.raise_from(SecurityError(SecurityErrorType.NO_SHARED_CIPHER), e)
            else:
                six.raise_from(SecurityError(SecurityErrorType.UNKNOWN_ERROR), e)
        else:
            server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
            protocol_versions = list(map(TlsProtocolVersion, tls_client.capabilities.tls_versions))
            if server_hello.protocol_version not in protocol_versions:
                raise SecurityError(SecurityErrorType.NO_SHARED_VERSION)

        return self._get_simulation_result(server_messages)

    @staticmethod
    def _get_tls_client_key(tls_client):
        #  neccessary only because PY2 does not preverse the order of enums
        tls_client_name_parts = tls_client.name.split('_')
        return (tls_client_name_parts[0], int(tls_client_name_parts[1]))

    def _get_results(self, analyzable):
        succeeded_clients = []
        failed_clients = []

        for tls_client in sorted(TlsClient, key=self._get_tls_client_key):
            try:
                simulation_result = self._simulate_tls_client(analyzable, tls_client.value, analyzable.address)
            except (NetworkError, SecurityError) as e:
                failed_clients.append((tls_client.value.meta, e.error.value))
                LogSingleton().log(
                    level=60,
                    msg=six.u('Connection to server has been failed with the client %s') % (tls_client.value.meta, )
                )
            else:
                succeeded_clients.append((tls_client.value.meta, simulation_result))
                LogSingleton().log(
                    level=60,
                    msg=six.u('Connection to server has been succeeded with the client %s') % (tls_client.value.meta, )
                )

        return succeeded_clients, failed_clients

    @staticmethod
    def _get_merged_results(client_results):
        if not client_results:
            return client_results

        merged_results = client_results[:1]
        for client_result in client_results:
            last_merged_client_params, last_merged_client_result = merged_results[-1]
            if (last_merged_client_params.client == client_result[0].client and
                    last_merged_client_result == client_result[1]):
                merged_results[-1] = (ClientVersionedParamsBase(
                    last_merged_client_params.client,
                    last_merged_client_params.first_version,
                    client_result[0].last_version
                ), merged_results[-1][1])
            else:
                merged_results.append(client_result)

        return merged_results

    def analyze(self, analyzable, protocol_version):
        succeeded_clients, failed_clients = self._get_results(analyzable)
        succeeded_clients = self._get_merged_results(succeeded_clients)
        failed_clients = self._get_merged_results(failed_clients)

        return AnalyzerResultSimulations(
            target=AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            succeeded_clients=collections.OrderedDict(succeeded_clients),
            failed_clients=collections.OrderedDict(failed_clients),
        )
