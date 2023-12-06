# -*- coding: utf-8 -*-

import codecs

import attr
import six

from cryptodatahub.common.algorithm import KeyExchange
from cryptodatahub.common.key import PublicKeySize
from cryptodatahub.tls.algorithm import TlsNamedCurve

from cryptoparser.common.exception import NotEnoughData

from cryptoparser.tls.extension import TlsExtensionType, TlsExtensionKeyShareClient, TlsExtensionKeyShareReservedClient
from cryptoparser.tls.subprotocol import TlsExtensionsClient, TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.version import TlsProtocolVersion, TlsVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.dhparam import (
    parse_tls_dh_params,
    DHParameter,
    DHPublicKey,
    DHPublicNumbers,
)
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.tls.client import (
    TlsHandshakeClientHelloKeyExchangeDHE,
    NAMED_CURVE_TO_RFC7919_WELL_KNOWN,
    RFC7919_WELL_KNOWN_TO_NAMED_CURVE,
    key_share_entry_from_named_curve,
)
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultDHParams(AnalyzerResultTls):
    """
    :class: Analyzer result relates to Diffie-Hellman (DH) key exchange

    :param groups: supported DH named groups (can be negotiated using TLS 1.3 or TLS 1.2 with extension defined in RFC
        7919)
    :param dhparam: DH paramater sent by the server using TLS versions up to 1.2
    :param key_reuse: whether DH keys are shared between different connections (not ephemeral)
    """

    groups = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(TlsNamedCurve)),
        metadata={'human_readable_name': 'Named Groups'}
    )
    dhparam = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(DHParameter)),
        metadata={'human_readable_name': 'Diffie-Hellman Parameter'}
    )
    key_reuse = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(bool)))


class AnalyzerDHParams(AnalyzerTlsBase):

    @classmethod
    def get_name(cls):
        return 'dhparams'

    @classmethod
    def get_help(cls):
        return 'Check whether DH parameters are offered by the server(s)'

    @staticmethod
    def _get_extension_key_share(server_messages):
        server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
        try:
            extension = server_hello.extensions.get_item_by_type(TlsExtensionType.KEY_SHARE)
        except KeyError as e:
            six.raise_from(StopIteration(), e)

        return extension

    @staticmethod
    def _get_selected_group_tls_1_3(server_messages):
        key_share_extension = AnalyzerDHParams._get_extension_key_share(server_messages)
        return key_share_extension.selected_group

    @staticmethod
    def _get_public_key_tls_1_3(server_messages):
        key_share_extension = AnalyzerDHParams._get_extension_key_share(server_messages)
        well_known = NAMED_CURVE_TO_RFC7919_WELL_KNOWN[key_share_extension.key_share_entry.group]
        y = int(  # pylint: disable=invalid-name
            codecs.encode(bytes(list(key_share_extension.key_share_entry.key_exchange)), 'hex_codec'), 16
        )

        public_numbers = DHPublicNumbers(y, well_known.value.parameter_numbers)

        return DHPublicKey(public_numbers, well_known.value.key_size)

    @staticmethod
    def _get_public_key_tls_1_x(server_messages):
        server_key_exchange_message = server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE]
        return parse_tls_dh_params(server_key_exchange_message.param_bytes)

    @staticmethod
    def _get_server_messages(analyzable, is_tls_1_3, client_hello):
        try:
            if is_tls_1_3:
                last_handshake_message_type = TlsHandshakeType.SERVER_HELLO
            else:
                last_handshake_message_type = TlsHandshakeType.SERVER_KEY_EXCHANGE

            return analyzable.do_tls_handshake(
                client_hello,
                last_handshake_message_type=last_handshake_message_type
            )
        except TlsAlert as e:
            acceptable_alerts = AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS + [
                TlsAlertDescription.INTERNAL_ERROR,
                TlsAlertDescription.UNRECOGNIZED_NAME
            ]
            if e.description not in acceptable_alerts:
                raise e
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e
        except SecurityError:
            pass

        raise StopIteration

    @staticmethod
    def _get_public_key(analyzable, is_tls_1_3, client_hello):
        server_messages = AnalyzerDHParams._get_server_messages(analyzable, is_tls_1_3, client_hello)

        if is_tls_1_3:
            dh_public_key = AnalyzerDHParams._get_public_key_tls_1_3(server_messages)
        else:
            dh_public_key = AnalyzerDHParams._get_public_key_tls_1_x(server_messages)

        return dh_public_key

    @staticmethod
    def _remove_selected_group_among_supported_ones(client_hello, selected_group):
        try:
            elliptic_curves_extension = client_hello.extensions.get_item_by_type(
                TlsExtensionType.SUPPORTED_GROUPS
            )
        except KeyError:
            return False

        elliptic_curves = elliptic_curves_extension.elliptic_curves
        for elliptic_curve in elliptic_curves:
            if elliptic_curve == selected_group:
                try:
                    elliptic_curves.remove(elliptic_curve)
                except NotEnoughData:
                    client_hello.extensions.remove(elliptic_curves_extension)
                    return False

        return True

    @staticmethod
    def _analyze_tls_1_x(analyzable, client_hello):
        dhparam = None
        named_groups = []
        has_extenstion = True
        while True:
            try:
                server_messages = AnalyzerDHParams._get_server_messages(analyzable, False, client_hello)
                dh_public_key = AnalyzerDHParams._get_public_key_tls_1_x(server_messages)
                _dhparam = DHParameter(
                    dh_public_key.public_numbers.parameter_numbers,
                    PublicKeySize(KeyExchange.DHE, dh_public_key.key_size)
                )
            except StopIteration:
                break

            is_rfc7919_dhparam = (_dhparam.well_known and
                                  _dhparam.well_known in RFC7919_WELL_KNOWN_TO_NAMED_CURVE)
            if is_rfc7919_dhparam:
                named_group = RFC7919_WELL_KNOWN_TO_NAMED_CURVE[_dhparam.well_known]

                # no supported group extension, but FFDHE parameter is used
                if not has_extenstion or named_group in named_groups:
                    dhparam = _dhparam
                    named_groups = []
                    LogSingleton().log(level=60, msg=six.u('Server offers %s (%s)') % (
                        dhparam.well_known.value, client_hello.protocol_version,
                    ))
                    break

                has_extenstion = AnalyzerDHParams._remove_selected_group_among_supported_ones(client_hello, named_group)
                named_groups.append(named_group)
                LogSingleton().log(level=60, msg=six.u('Server offers %s (%s)') % (
                    _dhparam.well_known.value, client_hello.protocol_version,
                ))
            else:
                # no extension support, so only one DH parameter is possible
                dhparam = _dhparam
                if dhparam.well_known:
                    LogSingleton().log(level=60, msg=six.u('Server offers %s (%s)') % (
                        dhparam.well_known.value, client_hello.protocol_version,
                    ))
                else:
                    LogSingleton().log(
                        level=60,
                        msg=six.u('Server offers %s-bit custom DH public parameter (%s)') % (
                            dhparam.key_size, client_hello.protocol_version,
                        )
                    )
                break

        return dhparam, named_groups

    @staticmethod
    def _analyze_tls_1_3(analyzable, client_hello, protocol_version):
        named_groups = []
        has_extenstion = True
        while has_extenstion:
            try:
                server_messages = AnalyzerDHParams._get_server_messages(analyzable, True, client_hello)
                named_group = AnalyzerDHParams._get_selected_group_tls_1_3(server_messages)
            except StopIteration:
                break

            named_groups.append(named_group)
            has_extenstion = AnalyzerDHParams._remove_selected_group_among_supported_ones(client_hello, named_group)
            LogSingleton().log(level=60, msg=six.u('Server offers FFDHE public parameter with size %d-bit (%s)') % (
                named_group.value.named_group.value.size, protocol_version,
            ))

        return named_groups

    def analyze(self, analyzable, protocol_version):
        client_hello = TlsHandshakeClientHelloKeyExchangeDHE(protocol_version, analyzable.address)
        is_tls_1_3 = protocol_version > TlsProtocolVersion(TlsVersion.TLS1_2)

        if is_tls_1_3:
            named_groups = self._analyze_tls_1_3(analyzable, client_hello, protocol_version)
            dhparam = None
        else:
            dhparam, named_groups = self._analyze_tls_1_x(analyzable, client_hello)

        key_reuse = None
        if named_groups or dhparam:
            try_count = 3
            ephemeral_keys = set()
            client_hello = TlsHandshakeClientHelloKeyExchangeDHE(protocol_version, analyzable.address)

            if named_groups:
                extensions = [
                    extension
                    for extension in client_hello.extensions
                    if extension.extension_type not in (TlsExtensionType.KEY_SHARE, TlsExtensionType.KEY_SHARE_RESERVED)
                ]
                client_hello.extensions = TlsExtensionsClient(
                    extensions + [
                        TlsExtensionKeyShareClient([key_share_entry_from_named_curve(named_groups[0])]),
                        TlsExtensionKeyShareReservedClient([key_share_entry_from_named_curve(named_groups[0])]),
                    ]
                )

            for _ in range(try_count):
                try:
                    dh_public_key = self._get_public_key(analyzable, is_tls_1_3, client_hello)
                except StopIteration:
                    key_reuse = None
                    break
                else:
                    ephemeral_keys.add(dh_public_key.public_numbers.y)
            else:
                key_reuse = len(ephemeral_keys) < try_count

        return AnalyzerResultDHParams(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            named_groups, dhparam, key_reuse
        )
