# -*- coding: utf-8 -*-

import codecs

import attr
import six

from cryptoparser.tls.algorithm import TlsNamedCurve
from cryptoparser.tls.extension import TlsExtensionType
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription
from cryptoparser.tls.version import TlsProtocolVersionFinal, TlsVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.dhparam import (
    parse_tls_dh_params,
    DHParameter,
    DHPublicKey,
    DHPublicNumbers,
    WellKnownDHParams,
)
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.tls.client import TlsHandshakeClientHelloKeyExchangeDHE
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultDHParams(AnalyzerResultTls):
    dhparams = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.instance_of(DHParameter)),
        metadata={'human_readable_name': 'Diffie-Hellman Parameters'}
    )


class AnalyzerDHParams(AnalyzerTlsBase):
    _NAMED_CURVE_TO_WELL_KNOWN = {
        TlsNamedCurve.FFDHE2048: WellKnownDHParams.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
        TlsNamedCurve.FFDHE3072: WellKnownDHParams.RFC7919_3072_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
        TlsNamedCurve.FFDHE4096: WellKnownDHParams.RFC7919_4096_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
        TlsNamedCurve.FFDHE6144: WellKnownDHParams.RFC7919_6144_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
        TlsNamedCurve.FFDHE8192: WellKnownDHParams.RFC7919_8192_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP,
    }
    _WELL_KNOWN_TO_NAMED_CURVE = {
        WellKnownDHParams.RFC7919_2048_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP: TlsNamedCurve.FFDHE2048,
        WellKnownDHParams.RFC7919_3072_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP: TlsNamedCurve.FFDHE3072,
        WellKnownDHParams.RFC7919_4096_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP: TlsNamedCurve.FFDHE4096,
        WellKnownDHParams.RFC7919_6144_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP: TlsNamedCurve.FFDHE6144,
        WellKnownDHParams.RFC7919_8192_BIT_FINITE_FIELD_DIFFIE_HELLMAN_GROUP: TlsNamedCurve.FFDHE8192,
    }

    @classmethod
    def get_name(cls):
        return 'dhparams'

    @classmethod
    def get_help(cls):
        return 'Check whether DH parameters are offered by the server(s)'

    @staticmethod
    def _get_public_key_tls_1_3(server_messages):
        server_hello = server_messages[TlsHandshakeType.SERVER_HELLO]
        try:
            key_share_extension = server_hello.extensions.get_item_by_type(TlsExtensionType.KEY_SHARE)
        except KeyError as e:
            six.raise_from(StopIteration(), e)

        well_known = AnalyzerDHParams._NAMED_CURVE_TO_WELL_KNOWN[key_share_extension.key_share_entry.group]
        y = int(  # pylint: disable=invalid-name
            codecs.encode(bytes(list(key_share_extension.key_share_entry.key_exchange)), 'hex_codec'), 16
        )

        public_numbers = DHPublicNumbers(y, well_known.value.dh_param_numbers)

        return DHPublicKey(public_numbers, well_known.value.key_size)

    @staticmethod
    def _get_public_key_tls_1_x(server_messages):
        server_key_exchange_message = server_messages[TlsHandshakeType.SERVER_KEY_EXCHANGE]
        return parse_tls_dh_params(server_key_exchange_message.param_bytes)

    @staticmethod
    def _get_dh_param(analyzable, is_tls_1_3, client_hello):
        dh_public_keys = []

        for _ in (1, 2):
            try:
                if is_tls_1_3:
                    last_handshake_message_type = TlsHandshakeType.SERVER_HELLO
                else:
                    last_handshake_message_type = TlsHandshakeType.SERVER_KEY_EXCHANGE
                server_messages = analyzable.do_tls_handshake(
                    client_hello,
                    last_handshake_message_type=last_handshake_message_type
                )
                if is_tls_1_3:
                    dh_public_key = AnalyzerDHParams._get_public_key_tls_1_3(server_messages)
                else:
                    dh_public_key = AnalyzerDHParams._get_public_key_tls_1_x(server_messages)
                dh_public_keys.append(dh_public_key)

                if len(dh_public_keys) == 2:
                    return DHParameter(
                        dh_public_keys[0],
                        dh_public_keys[0].public_numbers.y == dh_public_keys[1].public_numbers.y,
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
                break

        raise StopIteration

    @staticmethod
    def _remove_selected_group_among_supported_ones(client_hello, selected_group):
        selected_named_curve = AnalyzerDHParams._WELL_KNOWN_TO_NAMED_CURVE[selected_group.well_known]

        key_share_entries = client_hello.extensions.get_item_by_type(
            TlsExtensionType.KEY_SHARE
        ).key_share_entries
        for entry_num, _ in enumerate(key_share_entries):
            if key_share_entries[entry_num].group == selected_named_curve:
                del key_share_entries[entry_num]
                break

        elliptic_curves = client_hello.extensions.get_item_by_type(
            TlsExtensionType.SUPPORTED_GROUPS
        ).elliptic_curves
        for entry_num, _ in enumerate(elliptic_curves):
            if elliptic_curves[entry_num] == selected_named_curve:
                del elliptic_curves[entry_num]
                break

    def analyze(self, analyzable, protocol_version):
        client_hello = TlsHandshakeClientHelloKeyExchangeDHE(protocol_version, analyzable.address)

        dhparams = []
        is_tls_1_3 = protocol_version > TlsProtocolVersionFinal(TlsVersion.TLS1_2)
        while True:
            try:
                dhparams.append(self._get_dh_param(analyzable, is_tls_1_3, client_hello))
            except StopIteration:
                break

            if not is_tls_1_3:
                break

            if len(client_hello.extensions.get_item_by_type(TlsExtensionType.SUPPORTED_GROUPS).elliptic_curves) == 1:
                break
            self._remove_selected_group_among_supported_ones(client_hello, dhparams[-1])

        return AnalyzerResultDHParams(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            dhparams
        )
