# -*- coding: utf-8 -*-

from collections import OrderedDict

import six

import attr

from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsHandshakeType
from cryptoparser.tls.extension import (
    TlsExtensionType,
    TlsNamedCurve,
)
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.analyzer import AnalyzerTlsBase
from cryptolyzer.common.dhparam import parse_ecdh_params
from cryptolyzer.common.exception import NetworkError, NetworkErrorType, SecurityError
from cryptolyzer.common.result import AnalyzerResultTls, AnalyzerTargetTls
from cryptolyzer.common.utils import LogSingleton
from cryptolyzer.tls.client import TlsHandshakeClientHelloKeyExchangeECDHx
from cryptolyzer.tls.exception import TlsAlert


@attr.s
class AnalyzerResultCurves(AnalyzerResultTls):  # pylint: disable=too-few-public-methods
    """
    :class: Analyzer result relates to elliptic curve Diffie-Hellman (ECDH) key exchange

    :param groups: supported ECDH named groups (can be negotiated using named group extensions)
    :param extension_supported: whether named group extension supported
    """

    curves = attr.ib(
        validator=attr.validators.deep_iterable(attr.validators.in_(TlsNamedCurve)),
        metadata={'human_readable_name': 'Named Curves'},
    )
    extension_supported = attr.ib(
        validator=attr.validators.optional(attr.validators.instance_of(bool)),
        metadata={'human_readable_name': 'Named Curve Extension Supported'},
    )


class AnalyzerCurves(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'curves'

    @classmethod
    def get_help(cls):
        return 'Check which elliptic curves supported by the server(s)'

    @staticmethod
    def _get_response_message(l7_client, client_hello, protocol_version):
        try:
            if protocol_version <= TlsProtocolVersion(TlsVersion.TLS1_2):
                last_handshake_message_type = TlsHandshakeType.SERVER_KEY_EXCHANGE
            else:
                last_handshake_message_type = TlsHandshakeType.SERVER_HELLO

            server_messages = l7_client.do_tls_handshake(
                hello_message=client_hello,
                last_handshake_message_type=last_handshake_message_type
            )
            return server_messages[last_handshake_message_type]
        except NetworkError as e:
            if e.error != NetworkErrorType.NO_RESPONSE:
                raise e

        return None

    @staticmethod
    def get_supported_curve(protocol_version, response_message):
        if protocol_version > TlsProtocolVersion(TlsVersion.TLS1_2):
            return response_message.extensions.get_item_by_type(TlsExtensionType.KEY_SHARE).selected_group

        try:
            supported_curve, _ = parse_ecdh_params(response_message.param_bytes)
        except NotImplementedError as e:
            if isinstance(e.args[0], TlsNamedCurve):
                supported_curve = TlsNamedCurve(e.args[0])
            else:
                raise e

        return supported_curve

    @staticmethod
    def _get_server_key_exchange(analyzable, client_hello, protocol_version, checkable_curves, extension_supported):
        try:
            return AnalyzerCurves._get_response_message(analyzable, client_hello, protocol_version)
        except TlsAlert as e:
            if checkable_curves is None:
                acceptable_alerts = AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS + [
                    TlsAlertDescription.PROTOCOL_VERSION,
                    TlsAlertDescription.UNRECOGNIZED_NAME,
                ]
                if e.description in acceptable_alerts:
                    extension_supported = None
                    six.raise_from(StopIteration(extension_supported), e)

            if e.description in AnalyzerTlsBase._ACCEPTABLE_HANDSHAKE_FAILURE_ALERTS:
                six.raise_from(StopIteration(extension_supported), e)

            raise e
        except SecurityError as e:
            if checkable_curves is None:
                extension_supported = None

            six.raise_from(StopIteration(extension_supported), e)
        finally:
            del client_hello.extensions[-1]

        # cannot be reached as exception has been raised, just a pylint bug workaround
        raise NotImplementedError()

    def analyze(self, analyzable, protocol_version):
        supported_curves = OrderedDict()
        checkable_curves = None
        extension_supported = True

        while True:
            client_hello = TlsHandshakeClientHelloKeyExchangeECDHx(
                protocol_version, analyzable.address, named_curves=checkable_curves,
            )
            try:
                server_key_exchange = self._get_server_key_exchange(
                    analyzable, client_hello, protocol_version, checkable_curves, extension_supported
                )
            except StopIteration as e:
                extension_supported = e.args[0]
                break

            if server_key_exchange is None:
                break

            if checkable_curves is None:
                # initial curve list comes from the generated client hello
                checkable_curves = client_hello.extensions.get_item_by_type(
                    TlsExtensionType.SUPPORTED_GROUPS
                ).elliptic_curves

            supported_curve = self.get_supported_curve(protocol_version, server_key_exchange)

            try:
                checkable_curves.remove(supported_curve)
            except ValueError:
                # choosen curve is an already checked one
                extension_supported = False
                break

            LogSingleton().log(level=60, msg=six.u('Server offers elliptic-curve %s') % (
                supported_curve.value.named_group.name,
            ))
            supported_curves.update([(supported_curve.name, supported_curve), ])

        return AnalyzerResultCurves(
            AnalyzerTargetTls.from_l7_client(analyzable, protocol_version),
            list(supported_curves.values()),
            extension_supported
        )
