#!/usr/bin/env python
# -*- coding: utf-8 -*-

import datetime

from collections import OrderedDict

import cryptography.x509  # pylint: disable=import-error

from cryptoparser.tls.extension import TlsExtensionCertificateStatusRequest
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase, AnalyzerResultBase
from cryptolyzer.tls.client import TlsAlert, \
    TlsHandshakeClientHelloBasic, \
    TlsHandshakeClientHelloAuthenticationDSS, \
    TlsHandshakeClientHelloAuthenticationRSA, \
    TlsHandshakeClientHelloAuthenticationECDSA
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common import x509 as x509


class TlsPublicKey(object):  # pylint: disable=too-few-public-methods
    def __init__(self, certificate_bytes, certificate_chain, certificate_status):
        self._certificate_bytes = certificate_bytes
        self.certificate_chain = certificate_chain
        self.certificate_status = certificate_status

    def __hash__(self):
        return hash((bytes(certificate_byte) for certificate_byte in self._certificate_bytes))


class AnalyzerResultPublicKeys(AnalyzerResultBase):  # pylint: disable=too-few-public-methods
    def __init__(self, tls_public_keys):
        now = datetime.datetime.utcnow()

        self.public_keys = []
        for tls_public_key in tls_public_keys:
            certificate_chain = []
            for certificate in tls_public_key.certificate_chain:
                ocsp_responders = x509.get_ocsp_responders(certificate)
                has_ocsp_must_staple = x509.has_ocsp_must_staple(certificate)
                ocsp_staple = x509.get_ocsp_staple(
                    tls_public_key.certificate_status,
                    tls_public_key.certificate_chain[1], now
                )
                ca_issuers = x509.get_ca_issuers(certificate)
                crl_distribution_points = x509.get_crl_distribution_points(certificate)
                subject_alternative_names = x509.get_subject_alternative_names(certificate)
                extended_validation = x509.is_extended_validation(certificate)
                hashes_and_pins = x509.get_hashes(certificate)
                scts = x509.get_scts(certificate)

                certificate_chain.append(OrderedDict([
                    ('identity', OrderedDict([
                        ('version', certificate.version.name),
                        ('serial_number', str(certificate.serial_number)),
                        ('subject', x509.get_name_as_dict(certificate.subject)),
                        ('subject_alternative_names', sorted(subject_alternative_names)),
                        ('issuer', x509.get_name_as_dict(certificate.issuer)),
                        ('key_type', type(certificate.public_key()).__name__[1:-len('PublicKey')]),
                        ('key_size', certificate.public_key().key_size),
                        ('signature_algorithm', certificate.signature_algorithm_oid._name),
                        ('hashes', hashes_and_pins),
                    ])),
                    ('validity', OrderedDict([
                        ('not_before', certificate.not_valid_before),
                        ('not_after', certificate.not_valid_after),
                        ('period', certificate.not_valid_after - certificate.not_valid_before),
                        ('remaining', certificate.not_valid_after - now if now < certificate.not_valid_after else None),
                        ('extended_validation', extended_validation),
                        ('crl_distribution_points', list(map(lambda cdp: cdp.url, crl_distribution_points))),
                        ('ca_issuers', list(map(lambda ocsp: ocsp.url, ca_issuers))),
                        ('ocsp_responders', list(map(lambda ocsp: ocsp.url, ocsp_responders))),
                        ('ocsp_must_staple', has_ocsp_must_staple),
                        ('ocsp_staple', ocsp_staple),
                        ('scts', scts),
                    ])),
                ]))

            self.public_keys.append(certificate_chain)


class AnalyzerPublicKeys(AnalyzerTlsBase):
    @classmethod
    def get_name(cls):
        return 'pubkeys'

    @classmethod
    def get_help(cls):
        return 'Check which certificate used by the server(s)'

    @staticmethod
    def _get_tls_public_key(server_messages):
        certificate_chain = []
        certificate_bytes = []

        for tls_certificate in server_messages[TlsHandshakeType.CERTIFICATE].certificate_chain:
            try:
                certificate = cryptography.x509.load_der_x509_certificate(
                    bytes(tls_certificate.certificate),
                    cryptography.hazmat.backends.default_backend()
                )
            except ValueError:
                pass
            else:
                certificate_bytes.append(tls_certificate.certificate)
                certificate_chain.append(certificate)

        certificate_status = \
            server_messages[TlsHandshakeType.CERTIFICATE_STATUS].status \
            if TlsHandshakeType.CERTIFICATE_STATUS in server_messages \
            else None

        return TlsPublicKey(
            certificate_bytes=certificate_bytes,
            certificate_chain=certificate_chain,
            certificate_status=certificate_status
        )

    @staticmethod
    def _is_cn_matches(common_name, host_name):
        hostname_parts = host_name.split('.')
        cn_parts = common_name.split('.')

        for index in range(-1, -len(hostname_parts) - 1, -1):
            if index < -len(cn_parts):
                return False
            if cn_parts[index] == '*':
                return True
            if cn_parts[index] != hostname_parts[index]:
                return False

        return True

    def _is_subject_matches(self, tls_public_key, host_name):
        cert = tls_public_key.certificate_chain[0]
        common_names = [
            attr.value
            for attr in cert.subject.get_attributes_for_oid(cryptography.x509.oid.NameOID.COMMON_NAME)
        ]

        subject_altname_extension = cert.extensions.get_extension_for_oid(
            cryptography.x509.ExtensionOID.SUBJECT_ALTERNATIVE_NAME
        )
        subject_alternative_names = subject_altname_extension.value.get_values_for_type(cryptography.x509.DNSName)

        for name in common_names + subject_alternative_names:
            if self._is_cn_matches(name, host_name):
                return True

        return False

    def analyze(self, l7_client, protocol_version):
        tls_public_keys = set()
        client_hello_messages = [
            TlsHandshakeClientHelloBasic(),
            TlsHandshakeClientHelloAuthenticationDSS(l7_client.host),
            TlsHandshakeClientHelloAuthenticationRSA(l7_client.host),
            TlsHandshakeClientHelloAuthenticationECDSA(l7_client.host),
        ]

        for client_hello in client_hello_messages:
            try:
                client_hello.protocol_version = protocol_version
                client_hello.extensions.append(TlsExtensionCertificateStatusRequest())
                server_messages = l7_client.do_tls_handshake(
                    client_hello,
                    client_hello.protocol_version,
                    TlsHandshakeType.SERVER_HELLO_DONE,
                )
            except TlsAlert as e:
                if (e.description != TlsAlertDescription.HANDSHAKE_FAILURE and
                        e.description != TlsAlertDescription.PROTOCOL_VERSION):
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            else:
                tls_public_key = self._get_tls_public_key(server_messages)
                if (isinstance(client_hello, TlsHandshakeClientHelloBasic) and
                        not self._is_subject_matches(tls_public_key, l7_client.host)):
                    continue
                tls_public_keys.add(tls_public_key)

        return AnalyzerResultPublicKeys(list(tls_public_keys))
