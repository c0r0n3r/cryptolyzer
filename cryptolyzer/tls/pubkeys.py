#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import datetime

from collections import OrderedDict

import cryptography.x509  # pylint: disable=import-error

from cryptography.hazmat.backends import default_backend  # pylint: disable=import-error
from cryptography.hazmat.primitives import hashes  # pylint: disable=import-error
from cryptography.hazmat.primitives import serialization  # pylint: disable=import-error

from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase, AnalyzerResultBase
from cryptolyzer.tls.client import TlsAlert, \
    TlsHandshakeClientHelloBasic, \
    TlsHandshakeClientHelloAuthenticationDSS, \
    TlsHandshakeClientHelloAuthenticationRSA, \
    TlsHandshakeClientHelloAuthenticationECDSA
from cryptolyzer.common.exception import NetworkError, NetworkErrorType


class TlsPublicKey(object):  # pylint: disable=too-few-public-methods
    def __init__(self, certificate_bytes, certificate_chain, certificate_status):
        self._certificate_bytes = certificate_bytes
        self.certificate_chain = certificate_chain
        self.certificate_status = certificate_status

    def __hash__(self):
        return hash((bytes(certificate_byte) for certificate_byte in self._certificate_bytes))


class AnalyzerResultPublicKeys(AnalyzerResultBase):  # pylint: disable=too-few-public-methods
    @staticmethod
    def _get_subject_alternative_names(certificate):
        try:
            extension = certificate.extensions.get_extension_for_class(
                cryptography.x509.SubjectAlternativeName
            )
        except cryptography.x509.ExtensionNotFound:
            return []
        else:
            return extension.value.get_values_for_type(cryptography.x509.DNSName)

    @staticmethod
    def _get_extended_validation(certificate):
        ev_oids_by_ca = {
            'A-Trust': ('1.2.40.0.17.1.22', ),
            'Actalis': ('1.3.159.1.17.1', ),
            'AffirmTrust': (
                '1.3.6.1.4.1.34697.2.1',
                '1.3.6.1.4.1.34697.2.2',
                '1.3.6.1.4.1.34697.2.3',
                '1.3.6.1.4.1.34697.2.4',
            ),
            'Buypass': ('2.16.578.1.26.1.3.3', ),
            'Camerfirma': (
                '1.3.6.1.4.1.17326.10.14.2.1.2',
                '1.3.6.1.4.1.17326.10.8.12.1.2',
            ),
            'Comodo Group': ('1.3.6.1.4.1.6449.1.2.1.5.1', ),
            'DigiCert': (
                '2.16.840.1.114412.1.3.0.2',
                '2.16.840.1.114412.2.1',
            ),
            'DigiNotar': ('2.16.528.1.1001.1.1.1.12.6.1.1.1', ),
            'E-Tugra': ('2.16.792.3.0.4.1.1.4', ),
            'ETSI': (
                '0.4.0.2042.1.4',
                '0.4.0.2042.1.5',
            ),
            'Entrust': ('2.16.840.1.114028.10.1.2', ),
            'Firmaprofesional': ('1.3.6.1.4.1.13177.10.1.3.10', ),
            'GeoTrust': ('1.3.6.1.4.1.14370.1.6', ),
            'GlobalSign': ('1.3.6.1.4.1.4146.1.1', ),
            'Go Daddy': ('2.16.840.1.114413.1.7.23.3', ),
            'Izenpe': ('1.3.6.1.4.1.14777.6.1.1', ),
            'Kamu Sertifikasyon Merkezi': ('2.16.792.1.2.1.1.5.7.1.9', ),
            'Logius PKIoverheid': ('2.16.528.1.1003.1.2.7', ),
            'Network Solutions': ('1.3.6.1.4.1.782.1.2.1.8.1', ),
            'OpenTrust/DocuSign France': ('1.3.6.1.4.1.22234.2.5.2.3.1', ),
            'QuoVadis': ('1.3.6.1.4.1.8024.0.2.100.1.2', ),
            'SECOM Trust Systems': ('1.2.392.200091.100.721.1', ),
            'SHECA': ('1.2.156.112570.1.1.3', ),
            'Starfield Technologies': ('2.16.840.1.114414.1.7.23.3', ),
            'StartCom Certification Authority': (
                '1.3.6.1.4.1.23223.1.1.1',
                '1.3.6.1.4.1.23223.2',
            ),
            'SwissSign': ('2.16.756.1.89.1.2.1.1', ),
            'Swisscom': ('2.16.756.1.83.21.0', ),
            'Symantec (VeriSign)': ('2.16.840.1.113733.1.7.23.6', ),
            'T-Systems': ('1.3.6.1.4.1.7879.13.24.1', ),
            'Thawte': ('2.16.840.1.113733.1.7.48.1', ),
            'Trustwave': ('2.16.840.1.114404.1.1.2.4.1', ),
            'Verizon Business (formerly Cybertrust)': ('1.3.6.1.4.1.6334.1.100.1', ),
            'Wells Fargo': ('2.16.840.1.114171.500.9', ),
            'WoSign': ('1.3.6.1.4.1.36305.2', ),
        }

        try:
            extension = certificate.extensions.get_extension_for_class(
                cryptography.x509.CertificatePolicies
            )
            for policy_information in extension.value:
                for ca_ev_oid_list in ev_oids_by_ca.values():
                    if policy_information.policy_identifier.dotted_string in ca_ev_oid_list:
                        return True
        except cryptography.x509.ExtensionNotFound:
            return False

        return False

    @staticmethod
    def _get_fingerprints(certificate):
        return {
            hash_algo.name: AnalyzerResultBase._bytes_to_colon_separated_hex(certificate.fingerprint(hash_algo()))
            for hash_algo in (hashes.SHA256, hashes.SHA1, hashes.MD5)
        }

    @staticmethod
    def _get_public_key_pin(certificate):
        public_key_in_der_format = certificate.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(public_key_in_der_format)

        return base64.b64encode(digest.finalize())

    def __init__(self, tls_certificate_chains):
        now = datetime.datetime.now()

        self.certificate_chains = []
        for tls_certificate_chain in tls_certificate_chains:
            certificate_chain = []
            for certificate in tls_certificate_chain.certificate_chain:
                subject_alternative_names = self._get_subject_alternative_names(certificate)
                extended_validation = self._get_extended_validation(certificate)
                fingerprints = self._get_fingerprints(certificate)
                public_key_pin = self._get_public_key_pin(certificate)

                certificate_chain.append(OrderedDict([
                    ('serial_number', str(certificate.serial_number)),
                    ('subject', OrderedDict(
                        [
                            (str(attribute.oid._name), attribute.value)  # pylint: disable=protected-access
                            for attribute in certificate.subject
                        ]
                    )),
                    ('subject_alternative_names', sorted(subject_alternative_names)),
                    ('issuer', OrderedDict(
                        [
                            (str(attribute.oid._name), attribute.value)  # pylint: disable=protected-access
                            for attribute in certificate.issuer
                        ]
                    )),
                    ('key_type', type(certificate.public_key()).__name__[1:-len('PublicKey')]),
                    ('key_size', certificate.public_key().key_size),
                    ('signature_algorithm', (
                        certificate.signature_algorithm_oid._name  # pylint: disable=protected-access
                    )),
                    ('extended_validation', extended_validation),
                    ('validity', OrderedDict([
                        ('not_before', str(certificate.not_valid_before)),
                        ('not_after', str(certificate.not_valid_after)),
                        ('period', str(
                            certificate.not_valid_after -
                            certificate.not_valid_before
                        )),
                        ('remaining', str(
                            certificate.not_valid_after - now
                            if now < certificate.not_valid_after
                            else None
                        )),

                    ])),
                    ('fingerprints', fingerprints),
                    ('public_key_pin', str(public_key_pin, 'ascii')),
                    ('version', str(certificate.version.name)),
                ]))
            self.certificate_chains.append(certificate_chain)


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
                server_messages = l7_client.do_tls_handshake(
                    client_hello,
                    client_hello.protocol_version,
                    TlsHandshakeType.CERTIFICATE
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

        return AnalyzerResultPublicKeys(tls_public_keys)
