#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import datetime
import cryptography.x509

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

from collections import OrderedDict

from cryptoparser.common.exception import NetworkError, NetworkErrorType
from cryptoparser.tls.client import TlsAlert, \
    TlsHandshakeClientHelloBasic, \
    TlsHandshakeClientHelloAuthenticationDSS, \
    TlsHandshakeClientHelloAuthenticationRSA, \
    TlsHandshakeClientHelloAuthenticationECDSA
from cryptoparser.tls.subprotocol import TlsHandshakeType, TlsAlertDescription

from cryptolyzer.common.analyzer import AnalyzerTlsBase, AnalyzerResultBase


class AnalyzerResultPublicKeys(AnalyzerResultBase):
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
        EXTENDED_VALIDATION_OIDs = {
            'A-Trust': '1.2.40.0.17.1.22',
            'Actalis': '1.3.159.1.17.1',
            'AffirmTrust': '1.3.6.1.4.1.34697.2.1',
            'AffirmTrust': '1.3.6.1.4.1.34697.2.2',
            'AffirmTrust': '1.3.6.1.4.1.34697.2.3',
            'AffirmTrust': '1.3.6.1.4.1.34697.2.4',
            'Buypass': '2.16.578.1.26.1.3.3',
            'Camerfirma': '1.3.6.1.4.1.17326.10.14.2.1.2',
            'Camerfirma': '1.3.6.1.4.1.17326.10.8.12.1.2',
            'Comodo Group': '1.3.6.1.4.1.6449.1.2.1.5.1',
            'DigiCert': '2.16.840.1.114412.1.3.0.2',
            'DigiCert': '2.16.840.1.114412.2.1',
            'DigiNotar (defunct)[10]': '2.16.528.1.1001.1.1.1.12.6.1.1.1',
            'E-Tugra': '2.16.792.3.0.4.1.1.4',
            'ETSI': '0.4.0.2042.1.4',
            'ETSI': '0.4.0.2042.1.5',
            'Entrust': '2.16.840.1.114028.10.1.2',
            'Firmaprofesional': '1.3.6.1.4.1.13177.10.1.3.10',
            'GeoTrust': '1.3.6.1.4.1.14370.1.6',
            'GlobalSign': '1.3.6.1.4.1.4146.1.1',
            'Go Daddy': '2.16.840.1.114413.1.7.23.3',
            'Izenpe': '1.3.6.1.4.1.14777.6.1.1',
            'Kamu Sertifikasyon Merkezi': '2.16.792.1.2.1.1.5.7.1.9',
            'Logius PKIoverheid': '2.16.528.1.1003.1.2.7',
            'Network Solutions': '1.3.6.1.4.1.782.1.2.1.8.1',
            'OpenTrust/DocuSign France': '1.3.6.1.4.1.22234.2.5.2.3.1',
            'QuoVadis': '1.3.6.1.4.1.8024.0.2.100.1.2',
            'SECOM Trust Systems': '1.2.392.200091.100.721.1',
            'SHECA': '1.2.156.112570.1.1.3',
            'Starfield Technologies': '2.16.840.1.114414.1.7.23.3',
            'StartCom Certification Authority': '1.3.6.1.4.1.23223.1.1.1',
            'StartCom Certification Authority': '1.3.6.1.4.1.23223.2',
            'SwissSign': '2.16.756.1.89.1.2.1.1',
            'Swisscom': '2.16.756.1.83.21.0',
            'Symantec (VeriSign)': '2.16.840.1.113733.1.7.23.6',
            'T-Systems': '1.3.6.1.4.1.7879.13.24.1',
            'Thawte': '2.16.840.1.113733.1.7.48.1',
            'Trustwave': '2.16.840.1.114404.1.1.2.4.1',
            'Verizon Business (formerly Cybertrust)': '1.3.6.1.4.1.6334.1.100.1',
            'Wells Fargo': '2.16.840.1.114171.500.9',
            'WoSign': '1.3.6.1.4.1.36305.2',
        }

        try:
            extension = certificate.extensions.get_extension_for_class(
                cryptography.x509.CertificatePolicies
            )
            extended_validation_oids = EXTENDED_VALIDATION_OIDs.values()
            for policy_information in extension.value:
                if policy_information.policy_identifier.dotted_string in extended_validation_oids:
                    return True
            else:
                return False
        except cryptography.x509.ExtensionNotFound:
            return False

    @staticmethod
    def _get_fingerprints(certificate):
        return {
           hash_algo.name: AnalyzerResultBase._bytes_to_colon_separated_hex(certificate.fingerprint(hash_algo()))
           for hash_algo in [ hashes.SHA256, hashes.SHA1, hashes.MD5 ]
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
            for tls_certificate in tls_certificate_chain:
                certificate  = tls_certificate._certificate
                subject_alternative_names = self._get_subject_alternative_names(certificate)
                extended_validation = self._get_extended_validation(certificate)
                fingerprints = self._get_fingerprints(certificate)
                public_key_pin = self._get_public_key_pin(certificate)

                certificate_chain.append(OrderedDict([
                    ('serial_number', str(certificate.serial_number)),
                    ('subject', OrderedDict(
                        [
                            (str(attribute.oid._name), attribute.value)
                            for attribute in certificate.subject
                        ]
                    )),
                    ('subject', OrderedDict(
                        [
                            (str(attribute.oid._name), attribute.value)
                            for attribute in certificate.subject
                        ]
                    )),
                    ('subject_alternative_names', sorted(subject_alternative_names)),
                    ('issuer', OrderedDict(
                        [
                            (str(attribute.oid._name), attribute.value)
                            for attribute in certificate.issuer
                        ]
                    )),
                    ('key_type', type(certificate.public_key()).__name__[1:-len('PublicKey')]),
                    ('key_size', certificate.public_key().key_size),
                    ('signature_algorithm', certificate.signature_algorithm_oid._name),
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

    def analyze(self, l7_client, protocol_version):
        certificate_chains = set()
        client_hello_messages = [
            TlsHandshakeClientHelloBasic(),
            TlsHandshakeClientHelloAuthenticationDSS(l7_client.host),
            TlsHandshakeClientHelloAuthenticationRSA(l7_client.host),
            TlsHandshakeClientHelloAuthenticationECDSA(l7_client.host),
        ]

        for client_hello in client_hello_messages:
            try:
                server_messages = l7_client.do_tls_handshake(
                    client_hello,
                    client_hello.protocol_version,
                    TlsHandshakeType.CERTIFICATE
                )
            except TlsAlert as e:
                if e.description != TlsAlertDescription.HANDSHAKE_FAILURE:
                    raise e
            except NetworkError as e:
                if e.error != NetworkErrorType.NO_RESPONSE:
                    raise e
            else:
                certificate_chains.add(server_messages[TlsHandshakeType.CERTIFICATE].certificate_chain)

        return AnalyzerResultPublicKeys(certificate_chains)
