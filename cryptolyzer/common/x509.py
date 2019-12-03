# -*- coding: utf-8 -*-

import abc
import base64
import datetime
import ssl

from collections import OrderedDict
from six import iteritems

import cryptography
import cryptography.x509 as cryptography_x509  # pylint: disable=import-error
import cryptography.hazmat.primitives.asymmetric.rsa as cryptography_rsa
import cryptography.hazmat.primitives.asymmetric.ec as cryptography_ec
from cryptography.hazmat.primitives.asymmetric import padding as cryptography_padding
from cryptography.hazmat.primitives import hashes as cryptography_hashes  # pylint: disable=import-error
from cryptography.hazmat.primitives import serialization as cryptography_serialization  # pylint: disable=import-error
from cryptography.hazmat.backends import default_backend as cryptography_default_backend  # pylint: disable=import-error

from cryptoparser.common.algorithm import MAC
from cryptoparser.common.base import Serializable

import cryptolyzer.common.utils


def is_subject_matches(common_names, subject_alternative_names, host_name):
    try:
        ssl.match_hostname({
            'subject': (tuple([('commonName', name) for name in common_names]),),
            'subjectAltName': tuple([('DNS', name) for name in subject_alternative_names]),
        }, host_name)
    except ssl.CertificateError:
        return False

    return True


class PublicKey(Serializable):
    @property
    @abc.abstractmethod
    def valid_not_before(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def valid_not_after(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def validity_period(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def validity_remaining_time(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def key_type(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def key_size(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def signature_hash_algorithm(self):
        raise NotImplementedError()

    @property
    @abc.abstractmethod
    def fingerprints(self):
        raise NotImplementedError()


class PublicKeyX509(PublicKey):
    _EV_OIDS_BY_CA = {
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

    def __init__(self, certificate):
        self._certificate = certificate

    def __eq__(self, other):
        self_in_der_format = self._certificate.public_key().public_bytes(
            encoding=cryptography_serialization.Encoding.DER,
            format=cryptography_serialization.PublicFormat.SubjectPublicKeyInfo
        )
        other_in_der_format = other._certificate.public_key().public_bytes(  # pylint: disable=protected-access
            encoding=cryptography_serialization.Encoding.DER,
            format=cryptography_serialization.PublicFormat.SubjectPublicKeyInfo
        )

        return self_in_der_format == other_in_der_format

    @property
    def valid_not_before(self):
        return self._certificate.not_valid_before

    @property
    def valid_not_after(self):
        return self._certificate.not_valid_after

    @property
    def expired(self):
        return datetime.datetime.now() > self._certificate.not_valid_after

    @property
    def validity_period(self):
        return self._certificate.not_valid_after - self._certificate.not_valid_before

    @property
    def validity_remaining_time(self):
        now = datetime.datetime.now()
        return self._certificate.not_valid_after - now if now < self._certificate.not_valid_after else None

    @property
    def key_type(self):
        return type(self._certificate.public_key()).__name__[1:-len('PublicKey')]

    @property
    def key_size(self):
        return self._certificate.public_key().key_size

    @property
    def signature_hash_algorithm(self):
        return MAC[self._certificate.signature_hash_algorithm.name.upper()]

    @property
    def fingerprints(self):
        return {
            mac: cryptolyzer.common.utils.bytes_to_colon_separated_hex(self._certificate.fingerprint(hash_algo()))
            for mac, hash_algo in (
                (MAC.SHA256, cryptography_hashes.SHA256),
                (MAC.SHA1, cryptography_hashes.SHA1),
                (MAC.MD5, cryptography_hashes.MD5),
            )
        }

    @property
    def public_key_pin(self):
        public_key_in_der_format = self._certificate.public_key().public_bytes(
            encoding=cryptography_serialization.Encoding.DER,
            format=cryptography_serialization.PublicFormat.SubjectPublicKeyInfo
        )

        digest = cryptography_hashes.Hash(cryptography_hashes.SHA256(), backend=cryptography_default_backend())
        digest.update(public_key_in_der_format)

        return base64.b64encode(digest.finalize()).decode('ascii')

    @property
    def extended_validation(self):
        try:
            extension = self._certificate.extensions.get_extension_for_class(
                cryptography_x509.CertificatePolicies
            )
            for policy_information in extension.value:
                for ca_ev_oid_list in self._EV_OIDS_BY_CA.values():
                    if policy_information.policy_identifier.dotted_string in ca_ev_oid_list:
                        return True
        except cryptography_x509.ExtensionNotFound:
            return False

        return False

    @property
    def subject(self):
        return list(self._certificate.subject)

    @property
    def issuer(self):
        return list(self._certificate.issuer)

    @property
    def common_names(self):
        return [
            attr.value
            for attr in self._certificate.subject.get_attributes_for_oid(cryptography_x509.oid.NameOID.COMMON_NAME)
        ]

    @property
    def subject_alternative_names(self):
        try:
            extension = self._certificate.extensions.get_extension_for_class(
                cryptography_x509.SubjectAlternativeName
            )
        except cryptography_x509.ExtensionNotFound:
            return []
        else:
            return extension.value.get_values_for_type(cryptography_x509.DNSName)

    @property
    def crl_distribution_points(self):
        try:
            extension = self._certificate.extensions.get_extension_for_class(
                cryptography_x509.CRLDistributionPoints
            )
        except cryptography_x509.ExtensionNotFound:
            return []
        else:
            crl_distribution_points = []
            for distribution_point in extension.value:
                if distribution_point.full_name:
                    for full_name in distribution_point.full_name:
                        crl_distribution_points.append(full_name.value)
                elif distribution_point.relative_name:
                    attributes = distribution_point.relative_name.get_attributes_for_oid(
                        cryptography_x509.oid.NameOID.COMMON_NAME
                    )
                    for relative_name in attributes:
                        crl_distribution_points.append(relative_name.value)

            return crl_distribution_points

    @property
    def ocsp_responders(self):
        try:
            extension = self._certificate.extensions.get_extension_for_class(
                cryptography_x509.AuthorityInformationAccess
            )
        except cryptography_x509.ExtensionNotFound:
            return []
        else:
            return [
                access_description.access_location.value
                for access_description in extension.value
                if access_description.access_method == cryptography_x509.AuthorityInformationAccessOID.OCSP
            ]

    @property
    def is_ca(self):
        ca_type = cryptography_default_backend()._lib.X509_check_ca(  # pylint: disable=protected-access
            self._certificate._x509  # pylint: disable=protected-access
        )
        return ca_type > 0

    @property
    def is_self_signed(self):
        return self._certificate.subject and self._certificate.subject == self._certificate.issuer

    def verify(self, public_key):
        verify_args = {
            'signature': public_key._certificate.signature,  # pylint: disable=protected-access
            'data': public_key._certificate.tbs_certificate_bytes,  # pylint: disable=protected-access
        }
        public_key_signature_hash_algorithm = \
            public_key._certificate.signature_hash_algorithm  # pylint: disable=protected-access
        if isinstance(self._certificate.public_key(), cryptography_rsa.RSAPublicKey):
            verify_args['padding'] = cryptography_padding.PKCS1v15()
            verify_args['algorithm'] = public_key_signature_hash_algorithm
        if isinstance(self._certificate.public_key(), cryptography_ec.EllipticCurvePublicKey):
            verify_args['signature_algorithm'] = cryptography_ec.ECDSA(
                public_key_signature_hash_algorithm
            )
        else:
            verify_args['algorithm'] = public_key_signature_hash_algorithm

        try:
            self._certificate.public_key().verify(**verify_args)
        except cryptography.exceptions.InvalidSignature:
            return False

        return True

    def _asdict(self):
        return OrderedDict([
            ('serial_number', str(self._certificate.serial_number)),
            ('subject', OrderedDict(
                [
                    (attribute.oid._name, attribute.value)  # pylint: disable=protected-access
                    for attribute in self.subject
                ]
            )),
            ('subject_alternative_names', sorted(self.subject_alternative_names)),
            ('issuer', OrderedDict(
                [
                    (attribute.oid._name, attribute.value)  # pylint: disable=protected-access
                    for attribute in self.issuer
                ]
            )),
            ('key_type', self.key_type),
            ('key_size', self.key_size),
            ('signature_hash_algorithm', self.signature_hash_algorithm),
            ('extended_validation', self.extended_validation),
            ('validity', OrderedDict([
                ('not_before', str(self.valid_not_before)),
                ('not_after', str(self.valid_not_after)),
                ('period', str(self.validity_period)),
                ('remaining', str(self.validity_remaining_time.days) if self.validity_remaining_time else None),
            ])),
            ('revocation', OrderedDict([
                ('crl_distribution_points', self.crl_distribution_points),
                ('ocsp_responders', self.ocsp_responders),
            ])),
            ('fingerprints', {mac.name: fingerprint for (mac, fingerprint) in iteritems(self.fingerprints)}),
            ('public_key_pin', self.public_key_pin),
            ('version', self._certificate.version.name),
        ])
