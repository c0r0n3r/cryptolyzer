#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64
import datetime
import urllib3

from collections import OrderedDict

import cryptography.exceptions as cryptography_exceptions
import cryptography.x509 as cryptography_x509
from cryptography.hazmat.primitives import hashes as cryptography_hashes
from cryptography.hazmat.primitives import padding as cryptography_padding
from cryptography.hazmat.primitives import serialization as cryptography_serialization
from cryptography.hazmat.primitives.asymmetric import rsa as cryptography_rsa
from cryptography.hazmat.primitives.asymmetric import ec as cryptography_ec
from cryptography.hazmat.backends import default_backend as cryptography_default_backend

import cryptolyzer.common.utils as utils


def get_subject_alternative_names(certificate):
    try:
        extension = certificate.extensions.get_extension_for_class(
            cryptography_x509.SubjectAlternativeName
        )
    except cryptography_x509.ExtensionNotFound:
        return []
    else:
        return extension.value.get_values_for_type(cryptography_x509.DNSName)

def get_name_as_dict(name):
    return OrderedDict(
        [
            (str(attribute.oid._name), attribute.value)  # pylint: disable=protected-access
            for attribute in name
        ]
    )


def is_extended_validation(certificate):
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
            cryptography_x509.CertificatePolicies
        )
        for policy_information in extension.value:
            for ca_ev_oid_list in ev_oids_by_ca.values():
                if policy_information.policy_identifier.dotted_string in ca_ev_oid_list:
                    return True
    except cryptography_x509.ExtensionNotFound:
        return False

    return False


def get_fingerprints(certificate):
    return {
        hash_algo.name: utils.bytes_to_colon_separated_hex(certificate.fingerprint(hash_algo()))
        for hash_algo in (cryptography_hashes.SHA256, cryptography_hashes.SHA1, cryptography_hashes.MD5)
    }


def get_public_key_pin(certificate):
    public_key_in_der_format = certificate.public_key().public_bytes(
        encoding=cryptography_serialization.Encoding.DER,
        format=cryptography_serialization.PublicFormat.SubjectPublicKeyInfo
    )

    digest = cryptography_hashes.Hash(cryptography_hashes.SHA256(), backend=cryptography_default_backend())
    digest.update(public_key_in_der_format)

    return base64.b64encode(digest.finalize())


def get_hashes(certificate):
    hash_dict = OrderedDict()

    for hash_algo in [cryptography_hashes.SHA1, cryptography_hashes.SHA256]:
        hash_dict[hash_algo.name] = utils.bytes_to_colon_separated_hex(certificate.fingerprint(hash_algo()))

    public_key_in_der_format = certificate.public_key().public_bytes(
        encoding=cryptography_serialization.Encoding.DER,
        format=cryptography_serialization.PublicFormat.SubjectPublicKeyInfo
    )
    hash_dict['spki_sha256'] = utils.bytes_to_colon_separated_hex(
        utils.get_hash(public_key_in_der_format, cryptography_hashes.SHA256)
    )
    hash_dict['subject_spki_sha256'] = utils.bytes_to_colon_separated_hex(
        utils.get_hash(certificate.subject.public_bytes(
            backend=cryptography_default_backend()
        ) + public_key_in_der_format, cryptography_hashes.SHA256)
    )
    hash_dict['hpkp_sha256'] = utils.base64_encode(
        utils.get_hash(public_key_in_der_format, hash_algo)
    )

    return hash_dict


def get_crl_distribution_points(certificate):
    try:
        extension = certificate.extensions.get_extension_for_class(
            cryptography_x509.CRLDistributionPoints
        )
    except cryptography_x509.ExtensionNotFound:
        return []

    urls = []
    for distribution_point in extension.value:
        for name in distribution_point.full_name:
            urls.append(urllib3.util.parse_url(name.value))

    return urls


def get_ocsp_responders(certificate):
    try:
        extension = certificate.extensions.get_extension_for_class(
            cryptography_x509.AuthorityInformationAccess
        )
    except cryptography_x509.ExtensionNotFound:
        return []

    ocsp_responders = [
        urllib3.util.parse_url(access_description.access_location.value)
        for access_description in extension.value
        if access_description.access_method == cryptography_x509.oid.AuthorityInformationAccessOID.OCSP
    ]

    return ocsp_responders


def has_ocsp_must_staple(certificate):
    try:
        certificate.extensions.get_extension_for_class(cryptography_x509.TLSFeature)
    except cryptography_x509.ExtensionNotFound:
        return False

    return True


def get_ocsp_staple(certificate_status, issuer_certificate, now=datetime.datetime.utcnow()):
    if not certificate_status:
        return OrderedDict()

    ca_public_key = issuer_certificate.public_key()
    ocsp_response = cryptography_x509.ocsp.load_der_ocsp_response(bytes(certificate_status))

    try:
        """
        if isinstance(ca_public_key, cryptography_ec.EllipticCurvePublicKey):
            ca_public_key.verify(
                basic_ocsp_response['signature'].native,
                basic_ocsp_response['tbs_response_data'].dump(),
                cryptography_ec.ECDSA(cryptography_hashes.SHA384())
            )
        elif isinstance(ca_public_key, cryptography_rsa.RSAPublicKey):
            ca_public_key.verify(
                basic_ocsp_response['signature'].native,
                basic_ocsp_response['tbs_response_data'].dump(),
                cryptography_padding.PKCS1v15(),
                cryptography_hashes.SHA256(),
            )
        else:
            raise NotImplementedError
        """
    except cryptography_exceptions.InvalidSignature:
        verified = False
    else:
        verified = True

    #single_response = basic_ocsp_response['tbs_response_data']['responses'][0]

    if ocsp_response.response_status != cryptography_x509.ocsp.OCSPResponseStatus.SUCCESSFUL:
        return OrderedDict()

    ocsp_staple = OrderedDict([
        ('status', ocsp_response.response_status.name.lower()),
        ('certificate_status', ocsp_response.certificate_status.name.lower()),
        ('responder_name', get_name_as_dict(ocsp_response.responder_name)),
        ('produced_at', ocsp_response.produced_at),
        ('this_update', ocsp_response.this_update),
        ('next_update', ocsp_response.next_update),
        ( 'period', ocsp_response.next_update - ocsp_response.this_update),
        (
            'remaining',
            ocsp_response.next_update.replace(tzinfo=None) - now
            if now < ocsp_response.next_update.replace(tzinfo=None)
            else None
        ),
        ('revocation_time', ocsp_response.revocation_time),
        ('revocation_reason', ocsp_response.revocation_reason),
        ('hash_algorithm', ocsp_response.hash_algorithm.name),
        ('issuer_name_hash', utils.bytes_to_colon_separated_hex(ocsp_response.issuer_name_hash)),
        ('issuer_key_hash', utils.bytes_to_colon_separated_hex(ocsp_response.issuer_key_hash)),
        ('serial_number', str(ocsp_response.serial_number)),
    ])

    return ocsp_staple


def get_ca_issuers(certificate):
    try:
        extension = certificate.extensions.get_extension_for_class(
            cryptography_x509.AuthorityInformationAccess
        )
    except cryptography_x509.ExtensionNotFound:
        return []

    ca_issuers = [
        urllib3.util.parse_url(access_description.access_location.value)
        for access_description in extension.value
        if access_description.access_method == cryptography_x509.oid.AuthorityInformationAccessOID.CA_ISSUERS
    ]

    return ca_issuers


def get_scts(certificate):
    try:
        extension = certificate.extensions.get_extension_for_class(
            cryptography_x509.PrecertificateSignedCertificateTimestamps
        )
    except cryptography_x509.ExtensionNotFound:
        return []

    scts = [
        OrderedDict([
            ('log_id', utils.base64_encode(sct.log_id)),
            ('timestamp', sct.timestamp),
        ])
        for sct in extension.value
    ]

    return scts
