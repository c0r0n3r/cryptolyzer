#!/usr/bin/env python
# -*- coding: utf-8 -*-

import base64

import cryptography.x509 as cryptography_x509
from cryptography.hazmat.primitives import hashes as cryptography_hashes
from cryptography.hazmat.primitives import serialization as cryptography_serialization
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
