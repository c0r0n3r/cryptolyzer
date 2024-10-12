# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

from collections import OrderedDict

import datetime
import asn1crypto

from cryptodatahub.common.algorithm import Authentication
from cryptodatahub.common.entity import Entity

from cryptoparser.tls.extension import TlsExtensionsBase, TlsExtensionSignedCertificateTimestampServer
from cryptoparser.tls.subprotocol import TlsAlertDescription, TlsHandshakeType
from cryptoparser.tls.version import TlsVersion, TlsProtocolVersion

from cryptolyzer.common.exception import SecurityError, SecurityErrorType
from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.tls.exception import TlsAlert
from cryptolyzer.tls.pubkeys import AnalyzerPublicKeys, CertificateStatus

from .classes import TestTlsCases, L7ServerTlsTest, L7ServerTlsPlainTextResponse


OCSP_RESPONSE_GOOD = asn1crypto.ocsp.OCSPResponse.load(bytes(
    b'\x30\x82\x06\x37\x0a\x01\x00\xa0\x82\x06\x30\x30\x82\x06\x2c\x06' +
    b'\x09\x2b\x06\x01\x05\x05\x07\x30\x01\x01\x04\x82\x06\x1d\x30\x82' +
    b'\x06\x19\x30\x82\x01\x18\xa0\x03\x02\x01\x00\xa1\x81\x8a\x30\x81' +
    b'\x87\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31\x17' +
    b'\x30\x15\x06\x03\x55\x04\x0a\x13\x0e\x56\x65\x72\x69\x53\x69\x67' +
    b'\x6e\x2c\x20\x49\x6e\x63\x2e\x31\x1f\x30\x1d\x06\x03\x55\x04\x0b' +
    b'\x13\x16\x56\x65\x72\x69\x53\x69\x67\x6e\x20\x54\x72\x75\x73\x74' +
    b'\x20\x4e\x65\x74\x77\x6f\x72\x6b\x31\x3e\x30\x3c\x06\x03\x55\x04' +
    b'\x03\x13\x35\x56\x65\x72\x69\x53\x69\x67\x6e\x20\x43\x6c\x61\x73' +
    b'\x73\x20\x33\x20\x53\x65\x63\x75\x72\x65\x20\x53\x65\x72\x76\x65' +
    b'\x72\x20\x43\x41\x20\x2d\x20\x47\x32\x20\x4f\x43\x53\x50\x20\x52' +
    b'\x65\x73\x70\x6f\x6e\x64\x65\x72\x18\x0f\x32\x30\x31\x31\x30\x36' +
    b'\x30\x38\x31\x36\x31\x39\x35\x38\x5a\x30\x73\x30\x71\x30\x49\x30' +
    b'\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05\x00\x04\x14\x6c\x2b\xc5\x5a' +
    b'\xaf\x8d\x96\xbf\x60\xad\xf8\x1d\x02\x3f\x23\xb4\x8a\x00\x59\xc2' +
    b'\x04\x14\xa5\xef\x0b\x11\xce\xc0\x41\x03\xa3\x4a\x65\x90\x48\xb2' +
    b'\x1c\xe0\x57\x2d\x7d\x47\x02\x10\x30\x11\x9e\x6e\xf4\x1b\xdb\xa3' +
    b'\xfe\xfe\x71\x1d\xbe\x8f\x61\x91\x80\x00\x18\x0f\x32\x30\x31\x31' +
    b'\x30\x36\x30\x38\x31\x36\x31\x39\x35\x38\x5a\xa0\x11\x18\x0f\x32' +
    b'\x30\x31\x31\x30\x36\x31\x35\x31\x36\x31\x39\x35\x38\x5a\x30\x0d' +
    b'\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x05\x05\x00\x03\x81\x81' +
    b'\x00\x13\x96\xc6\xb0\xd5\xbf\xbd\x86\x24\x2d\x7d\x66\x04\x56\x76' +
    b'\x4d\x8d\xc9\x7c\xb2\xa3\x89\xeb\xb0\x49\x43\x96\x85\xec\xc7\xa5' +
    b'\xa2\x31\x39\x7c\x42\x1a\x6e\x96\x16\x37\x1b\xf9\x1b\xdc\x17\xb6' +
    b'\x50\x50\xcb\x19\x33\x9b\x3e\xe4\xe0\x0c\x0e\x03\x58\x88\x6d\xc6' +
    b'\x6f\xd6\x30\x8a\xb3\x62\xdc\x28\xb5\x46\x3f\x4a\x23\x9d\x06\x07' +
    b'\x69\xc8\x6e\xcc\x31\xb6\x74\x8b\xe9\x04\xf6\xf4\xff\xec\x32\xd7' +
    b'\xe0\x6b\xb2\x47\x17\x60\x27\x51\xae\x81\x22\xce\x0c\x4a\x1a\x26' +
    b'\x91\xa0\x25\xd3\x48\xa5\x2f\x45\x49\x4d\x0f\x0e\x78\x16\xcc\x82' +
    b'\x5d\xa0\x82\x04\x66\x30\x82\x04\x62\x30\x82\x04\x5e\x30\x82\x03' +
    b'\x46\xa0\x03\x02\x01\x02\x02\x10\x7a\xa6\x30\x92\x98\x6d\xf4\xa5' +
    b'\x71\x6f\x99\x3e\xc7\xa8\x3f\xff\x30\x0d\x06\x09\x2a\x86\x48\x86' +
    b'\xf7\x0d\x01\x01\x05\x05\x00\x30\x81\xb5\x31\x0b\x30\x09\x06\x03' +
    b'\x55\x04\x06\x13\x02\x55\x53\x31\x17\x30\x15\x06\x03\x55\x04\x0a' +
    b'\x13\x0e\x56\x65\x72\x69\x53\x69\x67\x6e\x2c\x20\x49\x6e\x63\x2e' +
    b'\x31\x1f\x30\x1d\x06\x03\x55\x04\x0b\x13\x16\x56\x65\x72\x69\x53' +
    b'\x69\x67\x6e\x20\x54\x72\x75\x73\x74\x20\x4e\x65\x74\x77\x6f\x72' +
    b'\x6b\x31\x3b\x30\x39\x06\x03\x55\x04\x0b\x13\x32\x54\x65\x72\x6d' +
    b'\x73\x20\x6f\x66\x20\x75\x73\x65\x20\x61\x74\x20\x68\x74\x74\x70' +
    b'\x73\x3a\x2f\x2f\x77\x77\x77\x2e\x76\x65\x72\x69\x73\x69\x67\x6e' +
    b'\x2e\x63\x6f\x6d\x2f\x72\x70\x61\x20\x28\x63\x29\x30\x39\x31\x2f' +
    b'\x30\x2d\x06\x03\x55\x04\x03\x13\x26\x56\x65\x72\x69\x53\x69\x67' +
    b'\x6e\x20\x43\x6c\x61\x73\x73\x20\x33\x20\x53\x65\x63\x75\x72\x65' +
    b'\x20\x53\x65\x72\x76\x65\x72\x20\x43\x41\x20\x2d\x20\x47\x32\x30' +
    b'\x1e\x17\x0d\x31\x31\x30\x35\x32\x31\x30\x30\x30\x30\x30\x30\x5a' +
    b'\x17\x0d\x31\x31\x30\x38\x31\x39\x32\x33\x35\x39\x35\x39\x5a\x30' +
    b'\x81\x87\x31\x0b\x30\x09\x06\x03\x55\x04\x06\x13\x02\x55\x53\x31' +
    b'\x17\x30\x15\x06\x03\x55\x04\x0a\x13\x0e\x56\x65\x72\x69\x53\x69' +
    b'\x67\x6e\x2c\x20\x49\x6e\x63\x2e\x31\x1f\x30\x1d\x06\x03\x55\x04' +
    b'\x0b\x13\x16\x56\x65\x72\x69\x53\x69\x67\x6e\x20\x54\x72\x75\x73' +
    b'\x74\x20\x4e\x65\x74\x77\x6f\x72\x6b\x31\x3e\x30\x3c\x06\x03\x55' +
    b'\x04\x03\x13\x35\x56\x65\x72\x69\x53\x69\x67\x6e\x20\x43\x6c\x61' +
    b'\x73\x73\x20\x33\x20\x53\x65\x63\x75\x72\x65\x20\x53\x65\x72\x76' +
    b'\x65\x72\x20\x43\x41\x20\x2d\x20\x47\x32\x20\x4f\x43\x53\x50\x20' +
    b'\x52\x65\x73\x70\x6f\x6e\x64\x65\x72\x30\x81\x9f\x30\x0d\x06\x09' +
    b'\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00\x03\x81\x8d\x00\x30' +
    b'\x81\x89\x02\x81\x81\x00\xf4\x0d\x10\xcd\xc8\x00\x0e\x71\xc2\x1a' +
    b'\x6e\xc9\x0d\x20\x92\x82\xed\x9b\xa7\xa6\x8f\x36\xd9\xa0\x22\x23' +
    b'\x44\xdf\x4f\xca\xde\xb4\x99\x63\x94\xe1\xdf\x45\xf0\x32\xb4\x5e' +
    b'\x73\x63\x11\x43\xc1\xa1\x5f\xda\xe2\x8b\xfb\x66\xa5\xa3\x1c\xc2' +
    b'\x54\x7b\x35\xae\x45\x57\x5f\x90\xb4\x8e\x7d\x38\x2f\x04\x81\xf9' +
    b'\x22\xa0\xe0\xee\x60\x8b\xc8\x9b\xdd\xdf\xdc\xaa\x0b\x39\xad\xee' +
    b'\x19\x01\xe2\xbc\x1a\xb9\x8f\x4e\xab\x7b\x90\x40\xeb\x08\x38\xd7' +
    b'\x9e\xfe\xfb\xc3\xa5\xd9\x08\xfb\x57\x09\xd3\x67\xb3\x46\x55\x66' +
    b'\x16\x0a\x0d\x72\xd0\x19\x02\x03\x01\x00\x01\xa3\x82\x01\x18\x30' +
    b'\x82\x01\x14\x30\x09\x06\x03\x55\x1d\x13\x04\x02\x30\x00\x30\x81' +
    b'\xac\x06\x03\x55\x1d\x20\x04\x81\xa4\x30\x81\xa1\x30\x81\x9e\x06' +
    b'\x0b\x60\x86\x48\x01\x86\xf8\x45\x01\x07\x17\x03\x30\x81\x8e\x30' +
    b'\x28\x06\x08\x2b\x06\x01\x05\x05\x07\x02\x01\x16\x1c\x68\x74\x74' +
    b'\x70\x73\x3a\x2f\x2f\x77\x77\x77\x2e\x76\x65\x72\x69\x73\x69\x67' +
    b'\x6e\x2e\x63\x6f\x6d\x2f\x43\x50\x53\x30\x62\x06\x08\x2b\x06\x01' +
    b'\x05\x05\x07\x02\x02\x30\x56\x30\x15\x16\x0e\x56\x65\x72\x69\x53' +
    b'\x69\x67\x6e\x2c\x20\x49\x6e\x63\x2e\x30\x03\x02\x01\x01\x1a\x3d' +
    b'\x56\x65\x72\x69\x53\x69\x67\x6e\x27\x73\x20\x43\x50\x53\x20\x69' +
    b'\x6e\x63\x6f\x72\x70\x2e\x20\x62\x79\x20\x72\x65\x66\x65\x72\x65' +
    b'\x6e\x63\x65\x20\x6c\x69\x61\x62\x2e\x20\x6c\x74\x64\x2e\x20\x28' +
    b'\x63\x29\x39\x37\x20\x56\x65\x72\x69\x53\x69\x67\x6e\x30\x13\x06' +
    b'\x03\x55\x1d\x25\x04\x0c\x30\x0a\x06\x08\x2b\x06\x01\x05\x05\x07' +
    b'\x03\x09\x30\x0b\x06\x03\x55\x1d\x0f\x04\x04\x03\x02\x07\x80\x30' +
    b'\x0f\x06\x09\x2b\x06\x01\x05\x05\x07\x30\x01\x05\x04\x02\x05\x00' +
    b'\x30\x25\x06\x03\x55\x1d\x11\x04\x1e\x30\x1c\xa4\x1a\x30\x18\x31' +
    b'\x16\x30\x14\x06\x03\x55\x04\x03\x13\x0d\x4f\x43\x53\x50\x38\x2d' +
    b'\x54\x47\x56\x37\x2d\x35\x35\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7' +
    b'\x0d\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\x6d\x08\x61\x33\xf7' +
    b'\xdd\xc9\xcf\xb5\x47\xca\x84\xd5\xb4\x77\xaf\xfa\x82\xae\x94\x80' +
    b'\x9b\xc6\xf5\x95\xfd\x24\x26\xb9\x51\x11\x31\x30\x65\x6a\xcf\xd4' +
    b'\x42\xcf\x0f\x1f\x8b\x6f\xde\x29\x73\x69\x87\x0c\x94\xff\x65\x57' +
    b'\xbe\xa5\xb0\x3d\x82\x2d\x3c\x54\xfe\xe2\x37\x1f\xf6\x76\x92\x73' +
    b'\x0d\x8f\xf2\xa1\x5e\x74\xdc\x76\x50\xba\x1f\xc7\xb9\x04\x8d\x18' +
    b'\x2c\xa7\x1e\xc0\x27\xce\xf2\x2e\x26\x7d\x98\xd9\x35\x16\x87\x31' +
    b'\x37\xef\x6b\xa2\x27\x04\x8f\x30\x43\x13\xe4\x64\x09\x99\x64\x87' +
    b'\xc3\xab\x66\x23\x1a\x52\xc7\x4b\x60\x49\x93\x1e\x10\xfe\xa8\xfd' +
    b'\xbd\x13\x4e\xfc\x83\x19\x75\x7b\x56\xe1\xdf\x11\x02\x12\x00\xe6' +
    b'\x71\x26\x25\x6d\xf9\x01\x37\x38\x62\x1b\x65\x30\xf7\x5e\x37\x7c' +
    b'\xca\x36\x0f\xcf\x10\x51\xb2\xaa\xf7\x47\xfd\xcc\xde\xca\x95\x69' +
    b'\x6e\x2a\x99\xc9\xaf\xc4\xc0\xb8\xf8\x53\x70\x5c\x4a\x2d\x79\x8f' +
    b'\x82\x34\xca\x94\x8d\x3f\xad\x0a\xbd\x6c\x9a\x54\xba\x10\xed\x17' +
    b'\xaf\xad\x19\xe5\xf3\x54\x76\xc7\x45\xcf\x8d\x43\xfd\x2b\x04\x32' +
    b'\x49\xb3\x8f\xb3\xdd\x6f\x00\xe8\xba\xf3\x78\x1a\xf7\x19\x1d\x23' +
    b'\x56\x51\x0b\x00\x20\x1c\x3c\x9c\x99\xe3\x05' +
    b''
))


OCSP_RESPONSE_REVOKED = asn1crypto.ocsp.OCSPResponse.load(bytes(
    b'\x30\x82\x01\xe7\x0a\x01\x00\xa0\x82\x01\xe0\x30\x82\x01\xdc\x06' +
    b'\x09\x2b\x06\x01\x05\x05\x07\x30\x01\x01\x04\x82\x01\xcd\x30\x82' +
    b'\x01\xc9\x30\x81\xb2\xa2\x16\x04\x14\xee\xdd\x79\xc0\xd3\x79\xb0' +
    b'\x4d\x7e\x47\xbc\x70\xa6\xe7\xc6\x2a\xae\xba\xde\xc9\x18\x0f\x32' +
    b'\x30\x31\x31\x30\x36\x30\x39\x31\x37\x32\x35\x34\x33\x5a\x30\x81' +
    b'\x86\x30\x81\x83\x30\x4a\x30\x09\x06\x05\x2b\x0e\x03\x02\x1a\x05' +
    b'\x00\x04\x14\x14\xa7\xe2\x19\xf4\x6b\x93\xe1\x41\x25\x8f\x08\xbc' +
    b'\x85\x76\x46\x71\xf1\x36\xb0\x04\x14\xee\xdd\x79\xc0\xd3\x79\xb0' +
    b'\x4d\x7e\x47\xbc\x70\xa6\xe7\xc6\x2a\xae\xba\xde\xc9\x02\x11\x00' +
    b'\x92\x39\xd5\x34\x8f\x40\xd1\x69\x5a\x74\x54\x70\xe1\xf2\x3f\x43' +
    b'\xa1\x11\x18\x0f\x32\x30\x31\x31\x30\x33\x31\x35\x32\x30\x31\x35' +
    b'\x32\x30\x5a\x18\x0f\x32\x30\x31\x31\x30\x36\x30\x39\x31\x37\x32' +
    b'\x35\x34\x33\x5a\xa0\x11\x18\x0f\x32\x30\x31\x31\x30\x36\x31\x33' +
    b'\x31\x37\x32\x35\x34\x33\x5a\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7' +
    b'\x0d\x01\x01\x05\x05\x00\x03\x82\x01\x01\x00\x48\xdb\xa5\x78\x6f' +
    b'\x86\x50\x83\xc2\xb3\xe5\x3b\x75\x92\x0b\x2b\x3c\x04\x3a\xb1\x54' +
    b'\x59\x6e\x47\x4a\x10\x80\xcb\xf3\x9a\xfa\xed\x3c\x27\x42\x03\xc3' +
    b'\x21\xa0\x66\xa0\x45\x43\x2e\xeb\x8f\x3a\xbc\x81\x2a\xf2\xb6\x32' +
    b'\xdf\x27\xc2\x96\x08\xba\xe2\xed\x07\xac\xfc\x0c\xd8\x98\xbd\x19' +
    b'\x42\x7a\x11\xfa\x62\x86\xce\x4c\x63\x35\x38\x7f\x0c\xf8\xd3\xd3' +
    b'\x91\x73\xf1\x4c\xc6\xeb\x70\xba\x56\x49\x72\x04\x1c\xfd\xbc\x05' +
    b'\x9d\xf5\x53\x1f\x66\x39\x76\xa8\xa4\x02\x3e\xa6\x93\x8c\x17\x98' +
    b'\x71\x12\xd0\x28\xd2\x1b\x25\x43\xf0\x96\x1c\x71\x94\xb7\xeb\x6e' +
    b'\x96\x07\xc3\x16\xf5\xcb\x4e\x0f\xfb\x37\x67\x71\x56\x21\xd5\xcf' +
    b'\xbd\x7d\xee\xbe\x4f\x4b\x4e\x78\x1e\xa8\x30\x7e\xc6\x41\x25\x14' +
    b'\x5e\x37\x46\x8d\x76\x40\x35\xec\xf1\x85\x89\xa2\xc6\xd8\x98\x48' +
    b'\x28\xeb\x1d\xa1\x19\x88\x79\x8d\x1e\xbc\x3d\xab\xaf\x1a\xc9\xfd' +
    b'\xe6\x42\xa3\x0c\x5c\x77\x11\x2e\x31\xe0\x65\xc0\xa8\xd9\x28\x60' +
    b'\x03\xd6\xfa\x34\x79\xaa\xd7\x44\xf1\x99\x9f\x27\xa6\x8b\xb4\xfb' +
    b'\x21\x74\xe6\x53\x15\xa5\x70\xb2\xde\xf9\x48\x22\xe6\x6b\x8f\xbf' +
    b'\x7b\x5b\x09\x03\xb1\xa4\xfc\x71\xbe\x16\xee' +
    b''
))


class TestTlsPubKeys(TestTlsCases.TestTlsBase):
    @staticmethod
    def get_result(
            host, port, protocol_version=TlsProtocolVersion(TlsVersion.TLS1_2), timeout=None, ip=None, scheme='tls'
    ):  # pylint: disable=too-many-arguments,too-many-positional-arguments
        analyzer = AnalyzerPublicKeys()
        l7_client = L7ClientTlsBase.from_scheme(scheme, host, port, timeout, ip)
        result = analyzer.analyze(l7_client, protocol_version)
        return result

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=[
            [],
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
            SecurityError(SecurityErrorType.UNPARSABLE_MESSAGE),
        ]
    )
    def test_error_response_error_no_response_last_time(self, _):
        result = self.get_result('www.cloudflare.com', 443)
        self.assertEqual(len(result.pubkeys), 0)

    @mock.patch.object(
        L7ClientTlsBase, 'do_tls_handshake',
        side_effect=TlsAlert(TlsAlertDescription.UNRECOGNIZED_NAME)
    )
    def test_error_unrecognized_name(self, mocked_do_tls_handshake):
        result = self.get_result('www.cloudflare.com', 443)
        self.assertEqual(len(result.pubkeys), 0)
        self.assertEqual(mocked_do_tls_handshake.call_count, 5)

    @mock.patch.object(AnalyzerPublicKeys, '_get_server_messages', return_value={TlsHandshakeType.SERVER_HELLO})
    def test_error_no_server_key_exchange(self, _):
        result = self.get_result('www.cloudflare.com', 443)
        self.assertEqual(len(result.pubkeys), 0)

    def test_eq(self):
        result_badssl_com = self.get_result('badssl.com', 443, timeout=10)
        result_wrong_host_badssl_com = self.get_result('wrong.host.badssl.com', 443, timeout=10)
        self.assertEqual(
            result_badssl_com.pubkeys[0].certificate_chain,
            result_wrong_host_badssl_com.pubkeys[0].certificate_chain
        )

        result_expired_badssl_com = self.get_result('expired.badssl.com', 443, timeout=10)
        result_self_signed_badssl_com = self.get_result('self-signed.badssl.com', 443, timeout=10)
        result_untrusted_root_badssl_com = self.get_result('untrusted-root.badssl.com', 443, timeout=10)
        result_revoked_badssl_com = self.get_result('revoked.badssl.com', 443, timeout=10)
        self.assertNotEqual(
            result_expired_badssl_com.pubkeys[0].certificate_chain,
            result_self_signed_badssl_com.pubkeys[0].certificate_chain
        )
        self.assertNotEqual(
            result_expired_badssl_com.pubkeys[0].certificate_chain,
            result_untrusted_root_badssl_com.pubkeys[0].certificate_chain
        )
        self.assertNotEqual(
            result_expired_badssl_com.pubkeys[0].certificate_chain,
            result_revoked_badssl_com.pubkeys[0].certificate_chain
        )

    def test_subject_match(self):
        result = self.get_result('badssl.com', 443, timeout=10)
        self.assertTrue(result.pubkeys[0].subject_matches)

        result = self.get_result('wrong.host.badssl.com', 443, timeout=10)
        self.assertFalse(result.pubkeys[0].subject_matches)

    def test_fallback_certificate(self):
        result = self.get_result(
            'unexisting-hostname-to-get-wildcard-certificate-without-sni.badssl.com', 443, timeout=10
        )
        self.assertEqual(len(result.pubkeys), 1)
        self.assertEqual(
            'Server offers RSA X.509 public key (with SNI)\n',
            self.log_stream.getvalue()
        )

    def test_certificate_chain(self):
        result = self.get_result('badssl.com', 443, timeout=10)
        self.assertEqual(len(result.pubkeys), 1)

        trusted_root_chain = result.pubkeys[0].certificate_chain
        self.assertEqual(len(trusted_root_chain.items), 3)
        self.assertFalse(trusted_root_chain.contains_anchor)
        self.assertEqual(
            trusted_root_chain.trust_roots,
            {Entity.APPLE: True, Entity.GOOGLE: True, Entity.MICROSOFT: True, Entity.MOZILLA: True}
        )
        self.assertTrue(trusted_root_chain.ordered)

        result = self.get_result('self-signed.badssl.com', 443, timeout=10)
        self.assertEqual(len(result.pubkeys), 1)

        self_signed_chain = result.pubkeys[0].certificate_chain
        self.assertEqual(len(self_signed_chain.items), 1)
        self.assertTrue(self_signed_chain.contains_anchor)
        self.assertTrue(self_signed_chain.ordered)
        self.assertEqual(
            self_signed_chain.trust_roots,
            {Entity.APPLE: False, Entity.GOOGLE: False, Entity.MICROSOFT: False, Entity.MOZILLA: False}
        )

        result = self.get_result('untrusted-root.badssl.com', 443, timeout=10)
        self.assertEqual(len(result.pubkeys), 1)

        untrusted_root_chain = result.pubkeys[0].certificate_chain
        self.assertEqual(len(untrusted_root_chain.items), 2)
        self.assertTrue(untrusted_root_chain.contains_anchor)
        self.assertTrue(untrusted_root_chain.ordered)
        self.assertEqual(
            untrusted_root_chain.trust_roots,
            {Entity.APPLE: False, Entity.GOOGLE: False, Entity.MICROSOFT: False, Entity.MOZILLA: False}
        )

        self.assertNotEqual(self_signed_chain.items[0], untrusted_root_chain.items[1])

        result = self.get_result('incomplete-chain.badssl.com', 443, timeout=10)
        self.assertEqual(len(result.pubkeys), 1)

        incomplete_chain = result.pubkeys[0].certificate_chain
        self.assertEqual(len(incomplete_chain.items), 1)
        self.assertFalse(incomplete_chain.contains_anchor)
        self.assertEqual(incomplete_chain.ordered, None)
        self.assertEqual(
            incomplete_chain.trust_roots,
            {Entity.APPLE: False, Entity.GOOGLE: False, Entity.MICROSOFT: False, Entity.MOZILLA: False}
        )
        self.assertEqual(result.pubkeys[0].certificate_status, None)

    def test_certificate_status(self):
        certificate_status = CertificateStatus(None)
        self.assertEqual(certificate_status._asdict(), OrderedDict())

        certificate_status = CertificateStatus(OCSP_RESPONSE_GOOD)
        self.assertEqual(certificate_status.status, 'good')
        self.assertEqual(
            certificate_status.responder,
            OrderedDict([
                ('country_name', 'US'),
                ('organization_name', 'VeriSign, Inc.'),
                ('organizational_unit_name', 'VeriSign Trust Network'),
                ('common_name', 'VeriSign Class 3 Secure Server CA - G2 OCSP Responder')
            ])
        )

        certificate_status = CertificateStatus(OCSP_RESPONSE_REVOKED)

        self.assertEqual(certificate_status.status, 'revoked')
        self.assertEqual(
            certificate_status.responder,
            'EE:DD:79:C0:D3:79:B0:4D:7E:47:BC:70:A6:E7:C6:2A:AE:BA:DE:C9'
        )
        self.assertEqual(
            certificate_status.revocation_time,
            datetime.datetime(2011, 3, 15, 20, 15, 20, tzinfo=asn1crypto.util.timezone.utc)
        )
        self.assertEqual(certificate_status.update_interval, datetime.timedelta(days=4))
        self.assertEqual(certificate_status.revocation_reason, None)

        result = self.get_result('www.wikipedia.org', 443)
        self.assertEqual(len(result.pubkeys), 2)

        now = datetime.datetime.now(asn1crypto.util.timezone.utc)

        for pubkey_index in range(2):
            certificate_status = result.pubkeys[pubkey_index].certificate_status
            with self.subTest():
                self.assertEqual(certificate_status.status, 'good')
                self.assertLess(certificate_status.produced_at, now)
                self.assertLess(certificate_status.this_update, now)
                self.assertGreater(certificate_status.next_update, now)
                self.assertEqual(certificate_status.revocation_time, None)
                self.assertEqual(certificate_status.revocation_reason, None)

                markdnow_result = certificate_status.as_markdown()
                self.assertIn('Status: good\n', markdnow_result)
                self.assertIn('Revocation Time: n/a\n', markdnow_result)

    @mock.patch.object(
        TlsExtensionsBase, 'get_item_by_type',
        return_value=TlsExtensionSignedCertificateTimestampServer([])
    )
    def test_signed_certificate_timestamp_extension(self, _):
        result = self.get_result('www.cloudflare.com', 443)
        self.assertFalse(any(pubkey.scts for pubkey in result.pubkeys))

    def test_plain_text_response(self):
        threaded_server = L7ServerTlsTest(
            L7ServerTlsPlainTextResponse('localhost', 0, timeout=0.2),
        )
        threaded_server.start()
        self.assertEqual(
            self.get_result(
                'localhost',
                threaded_server.l7_server.l4_transfer.bind_port,
                TlsProtocolVersion(TlsVersion.TLS1)
            ).pubkeys,
            []
        )

    def test_untrusted(self):
        result = self.get_result('untrusted.badssl.com', 443, timeout=10)
        for pubkey in result.pubkeys:
            with self.subTest():
                self.assertEqual(
                    pubkey.certificate_chain.trust_roots,
                    {Entity.APPLE: False, Entity.GOOGLE: False, Entity.MICROSOFT: False, Entity.MOZILLA: False}
                )

    def test_real(self):
        result = self.get_result('cloudflare.com', 443)
        self.assertEqual(len(result.pubkeys), 2)

        self.assertTrue(all(pubkey.certificate_status is not None for pubkey in result.pubkeys))
        self.assertTrue(all(pubkey.scts is None for pubkey in result.pubkeys))

        self.assertTrue(all(pubkey.certificate_chain.ordered for pubkey in result.pubkeys))
        self.assertFalse(all(pubkey.certificate_chain.revoked for pubkey in result.pubkeys))
        for pubkey in result.pubkeys:
            with self.subTest(pubkey=pubkey):
                self.assertEqual(
                    pubkey.certificate_chain.trust_roots,
                    {Entity.APPLE: True, Entity.GOOGLE: True, Entity.MICROSOFT: True, Entity.MOZILLA: False}
                )
        self.assertFalse(any(pubkey.certificate_chain.contains_anchor for pubkey in result.pubkeys))
        self.assertEqual(
            [pubkey.certificate_chain.items[-2].key_type for pubkey in result.pubkeys],
            [Authentication.RSA, Authentication.ECDSA]
        )
        self.assertEqual(
            [pubkey.certificate_chain.items[0].key_type for pubkey in result.pubkeys],
            [Authentication.RSA, Authentication.ECDSA]
        )
        self.assertEqual(
            [pubkey.certificate_chain.items[-2].key_size for pubkey in result.pubkeys],
            [2048, 256]
        )
        self.assertEqual(
            [pubkey.certificate_chain.items[0].key_size for pubkey in result.pubkeys],
            [2048, 256]
        )
        for tls_public_key in result.pubkeys:
            with self.subTest():
                self.assertEqual(tls_public_key.certificate_status.status, 'good')
                self.assertEqual(tls_public_key.scts, None)
        for pubkey in result.pubkeys:
            leaf_certificate = pubkey.certificate_chain.items[0]
            with self.subTest():
                self.assertIn(
                    Entity.GOOGLE,
                    [sct.log.operator for sct in leaf_certificate.signed_certificate_timestamps]
                )
        for pubkey in result.pubkeys:
            leaf_certificate = pubkey.certificate_chain
            with self.subTest():
                self.assertEqual(
                    pubkey.certificate_chain.trust_roots,
                    {Entity.APPLE: True, Entity.GOOGLE: True, Entity.MICROSOFT: True, Entity.MOZILLA: False}
                )

    def test_json(self):
        result = self.get_result('expired.badssl.com', 443, timeout=10)
        self.assertTrue(result.as_json())

        result = self.get_result('self-signed.badssl.com', 443, timeout=10)
        self.assertTrue(result.as_json())

        result = self.get_result('untrusted-root.badssl.com', 443, timeout=10)
        self.assertTrue(result.as_json())

        result = self.get_result('revoked.badssl.com', 443, timeout=10)
        self.assertTrue(result.as_json())
