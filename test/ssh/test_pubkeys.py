# -*- coding: utf-8 -*-

try:
    from unittest import mock
except ImportError:
    import mock

from collections import OrderedDict

from cryptoparser.common.algorithm import Authentication, Hash
from cryptoparser.ssh.ciphersuite import SshHostKeyAlgorithm
from cryptoparser.ssh.subprotocol import SshReasonCode

from cryptolyzer.common.exception import NetworkError, NetworkErrorType

from cryptolyzer.ssh.client import L7ClientSsh, SshClientHandshake, SshDisconnect
from cryptolyzer.ssh.pubkeys import AnalyzerPublicKeys

from .classes import TestSshCases


class TestSshPubkeys(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port=None, timeout=None, ip=None):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7ClientSsh(host, port, timeout, ip=ip)
        result = analyzer.analyze(l7_client)
        return result

    @mock.patch.object(
        SshClientHandshake, '_process_kex_init',
        side_effect=NetworkError(NetworkErrorType.NO_CONNECTION)
    )
    def test_error_no_connection(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('github.com', 22)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @mock.patch.object(
        SshClientHandshake, '_process_kex_init',
        side_effect=NetworkError(NetworkErrorType.NO_RESPONSE)
    )
    def test_error_no_response(self, _):
        result = self.get_result('github.com', 22)
        self.assertEqual(result.public_keys, [])

    @mock.patch.object(
        SshClientHandshake, '_process_kex_init',
        side_effect=SshDisconnect(SshReasonCode.HOST_NOT_ALLOWED_TO_CONNECT, '')
    )
    def test_error_disconnect(self, _):
        result = self.get_result('github.com', 22)
        self.assertEqual(result.public_keys, [])

    @mock.patch.object(AnalyzerPublicKeys, '_get_dh_key_exchange_reply_message_class', side_effect=StopIteration)
    def test_error_no_kex_reply(self, _):
        result = self.get_result('github.com', 22)
        self.assertEqual(result.public_keys, [])

    def test_real_no_gex(self):
        result = self.get_result('github.com', 22)
        self.assertEqual(
            list(map(lambda public_key: public_key.key_type, result.public_keys)),
            [Authentication.ECDSA, Authentication.EDDSA, Authentication.RSA],
        )
        self.assertEqual(result.public_keys[0].fingerprints, OrderedDict([
            (Hash.SHA2_256, 'SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM='),
            (Hash.SHA1, 'SHA1:M1irXdPjBsRhyED3SH6TtpfjBgA='),
            (Hash.MD5, 'MD5:7b:99:81:1e:4c:91:a5:0d:5a:2e:2e:80:13:3f:24:ca'),
        ]))
        self.assertEqual(result.public_keys[1].fingerprints, OrderedDict([
            (Hash.SHA2_256, 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU='),
            (Hash.SHA1, 'SHA1:6WGeLtVsLypxcp24C6zCzpzM6NQ='),
            (Hash.MD5, 'MD5:65:96:2d:fc:e8:d5:a9:11:64:0c:0f:ea:00:6e:5b:bd'),
        ]))
        self.assertEqual(result.public_keys[2].fingerprints, OrderedDict([
            (Hash.SHA2_256, 'SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8='),
            (Hash.SHA1, 'SHA1:v2toJdKXfFEaR1u++4iq1UqSrHM='),
            (Hash.MD5, 'MD5:16:27:ac:a5:76:28:2d:36:63:1b:56:4d:eb:df:a6:48'),
        ]))

    def test_host_cert(self):
        result = self.get_result('scm.infra.centos.org', 22)
        self.assertEqual(
            list(map(lambda public_key: public_key.key_type, result.public_keys)),
            [Authentication.ECDSA, Authentication.EDDSA, Authentication.RSA, Authentication.EDDSA],
        )
        self.assertEqual(
            list(map(lambda public_key: public_key.host_key_algorithm.value.code, result.public_keys)),
            ['ecdsa-sha2-nistp256', 'ssh-ed25519', 'ssh-rsa', 'ssh-ed25519-cert-v01@openssh.com'],
            [
                SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                SshHostKeyAlgorithm.SSH_ED25519,
                SshHostKeyAlgorithm.SSH_RSA,
                SshHostKeyAlgorithm.SSH_ED25519_CERT_V01_OPENSSH_COM
            ]
        )
        self.assertEqual(result.public_keys[3].key_id, 'scm.infra.centos.org')
