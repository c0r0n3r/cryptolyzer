# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

from unittest import mock

from collections import OrderedDict

from cryptodatahub.common.algorithm import Authentication, Hash
from cryptodatahub.common.grade import Grade
from cryptodatahub.dnsrec.algorithm import SshFpAlgorithm, SshFpFingerprintType

from cryptodatahub.ssh.algorithm import SshHostKeyAlgorithm
from cryptoparser.dnsrec.record import DnsRecordSshfp
from cryptoparser.ssh.subprotocol import SshReasonCode

from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams

from cryptolyzer.dnsrec.client import L7ClientDns
from cryptolyzer.ssh.client import L7ClientSsh, SshClientHandshake, SshDisconnect
from cryptolyzer.ssh.pubkeys import AnalyzerPublicKeys, SshFpVerificationStatus, SshPublicKeyWithSshfpState
from cryptolyzer.ssh.server import L7ServerSsh, SshServerConfiguration

from .classes import L7ServerSshTest, TestSshCases


class TestSshPubkeys(TestSshCases.TestSshClientBase):
    @staticmethod
    def get_result(host, port=None, l4_socket_params=L4TransferSocketParams(), ip=None):
        analyzer = AnalyzerPublicKeys()
        l7_client = L7ClientSsh(host, port, l4_socket_params, ip=ip)
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

    def test_get_name(self):
        self.assertEqual(AnalyzerPublicKeys.get_name(), 'pubkeys')

    def test_get_help(self):
        self.assertIsInstance(AnalyzerPublicKeys.get_help(), str)

    def test_sshfp_verification_status_grades(self):
        self.assertEqual(SshFpVerificationStatus.MISSING.value.grade, Grade.DEPRECATED)
        self.assertEqual(SshFpVerificationStatus.MATCH.value.grade, Grade.SECURE)
        self.assertEqual(SshFpVerificationStatus.MISMATCH.value.grade, Grade.INSECURE)

    @mock.patch.object(L7ClientDns, 'get_sshfp_records', side_effect=NetworkError(NetworkErrorType.NO_ADDRESS))
    def test_sshfp_dns_error(self, _):
        result = self.get_result('github.com', 22)
        for entry in result.public_keys:
            self.assertEqual(entry.sshfp_status, SshFpVerificationStatus.MISSING)

    @mock.patch.object(L7ClientDns, 'get_sshfp_records', return_value=[
        DnsRecordSshfp(
            algorithm=SshFpAlgorithm.RSA,
            fingerprint_type=SshFpFingerprintType.SHA2_256,
            fingerprint=b'\x00' * 32,
        )
    ])
    def test_sshfp_mismatch(self, _):
        result = self.get_result('github.com', 22)
        rsa_entries = [
            e for e in result.public_keys
            if e.public_key.public_key.key_type == Authentication.RSA
        ]
        self.assertGreater(len(rsa_entries), 0)
        self.assertEqual(rsa_entries[0].sshfp_status, SshFpVerificationStatus.MISMATCH)

    def test_real_no_gex(self):
        result = self.get_result('github.com', 22)
        self.assertEqual(
            list(map(lambda entry: entry.public_key.public_key.key_type, result.public_keys)),
            [Authentication.ECDSA, Authentication.EDDSA, Authentication.RSA],
        )
        self.assertIsInstance(result.public_keys[0], SshPublicKeyWithSshfpState)
        self.assertEqual(result.public_keys[0].public_key.fingerprints, OrderedDict([
            (Hash.SHA2_256, 'SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM='),
            (Hash.SHA1, 'SHA1:M1irXdPjBsRhyED3SH6TtpfjBgA='),
            (Hash.MD5, 'MD5:7b:99:81:1e:4c:91:a5:0d:5a:2e:2e:80:13:3f:24:ca'),
        ]))
        self.assertEqual(result.public_keys[1].public_key.fingerprints, OrderedDict([
            (Hash.SHA2_256, 'SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU='),
            (Hash.SHA1, 'SHA1:6WGeLtVsLypxcp24C6zCzpzM6NQ='),
            (Hash.MD5, 'MD5:65:96:2d:fc:e8:d5:a9:11:64:0c:0f:ea:00:6e:5b:bd'),
        ]))
        self.assertEqual(result.public_keys[2].public_key.fingerprints, OrderedDict([
            (Hash.SHA2_256, 'SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s='),
            (Hash.SHA1, 'SHA1:b0xgN1AYuuCRjjfZFivBW6QOY2U='),
            (Hash.MD5, 'MD5:d5:2c:63:d9:bc:75:9d:de:b1:4e:36:28:9f:7a:9c:39'),
        ]))
        log_lines = self.get_log_lines()
        for idx, entry in enumerate(result.public_keys):
            self.assertIn(
                f'Server offers {entry.public_key.host_key_algorithm.value.code} host key', log_lines[idx]
            )

    def test_host_cert(self):
        result = self.get_result('syslog.ips.nl', 22)
        self.assertEqual(
            list(map(lambda entry: entry.public_key.public_key.key_type, result.public_keys)),
            [Authentication.ECDSA, Authentication.EDDSA, Authentication.RSA, Authentication.RSA],
        )
        self.assertEqual(
            list(map(lambda entry: entry.public_key.host_key_algorithm.value.code, result.public_keys)),
            ['ecdsa-sha2-nistp256', 'ssh-ed25519', 'ssh-rsa', 'ssh-rsa-cert-v01@openssh.com'],
            [
                SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                SshHostKeyAlgorithm.SSH_ED25519,
                SshHostKeyAlgorithm.SSH_RSA,
                SshHostKeyAlgorithm.SSH_RSA_CERT_V01_OPENSSH_COM,
            ]
        )
        self.assertEqual(result.public_keys[3].public_key.key_id, 'avy.fabriquehq.nl')

    def test_real_sshfp_verification(self):
        result = self.get_result('sourceware.org', 22)
        self.assertGreater(len(result.public_keys), 0)
        for entry in result.public_keys:
            self.assertIsInstance(entry, SshPublicKeyWithSshfpState)
            self.assertIsInstance(entry.sshfp_status, SshFpVerificationStatus)
            self.assertIn(entry.sshfp_status, (
                SshFpVerificationStatus.MATCH,
                SshFpVerificationStatus.MISMATCH,
                SshFpVerificationStatus.MISSING,
            ))
        statuses = {entry.sshfp_status for entry in result.public_keys}
        self.assertIn(SshFpVerificationStatus.MATCH, statuses)

    def test_pubkeys_with_algorithm_limit(self):
        server_configuration = SshServerConfiguration(max_remote_algorithm_count=50)
        threaded_server = L7ServerSshTest(L7ServerSsh(
            'localhost', 0, L4TransferSocketParams(timeout=0.2), configuration=server_configuration
        ))
        threaded_server.start()

        try:
            result = self.get_result('localhost', threaded_server.l7_server.l4_transfer.bind_port)
            self.assertIsNotNone(result)
        except (NetworkError, SshDisconnect, StopIteration):
            pass
