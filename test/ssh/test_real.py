# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import unittest

import test.ssh.test_ciphers
import test.ssh.test_versions
from test.common.markers import live_server


from cryptodatahub.ssh.algorithm import SshHostKeyAlgorithm
from cryptoparser.ssh.version import (
    SshProtocolVersion,
    SshVersion,
)


class TestReal(unittest.TestCase):
    @live_server
    def test_ciphers(self):
        result = test.ssh.test_ciphers.TestSshCiphers.get_result('github.com')
        self.assertEqual(
            result.host_key_algorithms,
            [
                SshHostKeyAlgorithm.SSH_ED25519,
                SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                SshHostKeyAlgorithm.RSA_SHA2_512,
                SshHostKeyAlgorithm.RSA_SHA2_256,
                SshHostKeyAlgorithm.SSH_RSA,
            ]
        )

        result = test.ssh.test_ciphers.TestSshCiphers.get_result('gitlab.com')
        self.assertEqual(
            result.host_key_algorithms,
            [
                SshHostKeyAlgorithm.SSH_DSS,
                SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                SshHostKeyAlgorithm.SSH_ED25519,
                SshHostKeyAlgorithm.RSA_SHA2_256,
                SshHostKeyAlgorithm.RSA_SHA2_512,
                SshHostKeyAlgorithm.SSH_RSA,
            ]
        )

    @live_server
    def test_versions(self):
        result = test.ssh.test_versions.TestSshVersions.get_result('github.com')
        self.assertEqual(result.protocol_versions, [SshProtocolVersion(SshVersion.SSH2)])
        self.assertRegex(result.software_version.raw, '[0-9a-f]{7,8}')

        result = test.ssh.test_versions.TestSshVersions.get_result('gitlab.com')
        self.assertEqual(result.protocol_versions, [SshProtocolVersion(SshVersion.SSH2)])
        self.assertEqual(result.software_version.raw, 'GitLab-SSHD')
