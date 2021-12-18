# -*- coding: utf-8 -*-

import unittest

import test.ssh.test_ciphers
import test.ssh.test_versions

from cryptoparser.ssh.ciphersuite import SshHostKeyAlgorithm
from cryptoparser.ssh.version import (
    SshProtocolVersion,
    SshSoftwareVersionUnparsed,
    SshSoftwareVersionOpenSSH,
    SshVersion,
)


class TestReal(unittest.TestCase):
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
                SshHostKeyAlgorithm.RSA_SHA2_512,
                SshHostKeyAlgorithm.RSA_SHA2_256,
                SshHostKeyAlgorithm.SSH_RSA,
                SshHostKeyAlgorithm.ECDSA_SHA2_NISTP256,
                SshHostKeyAlgorithm.SSH_ED25519,
            ]
        )

    def test_versions(self):
        result = test.ssh.test_versions.TestSshVersions.get_result('github.com')
        self.assertEqual(result.protocol_versions, [SshProtocolVersion(SshVersion.SSH2)])
        self.assertEqual(result.software_version, SshSoftwareVersionUnparsed('babeld-b6e6da7b'))

        result = test.ssh.test_versions.TestSshVersions.get_result('gitlab.com')
        self.assertEqual(result.protocol_versions, [SshProtocolVersion(SshVersion.SSH2)])
        self.assertEqual(result.software_version, SshSoftwareVersionOpenSSH('7.9p1'))
