#!/usr/bin/env python
# -*- coding: utf-8 -*-

import imaplib
import poplib
import smtplib
import socket
import sys
import unittest
try:
    from unittest import mock
except ImportError:
    import mock

from cryptoparser.tls.version import TlsVersion, TlsProtocolVersionFinal

from cryptolyzer.tls.client import L7ClientTlsBase
from cryptolyzer.common.exception import NetworkError, NetworkErrorType
from cryptolyzer.tls.versions import AnalyzerVersions


class TestL7ClientBase(unittest.TestCase):
    @staticmethod
    def get_result(proto, host, port, timeout=None):
        analyzer = AnalyzerVersions()
        l7_client = L7ClientTlsBase.from_scheme(proto, host, port, timeout)
        result = analyzer.analyze(l7_client, TlsProtocolVersionFinal(TlsVersion.TLS1_2))
        return result


class TestL7ClientTlsBase(TestL7ClientBase):
    @unittest.skipIf(
        sys.version_info < (3, 0),
        'There is no ConnectionRefusedError in Python < 3.0'
    )
    def test_error_connection_refused(self):
        with mock.patch.object(L7ClientTlsBase, '_setup_connection', side_effect=ConnectionRefusedError), \
                self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'badssl.com', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @unittest.skipIf(
        sys.version_info >= (3, 0),
        'ConnectionRefusedError is raised instead of socket.error in Python >= 3.0'
    )
    def test_error_connection_refused_socket_error(self):
        with mock.patch.object(L7ClientTlsBase, '_setup_connection', side_effect=socket.error), \
                self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'badssl.com', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    @mock.patch.object(L7ClientTlsBase, '_send', return_value=0)
    def test_error_send(self, _):
        with self.assertRaises(NetworkError) as context_manager:
            self.get_result('tls', 'badssl.com', 443)
        self.assertEqual(context_manager.exception.error, NetworkErrorType.NO_CONNECTION)

    def test_tls_client(self):
        self.assertEqual(
            self.get_result('tls', 'badssl.com', 443).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )

    def test_https_client(self):
        self.assertEqual(
            self.get_result('https', 'badssl.com', None).versions,
            [
                TlsProtocolVersionFinal(TlsVersion.TLS1_0),
                TlsProtocolVersionFinal(TlsVersion.TLS1_1),
                TlsProtocolVersionFinal(TlsVersion.TLS1_2),
            ]
        )


class TestClientPOP3(TestL7ClientBase):
    @mock.patch.object(poplib.POP3, '_shortcmd', return_value=b'-ERR')
    def test_error_unsupported_starttls(self, _):
        self.assertEqual(self.get_result('pop3', 'pop3.comcast.net', None, 10).versions, [])

    @mock.patch.object(poplib.POP3, '__init__', side_effect=poplib.error_proto)
    def test_error_pop3_error_on_connect(self, _):
        self.assertEqual(self.get_result('pop3', 'pop3.comcast.net', None, 10).versions, [])

    @mock.patch.object(poplib.POP3, 'quit', side_effect=poplib.error_proto)
    def test_error_pop3_error_on_quit(self, _):
        self.assertEqual(
            self.get_result('pop3', 'pop3.comcast.net', None, 10).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_pop3_client(self):
        self.assertEqual(
            self.get_result('pop3', 'pop3.comcast.net', None, 10).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_pop3s_client(self):
        self.assertEqual(
            self.get_result('pop3s', 'pop.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )


class TestClientIMAP(TestL7ClientBase):
    @mock.patch.object(
        ClientIMAP, '_capabilities',
        mock.PropertyMock(return_value=(
            'IMAP4REV1',
            'LITERAL+',
            'SASL-IR',
            'LOGIN-REFERRALS',
            'ID',
            'ENABLE',
            'IDLE',
            'LOGINDISABLED',
        )),
        create=True
    )
    def test_error_unsupported_starttls(self):
        self.assertEqual(self.get_result('imap', 'imap.comcast.net', None, 10).versions, [])

    @mock.patch.object(imaplib.IMAP4, '__init__', side_effect=imaplib.IMAP4.error)
    def test_error_imap_error(self, _):
        self.assertEqual(self.get_result('imap', 'imap.comcast.net', None, 10).versions, [])

    @mock.patch.object(
        imaplib.IMAP4, 'xatom',
        return_value=[('BAD', 'command unknown or arguments invalid'), mock.DEFAULT]
    )
    def test_error_starttls_error(self, _):
        self.assertEqual(self.get_result('imap', 'imap.comcast.net', None, 10).versions, [])

    def test_imap_client(self):
        self.assertEqual(
            self.get_result('imap', 'imap.comcast.net', None, 10).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_imaps_client(self):
        self.assertEqual(
            self.get_result('imaps', 'imap.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )


class TestClientSMTP(TestL7ClientBase):
    @mock.patch.object(smtplib.SMTP, 'has_extn', return_value=False)
    def test_error_unsupported_starttls(self, _):
        self.assertEqual(self.get_result('smtp', 'smtp.gmail.com', None).versions, [])

    @mock.patch.object(smtplib.SMTP, 'connect', side_effect=smtplib.SMTPException)
    def test_error_smtp_error_on_connect(self, _):
        self.assertEqual(self.get_result('smtp', 'smtp.gmail.com', None).versions, [])

    @mock.patch.object(smtplib.SMTP, 'quit', side_effect=smtplib.SMTPServerDisconnected)
    def test_error_smtp_error_on_quit(self, _):
        self.assertEqual(
            self.get_result('smtp', 'smtp.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    @mock.patch.object(smtplib.SMTP, 'docmd', return_value=(454, 'TLS not available due to temporary reason'))
    def test_error_starttls_error(self, _):
        self.assertEqual(self.get_result('smtp', 'smtp.gmail.com', None).versions, [])

    def test_smtp_client(self):
        self.assertEqual(
            self.get_result('smtp', 'smtp.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )

    def test_smtps_client(self):
        self.assertEqual(
            self.get_result('smtps', 'smtp.gmail.com', None).versions,
            [TlsProtocolVersionFinal(version) for version in [TlsVersion.TLS1_0, TlsVersion.TLS1_1, TlsVersion.TLS1_2]]
        )
