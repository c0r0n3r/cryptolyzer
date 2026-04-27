# SPDX-License-Identifier: MPL-2.0
# -*- coding: utf-8 -*-

import unittest
from unittest import mock

from test.common.classes import TestThreadedServerHttp, TestThreadedServerHttps, TestThreadedServerHttpProxy

import urllib3
import urllib3.util
import requests.exceptions

from cryptolyzer.common.exception import SecurityError, SecurityErrorType
from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.httpx.client import L7ClientHttp, L7ClientHttps


class TestHttpHandshakeBase(unittest.TestCase):
    @mock.patch('requests.head')
    def test_error_ssl_unknown(self, mock_head):
        mock_head.side_effect = requests.exceptions.SSLError('unknown SSL error')
        with self.assertRaises(SecurityError) as ctx:
            L7ClientHttp(urllib3.util.parse_url('https://example.com')).do_handshake()

        self.assertEqual(ctx.exception.error, SecurityErrorType.UNKNOWN_ERROR)

    def test_error_ssl_certificate_verify_failed(self):
        with self.assertRaises(SecurityError) as ctx:
            L7ClientHttp(urllib3.util.parse_url('https://expired.badssl.com')).do_handshake()

        self.assertEqual(ctx.exception.error, SecurityErrorType.CERTIFICATE_VERIFY_FAILED)

    def test_proxy(self):
        test_http_server = TestThreadedServerHttp('127.0.0.1', 0)
        test_http_server.init_connection()
        test_http_server.start()

        test_http_proxy_server = TestThreadedServerHttpProxy('127.0.0.2', 0)
        test_http_proxy_server.init_connection()
        test_http_proxy_server.start()

        analyzer_result = L7ClientHttp(
                urllib3.util.parse_url(f'http://127.0.0.1:{test_http_server.bind_port}'),
                L4TransferSocketParams(
                    http_proxy=urllib3.util.parse_url(f'http://127.0.0.2:{test_http_proxy_server.bind_port}')
                )
        ).do_handshake()
        self.assertIn(b'Server: TestHTTPProxyRequestHandler\r\n', analyzer_result)

        test_http_proxy_server.kill()
        test_http_server.kill()

        test_http_server = TestThreadedServerHttps('127.0.0.1', 0)
        test_http_server.init_connection()
        test_http_server.start()

        test_http_proxy_server = TestThreadedServerHttpProxy('127.0.0.2', 0)
        test_http_proxy_server.init_connection()
        test_http_proxy_server.start()

        analyzer_result = L7ClientHttps(
                urllib3.util.parse_url(f'http://127.0.0.1:{test_http_server.bind_port}'),
                L4TransferSocketParams(
                    http_proxy=urllib3.util.parse_url(f'http://127.0.0.2:{test_http_proxy_server.bind_port}')
                )
        ).do_handshake()
        self.assertIn(b'Server: TestHTTPProxyRequestHandler\r\n', analyzer_result)

        test_http_proxy_server.kill()
        test_http_server.kill()
