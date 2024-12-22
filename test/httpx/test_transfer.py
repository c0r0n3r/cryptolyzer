# -*- coding: utf-8 -*-

import unittest

from test.common.classes import TestThreadedServerHttp, TestThreadedServerHttps, TestThreadedServerHttpProxy

import urllib3

from cryptolyzer.common.transfer import L4TransferSocketParams
from cryptolyzer.httpx.client import L7ClientHttp, L7ClientHttps


class TestHttpHandshakeBase(unittest.TestCase):
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
