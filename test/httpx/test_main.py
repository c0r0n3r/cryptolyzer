# -*- coding: utf-8 -*-

from test.common.classes import TestMainBase, TestThreadedServerHttp

from cryptolyzer.__main__ import main


class TestMain(TestMainBase):
    def setUp(self):
        self.main_func = main

    def test_http(self):
        test_http_server = TestThreadedServerHttp('127.0.0.1', 0)
        test_http_server.init_connection()
        test_http_server.start()

        uri = 'http://127.0.0.1:{}'.format(test_http_server.bind_port)

        result = self._get_test_analyzer_result_markdown('http', 'headers', uri)
        self.assertIn('Name: Server', result)
        self.assertIn('Value: TestThreadedServerHttp', result)
        self.assertIn('Name: Date', result)
        self.assertIn('Value: Thu, 01 Jan 1970 00:00:00 GMT', result)

        result = self._get_test_analyzer_result_markdown('http1_1', 'headers', uri)
        self.assertIn('Name: Server', result)
        self.assertIn('Value: TestThreadedServerHttp', result)
        self.assertIn('Name: Date', result)
        self.assertIn('Value: Thu, 01 Jan 1970 00:00:00 GMT', result)

        test_http_server.kill()

    def test_default_scheme(self):
        uri = 'example.org'
        result = self._get_test_analyzer_result_markdown('http', 'headers', uri, timeout=90)
        self.assertIn('Name: ETag', result)
