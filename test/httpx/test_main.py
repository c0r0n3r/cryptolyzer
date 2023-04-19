# -*- coding: utf-8 -*-

from test.common.classes import TestMainBase

from cryptolyzer.__main__ import main


class TestMain(TestMainBase):
    def setUp(self):
        self.main_func = main

    def test_http(self):
        uri = 'https://httpbin.org/response-headers?X-Test-Header-Name=X-Test-Header-Value'

        result = self._get_test_analyzer_result_markdown('http', 'headers', uri)
        self.assertIn('Name: X-Test-Header-Name', result)
        self.assertIn('Value: X-Test-Header-Value', result)

        result = self._get_test_analyzer_result_markdown('http1_1', 'headers', uri)
        self.assertIn('Name: X-Test-Header-Name', result)
        self.assertIn('Value: X-Test-Header-Value', result)

    def test_default_scheme(self):
        uri = 'httpbin.org/response-headers?X-Test-Header-Name=X-Test-Header-Value'
        result = self._get_test_analyzer_result_markdown('http', 'headers', uri)
        self.assertIn('Name: X-Test-Header-Name', result)
        self.assertIn('Value: X-Test-Header-Value', result)
