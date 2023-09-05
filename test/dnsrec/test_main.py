# -*- coding: utf-8 -*-

from test.common.classes import TestMainBase

from cryptolyzer.__main__ import main


class TestMain(TestMainBase):
    def setUp(self):
        self.main_func = main

    def test_default_scheme(self):
        uri = 'cloudflare.com#1.1.1.1'
        result = self._get_test_analyzer_result_markdown('dns', 'dnssec', uri, timeout=10)
        self.assertIn('* Scheme: dns', result)

    def test_dnssec(self):
        uri = 'cloudflare.com#1.1.1.1'
        result = self._get_test_analyzer_result_markdown('dns', 'dnssec', uri, timeout=10)
        self.assertIn('* DNS Public Keys', result)
        self.assertIn('* Digital Signatures', result)
        self.assertIn('* Resource Record Signature', result)

    def test_mail(self):
        uri = 'google.com#1.1.1.1'
        result = self._get_test_analyzer_result_markdown('dns', 'mail', uri, timeout=10)
        self.assertIn('* Exchange: smtp.google.com', result)
