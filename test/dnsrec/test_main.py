# -*- coding: utf-8 -*-

from test.common.classes import TestMainBase

from cryptolyzer.__main__ import main


class TestMain(TestMainBase):
    @classmethod
    def _get_main_func(cls):
        return main

    def test_default_scheme(self):
        uri = 'cloudflare.com#1.1.1.1'
        result = self._get_test_analyzer_result_markdown('dns', 'dnssec', uri, timeout=10)
        self.assertIn('* Scheme: dns', result)

    def test_dnssec(self):
        uri = 'cloudflare.com#1.1.1.1'
        result = self._get_test_analyzer_result_markdown('dns', 'dnssec', uri, timeout=10)
        self.assertIn('* DNS Public Keys', result)
        self.assertIn('* Delegation Signers', result)
        self.assertIn('* Resource Record Signature', result)

    def test_mail(self):
        uri = 'google.com#1.1.1.1'
        result = self._get_test_analyzer_result_markdown('dns', 'mail', uri, timeout=10)
        self.assertIn('* Exchange: smtp.google.com', result)
        self.assertIn('* Raw: v=spf1 include:_spf.google.com ~all', result)
        self.assertIn(
            '* Raw: v=DMARC1; p=reject; adkim=r; aspf=r; fo=0; pct=100; '
            'rua=mailto:mailauth-reports@google.com; rf=afrf; ri=86400; sp=None',
            result
        )
        self.assertIn('* Raw: v=STSv1; id=20210803T010101', result)
        self.assertIn('* Raw: v=TLSRPTv1; rua=mailto:sts-reports@google.com', result)
