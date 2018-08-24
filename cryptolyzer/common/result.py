#!/usr/bin/env python
# -*- coding: utf-8 -*-

import json

from cryptography.hazmat.backends import default_backend

from cryptoparser.common.base import JSONSerializable


class AnalyzerResultBase(JSONSerializable):
    @staticmethod
    def _bytes_to_colon_separated_hex(byte_array):
        return ':'.join(['{:02X}'.format(x) for x in byte_array])


class AnalyzerResultTls(AnalyzerResultBase):
    def __init__(self, analyzer, results):
        self.analyzer = analyzer
        self.results = results
