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


class DHParameter(JSONSerializable):
    def __init__(self, public_key):
        self.public_key = public_key

    @property
    def key_size(self):
        return self.public_key.key_size

    def as_json(self):
        result = { 'key_size' : self.key_size }
        result.update({
            key: value
            for key, value in self.__dict__.items()
            if key != 'public_key'
        })
        return result
