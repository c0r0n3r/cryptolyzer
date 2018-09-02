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
    def __init__(self, public_key, reused):
        self.public_key = public_key
        self.reused = reused

        codes = default_backend()._ffi.new("int[]", 1)
        if default_backend()._lib.Cryptography_DH_check(public_key._dh_cdata, codes) == 1:
            self.prime = (codes[0] & 0x01) == 0 # DH_CHECK_P_NOT_PRIME
            self.safe_prime = (codes[0] & 0x02) == 0 # DH_CHECK_P_NOT_SAFE_PRIME
        else:
            self.prime = None
            self.safe_prime = None

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
