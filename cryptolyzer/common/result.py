#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptography.hazmat.backends import default_backend  # pylint: disable=import-error

from cryptoparser.common.base import JSONSerializable


class AnalyzerResultBase(JSONSerializable):
    pass


class AnalyzerResultTls(AnalyzerResultBase):
    pass


class DHParameter(JSONSerializable):
    def __init__(self, public_key, reused):
        self.public_key = public_key
        self.reused = reused

        codes = default_backend()._ffi.new("int[]", 1)  # pylint: disable=protected-access
        cryptography_dh_check = default_backend()._lib.Cryptography_DH_check  # pylint: disable=protected-access
        if cryptography_dh_check(public_key._dh_cdata, codes) == 1:  # pylint: disable=protected-access
            self.prime = (codes[0] & 0x01) == 0  # DH_CHECK_P_NOT_PRIME
            self.safe_prime = (codes[0] & 0x02) == 0  # DH_CHECK_P_NOT_SAFE_PRIME
        else:
            self.prime = None
            self.safe_prime = None

    @property
    def key_size(self):
        return self.public_key.key_size

    def as_json(self):
        result = {'key_size': self.key_size}
        result.update({
            key: value
            for key, value in self.__dict__.items()
            if key != 'public_key'
        })
        return result
