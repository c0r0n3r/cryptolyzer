#!/usr/bin/env python
# -*- coding: utf-8 -*-

from cryptoparser.common.base import JSONSerializable


class AnalyzerResultBase(JSONSerializable):
    pass


class AnalyzerResultTls(AnalyzerResultBase):
    pass


class DHParameter(JSONSerializable):
    def __init__(self, public_key):
        self.public_key = public_key

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
