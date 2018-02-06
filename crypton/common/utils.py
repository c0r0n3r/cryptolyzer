#!/usr/bin/env python
# -*- coding: utf-8 -*-

import inspect


def get_leaf_classes(base_class):

    def _get_leaf_classes(base_class):
        subclasses = []

        if base_class.__subclasses__():
            for subclass in base_class.__subclasses__():
                subclasses += _get_leaf_classes(subclass)
        else:
            if not inspect.isabstract(base_class):
                return [base_class, ]

        return subclasses

    return _get_leaf_classes(base_class)
