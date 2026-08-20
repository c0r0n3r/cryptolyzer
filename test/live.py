# SPDX-License-Identifier: MPL-2.0

"""The tests that need a live server or a live DNS resolver, and nothing else.

The name does not match the discovery pattern, so a plain discovery run does not
load this module and the tests below are not collected twice.
"""

import pathlib

import unittest


def _iter_tests(suite):
    for test in suite:
        if isinstance(test, unittest.TestSuite):
            yield from _iter_tests(test)
        else:
            yield test


def _is_live(test):
    test_method = getattr(type(test), test.id().rsplit('.', 1)[-1], None)

    return getattr(test_method, 'live', False)


def load_tests(loader, standard_tests, pattern):
    test_directory = pathlib.Path(__file__).parent
    discovered_tests = loader.discover(
        start_dir=str(test_directory),
        pattern=pattern or 'test*.py',
        top_level_dir=str(test_directory.parent),
    )

    for test in _iter_tests(discovered_tests):
        if _is_live(test):
            standard_tests.addTest(test)

    return standard_tests
