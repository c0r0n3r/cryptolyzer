#!/usr/bin/env python
# -*- coding: utf-8 -*-

from setuptools import setup

setup(
    name='cryptolyzer',
    version='0.1',
    description='Fast and flexible cryptographic protocol analyzer',
    author='Szilárd Pfeiffer',
    author_email='coroner@pfeifferszilard.hu',
    license='AGPLv3',
    url='https://github.com/c0r0n3r/cryptolyzer',

    entry_points={
        'console_scripts': ['cryptolyze']
    },

    test_suite='tests',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'Intended Audience :: System Administrators',
        'Natural Language :: English',
        'License :: OSI Approved :: GNU Affero General Public License (AGPLv3)',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: 3.5',
        'Programming Language :: Python :: 3.6',
        'Topic :: Software Development :: Testing'
        'Topic :: Software Development :: Testing :: Traffic Generation'
        'Topic :: System :: Networking',
        'Topic :: Security'
    ],
)
