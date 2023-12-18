#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=invalid-name

import datetime
import os
import sys

sys.path.insert(0, os.path.abspath('..'))
from cryptolyzer.__setup__ import (  # noqa: E402, pylint: disable=wrong-import-position
    __author__,
    __description__,
    __title__,
    __version__,
)


extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.coverage',
    'sphinx.ext.napoleon'
]
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = __title__
copyright = f'{datetime.datetime.now().year}, {__author__}'  # pylint: disable=redefined-builtin
version = release = __version__

exclude_patterns = ['_build']

html_theme = 'alabaster'
html_sidebars = {
    '**': [
        'about.html',
        'navigation.html',
        'relations.html',
        'searchbox.html',
        'donate.html',
    ]
}
html_theme_options = {
    'description': __description__,
    'fixed_sidebar': True,
}
