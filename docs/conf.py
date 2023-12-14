#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=invalid-name

import datetime
import os
import sys
import urllib

try:
    import pathlib
except ImportError:  # pragma: no cover
    import pathlib2 as pathlib  # pragma: no cover

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
    'sphinx.ext.napoleon',
    'sphinx_sitemap',
]
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = __title__
copyright = f'{datetime.datetime.now().year}, {__author__}'  # pylint: disable=redefined-builtin

if 'READTHEDOCS' in os.environ:
    version = release = os.environ['READTHEDOCS_VERSION']

    html_baseurl = os.environ['READTHEDOCS_CANONICAL_URL']

    _baseurl_parsed = urllib.parse.urlparse(html_baseurl)
    _baseurl = urllib.parse.ParseResult(_baseurl_parsed.scheme, _baseurl_parsed.netloc, '/', '', '', '').geturl()

    sitemap_url_scheme = "{link}"

    _robots_txt_lines = [
        'User-agent: *',
        '',
        'Disallow: # Allow everything',
        '',
    ]
    for lang in ('en',):
        for tag in ('latest', 'stable'):
            _robots_txt_lines.append('Sitemap: {}{}/{}/sitemap.xml'.format(_baseurl, lang, tag))

    _html_extra_dir_name = 'readthedocs'
    _html_extra_path = pathlib.Path(_html_extra_dir_name)
    _html_extra_path.mkdir(exist_ok=True)
    with open(_html_extra_path / 'robots.txt', 'w+', encoding='ascii') as _robots_txt_file:
        _robots_txt_file.write(os.linesep.join(_robots_txt_lines))

    html_extra_path = [
        _html_extra_dir_name
    ]
else:
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
