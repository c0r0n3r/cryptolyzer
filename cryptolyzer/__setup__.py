# -*- coding: utf-8 -*-

import email.utils
import importlib.metadata

metadata = importlib.metadata.metadata('cryptolyzer')

__title__ = metadata['Name']
__technical_name__ = __title__.lower()
__version__ = metadata['Version']
__description__ = metadata['Summary']
__author__ = email.utils.parseaddr(metadata['Author-email'])[0]
__author_email__ = email.utils.parseaddr(metadata['Author-email'])[1]
__url__ = 'https://gitlab.com/coroner/' + __technical_name__
__license__ = metadata['License']
