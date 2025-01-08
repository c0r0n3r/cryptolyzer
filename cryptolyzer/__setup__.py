# -*- coding: utf-8 -*-

import importlib.metadata

metadata = importlib.metadata.metadata('cryptolyzer')

__title__ = metadata['Name']
__technical_name__ = __title__.lower()
__version__ = metadata['Version']
__description__ = metadata['Summary']
__author__ = metadata['Author']
__author_email__ = metadata['Author-email']
__url__ = 'https://gitlab.com/coroner/' + __technical_name__
__license__ = metadata['License']
