import datetime

from cryptolyzer.__setup__ import __author__, __title__, __version__


extensions = []
templates_path = ['_templates']
source_suffix = '.rst'
master_doc = 'index'

project = __title__
copyright = f'{datetime.datetime.now().year}, {__author__}'
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
    'description': 'Fast and flexible cryptographic settings analyzer library for Python with CLI',
    'fixed_sidebar': True,
    'collapse_navigation': False,
}
