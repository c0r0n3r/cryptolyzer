.. image:: https://gitlab.com/coroner/cryptolyzer/badges/master/pipeline.svg
    :alt:  Pipeline
    :target: https://gitlab.com/coroner/cryptolyzer/-/pipelines/master/latest
.. image:: https://coveralls.io/repos/gitlab/coroner/cryptolyzer/badge.svg?branch=master
    :alt:  Test Coverage
    :target: https://coveralls.io/gitlab/coroner/cryptolyzer/
.. image:: https://readthedocs.org/projects/cryptolyzer/badge/?version=latest
    :alt:  Documentation
    :target: https://cryptolyzer.readthedocs.io

**CryptoLyzer** is a fast, flexible, and comprehensive server cryptographic protocol
(`TLS <https://en.wikipedia.org/wiki/Transport_Layer_Security>`__,
`SSL <https://en.wikipedia.org/wiki/Transport_Layer_Security#SSL_1.0,_2.0,_and_3.0>`__,
`SSH <https://en.wikipedia.org/wiki/Secure_Shell>`__,
`DNSSEC <https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions>`__) and related setting
(`HTTP headers <https://en.wikipedia.org/wiki/List_of_HTTP_header_fields>`__,
`DNS records <https://en.wikipedia.org/wiki/List_of_DNS_record_types>`__) analyzer and fingerprint
(`JA3 <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`__,
`HASSH <https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c/>`__ tag) generator with
`application programming <https://en.wikipedia.org/wiki/API>`__ (API) and
`command line <https://en.wikipedia.org/wiki/Command-line_interface>`__ (CLI) interface.

However the API can provide the most complete functionality, the CLI also strives to be as comprehensive as possible. To
do that CLI provides three output formats. The first one for human analysis where the cryptographic algorithm names and
the values of key sizes and other security-related settings are colorized according to their security strength using the
well-known `traffic light rating system <https://en.wikipedia.org/wiki/Traffic_light_rating_system>`__. The other two
output formats (:ref:`Output Formats / Markdown`, :ref:`Output Formats / JSON`) are machine-readable, however the
Markdown format even human-readable and even suitable for generating documentation in different formats (e.g. DOCX, PDF,
...).

.. only:: html

  .. raw:: html

    <script async id="asciicast-618789" src="https://asciinema.org/a/618789.js"></script>

The strength of CryptoLyzer compared to its competitors is that it contains a custom implementation of cryptographic
protocols (`CryptoParser <https://cryptoparser.readthedocs.io>`__), which are as small as absolutely necessary for the
analysis, but as most comprehensive algorithm identifier sets of the cryptographic protocols
(`CryptoDataHub <https://cryptodatahub.readthedocs.io>`__) as possible. The combination of the two properly makes it
possible to check the support of rarely used, deprecated, non-standard, or experimental algorithms and methods that are
not yet or have never been supported by the most popular cryptographic algorithms. This way of working leads to the fact
that CryptoLyzer can recognize more TLS cipher suites than listed in total on
`Ciphersuite Info <https://ciphersuite.info/cs/>`__.

-----
Usage
-----

Pip
===

.. code:: shell

   pip install cryptolyzer

   cryptolyze tls all www.example.com
   cryptolyze tls1_2 ciphers www.example.com
   cryptolyze ssh2 ciphers www.example.com
   cryptolyze http headers www.example.com
   cryptolyze dns dnssec example.com

Docker
======

.. code:: shell

   docker run --rm coroner/cryptolyzer tls all www.example.com
   docker run --rm coroner/cryptolyzer tls1_2 ciphers www.example.com
   docker run --rm coroner/cryptolyzer ssh2 ciphers www.example.com
   docker run --rm coroner/cryptolyzer http headers www.example.com
   docker run --rm coroner/cryptolyzer dns dnssec example.com

.. code:: shell

   docker run -ti --rm -p 127.0.0.1:4433:4433 coroner/cryptolyzer ja3 generate 127.0.0.1:4433
   openssl s_client -connect 127.0.0.1:4433

   docker run -ti --rm -p 127.0.0.1:2121:2121 coroner/cryptolyzer ja3 generate ftp://127.0.0.1:2121
   openssl s_client -starttls ftp -connect 127.0.0.1:2121

.. code:: shell

   docker run -ti --rm -p 127.0.0.1:2222:4433 coroner/cryptolyzer hassh generate 127.0.0.1:2222
   openssl s_client -connect 127.0.0.1:2222

-------
Support
-------

Python implementation
=====================

-  CPython (3.9+)
-  PyPy (3.9+)

Operating systems
=================

-  Linux
-  macOS
-  Windows

------------
Social Media
------------

-  `Twitter <https://twitter.com/CryptoLyzer>`__
-  `Facebook <https://www.facebook.com/cryptolyzer>`__

-------------
Documentation
-------------

Detailed `documentation <https://cryptolyzer.readthedocs.io>`__ is available on the project's
`Read the Docs <https://readthedocs.com>`__ site.

-------
License
-------

The `code <https://gitlab.com/coroner/cryptolyzer>`__ is available under the terms of
`Mozilla Public License Version 2.0 <https://www.mozilla.org/en-US/MPL/2.0/>`__ (MPL 2.0).

A non-comprehensive, but straightforward description of MPL 2.0 can be found at
`Choose an open source license <https://choosealicense.com/licenses#mpl-2.0>`__ website.

-------
Credits
-------

-  `NLnet Foundation <https://nlnet.nl>`__ and `NGI Assure <https://www.assure.ngi.eu>`__, supports the project part of
   the `Next Generation Internet <https://ngi.eu>`__ initiative.
-  Icons made by `Freepik <https://www.flaticon.com/authors/freepik>`__ from `Flaticon <https://www.flaticon.com/>`__.
