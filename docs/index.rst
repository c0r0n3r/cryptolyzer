.. meta::
    :google-site-verification:
        2AAgZNptPaMHxDeXJegA8i8aW1jURVBpQseacnHQr8Q

.. meta::
    :description:
        Fast, flexible and comprehensive server cryptographic (TLS/SSL/SSH/DNSSEC) and related setting (HTTP headers,
        DNS records) analyzer with Python API and CLI.

.. meta::
    :keywords:
        cryptolyzer,ssl audit, ssl check,ssl checker,tls audit, tls check,tls checker,ssh audit ,ssh check,ssh checker

.. meta::
    :author:
        Szilárd Pfeiffer

=======
Summary
=======

.. include:: ../README.rst

=======
Details
=======

The main purpose of creating this application is the fact, that cryptography protocol analysis differs in many aspect
from establishing a connection using a cryptographic protocol. Analysis is mostly testing where we trigger special and
corner cases of the protocol and we also trying to establish connection with hardly supported, experimental, obsoleted
or even deprecated mechanisms or algorithms which are may or may not supported by the latest or any version of an
implementation of the cryptographic protocol.

As follows, it is neither a comprehensive nor a secure client/server implementation of any cryptographic protocol. On
the one hand analyzer implements only the absolutely necessary parts of the protocol to interact with servers. On the
other it may use completely insecure algorithms and mechanisms. It is not designed and contraindicated to use these
client/server implementations establishing secure connections. If you are searching for proper cryptographic protocol
implementations, there are several existing wrappers and native implementations for Python (eg: M2Crypto, pyOpenSSL,
Paramiko, ...).

.. toctree::
    :maxdepth: 3

    features
    installation
    cli
    api
    development

=======
History
=======

.. toctree::
    :maxdepth: 2

    changelog
