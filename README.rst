CryptoLyzer
===========

What is it and what is it not?
------------------------------

As the project name CryptoLyzer implies, it is an cryptographic protocol analyzer. The main purpose of creating this
application is the fact, that cryptography protocol analysis differs in many aspect from establishing a connection
using a cryptographic protocol. Analysis is mostly testing where we trigger special and corner cases of the protocol
and we also trying to establish connection with hardly supported, experimental, obsoleted or even deprecated mechanisms
or algorithms which are may or may not supported by the latest or any version of an implementation of the cryptographic 
protocol.

As follows, it is neither a comprehensive nor a secure client/server implementation of any cryptographic protocol. On 
the one hand analyzer implements only the absolutely necessary parts of the protocol to interact with servers. On the 
other it may use completely insecure algorithms and mechanisms. It is not designed and contraindicated to use these
client/server implementations establishing secure connections. If you are searching for proper cryptographic protocol 
implementations, there are several existing wrappers and native implementations for Python (eg: M2Crypto, pyOpenSSL, 
Paramiko, ...).

Quick start
-----------

CryptoLyzer can be installed directly via pip:

::

    pip install cryptolyzer

Development environment
-----------------------

If you want to setup a development environment, you are in need of `pipenv <https://docs.pipenv.org/>`__.

::

    $ cd cryptolyzer
    $ pipenv install --dev
    $ pipenv shell

License
-------

The code is available under the terms of Mozilla Public License Version 2.0 (MPL 2.0).

A non-comprehensive, but straightforward description of MPL 2 can be found at `Choose an open source
license <https://choosealicense.com/licenses#mpl-2.0>`__ website.
