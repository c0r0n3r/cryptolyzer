=========
Changelog
=========

.. _v0-6-0:

0.6.0 - 2021-05-27
==================

Improvements
------------

* TLS (``tls``)

  * Ciphers (``ciphers``)

    * add TLS 1.3 support (#35)

  * Elliptic Curves (``curves``)

    * add TLS 1.3 support (#35)

  * Diffie-Hellman (``dhparams``)

    * add TLS 1.3 support (#35)

  * Signature Algorithms (``sigalgos``)

    * add TLS 1.3 support (#35)

  * Versions (``versions``)

    * add TLS 1.3 support (#35)

.. _v0-5-0:

0.5.0 - 2021-04-08
==================

Features
--------

* TLS (``tls``)

   * add analyzer (``all``) for running all TLS analysis at once (#40)

* SSH (``ssh2``)

  * add analyzer for checking SSH servers against 
  `negotiated algorithms <https://tools.ietf.org/html/rfc4253#section-7.1>`_ (#33)

Usability
---------

* Generic

  * use human readable algorithms names in Markdown output (#48)
  * command line interface gives error output instead of traceback on exception (#49)

.. _v0-4-0:

0.4.0 - 2021-01-30
==================

Features
--------

* TLS (``tls``)

  * add analyzer for checking whether TLS server requires client certificate for authentication (#36)
  * `LDAP <https://en.wikipedia.org/wiki/Lightweight_Directory_Access_Protocol>`_ support (#25)

Notable fixes
-------------

* TLS (``tls``)

  * Generic

    * handle that a server indicates handshake failure by sending close notify alert (#44)
    * handle that a server does not respect lack of the signature algorithms extension (#43)

  * Versions (``versions``)

    * handle that a server supports only non-RSA public keys (#41)

Performance
-----------

* TLS (``tls``)

  * Cipher Suites (``ciphers``)

    * speed up TLS supported curve check (#39)

.. _v0-3-1:

0.3.1 - 2020-09-15
==================

Features
--------

* Generic

  * `Markdown <https://en.wikipedia.org/wiki/Markdown>`_ output format (#30)

* TLS (``tls``)

  * `XMPP (Jabber) <https://en.wikipedia.org/wiki/XMPP>`_ support (#26)

  * Cipher Suites (``ciphers``)

    * `GOST <https://en.wikipedia.org/wiki/GOST>`_ (national standards of the Russian Federation and CIS countries)
      support for TLS cipher suite checker (#32)

Notable fixes
-------------

* TLS (``tls``)

  * fix several uncertain test cases (#28)

Refactor
--------

* remove unnecessary unicode conversions (#29)
* switch from `cryptography <https://cryptography.io>`_ to `certvalidator <https://github.com/wbond/certvalidator>`_


.. _v0-3-0:

0.3.0 - 2020-04-30
==================

Features
--------

* TLS (``tls``)

  * RDP support (#21)

* JA3 (``ja3``)

  * `JA3 fingerprint <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`_ decoding
    support (#22)
  * `JA3 fingerprint <https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967>`_  generatoin
    support (#23)

Notable fixes
-------------

* FTP server check cause Python traceback on connection close (#27)

Refactor
--------

* use attrs to avoid boilerplates (#24)

.. _v0-2-0:

0.2.0 - 2019-12-05
==================

Features
--------

* TLS (``tls``)

  * Diffie-Hellman (``dhparams``)

    * check whether server uses `safe prime <https://en.wikipedia.org/wiki/Safe_prime>`_  as DH parameter to avoid
      `small subgroup confinement attack <https://en.wikipedia.org/wiki/Small_subgroup_confinement_attack>`_ (#13)
    * check whether server uses well-known (RFC defined) DH parameter (#13)
    * check whether server reuse the DH parameter (#13)

  * FTP opportunistic TLS (``STARTTLS``) support (#8)

Notable Fixes
-------------

* TLS (``tls``)

  * Cipher Suites (``ciphers``)

    * handle server long cipher suite list intolerance
    * fix cipher suite preference order calculation (#18)

  * Elliptic Curves (``curves``)

    * fix result when server does not support named group extension

  * Public Keys (``pubkeys``)

    * handle cross signed key in the certificate chain
    * fix JSON output in case of expired certificates (#15)
    * handle the case when only a self-singed CA is served as certificate (#17)
    * handle the case when CA with no basic constraint is served (#20)

  * handle rarely/incorrectly used TLS alerts
  * handle when there is no response from server (#11)
  * handle scheme other than tls in URL argument of the command line tool (#3)
  * handle plain text response to TLS handshake initiation (#19)
  * add default port for opportunistic TLS schemes (#6)
  * uniform timeout handling in TLS clients (#12)

Other
^^^^^

* improve unit tests (100% code coverage)
* Docker support and ready-to-use container on DockerHub 
  (`coroner/cryprolyzer <https://hub.docker.com/r/coroner/cryptolyzer>`_)
* build packages to several Linux distributions on `Open Build Service <https://build.opensuse.org/>`_

  * Debian (10, Testing)
  * Raspbian (10)
  * Ubuntu (19.10)
  * Fedora (29, 30, 31, Rawhide)
  * Mageia (7, Cauldron)

* IP address can be set to hostname in command line (#10)
* fix several Python packaging issues

.. _v0-1-0:

0.1.0 - 2019-03-20
==================

Features
--------

* add analyzer for checking TLS server against supported
  `protocol versions <https://en.wikipedia.org/wiki/Transport_Layer_Security#History_and_development>`_
* add analyzer for checking TLS server against supported
  `cipher suites <https://en.wikipedia.org/wiki/Cipher_suite>`_
* add analyzer for checking TLS server against supported
  `elliptic curves <https://en.wikipedia.org/wiki/Elliptic-curve_cryptography>`_ types
* add analyzer for checking TLS server against used
  `Diffie-Hellman parameters <https://wiki.openssl.org/index.php/Diffie-Hellman_parameters>`_
* add analyzer for checking TLS server against supported signature algorithms
* add analyzer for checking TLS server against used `X.509 <https://en.wikipedia.org/wiki/X.509>`_
  `public key certificates <https://en.wikipedia.org/wiki/Public_key_certificate>`_

Improvements
------------

* check TLS server against used fallback (handshake without
  `SNI <https://en.wikipedia.org/wiki/Server_Name_Indication>`_) certificates
* add `opportunistic TLS <https://en.wikipedia.org/wiki/Opportunistic_TLS>`_ (STARTTLS) support for
  `IMAP <https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol>`_,
  `SMTP <https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`_,
  `POP3 <https://en.wikipedia.org/wiki/Post_Office_Protocol>`_ protocols
