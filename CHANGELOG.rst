Changelog
=========

.. _v0-2-0:

0.2.0 - 2019-12-05
------------------

Features
^^^^^^^^

* TLS (``tls``)

  * Diffie-Hellman (``dhparams``)

    * check whether server uses `safe prime <https://en.wikipedia.org/wiki/Safe_prime>`_  as DH parameter to avoid
      `small subgroup confinement attack <https://en.wikipedia.org/wiki/Small_subgroup_confinement_attack>`_ (#13)
    * check whether server uses well-known (RFC defined) DH parameter (#13)
    * check whether server reuse the DH parameter (#13)

  * FTP opportunistic TLS (``STARTTLS``) support (#8)

Notable Fixes
^^^^^^^^^^^^^

* TLS (``tls``)

  * Cipher Suites (``ciphers``)

    * handle server long cipher suite list intolerance
    * fix cipher suite preference order calculation (#18)

  * Elliptic Curves (``curves``)

    * fix result when server does not support named group extension

  * Public Keys (``pubkeys``)

    * handle cross signed key in the certificate chain
    * fixed JSON output in case of expired certificates (#15)
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
------------------

Features
^^^^^^^^

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
^^^^^^^^^^^^

* check TLS server against used fallback (handshake without
  `SNI <https://en.wikipedia.org/wiki/Server_Name_Indication>`_) certificates
* add `opportunistic TLS <https://en.wikipedia.org/wiki/Opportunistic_TLS>`_ (STARTTLS) support for
  `IMAP <https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol>`_,
  `SMTP <https://en.wikipedia.org/wiki/Simple_Mail_Transfer_Protocol>`_,
  `POP3 <https://en.wikipedia.org/wiki/Post_Office_Protocol>`_ protocols
