Changelog
=========

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
