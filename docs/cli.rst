======================
Command-line Interface
======================

-------------
Generic Usage
-------------

Argument Structure
==================

The structure of the command-line interface tries to follow the structure and vocabulary of the analyzable protocol,
however, it also tries to be unified as much as possible. The protocol structure in the command-line interface is
represented by the structure of commands and subcommands. On each level of commands and subcommand the command line
interface's help lists and describes all the arguments available at a certain command level and also the available
subcommands.

.. code:: shell

   cryptolyze --help

Top-level Commands
------------------

At the top level of the command-line interface's command structure, we can determine some global parameters -- such as
the output format and log level -- and the analyzable protocol itself. The analyzable protocols may have multiple
versions or version-independent peculiarities, meaning that the command line interface should give a way to analyze
which versions of a protocol are supported by a service and which are version-independent peculiarities. The most
obvious example is the TLS protocol for demonstrating the command-line interface's structure. To analyze which versions
of the TLS protocol are supported by a service run on the domain *example.com* you can use the following command:

.. code:: shell

   cryptolyze tls versions example.com

Another example of version-independent analyses is when we want to know which versions of the different client
applications of different vendors are compatible with a certain service. In this scenario we can simulate the operation
of client applications, which is independent of the protocol version, meaning the command structure is similar to the
case when we analyzed the protocol version supported by a service.

.. code:: shell

   cryptolyze tls simulate example.com

Protocol Versions
`````````````````

Certain protocol parts may be available only a certain versions of the given protocol. The obvious example again is the
TLS, where the extensions are available only from the 1.2 version. It is also possible that a protocol part works
differently in the case of different protocol versions. An example of that is the Diffie-Hellman parameter negotiation
in TLS version 1.2 compared to version 1.3. It means that it makes sense to analyze using different protocol versions.


.. code:: shell

   cryptolyze tls1_2 simulate example.com
   
   cryptolyze tls1_2 dhparams example.com
   cryptolyze tls1_3 dhparams example.com

All-in-one Analysis
```````````````````

Just like at the top level of the command structure, the help also available at the level of protocol versions. At this
level help lists and describes the protocol-specific subcommands. This structured command hierarchy makes possible to
analyze the protocol part which is actually in the focus, which reduces the load on the server during the analysis and
also shortens analysis run time.  However, sometimes it is necessary to run all the available analyses at one, which
also possible using the following command.

.. code:: shell

   cryptolyze tls all example.com

Analysis Targets
````````````````

Any subcommand represents a certain type of analysis and as such must have a target -- *example.com* in the examples
above. The target -- independently from the command and the subcommand -- is always a URI, however different subcommands
can interpret only certain parts of the URI. For instance, in the case of an SSH server usually only the port of the
service is important beyond the address of the analyzable server. In the case of the TLS protocol port is less important
as its default value is determined by the application layer (e.g. IMAP/143, POP3/110), which is usually not changed by
the administrators. However, the application layer protocol also determines the way we can initiate the TLS layer
(`opportunistic TLS <https://en.wikipedia.org/wiki/Opportunistic_TLS>`__), meaning that it must be passed to the
analyzer. The scheme part of the URI servers that purpose when we analyze a TLS server.


.. code:: shell

   cryptolyze ssh ciphers example.com:2222
   cryptolyze tls versions smtp://smtp.google.com:25

Another important information about the target is the address, which may come from the domain name, but it is possible
that a fully qualified domain name is resolved with multiple IP addresses and we want to determine the IP address. When
the domain name has significance in itself -- which is the case in TLS, because of server name indication (SNI) -- the
IP address should be given separately, using the fragment part of the URI. Anyway, all the subcommands have their own
help, which contains the interpreted part of the URI and their possible values.

.. code:: shell

   cryptolyze tls versions tls://dns.google:443#8.8.4.4

Additional parameters may required for some analysis -- for instance query string should be given to get the necessary
response for HTTP header analysis -- can be given as follows.

.. code:: shell

    cryptolyze http headers https://example.com/?parameter=value

The same method is used when the protocol is not HTTP, but the client requires additional parameters for the analysis,
an example of which is the [to stream attribute](://datatracker.ietf.org/doc/html/rfc6120#section-4.7.2) in the case of
the XMPP protocol, which can be given as follows.

.. code:: shell

    cryptolyze tls versions xmppclient://xmpp.igniterealtime.org/?stream_to=igniterealtime.org

The command-line interface makes available to give multiple analyzable target as arguments, when the targets are analyzed one after another.

.. code:: shell

   cryptolyze tls versions tls://dns.google tls://one.one.one.one ...

Logging
```````

The command-line interface and the Python API provide the same log messages. The content of the messages relates to the
analysis process, so the log levels also refer to the analysis process, not the result of the analysis. It means that
changing the log level to critical will suppress messages that are about the offered cryptographic algorithms, or HTTP
headers by the server, but keep the messages about connection failures for instance.

.. code:: shell

   cryptolyze tls versions --log-level critical tls://dns.google

-----------------------
Cryptographic Protocols
-----------------------

All the cryptographic protocols have the same building blocks, namely peer authentication, key exchange, symmetric
encryption, and message integrity, so they can be analyzed more or less in the same. However, the information on which
the analysis is based can be acquired differently, and the results are similar enough to use (almost) the same structure
in the case of different cryptographic protocols. The technical terms used in the standards of the different
cryptographic protocols may differ from each other, the command-line interface uses the same terms for the same
cryptographic protocol parts to create uniformity.

.. code:: shell

   cryptolyze tls1_2 ciphers example.com
   cryptolyze ssh2 ciphers example.com
   
   cryptolyze tls1_2 dhparams example.com
   cryptolyze ssh2 dhparams example.com
   
   cryptolyze tls1_2 pubkeys example.com
   cryptolyze ssh2 pubkeys example.com

Obviously, there are differences between the cryptographic protocols, meaning that there can be subcommands exclusive
for a protocol, or for a protocol version. For instance, the negotiation of elliptic-curve between the peers is part of
the cipher suite (algorithm) negotiation in the case of the SSH protocol, while in the case of TLS protocol an extension
server that purpose. It means that the elliptic curves supported by a TLS server can be analyzed independently from the
cipher suite negotiation, so there is a subcommand for that (and other) purpose.

.. code:: shell

   cryptolyze tls1_2 curves example.com
   cryptolyze tls1_2 pubkeyreq example.com
   cryptolyze tls1_2 sigalgos example.com

---------------
Other Protocols
---------------

Domain Name System
==================

The domain name system can be analyzed from two perspectives. On the one hand, it is important to analyze how the
records of a certain domain can be transported via the internet, especially since DNS systems use unauthenticated
messages. The `DNSSSEC <https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions>`__ protocol provides
authenticity and integrity for the DNS system, using public key cryptography and message authentication, which can be
analyzed just as in other cryptographic protocols. In accordance with the above, there is a subcommand (``dnssec``) used
to analyze DNSSEC support if available.

.. code:: shell

   cryptolyze dns dnssec example.com

On the other hand, there are several security methods that publish related data in different DNS records. However, the
content of these records is simply text and is not necessarily straightforward for the user. The analyzer in that case
does not analyze the configuration of a running service as it does in the case of ``tls``, ``ssh`, or ``dnssec``, but
the published configuration of security method such as DMARC or SPF, published in a DNS record. For instance, the
content of the e-mail system-related DNS records can be analyzed by the ``mail`` subcommand.

.. code:: shell

   cryptolyze dns mail example.com

Hypertext Transfer Protocol
===========================

Similarly to DNS, the HTTP protocol can also be analyzed from more than one perspective. The confidentiality and
integrity of the transfer data are guaranteed by the TLS protocol, which can be analyzed by the ``tls`` subcommand.

.. code:: shell

   cryptolyze http headers example.com

--------------
Output Formats
--------------

Highlighted
===========

The default format provides a human-readable output using the traffic light rating system, with the well-known red,
amber (yellow), and green colors, where these colors indicate the different security levels of the cryptographic
algorithms, (a)symmetric key sizes, or any methods that respectively considered

* **insecure**: should not be used in any circumstances
* **questionable**: should not be preferred, or may be omitted depending on the details
* **secure**: should be used exclusively, or at least preferred

This output contains not only the security level of the algorithms, key size, or methods but also states the reason,
whether they are considered insecure or questionable. For instance, the encryption algorithm DES is insecure -- because
it is affected by the Sweet32 attack --, or Diffie--Hellman key exchange with if larger key sizes are used questionable,
because of the D(HE)at attack. These findings are part of the output to able the user to understand the reason and
handle the threat properly.

.. only:: html

  .. raw:: html

    <script async id="asciicast-618795" src="https://asciinema.org/a/618795.js"></script>


.. _Output Formats / Markdown:

Markdown
========

The output similar to the highlighted output format, except that it is not colorized.

.. code:: shell

    $ cryptolyze --output-format=markdown tls versions dns.google

.. code:: markdown

    * Target:
        * Scheme: tls
        * Address: dns.google
        * IP address: 8.8.4.4
        * Port: 443
        * Protocol Version: n/a
    * Protocol Versions:
        1. TLS 1.2
        2. TLS 1.3
    * Alerts Unsupported TLS Version: yes

As a consequence of the Markdown format, it is still human-readable, but it also makes possible the post-processing by
document converter tools such as `Pandoc <https://pandoc.org/>`__, giving the opportunity to create a standalone
document or insert the analysis result into a report easily.

.. code:: shell

    $ cryptolyze --output-format=markdown tls all example.com \
    | pandoc --from markdown --to docx --output analysis.docx

.. _Output Formats / JSON:

JSON
====

The JSON output format serves the purpose of machine processing. Along with the fact that CryptoLyzer has a Python API,
one may want to process the analysis result from other programming languages, or just simply transform it using other
tools. One can simply pretty-print the JSON output by ``jq``,

.. code:: shell

    $ cryptolyze --output-format=json tls versions dns.google | jq

.. code:: json

    {
        "target": {
            "scheme": "tls",
            "address": "dns.google",
            "ip": "8.8.8.8",
            "port": 443,
            "proto_version": null
        },
        "versions": [
            "tls1_2",
            "tls1_3"
        ],
        "alerts_unsupported_tls_version": true
    }

or can perform more complex transformations, such as selecting the public key types of an SSH server from the analysis result.

.. code:: shell

    $ cryptolyze --output-format json ssh2 pubkeys github.com \
    | jq --raw-output .public_keys[].key_type

    ECDSA
    ED25519
    RSA
