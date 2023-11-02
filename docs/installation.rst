------------
Installation
------------

Python Package
==============

.. code:: shell

   pip install cryptolyzer

Docker
======

.. code:: shell

   podman pull coroner/cryptolyzer

Operating System Package
========================

Deb
---

.. code:: shell

   apt update && apt install -y gnupg2 curl
   echo 'deb https://download.opensuse.org/repositories/home:/pfeiffersz:/cryptolyzer:/dev/Debian_Testing/ /' >/etc/apt/sources.list.d/cryptolyzer.list
   curl -s https://download.opensuse.org/repositories/home:/pfeiffersz:/cryptolyzer:/dev/Debian_Testing/Release.key | apt-key add -

   apt update && apt install -y python3-pkg-resources python3-cryptoparser python3-cryptolyzer

   cryptolyze tls all www.example.com
   cryptolyze tls1_2 ciphers www.example.com
   cryptolyze ssh2 ciphers www.example.com
   cryptolyze http headers www.example.com

RPM
---

.. code:: shell

   dnf install 'dnf-command(config-manager)'
   dnf config-manager --add-repo https://download.opensuse.org/repositories/home:/pfeiffersz:/cryptolyzer:/dev/Fedora_Rawhide/
   rpm --import http://download.opensuse.org/repositories/home:/pfeiffersz:/cryptolyzer:/dev/Fedora_31/repodata/repomd.xml.key
   dnf install python3-urllib3 python3-cryptography cryptoparser cryptolyzer
