FROM python:3.8-slim

LABEL maintainer Szilárd Pfeiffer "coroner@pfeifferszilard.hu"

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ADD . /usr/src/cryptolyzer
WORKDIR /usr/src/cryptolyzer
RUN pip3 --no-cache-dir install .
WORKDIR /usr/src/cryptolyzer/submodules/cryptoparser
RUN pip3 --no-cache-dir install --force-reinstall .

ENTRYPOINT ["cryptolyze"]
CMD []
