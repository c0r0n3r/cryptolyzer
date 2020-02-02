FROM python:3.8-slim

MAINTAINER Szilárd Pfeiffer "coroner@pfeifferszilard.hu"

ADD . /usr/src/cryptolyzer
WORKDIR /usr/src/cryptolyzer
RUN pip3 install .
WORKDIR /usr/src/cryptolyzer/submodules/cryptoparser
RUN pip3 install --force-reinstall .

ENTRYPOINT ["cryptolyze"]
CMD []
