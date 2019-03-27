FROM debian

MAINTAINER Szilárd Pfeiffer "coroner@pfeifferszilard.hu"

ENV DEBIAN_FRONTEND noninteractive

RUN apt-get update
RUN apt-get install -y python3 python3-pip

ADD submodules/cryptoparser /usr/src/cryptoparser
WORKDIR /usr/src/cryptoparser
RUN pip3 install .
ADD . /usr/src/cryptolyzer
WORKDIR /usr/src/cryptolyzer
RUN pip3 install .

RUN if [ "x$LOCAL_BUILD" == "x" ] ; \
 then \
 apt-get purge -y python3-pip \
 && apt-get autoremove -y \
 && apt-get clean \
 && rm -rf /var/lib/apt/lists/* \
 && rm -rf /var/tmp/* \
 && rm -rf /tmp/* \
 ; fi

ENTRYPOINT ["cryptolyze"]
CMD []
