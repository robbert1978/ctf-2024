FROM ubuntu:22.04
MAINTAINER LJP-TW

ENV DEBAIN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y python3 socat

RUN useradd -m ctf

USER ctf

CMD socat tcp-listen:1337,reuseaddr,fork exec:/home/ctf/run.py,pty,echo=0,raw,iexten=0