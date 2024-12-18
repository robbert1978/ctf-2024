FROM ubuntu:20.04

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ Asia/Seoul
ENV PYTHONIOENCODING UTF-8
ENV LC_CTYPE C.UTF-8

RUN apt-get update -y && apt-get upgrade -y
RUN apt-get install gdbserver python3-pip cpio libpixman-1-dev libepoxy-dev libspice-server-dev libfdt-dev libusb-1.0.0-dev libasound-dev libaio-dev libslirp-dev -y

RUN useradd --create-home --shell /bin/bash dreamhack

WORKDIR /home/dreamhack

ADD ./prob /home/dreamhack
RUN cp -r /home/dreamhack/libs/* /lib/x86_64-linux-gnu/

RUN chown -R root:root /home/dreamhack
RUN chmod -R a=wx /tmp

RUN chmod a=rx bridge.py
RUN chmod a=rx run.sh
RUN chmod a=rx ynetd

USER dreamhack
WORKDIR /home/dreamhack
CMD ./ynetd -p 4321 "timeout 120 python3 bridge.py"
