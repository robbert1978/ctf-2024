FROM ubuntu:22.04@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97 AS builder

RUN useradd -u 1000 jail

FROM pwn.red/jail

COPY --from=builder / /srv
COPY epfl_heap /srv/app/epfl_heap
COPY run /srv/app/run
COPY sandbox.js /srv/app/
RUN mkdir -p /srv/app/libs
COPY ./libs/libfrida-gum-1.0.so /srv/app/libs/
COPY ./libs/libfrida-gumjs-1.0.so /srv/app/libs/
COPY ./libs/libm.so.6 /srv/app/libs/
COPY frida-gadget.so /srv/app/
COPY frida-gadget.config /srv/app/
COPY flag /srv/app/flag

RUN chmod 755 /srv/app/run 
RUN chmod 755 /srv/app/epfl_heap
RUN chmod 755 /srv/app/frida-gadget.so
RUN chmod 755 /srv/app/libs/libfrida-gum-1.0.so
RUN chmod 755 /srv/app/libs/libfrida-gumjs-1.0.so
RUN chmod 755 /srv/app/libs/libm.so.6
RUN chmod 744 /srv/app/flag

ENV JAIL_TIME=120
ENV JAIL_CONNS_PER_IP=5
ENV JAIL_MEM=20M

