FROM python:3.12.4-slim-bookworm AS app
WORKDIR /app
COPY --chmod=555 parser .
COPY --chmod=555 run.py run
RUN echo "FLAG{*** REDACTED ***}" > /flag.txt
RUN mv /flag.txt /flag-$(md5sum /flag.txt | awk '{print $1}').txt

FROM pwn.red/jail
COPY --from=app / /srv
ENV JAIL_TIME=180 JAIL_MEM=40M JAIL_CPU=100 JAIL_POW=15000 JAIL_TMP_SIZE=10240
