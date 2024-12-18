# Ubuntu 22.04
FROM ubuntu@sha256:1b8d8ff4777f36f19bfe73ee4df61e3a0b789caeff29caa019539ec7c9a57f95 AS base
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && \
    apt-get install php-cli -qy && \
    rm -rf /var/lib/apt/lists/*

# No cheese, please!
RUN sed -i 's/disable_classes =$/disable_classes = '$(php -r 'print(join(",",array_diff(get_declared_classes(),["Exception","Shmop"])));')'/g' /etc/php/*/cli/php.ini

WORKDIR /app

COPY share/chall.php chall.php
COPY share/run.sh run

RUN echo "crew{test_flag}" > /flag-$(cat /dev/urandom | tr -cd 'a-f0-9' | head -c 32).txt
RUN chmod +x /app/run

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=30000 JAIL_CPU=100 JAIL_MEM=20M JAIL_TMP_SIZE=1M
