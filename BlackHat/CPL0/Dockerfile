FROM ubuntu:22.04@sha256:0eb0f877e1c869a300c442c41120e778db7161419244ee5cbc6fa5f134e74736 AS base
RUN apt update && apt install -y qemu-system cpio libsndio7.0
WORKDIR /app
COPY --chmod=555 app/qemu-system-x86_64 .
COPY --chmod=555 app/run.sh run
COPY --chmod=444 app/rootfs.cpio .
COPY --chmod=444 app/bzImage .
COPY --chmod=555 app/pc-bios pc-bios

FROM pwn.red/jail
COPY --from=base / /srv
ENV JAIL_TIME=180 JAIL_CPU=500 JAIL_MEM=256M
