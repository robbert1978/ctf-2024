FROM rust:1.83-bullseye AS builder

ADD . /build
WORKDIR /build

RUN cargo build

FROM debian:bullseye

RUN apt-get -y update &&  \ 
    apt-get install --no-install-recommends  \
    -y uuid-runtime && \
    rm -rf /var/lib/apt/lists/*

COPY --from=0 /build/target/debug/web /app/web
RUN useradd -U -s /bin/sh -M ctf
ADD flag /flag
RUN chmod 444 /flag
ADD config.yaml /app/config/
RUN chmod 444 /app/config/config.yaml
RUN sed -i "s/<uuid>/$(uuidgen)/" /flag
WORKDIR /app
USER ctf
EXPOSE 8080
ENTRYPOINT ["./web"]
