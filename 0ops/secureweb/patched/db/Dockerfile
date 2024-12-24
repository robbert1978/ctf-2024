FROM mariadb:latest

RUN apt-get -y update &&  \ 
    apt-get install --no-install-recommends  \
    -y uuid-runtime && \
    rm -rf /var/lib/apt/lists/*

ADD ctf.sql /docker-entrypoint-initdb.d/ctf.sql
RUN sed -i "s/<uuid>/$(uuidgen)/" /docker-entrypoint-initdb.d/ctf.sql