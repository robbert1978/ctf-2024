FROM ubuntu@sha256:8e5c4f0285ecbb4ead070431d29b576a530d3166df73ec44affc1cd27555141b

RUN apt-get update
RUN apt-get install -y socat

RUN useradd -m -s /bin/bash chall
RUN chown root:chall /home/chall
RUN chmod 1733 /tmp /var/tmp /dev/shm

COPY --chown=root:chall ezdb flag /home/chall/
RUN chmod +x /home/chall/ezdb

WORKDIR /home/chall
CMD socat TCP-LISTEN:40000,reuseaddr,fork EXEC:/home/chall/ezdb
