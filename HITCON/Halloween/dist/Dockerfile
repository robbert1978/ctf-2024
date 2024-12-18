FROM ubuntu@sha256:0eb0f877e1c869a300c442c41120e778db7161419244ee5cbc6fa5f134e74736
RUN apt-get update && \
    DEBAIN_FRONTEND=noninteractive apt-get install -qy qemu-system-x86 socat
RUN apt-get clean

RUN useradd -m chal
COPY ./share /home/chal

RUN chmod -R 755 /home/chal
RUN chmod -R 774 /tmp
RUN chmod -R 774 /var/tmp
RUN chmod -R 774 /dev
RUN chmod -R 774 /run
RUN chmod 1733 /tmp /var/tmp /dev/shm
RUN chown -R root:root /home/chal
RUN chmod 0755 /home/chal

CMD ["/home/chal/run"]
