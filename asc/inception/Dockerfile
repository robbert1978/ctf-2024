FROM ubuntu@sha256:0e5e4a57c2499249aafc3b40fcd541e9a456aab7296681a3994d631587203f97

RUN apt-get update
RUN apt-get install -y socat python3 python3-pip qemu-system-arm

RUN useradd -ms /bin/bash inception
RUN chown root:inception /home/inception
RUN chmod 1733 /tmp /var/tmp /dev/shm

COPY --chown=root:inception run.py portal rootfs.cpio zImage /home/inception/
RUN chmod +x /home/inception/run.py /home/inception/portal

WORKDIR /home/inception
USER inception
CMD socat TCP-LISTEN:30000,reuseaddr,fork EXEC:"/home/inception/run.py"
