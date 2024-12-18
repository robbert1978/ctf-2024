FROM ubuntu:22.04

# Setup environ
ENV user ctf
ENV binary cs1337

# Install packages
RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirror.kakao.com/g" /etc/apt/sources.list \
 && apt-get update \
 && DEBIAN_FRONTEND=noninteractive \
    apt-get install --no-install-recommends -y gdb supervisor libcurl4-openssl-dev sqlite3 libsqlite3-dev net-tools \
 && rm -rf /var/lib/apt/lists/*

RUN chmod 1733 /tmp /var/tmp /dev/shm

RUN adduser --disabled-password --gecos "" $user
COPY supervisord.conf /etc/supervisord.conf
ADD $binary /home/$user/$binary
ADD index.html /home/$user/index.html
ADD login.html /home/$user/login.html
ADD signup.html /home/$user/signup.html
ADD board.html /home/$user/board.html

RUN mkdir -p /home/$user/db
ADD simple_board.db /home/$user/db/simple_board.db
RUN chown -R $user:$user /home/$user/db
RUN chmod -R 777 /home/$user/db
ADD flag /home/$user/flag
RUN chown -R root:$user /home/$user/
RUN chown root:$user /home/$user/$binary

RUN chmod 2755 /home/$user/$binary
RUN chmod 777 /home/$user/db/simple_board.db

RUN md5sum /home/$user/flag | awk '{print $1}' | xargs -I {} mv /home/$user/flag /home/$user/flag_{}

RUN chmod 440 /home/$user/flag_*
RUN chmod 440 /home/$user/board.html
RUN chmod 440 /home/$user/index.html
RUN chmod 440 /home/$user/login.html
RUN chmod 440 /home/$user/signup.html

# RUN service supervisor restart
EXPOSE 1338
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisord.conf"]