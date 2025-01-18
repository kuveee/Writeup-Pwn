FROM amd64/ubuntu:22.04


RUN apt-get update && \
        apt-get -y upgrade && \
        apt-get install -y \
        xinetd \
        iproute2

RUN groupadd -r user && useradd -r -g user user

COPY --chown=root:user ./build/start.sh /home/user/start.sh
COPY --chown=root:user ./build/flag.txt /home/user/flag.txt
COPY --chown=root:user ./build/password.txt /home/user/password.txt
COPY --chown=root:user ./dist/chall /home/user/chall
COPY --chown=root:root ./build/ctf.conf /etc/xinetd.d/ctf

WORKDIR /home/user

RUN chmod 444 ./flag.txt && \
        chmod 444 ./password.txt && \
        chmod 555 ./chall && \
        chmod 555 ./start.sh && \
        chmod 444 /etc/xinetd.d/ctf

USER user
EXPOSE 41778

CMD ["xinetd", "-dontfork", "-f","/etc/xinetd.d/ctf"]
