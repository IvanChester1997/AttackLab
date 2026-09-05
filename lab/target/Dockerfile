FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        openssh-server \
        vsftpd \
        telnetd \
        xinetd \
        nginx \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && useradd -m -s /bin/bash labuser \
    && echo 'labuser:labpassword' | chpasswd \
    && echo 'root:labrootpassword' | chpasswd

COPY start.sh /usr/local/bin/start-lab.sh
RUN chmod +x /usr/local/bin/start-lab.sh

EXPOSE 21 22 23 80

CMD ["/usr/local/bin/start-lab.sh"]
