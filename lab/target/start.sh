#!/bin/bash
set -e

mkdir -p /run/sshd /var/run/vsftpd/empty

cat > /etc/vsftpd.conf <<'CONFIG'
listen=YES
listen_ipv6=NO
anonymous_enable=YES
local_enable=YES
write_enable=NO
xferlog_enable=YES
CONFIG

cat > /etc/xinetd.d/telnet <<'CONFIG'
service telnet
{
    type            = UNLISTED
    port            = 23
    protocol        = tcp
    socket_type     = stream
    wait            = no
    user            = root
    server          = /usr/sbin/telnetd
    disable         = no
}
CONFIG

nginx

/usr/sbin/sshd

/usr/sbin/vsftpd /etc/vsftpd.conf &

xinetd -dontfork
