#!/bin/bash

rm /etc/localtime
ln -s /usr/share/zoneinfo/Europe/London /etc/localtime
setenforce 0
sed -i "s/SELINUX=enforcing/SELINUX=disabled/g" /etc/sysconfig/selinux

yum update -y
yum install -y \
   mariadb-devel \
   mariadb-server \
   ntp

systemctl stop firewalld
systemctl disable firewalld
systemctl enable ntpd
systemctl enable mariadb
systemctl start mariadb

mysql -u root -e "USE mysql; CREATE USER 'testadmin'@'%' IDENTIFIED BY 'testadminpass'; GRANT ALL PRIVILEGES ON *.* TO 'testadmin'@'%' WITH GRANT OPTION;"

cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

reboot
