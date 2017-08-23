#!/bin/bash

VAULT_VER="0.8.1"

#yum upgrade -y

rm /etc/localtime
ln -s /usr/share/zoneinfo/Europe/London /etc/localtime

systemctl stop firewalld
systemctl disable firewalld

cat <<EOF >> /etc/sysctl.conf
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1 
EOF

yum install -y \
  unzip \
  wget \
  curl

wget -qO vault.zip https://releases.hashicorp.com/vault/${VAULT_VER}/vault_${VAULT_VER}_linux_amd64.zip
unzip vault.zip
mkdir -p /home/vagrant/vault-data

mv /vagrant/vault.service /etc/systemd/system/vault.service
systemctl enable vault
systemctl start vault
sleep 5

curl -s \
  -X PUT \
  -d "{\"secret_shares\":1, \"secret_threshold\":1}" \
  http://127.0.0.1:8200/v1/sys/init > /home/vagrant/vault.init

UNSEAL_KEY=$(cat /home/vagrant/vault.init | python -c 'import json,sys;obj=json.load(sys.stdin);print obj["keys"][0]')
VAULT_TOKEN=$(cat /home/vagrant/vault.init | python -c 'import json,sys;obj=json.load(sys.stdin);print obj["root_token"]')

curl -s \
    -X PUT \
    -d "{\"key\": \"${UNSEAL_KEY}\"}" \
    http://127.0.0.1:8200/v1/sys/unseal

curl -s \
    -X POST \
    -H "X-Vault-Token:$VAULT_TOKEN" \
    -d '{"type":"app-id"}' \
    http://127.0.0.1:8200/v1/sys/auth/app-id

curl -s \
    -X PUT \
    -H "X-Vault-Token:$VAULT_TOKEN" \
    -d '{"rules":"path \"secret/*\" { policy = \"write\" }"}' \
    http://127.0.0.1:8200/v1/sys/policy/devtest
  

APPID="6a1ab78a-0f5b-4287-9371-cca1fc70b0f1"
USERID="06ba5ac6-3d85-43df-81b5-cf56f4f4624e"

curl -s \
    -X POST \
    -H "X-Vault-Token:$VAULT_TOKEN" \
    -d '{"value":"devtest", "display_name":"devapp"}' \
    http://localhost:8200/v1/auth/app-id/map/app-id/${APPID}

curl -s \
    -X POST \
    -H "X-Vault-Token:$VAULT_TOKEN" \
    -d "{\"value\":\"${APPID}\"}" \
    http://localhost:8200/v1/auth/app-id/map/user-id/${USERID}


echo "*** app_id: ${APPID} ***" 1>&2
echo "--- user_id: ${USERID} ---" 1>&2
