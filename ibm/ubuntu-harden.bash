#!/bin/bash
ufw --force disable

# Create some user so we can login later
u=$1
useradd -m -s /bin/bash -U $u
usermod -aG docker $u
mkdir /home/$u/.ssh
chmod 700 /home/$u/.ssh
cp ~/.ssh/authorized_keys /home/$u/.ssh/
cp ~/.ssh/known_hosts /home/$u/.ssh/
if [ -f /root/.ssh/gitmirror_id_rsa ]; then mv /root/.ssh/gitmirror_id_rsa /home/$u/.ssh/id_rsa;chmod 600 /home/$u/.ssh/id_rsa; fi;
chmod 600 /home/$u/.ssh/authorized_keys
chown -R $u:$u /home/$u/.ssh
echo "$u ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/10-$u

# Harden SSH
sed -i -e '/^PermitRootLogin/d' /etc/ssh/sshd_config
sed -i -e '/^ChallengeResponseAuthentication/d' /etc/ssh/sshd_config
sed -i -e '/^PasswordAuthentication/d' /etc/ssh/sshd_config
sed -i -e '/^UsePAM/d' /etc/ssh/sshd_config
echo 'PermitRootLogin no' >> /etc/ssh/sshd_config
echo 'DebianBanner no' >> /etc/ssh/sshd_config
echo 'ChallengeResponseAuthentication no' >> /etc/ssh/sshd_config
echo 'PasswordAuthentication no' >> /etc/ssh/sshd_config
echo 'UsePAM yes' >> /etc/ssh/sshd_config
echo 'AuthenticationMethods publickey' >> /etc/ssh/sshd_config
echo "AllowUsers $u" >> /etc/ssh/sshd_config
# Disable insecure algos
echo 'KexAlgorithms curve25519-sha256@libssh.org,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256' >> /etc/ssh/sshd_config
echo 'Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr' >> /etc/ssh/sshd_config
echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,umac-128-etm@openssh.com,hmac-sha2-512,hmac-sha2-256,umac-128@openssh.com' >> /etc/ssh/sshd_config
service ssh restart

# Harden against TCP attacks
printf "
# Ignore ICMP broadcast requests
net.ipv4.icmp_echo_ignore_broadcasts = 1
# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
# Ignore send redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Block SYN attacks
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5
# Log Martians
net.ipv4.conf.all.log_martians = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
# Ignore ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
# Ignore Directed pings
net.ipv4.icmp_echo_ignore_all = 1
" >> /etc/sysctl.d/10-network-security.conf

echo 1 > /proc/sys/net/ipv4/ip_forward
echo 'net.ipv4.ip_forward=1' >> /etc/sysctl.d/99-sysctl.conf
echo 1 > /proc/sys/net/ipv6/conf/default/forwarding
echo 1 > /proc/sys/net/ipv6/conf/all/forwarding
echo 'net.ipv6.conf.default.forwarding=1' >> /etc/sysctl.d/99-sysctl.conf
echo 'net.ipv6.conf.all.forwarding=1' >> /etc/sysctl.d/99-sysctl.conf
sed -i -e '/DEFAULT_FORWARD_POLICY=/d' /etc/default/ufw
echo 'DEFAULT_FORWARD_POLICY="ACCEPT"' >> /etc/default/ufw
echo 'net/ipv4/ip_forward=1' >> /etc/ufw/sysctl.conf
echo 'net/ipv6/conf/default/forwarding=1' >> /etc/ufw/sysctl.conf
echo 'net/ipv6/conf/all/forwarding=1' >> /etc/ufw/sysctl.conf
