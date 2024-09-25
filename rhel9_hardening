#!/bin/bash

# Ensure the script is being run as root
if [ "$(id -u)" -ne 0 ]; then
  echo "This script must be run as root" >&2
  exit 1
fi

# Update system packages
echo "Updating system packages..."
dnf update -y

# Install essential security tools
echo "Installing security-related packages..."
dnf install -y epel-release
dnf install -y aide mlocate openssh-server chrony firewalld audit

# 1. Secure SSH Configuration
#echo "Hardening SSH configuration..."
#SSH_CONF="/etc/ssh/sshd_config"
#cp "$SSH_CONF" "$SSH_CONF.bak"
#sed -i 's/#PermitRootLogin yes/PermitRootLogin no/' "$SSH_CONF"
#sed -i 's/#PasswordAuthentication yes/PasswordAuthentication no/' "$SSH_CONF"
#sed -i 's/#X11Forwarding yes/X11Forwarding no/' "$SSH_CONF"
#echo "AllowUsers your_secure_user" >> "$SSH_CONF"
#systemctl restart sshd

# 2. Disable unnecessary services
echo "Disabling unnecessary services..."
systemctl disable --now cups
systemctl disable --now avahi-daemon
systemctl disable --now bluetooth
systemctl disable --now postfix

# 3. Set password aging policies
echo "Configuring password aging policies..."
AUTH_FILE="/etc/login.defs"
cp "$AUTH_FILE" "$AUTH_FILE.bak"
sed -i 's/PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' "$AUTH_FILE"
sed -i 's/PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' "$AUTH_FILE"
sed -i 's/PASS_WARN_AGE.*/PASS_WARN_AGE   7/' "$AUTH_FILE"

# 4. Configure automatic updates
echo "Configuring automatic updates..."
dnf install -y dnf-automatic
systemctl enable --now dnf-automatic-install.timer

# 5. Install and configure AIDE (File Integrity Monitoring)
echo "Installing and initializing AIDE..."
aide --init
mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo "0 5 * * * /usr/sbin/aide --check" > /etc/cron.d/aide

# 6. Configure Firewall with Firewalld
echo "Configuring firewall..."
systemctl enable --now firewalld
firewall-cmd --set-default-zone=drop
firewall-cmd --permanent --add-service=ssh
firewall-cmd --permanent --add-service=https
firewall-cmd --permanent --add-service=http
firewall-cmd --reload

# 7. Enable auditd for logging critical events
echo "Enabling auditd..."
systemctl enable --now auditd
auditctl -e 1

# 8. Restrict Core Dumps
echo "Restricting core dumps..."
echo "* hard core 0" >> /etc/security/limits.conf
sysctl -w fs.suid_dumpable=0

# 9. Enable SELinux in enforcing mode
echo "Enabling SELinux..."
sed -i 's/SELINUX=permissive/SELINUX=enforcing/' /etc/selinux/config
setenforce 1

# 10. Set permissions on critical files
echo "Setting permissions on critical system files..."
chown root:root /etc/passwd /etc/shadow /etc/gshadow /etc/group
chmod 644 /etc/passwd /etc/group
chmod 000 /etc/shadow /etc/gshadow

# 11. Enable NTP for time synchronization
echo "Configuring chrony for time synchronization..."
systemctl enable --now chronyd
chronyc sources

# 12. Disable IPv6 if not needed
echo "Disabling IPv6..."
echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf
echo "net.ipv6.conf.default.disable_ipv6 = 1" >> /etc/sysctl.conf
sysctl -p

# 13. Remove unnecessary software
echo "Removing unnecessary software packages..."
dnf remove -y telnet-server rsh-server xinetd ypbind tftp-server

# 14. Enable system logs rotation
echo "Configuring logrotate..."
LOGROTATE_CONF="/etc/logrotate.conf"
cp "$LOGROTATE_CONF" "$LOGROTATE_CONF.bak"
sed -i 's/weekly/daily/' "$LOGROTATE_CONF"
sed -i 's/rotate 4/rotate 12/' "$LOGROTATE_CONF"

# 15. Set up a banner for unauthorized access warning
echo "Setting up an unauthorized access banner..."
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue
echo "Authorized users only. All activity may be monitored and reported." > /etc/issue.net

# 16. Configure sysctl settings for additional kernel hardening
echo "Applying kernel hardening settings..."
cat <<EOF >> /etc/sysctl.conf
# Disable IP forwarding
net.ipv4.ip_forward = 0
# Disable packet redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
# Disable ICMP redirects
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
# Enable IP spoofing protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
EOF
sysctl -p

# 17. Remove unnecessary users and groups
echo "Cleaning up unnecessary users and groups..."
for user in games gopher; do
    userdel $user 2>/dev/null
done

for group in games gopher; do
    groupdel $group 2>/dev/null
done

echo "System hardening completed. Please reboot the server for all changes to take effect."
