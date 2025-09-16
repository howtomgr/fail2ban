# Fail2ban Installation Guide

Fail2ban is a free and open-source intrusion prevention software framework that protects servers from brute-force attacks. Written in Python, it monitors log files and bans IP addresses that show malicious signs such as too many password failures or seeking exploits. It serves as a powerful FOSS alternative to commercial security solutions like Cloudflare Rate Limiting, AWS WAF, or proprietary IPS systems, providing enterprise-grade protection without licensing costs or vendor lock-in.

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Supported Operating Systems](#supported-operating-systems)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Service Management](#service-management)
6. [Troubleshooting](#troubleshooting)
7. [Security Considerations](#security-considerations)
8. [Performance Tuning](#performance-tuning)
9. [Backup and Restore](#backup-and-restore)
10. [System Requirements](#system-requirements)
11. [Support](#support)
12. [Contributing](#contributing)
13. [License](#license)
14. [Acknowledgments](#acknowledgments)
15. [Version History](#version-history)
16. [Appendices](#appendices)

## 1. Prerequisites

- **Hardware Requirements**:
  - CPU: 1 core minimum (2+ cores recommended for high-traffic servers)
  - RAM: 512MB minimum (1GB+ recommended)
  - Storage: 100MB for installation, plus log storage
  - Network: Stable connectivity for updates
- **Operating System**: 
  - Linux: Any modern distribution with systemd or init
  - macOS: 10.14+ (limited support)
  - Windows: WSL2 with Linux distribution
  - FreeBSD: 11.0+
- **Network Requirements**:
  - Firewall access (iptables, nftables, pf, or ipfw)
  - Root access to modify firewall rules
- **Dependencies**:
  - Python 3.5+ (3.8+ recommended)
  - iptables, nftables, or equivalent firewall
  - systemd or init system
  - Log files to monitor (sshd, nginx, apache, etc.)
- **System Access**: root or sudo privileges required


## 2. Supported Operating Systems

This guide supports installation on:
- RHEL 8/9 and derivatives (CentOS Stream, Rocky Linux, AlmaLinux)
- Debian 11/12
- Ubuntu 20.04/22.04/24.04 LTS
- Arch Linux (rolling release)
- Alpine Linux 3.18+
- openSUSE Leap 15.5+ / Tumbleweed
- SUSE Linux Enterprise Server (SLES) 15+
- macOS 12+ (Monterey and later) 
- FreeBSD 13+
- Windows 10/11/Server 2019+ (where applicable)

## 3. Installation

### RHEL/CentOS/Rocky Linux/AlmaLinux

```bash
# Install EPEL repository
sudo dnf install -y epel-release

# Install fail2ban
sudo dnf install -y fail2ban fail2ban-systemd

# Install additional dependencies
sudo dnf install -y python3-systemd python3-pyinotify

# Enable and start service
sudo systemctl enable --now fail2ban

# Verify installation
fail2ban-client --version
sudo systemctl status fail2ban
```

### Debian/Ubuntu

```bash
# Update package index
sudo apt update

# Install fail2ban
sudo apt install -y fail2ban

# Install additional tools
sudo apt install -y python3-systemd python3-pyinotify iptables-persistent

# Enable and start service
sudo systemctl enable --now fail2ban

# Verify installation
fail2ban-client --version
sudo systemctl status fail2ban
```

### Arch Linux

```bash
# Install fail2ban
sudo pacman -S fail2ban

# Install additional dependencies
sudo pacman -S python-systemd python-pyinotify

# Enable and start service
sudo systemctl enable --now fail2ban

# Verify installation
fail2ban-client --version
```

### Alpine Linux

```bash
# Install fail2ban
apk add --no-cache fail2ban fail2ban-openrc

# Install additional dependencies
apk add --no-cache py3-systemd iptables ip6tables

# Enable and start service
rc-update add fail2ban default
rc-service fail2ban start

# Verify installation
fail2ban-client --version
```

### openSUSE/SLES

```bash
# openSUSE Leap/Tumbleweed
sudo zypper install -y fail2ban python3-systemd

# SLES 15
sudo SUSEConnect -p sle-module-basesystem/15.5/x86_64
sudo zypper install -y fail2ban

# Enable and start service
sudo systemctl enable --now fail2ban

# Configure firewall
sudo firewall-cmd --permanent --add-service=fail2ban
sudo firewall-cmd --reload

# Verify installation
fail2ban-client --version
```

### macOS

```bash
# Using Homebrew
brew install fail2ban

# Copy configuration files
sudo cp /usr/local/etc/fail2ban/fail2ban.conf /usr/local/etc/fail2ban/fail2ban.local
sudo cp /usr/local/etc/fail2ban/jail.conf /usr/local/etc/fail2ban/jail.local

# Start service
sudo brew services start fail2ban

# Verify installation
fail2ban-client --version
```

### FreeBSD

```bash
# Using pkg
pkg install py39-fail2ban

# Enable in rc.conf
echo 'fail2ban_enable="YES"' >> /etc/rc.conf

# Copy configuration
cp /usr/local/etc/fail2ban/fail2ban.conf /usr/local/etc/fail2ban/fail2ban.local
cp /usr/local/etc/fail2ban/jail.conf /usr/local/etc/fail2ban/jail.local

# Start service
service fail2ban start

# Verify installation
fail2ban-client --version
```

### Windows (WSL2)

```powershell
# Install WSL2 with Ubuntu
wsl --install -d Ubuntu-22.04

# Inside WSL2 Ubuntu
sudo apt update
sudo apt install -y fail2ban

# Configure for Windows logs monitoring
# Note: Limited functionality - primarily for learning/testing

# Verify installation
fail2ban-client --version
```

## Initial Configuration

### Basic Configuration

```bash
# Create local configuration files (never edit .conf files directly)
sudo cp /etc/fail2ban/fail2ban.conf /etc/fail2ban/fail2ban.local
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local

# Edit main configuration
sudo tee /etc/fail2ban/fail2ban.local <<EOF
[Definition]
loglevel = INFO
logtarget = /var/log/fail2ban.log
syslogsocket = auto
socket = /var/run/fail2ban/fail2ban.sock
pidfile = /var/run/fail2ban/fail2ban.pid
dbfile = /var/lib/fail2ban/fail2ban.sqlite3
dbpurgeage = 1d
EOF

# Configure basic jail settings
sudo tee /etc/fail2ban/jail.local <<EOF
[DEFAULT]
# Ban duration (in seconds)
bantime = 3600
# Time window for maxretry
findtime = 600
# Number of failures before ban
maxretry = 5
# Email notifications
destemail = admin@example.com
sender = fail2ban@example.com
mta = sendmail
# Action to take
action = %(action_mwl)s

# Whitelist
ignoreip = 127.0.0.1/8 ::1 192.168.0.0/16

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log

[nginx-limit-req]
enabled = true
filter = nginx-limit-req
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 10
findtime = 60
bantime = 600

[apache-auth]
enabled = false
port = http,https
filter = apache-auth
logpath = /var/log/apache*/*error.log
maxretry = 6

[postfix]
enabled = false
port = smtp,465,submission
filter = postfix
logpath = /var/log/mail.log
EOF

# Restart fail2ban
sudo systemctl restart fail2ban
```

### Custom Jail Configuration

```bash
# Create custom filter for application
sudo tee /etc/fail2ban/filter.d/myapp.conf <<EOF
[Definition]
failregex = ^<HOST> - - \[.*\] "POST /login HTTP/.*" 401
            ^Failed login from <HOST>
            ^Authentication failure for .* from <HOST>
ignoreregex =
EOF

# Create jail for custom application
sudo tee -a /etc/fail2ban/jail.local <<EOF

[myapp]
enabled = true
filter = myapp
port = 8080
logpath = /var/log/myapp/access.log
maxretry = 3
bantime = 3600
findtime = 300
EOF
```

## 5. Service Management

### systemd (RHEL, Debian, Ubuntu, Arch, openSUSE)

```bash
# Enable service
sudo systemctl enable fail2ban

# Start service
sudo systemctl start fail2ban

# Stop service
sudo systemctl stop fail2ban

# Restart service
sudo systemctl restart fail2ban

# Reload configuration
sudo systemctl reload fail2ban

# Check status
sudo systemctl status fail2ban

# View logs
sudo journalctl -u fail2ban -f
```

### OpenRC (Alpine Linux)

```bash
# Enable service
rc-update add fail2ban default

# Start service
rc-service fail2ban start

# Stop service
rc-service fail2ban stop

# Restart service
rc-service fail2ban restart

# Check status
rc-service fail2ban status

# View logs
tail -f /var/log/fail2ban.log
```

### rc.d (FreeBSD)

```bash
# Enable in rc.conf
echo 'fail2ban_enable="YES"' >> /etc/rc.conf

# Start service
service fail2ban start

# Stop service
service fail2ban stop

# Restart service
service fail2ban restart

# Check status
service fail2ban status
```

### launchd (macOS)

```bash
# Using brew services
brew services start fail2ban
brew services stop fail2ban
brew services restart fail2ban

# Check status
brew services list | grep fail2ban

# Manual control
sudo /usr/local/bin/fail2ban-client start
sudo /usr/local/bin/fail2ban-client stop
```

## Advanced Configuration

### Multi-Service Protection

```bash
# Comprehensive jail configuration
sudo tee /etc/fail2ban/jail.d/multi-service.conf <<EOF
# SSH Protection
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600
findtime = 600

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 10
bantime = 600
findtime = 60

# Web Server Protection
[nginx-http-auth]
enabled = true
filter = nginx-http-auth
port = http,https
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 5

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 86400

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2

# Database Protection
[mysqld-auth]
enabled = true
filter = mysqld-auth
port = 3306
logpath = /var/log/mysql/error.log
maxretry = 5

[postgresql]
enabled = true
port = 5432
filter = postgresql
logpath = /var/log/postgresql/*.log
maxretry = 5

# Mail Server Protection
[postfix]
enabled = true
port = smtp,465,submission
filter = postfix
logpath = /var/log/mail.log

[postfix-sasl]
enabled = true
port = smtp,465,submission,imap,imaps,pop3,pop3s
filter = postfix-sasl
logpath = /var/log/mail.log

[dovecot]
enabled = true
port = pop3,pop3s,imap,imaps,submission,465,sieve
filter = dovecot
logpath = /var/log/mail.log
EOF
```

### GeoIP Blocking

```bash
# Install GeoIP database
sudo apt install geoip-database geoip-bin  # Debian/Ubuntu
sudo dnf install GeoIP GeoIP-data         # RHEL/CentOS

# Create GeoIP action
sudo tee /etc/fail2ban/action.d/geoip-block.conf <<EOF
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = if [ "\$(geoiplookup <ip> | grep -v 'US\|CA\|GB')" ]; then iptables -I f2b-<name> 1 -s <ip> -j DROP; fi
actionunban = iptables -D f2b-<name> -s <ip> -j DROP
EOF

# Use in jail
sudo tee -a /etc/fail2ban/jail.local <<EOF

[sshd-geoip]
enabled = true
filter = sshd
action = geoip-block[name=%(__name__)s]
logpath = /var/log/auth.log
maxretry = 3
EOF
```

### Persistent Bans

```bash
# Create persistent ban action
sudo tee /etc/fail2ban/action.d/iptables-persistent.conf <<EOF
[Definition]
actionstart = iptables -N f2b-<name>
              iptables -A f2b-<name> -j RETURN
              iptables -I <chain> -p <protocol> --dport <port> -j f2b-<name>
              # Load persistent bans
              [ -f /etc/fail2ban/persistent/<name>.bans ] && while read ip; do iptables -I f2b-<name> 1 -s \$ip -j DROP; done < /etc/fail2ban/persistent/<name>.bans

actionstop = iptables -D <chain> -p <protocol> --dport <port> -j f2b-<name>
             iptables -F f2b-<name>
             iptables -X f2b-<name>

actionban = iptables -I f2b-<name> 1 -s <ip> -j DROP
            echo '<ip>' >> /etc/fail2ban/persistent/<name>.bans
            sort -u /etc/fail2ban/persistent/<name>.bans -o /etc/fail2ban/persistent/<name>.bans

actionunban = iptables -D f2b-<name> -s <ip> -j DROP
              sed -i '/<ip>/d' /etc/fail2ban/persistent/<name>.bans
EOF

# Create directory for persistent bans
sudo mkdir -p /etc/fail2ban/persistent
```

## Reverse Proxy Setup

### nginx Reverse Proxy Configuration

```nginx
# /etc/nginx/conf.d/fail2ban.conf
# Pass real IP to backend for fail2ban processing

map $remote_addr $proxy_forwarded_elem {
    ~^[0-9.]+$          "for=$remote_addr";
    ~^[0-9A-Fa-f:.]+$   "for=\"[$remote_addr]\"";
    default             "for=unknown";
}

map $http_forwarded $proxy_add_forwarded {
    ""      "$proxy_forwarded_elem";
    default "$http_forwarded, $proxy_forwarded_elem";
}

server {
    listen 80;
    server_name app.example.com;

    location / {
        proxy_pass http://backend;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Forwarded $proxy_add_forwarded;
        
        # Rate limiting
        limit_req zone=app_limit burst=10 nodelay;
        limit_req_status 429;
    }
}

# Define rate limit zone
limit_req_zone $binary_remote_addr zone=app_limit:10m rate=10r/s;
```

### HAProxy Configuration

```haproxy
# /etc/haproxy/haproxy.cfg
global
    log /dev/log local0
    log /dev/log local1 notice

defaults
    log global
    option httplog
    option forwardfor

frontend web_frontend
    bind *:80
    bind *:443 ssl crt /etc/ssl/certs/cert.pem
    
    # Track abusive behavior
    stick-table type ip size 100k expire 30m store conn_rate(3s),conn_cur,http_req_rate(10s)
    
    # Block if connection rate exceeds limit
    tcp-request connection reject if { src_conn_rate gt 20 }
    tcp-request connection track-sc0 src
    
    # Block if HTTP request rate exceeds limit
    http-request deny if { sc_http_req_rate(0) gt 20 }
    
    default_backend web_servers

backend web_servers
    # Forward real IP for fail2ban
    option forwardfor header X-Real-IP
    server web1 192.168.1.10:80 check
    server web2 192.168.1.11:80 check
```

### Apache Reverse Proxy

```apache
# /etc/apache2/sites-available/reverse-proxy.conf
<VirtualHost *:80>
    ServerName app.example.com
    
    # Enable required modules
    # a2enmod proxy proxy_http remoteip
    
    # Trust proxy headers from load balancer
    RemoteIPHeader X-Forwarded-For
    RemoteIPTrustedProxy 10.0.0.0/8
    
    # Log real IP
    LogFormat "%a %l %u %t \"%r\" %>s %O \"%{Referer}i\" \"%{User-Agent}i\"" proxy
    CustomLog ${APACHE_LOG_DIR}/access.log proxy
    
    ProxyPass / http://backend/
    ProxyPassReverse / http://backend/
    
    # Pass real IP to backend
    ProxyPreserveHost On
    RequestHeader set X-Real-IP "%{REMOTE_ADDR}s"
    RequestHeader set X-Forwarded-For "%{X-Forwarded-For}i"
</VirtualHost>
```

## Security Configuration

### Enhanced Security Rules

```bash
# Create comprehensive security configuration
sudo tee /etc/fail2ban/jail.d/security-enhanced.conf <<EOF
[DEFAULT]
# Aggressive ban settings for security
bantime = 86400    # 24 hours
findtime = 3600    # 1 hour window
maxretry = 3       # Low tolerance
chain = INPUT      # iptables chain
protocol = tcp     # Default protocol
action = %(action_mwl)s

# Recidive jail for repeat offenders
[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
bantime = 604800   # 1 week
findtime = 86400   # 1 day
maxretry = 3
action = iptables-allports[name=recidive, protocol=all]
         sendmail-whois-lines[name=recidive, logpath=/var/log/fail2ban.log]

# Port scanning detection
[portscan]
enabled = true
filter = portscan
logpath = /var/log/syslog
maxretry = 6
bantime = 7200
action = iptables-allports[name=portscan, protocol=all]

# Block bad bots
[apache-badbots]
enabled = true
port = http,https
filter = apache-badbots
logpath = /var/log/apache*/*access.log
bantime = 172800   # 2 days
maxretry = 1

# WordPress protection
[wordpress]
enabled = true
filter = wordpress
port = http,https
logpath = /var/log/apache*/*access.log
maxretry = 3
bantime = 3600

# Aggressive SSH protection
[sshd-aggressive]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 2
bantime = 86400
findtime = 300
EOF
```

### Custom Security Filters

```bash
# Create port scan detection filter
sudo tee /etc/fail2ban/filter.d/portscan.conf <<EOF
[Definition]
failregex = UFW BLOCK.* SRC=<HOST>
            rejected connection: .* SRC=<HOST>
            dropped: .* SRC=<HOST>
ignoreregex =
EOF

# Create WordPress attack filter
sudo tee /etc/fail2ban/filter.d/wordpress.conf <<EOF
[Definition]
failregex = ^<HOST> .* "POST /wp-login.php
            ^<HOST> .* "POST /xmlrpc.php
            ^<HOST> .* "GET /wp-admin/ HTTP/[0-9.]+" 403
            ^<HOST> .* "GET /wp-content/.*/.*\.php HTTP/[0-9.]+" 
ignoreregex = ^<HOST> .* "GET /wp-admin/admin-ajax.php
EOF

# Create bad bot filter
sudo tee /etc/fail2ban/filter.d/badbots.conf <<EOF
[Definition]
badbotscustom = EmailCollector|WebEMailExtrac|TrackBack/1\.02|sogou music spider|(?:Mozilla/\d+\.0\s+)$
badbots = Atomic_Email_Hunter/4\.0|atSpider/1\.0|autoemailspider|bwh3_user_agent|China Local Browse 2\.6|ContactBot/0\.2|ContentSmartz|DataCha0s/2\.0|DBrowse 1\.4b|DBrowse 1\.4d|Demo Bot DOT 16b|Demo Bot Z 16b|DSurf15a 01|DSurf15a 71|DSurf15a 81|DSurf15a VA|EBrowse 1\.4b|Educate Search VxB|EmailSiphon|EmailSpider|EmailWolf 1\.00|ESurf15a 15|ExtractorPro|Franklin Locator 1\.8|FSurf15a 01|Full Web Bot 0416B|Full Web Bot 0516B|Full Web Bot 2816B|Guestbook Auto Submitter|Industry Program 1\.0\.x|ISC Systems iRc Search 2\.1|IUPUI Research Bot v 1\.9a|LARBIN-EXPERIMENTAL \(efp@gmx\.net\)|LetsCrawl\.com/1\.0 \+http\://letscrawl\.com/|Lincoln State Web Browser|LMQueueBot/0\.2|LWP\:\:Simple/5\.803|Mac Finder 1\.0\.xx|MFC Foundation Class Library 4\.0|Microsoft URL Control - 6\.00\.8xxx|Missauga Locate 1\.0\.0|Missigua Locator 1\.9|Missouri College Browse|Mizzu Labs 2\.2|Mo College 1\.9|MVAClient|Mozilla/2\.0 \(compatible; NEWT ActiveX; Win32\)|Mozilla/3\.0 \(compatible; Indy Library\)|Mozilla/3\.0 \(compatible; scan4mail \(advanced version\) http\://www\.peterspages\.net/?scan4mail\)|Mozilla/4\.0 \(compatible; Advanced Email Extractor v2\.xx\)|Mozilla/4\.0 \(compatible; Iplexx Spider/1\.0 http\://www\.iplexx\.at\)|Mozilla/4\.0 \(compatible; MSIE 5\.0; Windows NT; DigExt; DTS Agent|Mozilla/4\.0 efp@gmx\.net|Mozilla/5\.0 \(Version\: xxxx Type\:xx\)|NameOfAgent \(CMS Spider\)|NASA Search 1\.0|Nsauditor/1\.x|PBrowse 1\.4b|PEval 1\.4b|Poirot|Port Huron Labs|Production Bot 0116B|Production Bot 2016B|Production Bot DOT 3016B|Program Shareware 1\.0\.2|PSurf15a 11|PSurf15a 51|PSurf15a VA|psycheclone|RSurf15a 41|RSurf15a 51|RSurf15a 81|searchbot admin@google\.com|ShablastBot 1\.0|snap\.com beta crawler v0|Snapbot/1\.0|Snapbot/1\.0 \(Snap Shots&#44; \+http\://www\.snap\.com\)|sogou develop spider|Sogou Orion spider/3\.0\(\+http\://www\.sogou\.com/docs/help/webmasters\.htm#07\)|sogou spider|Sogou web spider/3\.0\(\+http\://www\.sogou\.com/docs/help/webmasters\.htm#07\)|sohu agent|SSurf15a 11 |TSurf15a 11|Under the Rainbow 2\.2|User-Agent\: Mozilla/4\.0 \(compatible; MSIE 6\.0; Windows NT 5\.1\)|VadixBot|WebVulnCrawl\.unknown/1\.0 libwww-perl/5\.803|Wells Search II|WEP Search 00

failregex = ^<HOST> -.*"(GET|POST|HEAD).*HTTP.*".*(?:%(badbots)s|%(badbotscustom)s).*"$
ignoreregex =
EOF
```

### Firewall Integration

```bash
# iptables integration
sudo tee /etc/fail2ban/action.d/iptables-common.local <<EOF
[Init]
# Option: blocktype
# Note: This is the default block type for all iptables actions
blocktype = DROP

# Option: iptables
# Note: Path to iptables command
iptables = /sbin/iptables

# Option: protocol
# Note: Default protocol
protocol = tcp

# Option: chain
# Note: Default chain for filter table
chain = INPUT
EOF

# nftables integration
sudo tee /etc/fail2ban/action.d/nftables.local <<EOF
[Definition]
actionstart = nft add table inet fail2ban
              nft add chain inet fail2ban f2b-<name> { type filter hook input priority 0 \; }

actionstop = nft delete chain inet fail2ban f2b-<name>

actionban = nft add rule inet fail2ban f2b-<name> ip saddr <ip> drop

actionunban = nft delete rule inet fail2ban f2b-<name> handle \$(nft -a list chain inet fail2ban f2b-<name> | grep <ip> | awk '{print \$NF}')
EOF
```

## Database Setup

### SQLite Database Configuration

```bash
# Default SQLite database location
ls -la /var/lib/fail2ban/fail2ban.sqlite3

# Custom database configuration
sudo tee -a /etc/fail2ban/fail2ban.local <<EOF

[Definition]
# Database configuration
dbfile = /var/lib/fail2ban/fail2ban.sqlite3
dbpurgeage = 7d
EOF

# View database content
sudo sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "SELECT * FROM bans;"
sudo sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "SELECT jail, ip, COUNT(*) as count FROM bans GROUP BY jail, ip ORDER BY count DESC;"
```

### MySQL Backend Configuration

```bash
# Install MySQL connector
sudo apt install python3-pymysql  # Debian/Ubuntu
sudo dnf install python3-PyMySQL   # RHEL/CentOS

# Create database and user
mysql -u root -p <<EOF
CREATE DATABASE fail2ban;
CREATE USER 'fail2ban'@'localhost' IDENTIFIED BY 'secure_password';
GRANT ALL PRIVILEGES ON fail2ban.* TO 'fail2ban'@'localhost';
FLUSH PRIVILEGES;
EOF

# Configure fail2ban for MySQL
sudo tee /etc/fail2ban/fail2ban.d/mysql.conf <<EOF
[Definition]
dbdriver = mysql
dbhost = localhost
dbport = 3306
dbuser = fail2ban
dbpassword = secure_password
dbname = fail2ban
EOF
```

## Performance Optimization

### System Tuning

```bash
# Optimize fail2ban performance
sudo tee /etc/fail2ban/fail2ban.d/performance.conf <<EOF
[Definition]
# Use systemd journal instead of log files
backend = systemd

# Use pyinotify for better performance
backend = pyinotify

# Increase socket timeout
socket_timeout = 30

# Database optimization
dbmaxmatches = 100
dbpurgeage = 1d
EOF

# Configure systemd limits
sudo mkdir -p /etc/systemd/system/fail2ban.service.d
sudo tee /etc/systemd/system/fail2ban.service.d/limits.conf <<EOF
[Service]
# Increase limits for better performance
LimitNOFILE=65536
LimitNPROC=4096
MemoryLimit=512M
CPUQuota=50%
Nice=-5
EOF

sudo systemctl daemon-reload
sudo systemctl restart fail2ban
```

### Log Processing Optimization

```bash
# Use systemd journal backend for better performance
sudo tee /etc/fail2ban/jail.d/systemd-backend.conf <<EOF
[DEFAULT]
backend = systemd

[sshd]
enabled = true
backend = systemd
journalmatch = _SYSTEMD_UNIT=ssh.service + _COMM=sshd

[nginx]
enabled = true
backend = systemd
journalmatch = _SYSTEMD_UNIT=nginx.service
EOF

# Configure log rotation for fail2ban
sudo tee /etc/logrotate.d/fail2ban <<EOF
/var/log/fail2ban.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        fail2ban-client flushlogs 1>/dev/null
    endscript
}
EOF
```

## Monitoring

### Built-in Monitoring

```bash
# Check fail2ban status
sudo fail2ban-client status

# Check specific jail status
sudo fail2ban-client status sshd

# Get banned IPs for all jails
for jail in $(sudo fail2ban-client status | grep "Jail list" | sed 's/.*://;s/,//g'); do
    echo "=== $jail ==="
    sudo fail2ban-client status $jail | grep "Banned IP"
done

# Monitor fail2ban in real-time
sudo tail -f /var/log/fail2ban.log

# Show ban statistics
sudo fail2ban-client banned
```

### Monitoring Script

```bash
#!/bin/bash
# fail2ban-monitor.sh

LOG_FILE="/var/log/fail2ban-monitor.log"
ALERT_EMAIL="admin@example.com"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Check fail2ban service status
check_service() {
    if ! systemctl is-active --quiet fail2ban; then
        log "ERROR: fail2ban service is not running!"
        echo "fail2ban service down on $(hostname)" | mail -s "fail2ban Alert" "$ALERT_EMAIL"
        return 1
    fi
    log "fail2ban service is running"
}

# Monitor ban activity
monitor_bans() {
    local jail_list=$(fail2ban-client status | grep "Jail list" | sed 's/.*://;s/,//g')
    
    for jail in $jail_list; do
        local status=$(fail2ban-client status "$jail")
        local banned_count=$(echo "$status" | grep "Currently banned:" | awk '{print $NF}')
        local total_banned=$(echo "$status" | grep "Total banned:" | awk '{print $NF}')
        
        log "Jail: $jail - Currently banned: $banned_count, Total banned: $total_banned"
        
        # Alert if too many bans
        if [ "$banned_count" -gt 50 ]; then
            log "WARNING: High number of banned IPs in $jail jail"
            echo "High ban count in $jail: $banned_count IPs" | mail -s "fail2ban Warning" "$ALERT_EMAIL"
        fi
    done
}

# Check for suspicious patterns
check_patterns() {
    local recent_bans=$(tail -n 1000 /var/log/fail2ban.log | grep "Ban" | wc -l)
    
    if [ "$recent_bans" -gt 100 ]; then
        log "WARNING: High ban rate detected: $recent_bans bans in recent logs"
    fi
}

# Generate report
generate_report() {
    local report_file="/tmp/fail2ban-report-$(date +%Y%m%d).txt"
    
    {
        echo "Fail2ban Report - $(date)"
        echo "========================="
        echo
        fail2ban-client status
        echo
        echo "Ban Statistics by Jail:"
        echo "-----------------------"
        
        for jail in $(fail2ban-client status | grep "Jail list" | sed 's/.*://;s/,//g'); do
            echo
            echo "[$jail]"
            fail2ban-client status "$jail"
        done
        
        echo
        echo "Recent Activity:"
        echo "----------------"
        tail -n 50 /var/log/fail2ban.log | grep -E "(Ban|Unban|Found|Restore)"
    } > "$report_file"
    
    log "Report generated: $report_file"
    
    # Email report
    mail -s "Fail2ban Daily Report - $(hostname)" "$ALERT_EMAIL" < "$report_file"
}

# Main monitoring loop
main() {
    log "Starting fail2ban monitoring..."
    
    check_service || exit 1
    monitor_bans
    check_patterns
    generate_report
    
    log "Monitoring completed"
}

# Run monitoring
main

# Add to cron:
# */15 * * * * /usr/local/bin/fail2ban-monitor.sh
```

### Prometheus Integration

```bash
# Install fail2ban exporter
wget https://github.com/hectorjsmith/fail2ban-prometheus-exporter/releases/download/v0.10.0/fail2ban_exporter
chmod +x fail2ban_exporter
sudo mv fail2ban_exporter /usr/local/bin/

# Create systemd service
sudo tee /etc/systemd/system/fail2ban-exporter.service <<EOF
[Unit]
Description=Fail2ban Prometheus Exporter
After=network.target

[Service]
Type=simple
User=prometheus
ExecStart=/usr/local/bin/fail2ban_exporter
Restart=on-failure

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now fail2ban-exporter

# Configure Prometheus
echo "  - job_name: 'fail2ban'
    static_configs:
      - targets: ['localhost:9191']" >> /etc/prometheus/prometheus.yml
```

## 9. Backup and Restore

### Backup Script

```bash
#!/bin/bash
# fail2ban-backup.sh

BACKUP_DIR="/backup/fail2ban"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="$BACKUP_DIR/fail2ban_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop fail2ban to ensure database consistency
systemctl stop fail2ban

# Create backup
tar -czf "$BACKUP_FILE" \
    /etc/fail2ban/ \
    /var/lib/fail2ban/ \
    /var/log/fail2ban.log* \
    2>/dev/null

# Start fail2ban
systemctl start fail2ban

# Encrypt backup
gpg --cipher-algo AES256 --symmetric "$BACKUP_FILE"
rm "$BACKUP_FILE"

echo "Backup created: $BACKUP_FILE.gpg"

# Clean old backups (keep 30 days)
find "$BACKUP_DIR" -name "fail2ban_backup_*.gpg" -mtime +30 -delete

# Backup banned IPs list
fail2ban-client banned > "$BACKUP_DIR/banned_ips_$DATE.txt"
```

### Restore Script

```bash
#!/bin/bash
# fail2ban-restore.sh

BACKUP_FILE="$1"

if [ -z "$BACKUP_FILE" ]; then
    echo "Usage: $0 <backup-file.gpg>"
    exit 1
fi

# Decrypt backup
gpg --decrypt "$BACKUP_FILE" > /tmp/fail2ban_restore.tar.gz

# Stop fail2ban
systemctl stop fail2ban

# Extract backup
tar -xzf /tmp/fail2ban_restore.tar.gz -C /

# Restore permissions
chown -R root:root /etc/fail2ban
chmod 644 /etc/fail2ban/*.conf
chmod 644 /etc/fail2ban/*.local

# Start fail2ban
systemctl start fail2ban

# Clean up
rm /tmp/fail2ban_restore.tar.gz

echo "Restore completed"

# Reload jails
fail2ban-client reload
```

## 6. Troubleshooting

### Common Issues

1. **Service won't start**:
```bash
# Check for syntax errors
fail2ban-client -t

# Check logs
journalctl -u fail2ban -n 100
tail -f /var/log/fail2ban.log

# Check permissions
ls -la /var/run/fail2ban/
ls -la /var/lib/fail2ban/

# Start in foreground for debugging
fail2ban-server -f -x -v
```

2. **IPs not getting banned**:
```bash
# Test regex patterns
fail2ban-regex /var/log/auth.log /etc/fail2ban/filter.d/sshd.conf

# Check jail configuration
fail2ban-client get sshd logpath
fail2ban-client get sshd findtime
fail2ban-client get sshd maxretry

# Test specific log line
echo 'Dec 10 12:34:56 server sshd[12345]: Failed password for invalid user admin from 192.168.1.100 port 12345 ssh2' | fail2ban-regex - /etc/fail2ban/filter.d/sshd.conf
```

3. **Performance issues**:
```bash
# Check database size
ls -lh /var/lib/fail2ban/fail2ban.sqlite3

# Purge old entries
fail2ban-client set dbpurgeage 1d
sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "DELETE FROM bans WHERE timeofban < strftime('%s', 'now', '-7 days');"

# Monitor CPU usage
top -p $(pgrep fail2ban-server)

# Check number of monitored files
lsof -p $(pgrep fail2ban-server) | grep -c log
```

### Debug Mode

```bash
# Enable debug logging
sudo tee -a /etc/fail2ban/fail2ban.local <<EOF
[Definition]
loglevel = DEBUG
EOF

sudo systemctl restart fail2ban

# Watch debug logs
tail -f /var/log/fail2ban.log | grep -E "(DEBUG|ERROR|WARNING)"

# Test jail processing
fail2ban-client set sshd addlogpath /var/log/auth.log
fail2ban-client set sshd banip 192.168.1.100
fail2ban-client set sshd unbanip 192.168.1.100
```

## Integration Examples

### Python Integration

```python
#!/usr/bin/env python3
# fail2ban_api.py

import subprocess
import json
import socket
from datetime import datetime

class Fail2banManager:
    def __init__(self):
        self.socket_path = "/var/run/fail2ban/fail2ban.sock"
    
    def execute_command(self, command):
        """Execute fail2ban-client command"""
        try:
            result = subprocess.run(
                ['fail2ban-client'] + command.split(),
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            return f"Error: {e.stderr}"
    
    def get_status(self):
        """Get overall status"""
        return self.execute_command("status")
    
    def get_jail_status(self, jail):
        """Get specific jail status"""
        status = self.execute_command(f"status {jail}")
        
        # Parse status output
        lines = status.split('\n')
        result = {
            'filter': {},
            'actions': {},
            'currently_failed': 0,
            'total_failed': 0,
            'currently_banned': 0,
            'total_banned': 0,
            'banned_ips': []
        }
        
        for line in lines:
            if 'Currently failed:' in line:
                result['currently_failed'] = int(line.split(':')[1].strip())
            elif 'Total failed:' in line:
                result['total_failed'] = int(line.split(':')[1].strip())
            elif 'Currently banned:' in line:
                result['currently_banned'] = int(line.split(':')[1].strip())
            elif 'Total banned:' in line:
                result['total_banned'] = int(line.split(':')[1].strip())
            elif 'Banned IP list:' in line:
                ips = line.split(':')[1].strip()
                result['banned_ips'] = ips.split() if ips else []
        
        return result
    
    def ban_ip(self, jail, ip, duration=None):
        """Ban an IP address"""
        if duration:
            return self.execute_command(f"set {jail} banip {ip} {duration}")
        else:
            return self.execute_command(f"set {jail} banip {ip}")
    
    def unban_ip(self, jail, ip):
        """Unban an IP address"""
        return self.execute_command(f"set {jail} unbanip {ip}")
    
    def get_banned_ips(self):
        """Get all banned IPs across all jails"""
        banned = {}
        jails = self.get_jail_list()
        
        for jail in jails:
            status = self.get_jail_status(jail)
            if status['banned_ips']:
                banned[jail] = status['banned_ips']
        
        return banned
    
    def get_jail_list(self):
        """Get list of all jails"""
        status = self.get_status()
        for line in status.split('\n'):
            if 'Jail list:' in line:
                jails = line.split(':')[1].strip()
                return [j.strip() for j in jails.split(',')]
        return []
    
    def add_jail(self, jail_config):
        """Add a new jail configuration"""
        config_path = f"/etc/fail2ban/jail.d/{jail_config['name']}.conf"
        
        config_content = f"""[{jail_config['name']}]
enabled = true
port = {jail_config.get('port', 'http,https')}
filter = {jail_config.get('filter', jail_config['name'])}
logpath = {jail_config['logpath']}
maxretry = {jail_config.get('maxretry', 5)}
bantime = {jail_config.get('bantime', 3600)}
findtime = {jail_config.get('findtime', 600)}
"""
        
        with open(config_path, 'w') as f:
            f.write(config_content)
        
        # Reload configuration
        return self.execute_command("reload")

# Example usage
if __name__ == '__main__':
    f2b = Fail2banManager()
    
    # Get overall status
    print("Fail2ban Status:")
    print(f2b.get_status())
    print("\n" + "="*50 + "\n")
    
    # Get banned IPs
    print("Banned IPs by Jail:")
    banned = f2b.get_banned_ips()
    for jail, ips in banned.items():
        print(f"\n{jail}: {', '.join(ips) if ips else 'None'}")
    
    # Check specific jail
    print("\n" + "="*50 + "\n")
    print("SSH Jail Status:")
    ssh_status = f2b.get_jail_status('sshd')
    print(json.dumps(ssh_status, indent=2))
```

### Web Dashboard

```python
#!/usr/bin/env python3
# fail2ban_dashboard.py

from flask import Flask, render_template, jsonify, request
from fail2ban_api import Fail2banManager
import json

app = Flask(__name__)
f2b = Fail2banManager()

@app.route('/')
def dashboard():
    return render_template('dashboard.html')

@app.route('/api/status')
def api_status():
    jails = f2b.get_jail_list()
    status = {
        'jails': {},
        'total_banned': 0,
        'total_failed': 0
    }
    
    for jail in jails:
        jail_status = f2b.get_jail_status(jail)
        status['jails'][jail] = jail_status
        status['total_banned'] += jail_status['total_banned']
        status['total_failed'] += jail_status['total_failed']
    
    return jsonify(status)

@app.route('/api/ban', methods=['POST'])
def api_ban():
    data = request.json
    result = f2b.ban_ip(data['jail'], data['ip'], data.get('duration'))
    return jsonify({'success': True, 'result': result})

@app.route('/api/unban', methods=['POST'])
def api_unban():
    data = request.json
    result = f2b.unban_ip(data['jail'], data['ip'])
    return jsonify({'success': True, 'result': result})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
```

### Shell Integration

```bash
#!/bin/bash
# fail2ban-utils.sh - Fail2ban utility functions

# Source this file in other scripts: source /usr/local/lib/fail2ban-utils.sh

# Check if IP is banned
is_ip_banned() {
    local ip="$1"
    local jail="${2:-}"
    
    if [ -z "$jail" ]; then
        # Check all jails
        for j in $(fail2ban-client status | grep "Jail list" | sed 's/.*://;s/,//g'); do
            if fail2ban-client status "$j" | grep -q "$ip"; then
                echo "IP $ip is banned in jail: $j"
                return 0
            fi
        done
    else
        # Check specific jail
        if fail2ban-client status "$jail" | grep -q "$ip"; then
            return 0
        fi
    fi
    
    return 1
}

# Ban IP with reason logging
ban_ip_with_reason() {
    local jail="$1"
    local ip="$2"
    local reason="$3"
    local duration="${4:-3600}"
    
    echo "[$(date)] Banning IP $ip in jail $jail for $duration seconds. Reason: $reason" >> /var/log/fail2ban-manual-bans.log
    fail2ban-client set "$jail" banip "$ip" "$duration"
}

# Get ban statistics
get_ban_stats() {
    local total_banned=0
    local total_failed=0
    
    echo "Fail2ban Statistics"
    echo "=================="
    
    for jail in $(fail2ban-client status | grep "Jail list" | sed 's/.*://;s/,//g'); do
        local status=$(fail2ban-client status "$jail")
        local banned=$(echo "$status" | grep "Total banned:" | awk '{print $NF}')
        local failed=$(echo "$status" | grep "Total failed:" | awk '{print $NF}')
        
        echo "[$jail]"
        echo "  Failed: $failed"
        echo "  Banned: $banned"
        
        total_banned=$((total_banned + banned))
        total_failed=$((total_failed + failed))
    done
    
    echo
    echo "Totals:"
    echo "  Failed: $total_failed"
    echo "  Banned: $total_banned"
}

# Whitelist management
add_to_whitelist() {
    local ip="$1"
    
    # Add to fail2ban whitelist
    if grep -q "ignoreip" /etc/fail2ban/jail.local; then
        sed -i "/ignoreip/s/$/,$ip/" /etc/fail2ban/jail.local
    else
        echo "ignoreip = 127.0.0.1/8 ::1 $ip" >> /etc/fail2ban/jail.local
    fi
    
    # Reload configuration
    fail2ban-client reload
    
    echo "Added $ip to whitelist"
}

# Export functions for use in other scripts
export -f is_ip_banned
export -f ban_ip_with_reason
export -f get_ban_stats
export -f add_to_whitelist
```

## Maintenance

### Update Procedures

```bash
# RHEL/CentOS/Rocky/AlmaLinux
sudo dnf update fail2ban

# Debian/Ubuntu
sudo apt update && sudo apt upgrade fail2ban

# Arch Linux
sudo pacman -Syu fail2ban

# Alpine Linux
apk update && apk upgrade fail2ban

# openSUSE
sudo zypper update fail2ban

# FreeBSD
pkg update && pkg upgrade py39-fail2ban

# Always backup before updates
/usr/local/bin/fail2ban-backup.sh

# Restart after updates
sudo systemctl restart fail2ban
```

### Regular Maintenance Tasks

```bash
#!/bin/bash
# fail2ban-maintenance.sh

LOG_FILE="/var/log/fail2ban-maintenance.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Update filters from repository
update_filters() {
    log "Updating fail2ban filters..."
    
    cd /tmp
    git clone https://github.com/fail2ban/fail2ban.git
    
    # Backup existing filters
    cp -r /etc/fail2ban/filter.d /etc/fail2ban/filter.d.bak
    
    # Copy new filters
    cp /tmp/fail2ban/config/filter.d/* /etc/fail2ban/filter.d/
    
    # Test configuration
    if fail2ban-client -t; then
        log "Filter update successful"
    else
        log "ERROR: Filter update failed, restoring backup"
        rm -rf /etc/fail2ban/filter.d
        mv /etc/fail2ban/filter.d.bak /etc/fail2ban/filter.d
    fi
    
    rm -rf /tmp/fail2ban
}

# Clean old database entries
clean_database() {
    log "Cleaning fail2ban database..."
    
    # Get database size before
    size_before=$(ls -lh /var/lib/fail2ban/fail2ban.sqlite3 | awk '{print $5}')
    
    # Clean entries older than 30 days
    sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "DELETE FROM bans WHERE timeofban < strftime('%s', 'now', '-30 days');"
    sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "VACUUM;"
    
    # Get database size after
    size_after=$(ls -lh /var/lib/fail2ban/fail2ban.sqlite3 | awk '{print $5}')
    
    log "Database cleaned. Size: $size_before -> $size_after"
}

# Check and update GeoIP database
update_geoip() {
    log "Updating GeoIP database..."
    
    if command -v geoipupdate >/dev/null 2>&1; then
        geoipupdate
        log "GeoIP database updated"
    else
        log "GeoIP update tool not installed"
    fi
}

# Generate monthly report
generate_monthly_report() {
    log "Generating monthly report..."
    
    report_file="/var/log/fail2ban-monthly-$(date +%Y%m).txt"
    
    {
        echo "Fail2ban Monthly Report - $(date '+%B %Y')"
        echo "========================================"
        echo
        
        # Get ban statistics from database
        echo "Top 10 Banned IPs:"
        sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "SELECT ip, COUNT(*) as count FROM bans WHERE timeofban > strftime('%s', 'now', '-30 days') GROUP BY ip ORDER BY count DESC LIMIT 10;"
        
        echo
        echo "Bans by Jail:"
        sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "SELECT jail, COUNT(*) as count FROM bans WHERE timeofban > strftime('%s', 'now', '-30 days') GROUP BY jail ORDER BY count DESC;"
        
        echo
        echo "Daily Ban Trend:"
        sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 "SELECT date(timeofban, 'unixepoch') as day, COUNT(*) as count FROM bans WHERE timeofban > strftime('%s', 'now', '-30 days') GROUP BY day ORDER BY day;"
    } > "$report_file"
    
    log "Monthly report saved to: $report_file"
}

# Main maintenance routine
main() {
    log "Starting fail2ban maintenance..."
    
    update_filters
    clean_database
    update_geoip
    generate_monthly_report
    
    # Reload fail2ban
    fail2ban-client reload
    
    log "Maintenance completed"
}

# Run maintenance
main

# Schedule in cron:
# 0 2 1 * * /usr/local/bin/fail2ban-maintenance.sh
```

### Health Check Script

```bash
#!/bin/bash
# fail2ban-health.sh

# Check fail2ban health
check_health() {
    local status=0
    
    # Check service
    if ! systemctl is-active --quiet fail2ban; then
        echo "CRITICAL: fail2ban service is not running"
        status=2
    fi
    
    # Check database
    if [ ! -f /var/lib/fail2ban/fail2ban.sqlite3 ]; then
        echo "WARNING: Database file missing"
        status=1
    fi
    
    # Check socket
    if [ ! -S /var/run/fail2ban/fail2ban.sock ]; then
        echo "WARNING: Socket file missing"
        status=1
    fi
    
    # Check jails
    active_jails=$(fail2ban-client status | grep "Jail list" | wc -w)
    if [ "$active_jails" -lt 3 ]; then
        echo "WARNING: Only $active_jails jails active"
        status=1
    fi
    
    if [ $status -eq 0 ]; then
        echo "OK: fail2ban is healthy"
    fi
    
    exit $status
}

check_health
```

## Additional Resources

- [Official Fail2ban Documentation](https://www.fail2ban.org/)
- [Fail2ban GitHub Repository](https://github.com/fail2ban/fail2ban)
- [Fail2ban Wiki](https://github.com/fail2ban/fail2ban/wiki)
- [Filter Development Guide](https://fail2ban.readthedocs.io/en/latest/filters.html)
- [Action Development Guide](https://fail2ban.readthedocs.io/en/latest/actions.html)
- [Community Filters](https://github.com/fail2ban/fail2ban/tree/master/config/filter.d)
- [Best Practices Guide](https://www.fail2ban.org/wiki/index.php/Best_practices)
- [Security Hardening Guide](https://www.fail2ban.org/wiki/index.php/Security)

---

**Note:** This guide is part of the [HowToMgr](https://howtomgr.github.io) collection. Always refer to official documentation for the most up-to-date information.