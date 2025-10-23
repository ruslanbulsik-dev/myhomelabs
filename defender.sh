#!/bin/bash

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

set -euo pipefail

# Основные пути к логам
LOG_FILE="/var/log/server_hardening.log"
AUTH_LOG="/var/log/auth.log"
SYSLOG="/var/log/syslog"
FAIL2BAN_LOG="/var/log/fail2ban.log"
UFW_LOG="/var/log/ufw.log"
JOURNAL_LOG="/var/log/journal"
SSH_LOG="/var/log/auth.log"  # SSH логи идут в auth.log

# Создаем директорию для наших кастомных логов если нужно
mkdir -p /var/log/server_security

exec > >(tee -a "$LOG_FILE") 2>&1

echo "Starting server hardening at $(date)"
echo "Main script log: $LOG_FILE"

# Функция для логирования в отдельный файл безопасности
log_security() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/server_security/security_events.log
}

# Функция для показа путей к логам
show_log_paths() {
    echo ""
    echo "=== LOG FILES PATHS ==="
    echo "Main script log:          $LOG_FILE"
    echo "Security events log:      /var/log/server_security/security_events.log"
    echo "Authentication logs:      $AUTH_LOG"
    echo "System logs:              $SYSLOG"
    echo "Fail2Ban logs:            $FAIL2BAN_LOG"
    echo "Firewall (UFW) logs:      $UFW_LOG"
    echo "Journal logs:             $JOURNAL_LOG"
    echo "SSH connection logs:      $SSH_LOG"
    echo "APT logs:                 /var/log/apt/history.log"
    echo "Package install logs:     /var/log/apt/term.log"
    echo "Cron logs:                /var/log/cron.log"
    echo "Kernel logs:              /var/log/kern.log"
    echo "Database logs (if any):   /var/log/mysql/error.log"
    echo "Web server logs (if any): /var/log/nginx/*.log"
    echo ""
    echo "=== HOW TO VIEW LOGS ==="
    echo "tail -f $LOG_FILE              - Real-time script log"
    echo "tail -f $AUTH_LOG              - Real-time authentication log"
    echo "tail -f $FAIL2BAN_LOG          - Real-time Fail2Ban log"
    echo "journalctl -f                  - Real-time system journal"
    echo "grep 'sshd' $AUTH_LOG          - SSH connection attempts"
    echo "fail2ban-client status sshd    - Fail2Ban status for SSH"
    echo ""
}

BACKUP_TIMESTAMP=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="/etc/ssh/sshd_config.backup_$BACKUP_TIMESTAMP"

# Логируем начало настройки
log_security "Starting server hardening script"

# Улучшенная функция выбора порта
select_ssh_port() {
    echo "Searching for available SSH port..."
    log_security "Searching for available SSH port"
    
    # Список портов, которые нужно исключить (известные сервисы + 2222)
    EXCLUDED_PORTS="22 2222 3389 3306 5432 6379 27017 80 443 21 25 53 993 995 465 587"
    
    # Проверяем порты в диапазоне 5000-39999
    for port in {5000..39999}; do
        # Пропускаем исключенные порты
        if [[ " $EXCLUDED_PORTS " == *" $port "* ]]; then
            continue
        fi
        
        # Проверяем, занят ли порт
        if ! ss -tulpn | grep -q ":${port} "; then
            # Дополнительная проверка: пытаемся занять порт временно
            if python3 -c "import socket; s = socket.socket(); s.bind(('0.0.0.0', $port)); s.close()" 2>/dev/null; then
                echo "Found available port: $port"
                log_security "Selected SSH port: $port"
                NEW_SSH_PORT=$port
                return 0
            fi
        fi
    done
    
    # Если не нашли подходящий порт, используем резервный метод
    echo "Warning: Could not find ideal port, using alternative method..."
    log_security "Warning: Using alternative port selection method"
    for port in {5000..39999}; do
        if ! ss -tulpn | grep -q ":${port} " && [[ " $EXCLUDED_PORTS " != *" $port "* ]]; then
            echo "Selected port: $port"
            log_security "Selected SSH port (alternative): $port"
            NEW_SSH_PORT=$port
            return 0
        fi
    done
    
    echo "Error: No available ports found in range 5000-39999"
    log_security "ERROR: No available SSH ports found"
    return 1
}

# Функция для подготовки SSH директорий
prepare_ssh_directories() {
    echo "Preparing SSH directories..."
    log_security "Preparing SSH directories"
    
    # Создаем необходимые директории
    mkdir -p /run/sshd
    chmod 0755 /run/sshd
    
    # Проверяем и создаем другие системные директории SSH если нужно
    if [ ! -d /var/run/sshd ]; then
        mkdir -p /var/run/sshd
        chmod 0755 /var/run/sshd
    fi
    
    # Убедимся что права правильные на конфигурационных файлах
    chmod 600 /etc/ssh/sshd_config
}

# Определяем пользователя для SSH доступа
if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
    SSH_USER="$SUDO_USER"
    echo "Detected user: $SSH_USER"
    log_security "SSH user detected: $SSH_USER"
else
    echo "Please enter the username for SSH access (this user will have sudo rights):"
    read -r SSH_USER
    
    # Проверяем существование пользователя
    if ! id "$SSH_USER" &>/dev/null; then
        echo "Error: User $SSH_USER does not exist. Please create the user first."
        log_security "ERROR: User $SSH_USER does not exist"
        exit 1
    fi
    log_security "SSH user set: $SSH_USER"
fi

echo "SSH access will be configured for user: $SSH_USER"

# Функция для настройки SSH ключей
setup_ssh_keys() {
    echo "Setting up SSH keys..."
    log_security "Setting up SSH keys"
    
    # Запрос публичного ключа
    echo "Please paste your PUBLIC SSH key (starts with ssh-rsa, ssh-ed25519, etc.):"
    echo "You can get it from: cat ~/.ssh/id_rsa.pub or similar"
    read -r SSH_PUB_KEY
    
    if [ -z "$SSH_PUB_KEY" ]; then
        echo "Warning: No SSH key provided. You won't be able to connect after script completion!"
        log_security "WARNING: No SSH key provided"
        return 1
    fi
    
    # Создаем директорию .ssh для пользователя
    if [ "$SSH_USER" = "root" ]; then
        USER_HOME="/root"
    else
        USER_HOME="/home/$SSH_USER"
    fi
    
    mkdir -p "$USER_HOME/.ssh"
    chmod 700 "$USER_HOME/.ssh"
    
    # Добавляем ключ в authorized_keys
    echo "$SSH_PUB_KEY" >> "$USER_HOME/.ssh/authorized_keys"
    chmod 600 "$USER_HOME/.ssh/authorized_keys"
    
    # Устанавливаем правильного владельца
    if [ "$SSH_USER" != "root" ]; then
        chown -R "$SSH_USER:$SSH_USER" "$USER_HOME/.ssh"
    fi
    
    echo "SSH key added successfully for user $SSH_USER"
    log_security "SSH key added for user $SSH_USER"
}

# 1. Подготовка и смена SSH порта
echo "1. Preparing SSH and changing port..."
log_security "Starting SSH configuration"

# Подготавливаем директории SSH
prepare_ssh_directories

# Выбираем порт с улучшенной логикой
if ! select_ssh_port; then
    exit 1
fi

echo "Changing SSH port to $NEW_SSH_PORT"

# Резервное копирование конфига SSH с фиксированным именем
cp /etc/ssh/sshd_config "$BACKUP_FILE"
echo "Backup created: $BACKUP_FILE"
log_security "SSH config backed up to $BACKUP_FILE"

# Настройка SSH ключей
setup_ssh_keys

# Функция для проверки конфигурации SSH
check_ssh_config() {
    echo "Testing SSH configuration..."
    if ! sshd -t; then
        echo "Error: SSH configuration test failed"
        log_security "ERROR: SSH configuration test failed"
        return 1
    fi
    log_security "SSH configuration test passed"
    return 0
}

# Функция для безопасного перезапуска SSH
safe_restart_ssh() {
    echo "Attempting to restart SSH service..."
    log_security "Attempting SSH service restart"
    
    # Тестируем конфигурацию
    if ! check_ssh_config; then
        echo "Restoring original SSH configuration..."
        cp "$BACKUP_FILE" /etc/ssh/sshd_config
        systemctl restart ssh
        echo "Original configuration restored"
        log_security "Original SSH configuration restored"
        return 1
    fi
    
    # Пробуем перезагрузить SSH
    if ! systemctl restart ssh; then
        echo "SSH restart failed, checking system status..."
        log_security "WARNING: SSH restart failed, checking logs"
        sleep 2
        
        # Проверяем логи SSH
        echo "=== SSH Service Logs ==="
        journalctl -u ssh --since "1 minute ago" | tail -20
        
        # Проверяем и создаем директории если нужно
        prepare_ssh_directories
        
        # Пробуем еще раз
        echo "Retrying SSH restart..."
        if systemctl restart ssh; then
            echo "SSH successfully restarted on port $NEW_SSH_PORT"
            log_security "SSH successfully restarted on port $NEW_SSH_PORT"
            return 0
        fi
        
        # Если все еще не работает, восстанавливаем оригинальный конфиг
        echo "Restoring original SSH configuration..."
        cp "$BACKUP_FILE" /etc/ssh/sshd_config
        systemctl restart ssh
        echo "Original configuration restored. Manual intervention required."
        log_security "ERROR: SSH configuration failed, manual intervention required"
        return 1
    fi
    
    echo "SSH successfully restarted on port $NEW_SSH_PORT"
    log_security "SSH successfully restarted on port $NEW_SSH_PORT"
    return 0
}

# Настройка SSH - ЗАПРЕЩАЕМ root доступ по SSH
cat > /etc/ssh/sshd_config << EOF
# Basic configuration
Port $NEW_SSH_PORT
Protocol 2

# Authentication
PubkeyAuthentication yes
PasswordAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
KerberosAuthentication no
GSSAPIAuthentication no

# Security restrictions - ROOT SSH ACCESS DISABLED
PermitRootLogin no
X11Forwarding no
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
IgnoreRhosts yes
HostbasedAuthentication no
LoginGraceTime 60
Banner /etc/issue.net
AllowTcpForwarding no
AllowAgentForwarding no

# User access
AllowUsers $SSH_USER
EOF

# Создание баннера
cat > /etc/issue.net << EOF
****************************************************************
*                            WARNING                           *
* This is a private system. Unauthorized access is prohibited. *
* All activities are monitored and logged.                     *
****************************************************************
EOF

log_security "SSH configuration updated with port $NEW_SSH_PORT and user $SSH_USER"

# 2. Настройка sudo для пользователя
echo "2. Configuring sudo for user $SSH_USER..."
log_security "Configuring sudo for user $SSH_USER"

if [ "$SSH_USER" != "root" ]; then
    if ! groups "$SSH_USER" | grep -q "\bsudo\b"; then
        usermod -aG sudo "$SSH_USER"
        echo "User $SSH_USER added to sudo group"
        log_security "User $SSH_USER added to sudo group"
    fi
    
    # Настройка sudo без пароля для удобства (опционально)
    echo "$SSH_USER ALL=(ALL) NOPASSWD:ALL" > /etc/sudoers.d/$SSH_USER
    chmod 440 /etc/sudoers.d/$SSH_USER
    echo "Sudo without password configured for $SSH_USER"
    log_security "Sudo without password configured for $SSH_USER"
fi

# 3. Настройка системы аутентификации
echo "3. Configuring authentication security..."
log_security "Configuring authentication security"

# Установка сложности паролей
if [ -f /etc/security/pwquality.conf ]; then
    sed -i 's/# minlen = 8/minlen = 12/' /etc/security/pwquality.conf
    sed -i 's/# minclass = 0/minclass = 3/' /etc/security/pwquality.conf
fi

# 4. Установка fail2ban
echo "4. Installing and configuring fail2ban..."
log_security "Installing and configuring fail2ban"

apt-get update
apt-get install -y fail2ban

# Конфигурация fail2ban
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
destemail = root@localhost
sender = root@localhost
action = %(action_)s

[sshd]
enabled = true
port = $NEW_SSH_PORT
logpath = /var/log/auth.log
maxretry = 3
bantime = 86400

[sshd-ddos]
enabled = true
port = $NEW_SSH_PORT
logpath = /var/log/auth.log
maxretry = 5
bantime = 3600
EOF

log_security "Fail2Ban configured for SSH port $NEW_SSH_PORT"

# 5. Настройка UFW с проверкой порта
echo "5. Configuring UFW..."
log_security "Configuring UFW firewall"

apt-get install -y ufw

# Включаем логирование UFW
ufw logging on

# Сброс правил
ufw --force reset

# Базовые политики
ufw default deny incoming
ufw default allow outgoing

# Временно разрешаем старый порт SSH для безопасности
CURRENT_SSH_PORT=$(grep -E "^Port" "$BACKUP_FILE" 2>/dev/null | head -1 | awk '{print $2}' || echo "22")
if [ -n "$CURRENT_SSH_PORT" ] && [ "$CURRENT_SSH_PORT" != "$NEW_SSH_PORT" ]; then
    echo "Temporarily allowing current SSH port $CURRENT_SSH_PORT for fallback"
    ufw allow "${CURRENT_SSH_PORT}/tcp"
    log_security "Temporarily allowed old SSH port $CURRENT_SSH_PORT"
fi

# Разрешение текущих служб
echo "Detecting open ports..."
while IFS= read -r line; do
    PORT=$(echo "$line" | awk '{print $5}' | cut -d: -f2)
    PROTO=$(echo "$line" | awk '{print $1}')
    if [ -n "$PORT" ] && [ "$PORT" -ne "$NEW_SSH_PORT" ] && [ "$PORT" != "$CURRENT_SSH_PORT" ]; then
        echo "Allowing $PROTO port $PORT"
        ufw allow "$PORT/$PROTO"
        log_security "UFW allowed $PROTO port $PORT"
    fi
done < <(ss -tulpn | grep LISTEN | grep -v ":$NEW_SSH_PORT ")

# Разрешение нового SSH порта
ufw allow "$NEW_SSH_PORT/tcp"
log_security "UFW allowed new SSH port $NEW_SSH_PORT"

# Включение фаервола
ufw --force enable
log_security "UFW firewall enabled"

# 6. Безопасный перезапуск SSH
echo "6. Performing safe SSH restart..."
if ! safe_restart_ssh; then
    echo "Failed to restart SSH with new configuration. Please check manually."
    exit 1
fi

# 7. Удаляем временное правило для старого порта
if [ -n "$CURRENT_SSH_PORT" ] && [ "$CURRENT_SSH_PORT" != "$NEW_SSH_PORT" ]; then
    echo "Removing temporary rule for old SSH port $CURRENT_SSH_PORT"
    ufw delete allow "${CURRENT_SSH_PORT}/tcp"
    log_security "Removed temporary UFW rule for old SSH port $CURRENT_SSH_PORT"
fi

# 8. Дополнительные меры безопасности
echo "7. Applying additional security measures..."
log_security "Applying additional security measures"

# Настройка sysctl для сетевой безопасности
cat >> /etc/sysctl.conf << EOF

# Network Security
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
EOF

sysctl -p
log_security "Sysctl security settings applied"

# 9. Настройка очистки логов
echo "8. Setting up log rotation and disk cleanup..."
log_security "Setting up log rotation"

# Настройка logrotate
cat > /etc/logrotate.d/server_security << EOF
/var/log/server_security/*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
}

/var/log/server_hardening.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF

# Основные логи
cat > /etc/logrotate.d/custom << EOF
/var/log/syslog {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 syslog adm
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}

/var/log/auth.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 syslog adm
}

/var/log/fail2ban.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
    postrotate
        systemctl reload fail2ban
    endscript
}

/var/log/ufw.log {
    weekly
    rotate 4
    compress
    delaycompress
    missingok
    notifempty
    create 644 root root
}
EOF

# Очистка старых логов
find /var/log -name "*.log" -type f -mtime +30 -delete 2>/dev/null || true
find /var/log -name "*.gz" -type f -mtime +30 -delete 2>/dev/null || true

# Настройка размера journald
mkdir -p /etc/systemd/journald.conf.d
cat > /etc/systemd/journald.conf.d/00-limits.conf << EOF
[Journal]
SystemMaxUse=100M
SystemMaxFileSize=50M
SystemMaxFiles=5
EOF

# Очистка кэша пакетов
apt-get clean

# Настройка cron для регулярной очистки
cat > /etc/cron.weekly/disk-cleanup << 'EOF'
#!/bin/bash
# Weekly disk cleanup script
logger "Starting weekly disk cleanup"

apt-get autoremove -y
apt-get clean

# Очистка логов
find /var/log -name "*.log" -type f -mtime +7 -exec truncate -s 0 {} \; 2>/dev/null || true
find /tmp -type f -atime +7 -delete 2>/dev/null || true
find /var/tmp -type f -atime +7 -delete 2>/dev/null || true
journalctl --vacuum-time=7d 2>/dev/null || true

# Логируем завершение
logger "Weekly disk cleanup completed"
EOF

chmod +x /etc/cron.weekly/disk-cleanup
log_security "Disk cleanup cron job configured"

# Перезапуск остальных служб
systemctl restart fail2ban
systemctl restart systemd-journald
log_security "Fail2Ban and journald restarted"

# Проверка статуса SSH
echo "Checking SSH status..."
if systemctl is-active --quiet ssh; then
    echo "✓ SSH is running successfully on port $NEW_SSH_PORT"
    log_security "SSH service confirmed running on port $NEW_SSH_PORT"
else
    echo "✗ SSH is not running. Please check configuration."
    log_security "ERROR: SSH service not running after configuration"
    exit 1
fi

# Создание отчета о настройке с путями к логам
cat > /root/security_report.txt << EOF
SERVER SECURITY HARDENING REPORT
Generated: $(date)

SSH Configuration:
=================
New SSH Port: $NEW_SSH_PORT
Status: ACTIVE
Root SSH Login: DISABLED
Password Auth: Disabled
Key Auth: Enabled
Allowed User: $SSH_USER

Firewall Status:
================
$(ufw status verbose)

SSH Service Status:
===================
$(systemctl status ssh --no-pager -l)

=== LOG FILES ===
Main script log:          $LOG_FILE
Security events log:      /var/log/server_security/security_events.log
Authentication logs:      $AUTH_LOG
System logs:              $SYSLOG
Fail2Ban logs:            $FAIL2BAN_LOG
Firewall (UFW) logs:      $UFW_LOG
Journal logs:             $JOURNAL_LOG
SSH connection logs:      $SSH_LOG
APT logs:                 /var/log/apt/history.log
Package install logs:     /var/log/apt/term.log

=== MONITORING COMMANDS ===
Real-time script log:     tail -f $LOG_FILE
Real-time auth log:       tail -f $AUTH_LOG | grep -E '(sshd|fail2ban)'
Real-time Fail2Ban:       tail -f $FAIL2BAN_LOG
Real-time system:         journalctl -f
SSH connections:          netstat -tpn | grep :$NEW_SSH_PORT
Fail2Ban status:          fail2ban-client status sshd
UFW status:               ufw status verbose
Disk space:               df -h /
Memory usage:             free -h

Connection Test:
================
To test connection:
ssh -p $NEW_SSH_PORT -i your_private_key $SSH_USER@$(hostname -I | awk '{print $1}')

For MobaXterm:
- Host: $(hostname -I | awk '{print $1}')
- Port: $NEW_SSH_PORT  
- Username: $SSH_USER
- Use private key authentication
EOF

# Создаем удобный скрипт для просмотра логов
cat > /usr/local/bin/show-logs << 'EOF'
#!/bin/bash
echo "=== Security Logs Monitor ==="
echo "1 - Script log (tail -f)"
echo "2 - Authentication log (tail -f)"
echo "3 - Fail2Ban log (tail -f)"
echo "4 - System journal (journalctl -f)"
echo "5 - UFW log (tail -f)"
echo "6 - Check SSH connections"
echo "7 - Fail2Ban status"
echo "8 - UFW status"
echo "9 - All important logs (multitail)"
echo "0 - Exit"
echo ""
read -p "Select option: " choice

case $choice in
    1) tail -f /var/log/server_hardening.log ;;
    2) tail -f /var/log/auth.log | grep -E '(sshd|fail2ban)' ;;
    3) tail -f /var/log/fail2ban.log ;;
    4) journalctl -f ;;
    5) tail -f /var/log/ufw.log ;;
    6) netstat -tpn | grep :$(grep "^Port" /etc/ssh/sshd_config | awk '{print $2}') ;;
    7) fail2ban-client status sshd ;;
    8) ufw status verbose ;;
    9) 
        if command -v multitail >/dev/null; then
            multitail -s 2 /var/log/auth.log /var/log/fail2ban.log /var/log/server_hardening.log
        else
            echo "Install multitail: apt-get install multitail"
        fi
        ;;
    0) exit ;;
    *) echo "Invalid option" ;;
esac
EOF

chmod +x /usr/local/bin/show-logs

log_security "Server hardening completed successfully"

echo "Server hardening completed successfully!"
echo ""
echo "=== SUMMARY ==="
echo "SSH Port: $NEW_SSH_PORT (ACTIVE)"
echo "SSH User: $SSH_USER"
echo "Root SSH: DISABLED"
echo ""

# Показываем пути к логам
show_log_paths

echo "Quick log viewer: show-logs"
echo ""
echo "Test connection with:"
echo "ssh -p $NEW_SSH_PORT -i your_private_key $SSH_USER@$(hostname -I | awk '{print $1}')"
echo ""
echo "Full report: /root/security_report.txt"
echo "Security events: /var/log/server_security/security_events.log"

# Логируем завершение
log_security "Server hardening script completed"