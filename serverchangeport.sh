#!/bin/bash

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

set -euo pipefail

# 1. Смена SSH порта
echo "Checking available ports..."
NEW_SSH_PORT=$(ss -tulpn | awk '{print $5}' | cut -d: -f2 | \
    grep -E "^[0-9]+$" | sort -un | \
    awk '$1 > 1024 && $1 != 2222 && !seen[$1]++' | \
    head -n 1)

if [ -z "$NEW_SSH_PORT" ]; then
    echo "Error: No available ports found"
    exit 1
fi

echo "Changing SSH port to $NEW_SSH_PORT"
sed -i "s/^#Port 22/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/^Port 22/Port $NEW_SSH_PORT/" /etc/ssh/sshd_config
if ! grep -q "^Port $NEW_SSH_PORT" /etc/ssh/sshd_config; then
    echo "Port $NEW_SSH_PORT" >> /etc/ssh/sshd_config
fi

# 2. Установка fail2ban
echo "Installing fail2ban..."
apt-get update
apt-get install -y fail2ban

# Базовая конфигурация fail2ban
cat > /etc/fail2ban/jail.local << EOF
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $NEW_SSH_PORT
logpath = /var/log/auth.log
EOF

# 3. Настройка UFW
echo "Configuring UFW..."
apt-get install -y ufw

# Сброс правил
ufw --force reset

# Базовые политики
ufw default deny incoming
ufw default allow outgoing

# Разрешение текущих служб
echo "Detecting open ports..."
while IFS= read -r line; do
    PORT=$(echo "$line" | awk '{print $5}' | cut -d: -f2)
    PROTO=$(echo "$line" | awk '{print $1}')
    if [ -n "$PORT" ] && [ "$PORT" -ne "$NEW_SSH_PORT" ]; then
        echo "Allowing $PROTO port $PORT"
        ufw allow "$PORT/$PROTO"
    fi
done < <(ss -tulpn | grep LISTEN | grep -v ":$NEW_SSH_PORT ")

# Разрешение нового SSH порта
ufw allow "$NEW_SSH_PORT/tcp"

# Включение фаервола
ufw --force enable

# Перезапуск служб
systemctl restart ssh
systemctl restart fail2ban
systemctl enable fail2ban

echo "Configuration completed successfully!"
echo "New SSH port: $NEW_SSH_PORT"
echo "Don't forget to update your SSH client configuration!"