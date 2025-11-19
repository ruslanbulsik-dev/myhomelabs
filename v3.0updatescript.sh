#!/bin/bash

# Проверка прав root
if [ "$EUID" -ne 0 ]; then
    echo "Запускайте от root или через sudo"
    exit 1
fi

set -euo pipefail

# =============================================================================
# Настройки (можно менять в начале)
# =============================================================================
SUDO_NOPASSWD=1                  # 1 = sudo без пароля, 0 = с паролем
# FIXED_SSH_PORT=55227            # раскомментируйте, если нужен фиксированный порт

# =============================================================================
# Логи
# =============================================================================
mkdir -p /var/log/server_security
LOG_FILE="/var/log/server_hardening.log"
exec > >(tee -a "$LOG_FILE") 2>&1
echo "Запуск hardening $(date)"

log_security() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> /var/log/server_security/security_events.log
}

# =============================================================================
# Определение пользователя
# =============================================================================
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
    # Запущено через sudo обычным пользователем → используем его
    SSH_USER="$SUDO_USER"
    echo "Обнаружен пользователь, от которого запущен sudo: $SSH_USER"
else
    # Запущено напрямую от root → создаём нового пользователя
    echo "Скрипт запущен от root. Создаём нового пользователя с sudo-правами."
    while true; do
        echo -n "Введите имя нового пользователя: "
        read -r SSH_USER
        if id "$SSH_USER" &>/dev/null; then
            echo "Пользователь $SSH_USER уже существует. Используем его."
            break
        else
            adduser --gecos "" "$SSH_USER"   # adduser сам запросит пароль и данные
            usermod -aG sudo "$SSH_USER"
            echo "Пользователь $SSH_USER создан и добавлен в группу sudo"
            break
        fi
    done
fi

log_security "Рабочий пользователь: $SSH_USER"

# =============================================================================
# Установка пакетов
# =============================================================================
echo "Установка необходимых пакетов…"
apt-get update
apt-get install -y curl wget sudo cron ufw fail2ban python3 iproute2 openssh-server \
                  rsyslog logrotate unattended-upgrades apt-listchanges multitail

# Автоматические обновления безопасности
dpkg-reconfigure -plow unattended-upgrades < /dev/null

# =============================================================================
# SSH-ключи (с проверкой существующих)
# =============================================================================
USER_HOME=$(eval echo ~$SSH_USER)
SSH_DIR="$USER_HOME/.ssh"
AUTH_FILE="$SSH_DIR/authorized_keys"

mkdir -p "$SSH_DIR"
chmod 700 "$SSH_DIR"
touch "$AUTH_FILE"
chmod 600 "$AUTH_FILE"
chown -R "$SSH_USER:$SSH_USER" "$SSH_DIR"

if [ -s "$AUTH_FILE" ]; then
    echo "В $AUTH_FILE уже есть ключи."
    echo -n "Добавить новые ключи поверх существующих? (y/N): "
    read -r add_keys
else
    add_keys="y"
fi

if [[ "$add_keys" =~ ^[Yy]$ ]]; then
    echo "Вставляйте публичные ключи (по одному, пустая строка — окончание):"
    while IFS= read -r line && [ -n "$line" ]; do
        echo "$line" >> "$AUTH_FILE"
    done
    echo "Ключи добавлены/обновлены"
    log_security "SSH-ключи добавлены/обновлены для $SSH_USER"
else
    echo "Добавление новых ключей пропущено"
fi

# =============================================================================
# Выбор SSH-порта
# =============================================================================
if [[ -n "${FIXED_SSH_PORT:-}" ]]; then
    NEW_SSH_PORT="$FIXED_SSH_PORT"
else
    echo "Ищем свободный порт 1025–65535…"
    EXCLUDE="22 2222 3389 3306 5432 6379 27017 80 443"
    for p in $(shuf -i 1025-65535 -n 200); do
        if ! [[ " $EXCLUDE " == *" $p "* ]] && ! ss -tuln | grep -q ":$p "; then
            NEW_SSH_PORT=$p
            break
        fi
    done
    # если всё занято — берём случайный из диапазона
    [ -z "${NEW_SSH_PORT:-}" ] && NEW_SSH_PORT=$((RANDOM % 55535 + 10000))
fi

echo "Новый SSH-порт: $NEW_SSH_PORT"

# =============================================================================
# Настройка SSH (через sed — сохраняем оригинальные комментарии)
# =============================================================================
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup_$(date +%Y%m%d_%H%M%S)

sed -i -E '
    s/^#?Port .*/Port '"$NEW_SSH_PORT"'/;
    s/^#?PasswordAuthentication .*/PasswordAuthentication no/;
    s/^#?PermitRootLogin .*/PermitRootLogin no/;
    s/^#?X11Forwarding .*/X11Forwarding no/;
    s/^#?AllowAgentForwarding .*/AllowAgentForwarding no/;
    s/^#?AllowTcpForwarding .*/AllowTcpForwarding no/;
    s/^#?PubkeyAuthentication .*/PubkeyAuthentication yes/;
' /etc/ssh/sshd_config

cat >> /etc/ssh/sshd_config <<EOF

# Дополнительные безопасные параметры
UseDNS no
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 0
LoginGraceTime 30
AllowUsers $SSH_USER
Banner /etc/issue.net
EOF

cat > /etc/issue.net <<'EOF'
****************************************************************
* ВНИМАНИЕ: Несанкционированный доступ запрещён. Все действия логируются. *
****************************************************************
EOF

# =============================================================================
# Sudo
# =============================================================================
usermod -aG sudo "$SSH_USER"
if (( SUDO_NOPASSWD )); then
    echo "$SSH_USER ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/"$SSH_USER"-nopasswd
else
    echo "$SSH_USER ALL=(ALL:ALL) ALL" > /etc/sudoers.d/"$SSH_USER"
fi
chmod 440 /etc/sudoers.d/"$SSH_USER"*

# =============================================================================
# Fail2Ban
# =============================================================================
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 86400
findtime  = 600
maxretry  = 3

[sshd]
enabled  = true
port     = $NEW_SSH_PORT
maxretry = 3
bantime  = 86400

[recidive]
enabled = true
EOF
systemctl restart fail2ban

# =============================================================================
# UFW — только то, что нужно
# =============================================================================
ufw logging on
ufw --force reset
ufw default deny incoming
ufw default allow outgoing

# Текущий порт (если был не 22)
CURRENT_SSH_PORT=$(ss -tuln | awk '/:22 / {print $5}' | cut -d: -f2 || echo 22)

if (( CURRENT_SSH_PORT != NEW_SSH_PORT )); then
    ufw limit "$CURRENT_SSH_PORT/tcp" comment "Временный старый SSH"
fi

ufw limit "$NEW_SSH_PORT/tcp" comment "SSH"

echo -n "Открыть дополнительные порты? (через пробел, например 80 443 25565, Enter — нет): "
read -r extra_ports
for p in $extra_ports; do
    [[ -n "$p" ]] && ufw allow "$p/tcp" comment "Дополнительный $p"
done

ufw --force enable
log_security "UFW включён, открыт только SSH $NEW_SSH_PORT (+указанные)"

# =============================================================================
# Перезапуск SSH с защитой от локаута
# =============================================================================
if sshd -t 2>/dev/null; then
    systemctl restart ssh && echo "SSH успешно перезапущен на порту $NEW_SSH_PORT"
    # Удаляем временное правило старого порта
    [[ "$CURRENT_SSH_PORT" != "$NEW_SSH_PORT" ]] && ufw delete limit "$CURRENT_SSH_PORT/tcp" || true
else
    echo "Ошибка в конфигурации SSH — возвращаем резервную копию"
    cp /etc/ssh/sshd_config.backup_* /etc/ssh/sshd_config
    systemctl restart ssh
    exit 1
fi

# =============================================================================
# Защита разделов
# =============================================================================
for mp in /tmp /var/tmp /dev/shm; do
    mount | grep -q "$mp.*noexec" || (
        mount -o remount,noexec,nodev,nosuid "$mp" 2>/dev/null || true
        grep -q "$mp" /etc/fstab || echo "tmpfs $mp tmpfs rw,noexec,nodev,nosuid 0 0" >> /etc/fstab
    )
done

# =============================================================================
# Финал
# =============================================================================
echo "=================================================================="
echo "Готово!"
echo "Пользователь: $SSH_USER"
echo "SSH-порт:    $NEW_SSH_PORT"
echo "UFW:        только SSH + указанные вами порты"
echo "Подключайтесь: ssh $SSH_USER@IP -p $NEW_SSH_PORT"
echo "=================================================================="

log_security "Hardening завершён успешно"
