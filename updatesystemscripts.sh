#!/bin/bash

# Скрипт автоматической настройки security-обновлений на Ubuntu
# Для выполнения требует прав sudo

set -e  # Завершить скрипт при любой ошибке

echo "=== Начало настройки автоматических security-обновлений ==="

# Проверяем, что скрипт запущен с правами root
if [ "$EUID" -ne 0 ]; then
    echo "Ошибка: Скрипт должен быть запущен с правами root (sudo)"
    exit 1
fi

# Обновляем список пакетов
echo "1. Обновление списка пакетов..."
apt update

# Устанавливаем unattended-upgrades
echo "2. Установка unattended-upgrades..."
apt install -y unattended-upgrades

# Автоматически настраиваем unattended-upgrades (вместо интерактивного dpkg-reconfigure)
echo "3. Настройка автоматических обновлений..."
cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# Настраиваем только security-обновления
echo "4. Настройка получения только security-обновлений..."
cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
//  "${distro_id}:${distro_codename}-updates";
//  "${distro_id}:${distro_codename}-proposed";
//  "${distro_id}:${distro_codename}-backports";
};

Unattended-Upgrade::Package-Blacklist {
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

# Добавляем задание в cron для ежемесячного выполнения
echo "5. Добавление задания в cron..."
(crontab -l 2>/dev/null | grep -v "/usr/bin/unattended-upgrade"; echo "0 3 1 * * /usr/bin/unattended-upgrade") | crontab -

# Проверяем, что задание добавлено
echo "6. Проверка cron-заданий..."
crontab -l | grep unattended-upgrade

# Запускаем тестовое обновление
echo "7. Запуск тестового обновления (dry-run)..."
if /usr/bin/unattended-upgrade --dry-run -d; then
    echo "✅ Тестовое обновление выполнено успешно"
else
    echo "⚠️ Тестовое обновление завершилось с ошибками, проверьте настройки"
fi

# Проверяем конфигурацию
echo "8. Проверка конфигурации..."
echo "=== Файл 20auto-upgrades ==="
cat /etc/apt/apt.conf.d/20auto-upgrades
echo ""
echo "=== Файл 50unattended-upgrades (только важные строки) ==="
grep -E "(Allowed-Origins|AutoFix|Reboot)" /etc/apt/apt.conf.d/50unattended-upgrades

echo ""
echo "=== Настройка завершена! ==="
echo "✅ unattended-upgrades установлен и настроен"
echo "✅ Будут устанавливаться только security-обновления"
echo "✅ Cron настроен на выполнение 1 числа каждого месяца в 3:00"
echo "✅ Проверьте логи после выполнения: /var/log/unattended-upgrades/unattended-upgrades.log"
