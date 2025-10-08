#!/bin/bash

# Цвета для вывода
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Функция для вывода заголовка
print_header() {
    echo -e "${BLUE}================================================${NC}"
    echo -e "${BLUE}  Установка системы мониторинга${NC}"
    echo -e "${BLUE}  Grafana + Prometheus + Node Exporter + cAdvisor${NC}"
    echo -e "${BLUE}================================================${NC}"
    echo ""
}

# Функция для вывода сообщений
print_success() {
    echo -e "${GREEN}✓ $1${NC}"
}

print_error() {
    echo -e "${RED}✗ $1${NC}"
}

print_info() {
    echo -e "${YELLOW}➜ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

# Проверка запуска от root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        print_error "Пожалуйста, запустите скрипт от root (sudo)"
        exit 1
    fi
}

# Определение ОС
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        print_error "Не удалось определить операционную систему"
        exit 1
    fi
}

# Проверка доступности порта
check_port() {
    local port=$1
    if netstat -tuln 2>/dev/null | grep -q ":$port " || ss -tuln 2>/dev/null | grep -q ":$port "; then
        return 1
    fi
    return 0
}

# Установка Docker для Ubuntu/Debian
install_docker_ubuntu() {
    print_info "Установка Docker для Ubuntu/Debian..."
    
    # Обновление пакетов
    apt-get update -y
    
    # Установка зависимостей
    apt-get install -y \
        apt-transport-https \
        ca-certificates \
        curl \
        gnupg \
        lsb-release
    
    # Добавление GPG ключа Docker
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/$OS/gpg | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    
    # Добавление репозитория Docker
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/$OS \
      $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
    
    # Установка Docker
    apt-get update -y
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
}

# Установка Docker для CentOS/RHEL
install_docker_centos() {
    print_info "Установка Docker для CentOS/RHEL..."
    
    # Удаление старых версий
    yum remove -y docker docker-client docker-client-latest docker-common docker-latest docker-latest-logrotate docker-logrotate docker-engine
    
    # Установка зависимостей
    yum install -y yum-utils
    
    # Добавление репозитория Docker
    yum-config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
    
    # Установка Docker
    yum install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
}

# Установка Docker
install_docker() {
    print_info "Проверка установки Docker..."
    
    if command -v docker &> /dev/null; then
        print_success "Docker уже установлен"
        docker --version
        return 0
    fi
    
    detect_os
    
    case $OS in
        ubuntu|debian)
            install_docker_ubuntu
            ;;
        centos|rhel|rocky|almalinux)
            install_docker_centos
            ;;
        *)
            print_error "Неподдерживаемая ОС: $OS"
            print_info "Пожалуйста, установите Docker вручную"
            return 1
            ;;
    esac
    
    # Запуск Docker
    systemctl start docker
    systemctl enable docker
    
    if command -v docker &> /dev/null; then
        print_success "Docker успешно установлен"
        docker --version
        return 0
    else
        print_error "Ошибка при установке Docker"
        return 1
    fi
}

# Установка netstat если отсутствует
install_netstat() {
    if ! command -v netstat &> /dev/null && ! command -v ss &> /dev/null; then
        print_info "Установка net-tools..."
        if command -v apt-get &> /dev/null; then
            apt-get install -y net-tools
        elif command -v yum &> /dev/null; then
            yum install -y net-tools
        fi
    fi
}

# Установка Node Exporter
install_node_exporter() {
    print_info "Установка Node Exporter..."
    
    # Проверка порта
    if ! check_port 9100; then
        print_error "Порт 9100 уже занят!"
        print_info "Остановите процесс, использующий порт 9100, или измените порт"
        netstat -tulnp | grep :9100 || ss -tulnp | grep :9100
        return 1
    fi
    
    # Проверка существующего контейнера
    if docker ps -a | grep -q node_exporter; then
        print_info "Удаление существующего контейнера Node Exporter..."
        docker stop node_exporter 2>/dev/null
        docker rm node_exporter 2>/dev/null
    fi
    
    # Запуск Node Exporter
    docker run -d \
      --name=node_exporter \
      --restart=always \
      --net="host" \
      --pid="host" \
      -v "/:/host:ro,rslave" \
      prom/node-exporter:latest \
      --path.rootfs=/host
    
    if [ $? -eq 0 ]; then
        sleep 2
        if curl -s http://localhost:9100/metrics > /dev/null; then
            print_success "Node Exporter успешно установлен и запущен на порту 9100"
            print_info "Проверка: curl http://localhost:9100/metrics"
        else
            print_warning "Node Exporter запущен, но метрики пока недоступны (это нормально, подождите несколько секунд)"
        fi
        return 0
    else
        print_error "Ошибка при установке Node Exporter"
        return 1
    fi
}

# Установка cAdvisor
install_cadvisor() {
    print_info "Установка cAdvisor для мониторинга Docker контейнеров..."
    
    # Запрос порта
    read -p "Введите порт для cAdvisor (по умолчанию 9101): " CADVISOR_PORT
    CADVISOR_PORT=${CADVISOR_PORT:-9101}
    
    # Проверка порта
    if ! check_port $CADVISOR_PORT; then
        print_error "Порт ${CADVISOR_PORT} уже занят!"
        print_info "Процесс, использующий порт:"
        netstat -tulnp | grep :${CADVISOR_PORT} || ss -tulnp | grep :${CADVISOR_PORT}
        return 1
    fi
    
    # Проверка существующего контейнера
    if docker ps -a | grep -q cadvisor; then
        print_info "Удаление существующего контейнера cAdvisor..."
        docker stop cadvisor 2>/dev/null
        docker rm cadvisor 2>/dev/null
    fi
    
    # Запуск cAdvisor
    docker run -d \
      --name=cadvisor \
      --restart=always \
      --volume=/:/rootfs:ro \
      --volume=/var/run:/var/run:ro \
      --volume=/sys:/sys:ro \
      --volume=/var/lib/docker/:/var/lib/docker:ro \
      --volume=/dev/disk/:/dev/disk:ro \
      --publish=${CADVISOR_PORT}:8080 \
      --detach=true \
      --privileged \
      gcr.io/cadvisor/cadvisor:latest
    
    if [ $? -eq 0 ]; then
        sleep 2
        if curl -s http://localhost:${CADVISOR_PORT}/metrics > /dev/null; then
            print_success "cAdvisor успешно установлен и запущен на порту ${CADVISOR_PORT}"
            print_info "Проверка: curl http://localhost:${CADVISOR_PORT}/metrics"
        else
            print_warning "cAdvisor запущен, но метрики пока недоступны (это нормально, подождите несколько секунд)"
        fi
        return 0
    else
        print_error "Ошибка при установке cAdvisor"
        return 1
    fi
}

# Установка Alertmanager
install_alertmanager() {
    print_info "Установка Alertmanager для отправки уведомлений..."
    
    echo ""
    print_info "Для отправки уведомлений в Telegram нужны:"
    print_info "1. Bot Token (получите у @BotFather в Telegram)"
    print_info "2. Chat ID (получите у @userinfobot)"
    echo ""
    
    read -p "Введите Telegram Bot Token: " TG_TOKEN
    read -p "Введите Telegram Chat ID: " TG_CHAT_ID
    
    if [ -z "$TG_TOKEN" ] || [ -z "$TG_CHAT_ID" ]; then
        print_error "Token или Chat ID не указаны!"
        return 1
    fi
    
    # Проверка порта
    ALERT_PORT=9093
    if ! check_port $ALERT_PORT; then
        print_error "Порт ${ALERT_PORT} уже занят!"
        return 1
    fi
    
    # Создание директории
    mkdir -p /opt/monitoring/alertmanager
    
    # Создание конфигурации Alertmanager
    cat > /opt/monitoring/alertmanager/alertmanager.yml << EOF
global:
  resolve_timeout: 5m

route:
  group_by: ['alertname', 'cluster', 'service']
  group_wait: 10s
  group_interval: 10s
  repeat_interval: 12h
  receiver: 'telegram'

receivers:
  - name: 'telegram'
    telegram_configs:
      - bot_token: '${TG_TOKEN}'
        chat_id: ${TG_CHAT_ID}
        parse_mode: 'HTML'
        message: |
          <b>{{ .Status | toUpper }}</b>
          {{ range .Alerts }}
          <b>Alert:</b> {{ .Labels.alertname }}
          <b>Severity:</b> {{ .Labels.severity }}
          <b>Instance:</b> {{ .Labels.instance }} ({{ .Labels.nodename }})
          <b>Description:</b> {{ .Annotations.description }}
          <b>Time:</b> {{ .StartsAt.Format "2006-01-02 15:04:05" }}
          {{ end }}

inhibit_rules:
  - source_match:
      severity: 'critical'
    target_match:
      severity: 'warning'
    equal: ['alertname', 'instance']
EOF
    
    # Запуск Alertmanager
    if docker ps -a | grep -q "^alertmanager$\|[[:space:]]alertmanager$"; then
        print_info "Удаление существующего контейнера Alertmanager..."
        docker stop alertmanager 2>/dev/null
        docker rm alertmanager 2>/dev/null
    fi
    
    docker run -d \
      --name=alertmanager \
      --restart=always \
      -p ${ALERT_PORT}:9093 \
      -v /opt/monitoring/alertmanager:/etc/alertmanager \
      prom/alertmanager:latest \
      --config.file=/etc/alertmanager/alertmanager.yml \
      --storage.path=/alertmanager
    
    if [ $? -eq 0 ]; then
        print_success "Alertmanager успешно установлен на порту ${ALERT_PORT}"
        
        # Создание правил алертов для Prometheus
        create_alert_rules
        
        # Обновление конфигурации Prometheus для использования Alertmanager
        update_prometheus_for_alerts
        
        print_success "Alerting настроен!"
        print_info "Alertmanager доступен по адресу: http://$(hostname -I | awk '{print $1}'):${ALERT_PORT}"
        return 0
    else
        print_error "Ошибка при установке Alertmanager"
        return 1
    fi
}

# Создание правил алертов
create_alert_rules() {
    print_info "Создание правил алертов..."
    
    cat > /opt/monitoring/prometheus/alerts.yml << 'EOF'
groups:
  - name: node_alerts
    interval: 30s
    rules:
      # Сервер недоступен
      - alert: InstanceDown
        expr: up == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          description: "{{ $labels.nodename }} ({{ $labels.instance }}) недоступен более 1 минуты"
      
      # Высокая загрузка CPU
      - alert: HighCPUUsage
        expr: 100 - (avg by(instance, nodename) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          description: "{{ $labels.nodename }} ({{ $labels.instance }}) - высокая загрузка CPU: {{ $value | humanize }}%"
      
      # Критическая загрузка CPU
      - alert: CriticalCPUUsage
        expr: 100 - (avg by(instance, nodename) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 95
        for: 3m
        labels:
          severity: critical
        annotations:
          description: "{{ $labels.nodename }} ({{ $labels.instance }}) - критическая загрузка CPU: {{ $value | humanize }}%"
      
      # Мало свободной памяти
      - alert: HighMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          description: "{{ $labels.nodename }} ({{ $labels.instance }}) - высокое использование памяти: {{ $value | humanize }}%"
      
      # Критически мало памяти
      - alert: CriticalMemoryUsage
        expr: (1 - (node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes)) * 100 > 95
        for: 3m
        labels:
          severity: critical
        annotations:
          description: "{{ $labels.nodename }} ({{ $labels.instance }}) - критическое использование памяти: {{ $value | humanize }}%"
      
      # Мало свободного места на диске
      - alert: HighDiskUsage
        expr: (1 - (node_filesystem_avail_bytes{fstype!~"tmpfs|fuse.lxcfs|squashfs|vfat"} / node_filesystem_size_bytes{fstype!~"tmpfs|fuse.lxcfs|squashfs|vfat"})) * 100 > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          description: "{{ $labels.nodename }} ({{ $labels.instance }}) - мало места на диске {{ $labels.mountpoint }}: {{ $value | humanize }}%"
      
      # Критически мало места на диске
      - alert: CriticalDiskUsage
        expr: (1 - (node_filesystem_avail_bytes{fstype!~"tmpfs|fuse.lxcfs|squashfs|vfat"} / node_filesystem_size_bytes{fstype!~"tmpfs|fuse.lxcfs|squashfs|vfat"})) * 100 > 90
        for: 3m
        labels:
          severity: critical
        annotations:
          description: "{{ $labels.nodename }} ({{ $labels.instance }}) - критически мало места на диске {{ $labels.mountpoint }}: {{ $value | humanize }}%"

  - name: docker_alerts
    interval: 30s
    rules:
      # Контейнер использует много CPU
      - alert: ContainerHighCPU
        expr: sum(rate(container_cpu_usage_seconds_total{name!=""}[5m])) by (name, instance, nodename) * 100 > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          description: "Контейнер {{ $labels.name }} на {{ $labels.nodename }} использует много CPU: {{ $value | humanize }}%"
      
      # Контейнер использует много памяти
      - alert: ContainerHighMemory
        expr: (container_memory_usage_bytes{name!=""} / container_spec_memory_limit_bytes{name!=""}) * 100 > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          description: "Контейнер {{ $labels.name }} на {{ $labels.nodename }} использует много памяти: {{ $value | humanize }}%"
      
      # Контейнер перезапускается
      - alert: ContainerRestarting
        expr: rate(container_last_seen{name!=""}[5m]) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          description: "Контейнер {{ $labels.name }} на {{ $labels.nodename }} перезапускается"
EOF
    
    print_success "Правила алертов созданы"
}

# Обновление конфигурации Prometheus для алертов
update_prometheus_for_alerts() {
    print_info "Обновление конфигурации Prometheus..."
    
    # Создание резервной копии
    cp /opt/monitoring/prometheus/prometheus.yml /opt/monitoring/prometheus/prometheus.yml.backup
    
    # Добавление alerting и rule_files
    cat > /opt/monitoring/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

alerting:
  alertmanagers:
    - static_configs:
        - targets: ['localhost:9093']

rule_files:
  - 'alerts.yml'

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node_exporter'
    static_configs: []

  - job_name: 'cadvisor'
    static_configs: []
EOF
    
    # Перезапуск Prometheus
    docker restart prometheus
    print_success "Prometheus обновлён для работы с алертами"
}

# Установка Prometheus и Grafana (основной сервер)
install_monitoring_server() {
    print_info "Установка Prometheus и Grafana..."
    
    # Создание директорий
    mkdir -p /opt/monitoring/prometheus
    mkdir -p /opt/monitoring/grafana
    mkdir -p /opt/monitoring/alertmanager
    
    # Запрос портов
    read -p "Введите порт для Prometheus (по умолчанию 9091): " PROM_PORT
    PROM_PORT=${PROM_PORT:-9091}
    
    read -p "Введите порт для Grafana (по умолчанию 3002): " GRAFANA_PORT
    GRAFANA_PORT=${GRAFANA_PORT:-3002}
    
    # Проверка портов
    if ! check_port $PROM_PORT; then
        print_error "Порт ${PROM_PORT} уже занят!"
        return 1
    fi
    
    if ! check_port $GRAFANA_PORT; then
        print_error "Порт ${GRAFANA_PORT} уже занят!"
        return 1
    fi
    
    # Создание конфигурации Prometheus
    cat > /opt/monitoring/prometheus/prometheus.yml << 'EOF'
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']

  - job_name: 'node_exporter'
    static_configs: []

  - job_name: 'cadvisor'
    static_configs: []
EOF
    
    # Установка прав
    chmod 644 /opt/monitoring/prometheus/prometheus.yml
    
    # Запуск Prometheus
    if docker ps -a | grep -q "^prometheus$\|[[:space:]]prometheus$"; then
        print_info "Удаление существующего контейнера Prometheus..."
        docker stop prometheus 2>/dev/null
        docker rm prometheus 2>/dev/null
    fi
    
    docker run -d \
      --name=prometheus \
      --restart=always \
      -p ${PROM_PORT}:9090 \
      -v /opt/monitoring/prometheus:/etc/prometheus \
      prom/prometheus:latest \
      --config.file=/etc/prometheus/prometheus.yml \
      --storage.tsdb.path=/prometheus \
      --web.console.libraries=/usr/share/prometheus/console_libraries \
      --web.console.templates=/usr/share/prometheus/consoles
    
    if [ $? -eq 0 ]; then
        print_success "Prometheus успешно установлен на порту ${PROM_PORT}"
    else
        print_error "Ошибка при установке Prometheus"
        return 1
    fi
    
    # Запуск Grafana
    if docker ps -a | grep -q "^grafana$\|[[:space:]]grafana$"; then
        print_info "Удаление существующего контейнера Grafana..."
        docker stop grafana 2>/dev/null
        docker rm grafana 2>/dev/null
    fi
    
    # Установка прав для директории Grafana
    chown -R 472:472 /opt/monitoring/grafana 2>/dev/null
    
    docker run -d \
      --name=grafana \
      --restart=always \
      -p ${GRAFANA_PORT}:3000 \
      -v /opt/monitoring/grafana:/var/lib/grafana \
      -e "GF_SECURITY_ADMIN_PASSWORD=admin" \
      -e "GF_USERS_ALLOW_SIGN_UP=false" \
      grafana/grafana:latest
    
    if [ $? -eq 0 ]; then
        SERVER_IP=$(hostname -I | awk '{print $1}')
        print_success "Grafana успешно установлена на порту ${GRAFANA_PORT}"
        echo ""
        print_info "Grafana доступна по адресу: http://${SERVER_IP}:${GRAFANA_PORT}"
        print_info "Логин по умолчанию: admin"
        print_info "Пароль по умолчанию: admin"
        echo ""
        print_info "Prometheus доступен по адресу: http://${SERVER_IP}:${PROM_PORT}"
        echo ""
        print_info "Следующие шаги:"
        print_info "1. Добавьте серверы в конфигурацию (опция 5 в меню)"
        print_info "2. Откройте Grafana и добавьте Prometheus как источник данных:"
        print_info "   - URL: http://localhost:9090"
        print_info "3. Импортируйте дашборды: 1860 (серверы), 893 (Docker)"
    else
        print_error "Ошибка при установке Grafana"
        return 1
    fi
    
    echo ""
    print_info "Конфигурация Prometheus: /opt/monitoring/prometheus/prometheus.yml"
}

# Добавление сервера в конфигурацию
add_server_to_config() {
    if [ ! -f /opt/monitoring/prometheus/prometheus.yml ]; then
        print_error "Конфигурационный файл Prometheus не найден!"
        print_info "Сначала установите Prometheus на основном сервере (опция 1)"
        return 1
    fi
    
    echo ""
    read -p "Введите IP адрес сервера: " SERVER_IP
    read -p "Введите имя сервера (например, server001): " SERVER_NAME
    read -p "Есть ли на этом сервере Docker контейнеры? (y/n): " HAS_DOCKER
    
    # Валидация IP
    if ! [[ $SERVER_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        print_error "Неверный формат IP адреса"
        return 1
    fi
    
    print_info "Добавление сервера ${SERVER_NAME} (${SERVER_IP}) в конфигурацию..."
    
    # Создание резервной копии
    cp /opt/monitoring/prometheus/prometheus.yml /opt/monitoring/prometheus/prometheus.yml.backup
    
    # Добавление в node_exporter job
    python3 -c "
import yaml
import sys

with open('/opt/monitoring/prometheus/prometheus.yml', 'r') as f:
    config = yaml.safe_load(f)

# Добавление в node_exporter
for job in config['scrape_configs']:
    if job['job_name'] == 'node_exporter':
        if 'static_configs' not in job or job['static_configs'] is None:
            job['static_configs'] = []
        job['static_configs'].append({
            'labels': {
                'instance': '${SERVER_IP}',
                'nodename': '${SERVER_NAME}'
            },
            'targets': ['${SERVER_IP}:9100']
        })
        break

# Добавление в cadvisor если нужно
if '${HAS_DOCKER}'.lower() in ['y', 'yes']:
    for job in config['scrape_configs']:
        if job['job_name'] == 'cadvisor':
            if 'static_configs' not in job or job['static_configs'] is None:
                job['static_configs'] = []
            job['static_configs'].append({
                'labels': {
                    'instance': '${SERVER_IP}',
                    'nodename': '${SERVER_NAME}'
                },
                'targets': ['${SERVER_IP}:9101']
            })
            break

with open('/opt/monitoring/prometheus/prometheus.yml', 'w') as f:
    yaml.dump(config, f, default_flow_style=False, sort_keys=False)
" 2>/dev/null
    
    # Если python не установлен, используем простой метод
    if [ $? -ne 0 ]; then
        print_warning "Python не установлен, используется альтернативный метод..."
        
        # Добавляем node_exporter target
        cat >> /opt/monitoring/prometheus/prometheus.yml << EOF
      - labels:
          instance: ${SERVER_IP}
          nodename: ${SERVER_NAME}
        targets:
          - ${SERVER_IP}:9100
EOF
        
        # Добавляем cadvisor target если нужно
        if [[ "$HAS_DOCKER" == "y" || "$HAS_DOCKER" == "Y" ]]; then
            # Находим строку с cadvisor и добавляем после неё
            sed -i "/job_name: 'cadvisor'/,/static_configs:/a\\      - labels:\\n          instance: ${SERVER_IP}\\n          nodename: ${SERVER_NAME}\\n        targets:\\n          - ${SERVER_IP}:9101" /opt/monitoring/prometheus/prometheus.yml
        fi
    fi
    
    print_success "Сервер ${SERVER_NAME} (${SERVER_IP}) добавлен в конфигурацию"
    print_info "Перезапуск Prometheus..."
    
    docker restart prometheus
    
    if [ $? -eq 0 ]; then
        sleep 2
        print_success "Готово!"
        SERVER_IP_LOCAL=$(hostname -I | awk '{print $1}')
        print_info "Проверьте targets в Prometheus: http://${SERVER_IP_LOCAL}:9091/targets"
    else
        print_error "Ошибка при перезапуске Prometheus"
        print_info "Восстановление из резервной копии..."
        cp /opt/monitoring/prometheus/prometheus.yml.backup /opt/monitoring/prometheus/prometheus.yml
        return 1
    fi
}

# Тестирование алертов
test_alert() {
    if [ ! -f /opt/monitoring/alertmanager/alertmanager.yml ]; then
        print_error "Alertmanager не установлен!"
        print_info "Сначала установите Alertmanager (опция 9)"
        return 1
    fi
    
    print_info "Отправка тестового алерта в Telegram..."
    
    # Отправка тестового алерта через Alertmanager API
    curl -X POST http://localhost:9093/api/v1/alerts -H "Content-Type: application/json" -d '[
      {
        "labels": {
          "alertname": "TestAlert",
          "severity": "warning",
          "instance": "test-server",
          "nodename": "test"
        },
        "annotations": {
          "description": "Это тестовый алерт для проверки отправки в Telegram"
        },
        "startsAt": "'$(date -u +%Y-%m-%dT%H:%M:%S.000Z)'",
        "endsAt": "'$(date -u -d '+5 minutes' +%Y-%m-%dT%H:%M:%S.000Z)'"
      }
    ]' 2>/dev/null
    
    if [ $? -eq 0 ]; then
        print_success "Тестовый алерт отправлен!"
        print_info "Проверьте Telegram - должно прийти сообщение в течение 10-30 секунд"
    else
        print_error "Ошибка при отправке тестового алерта"
        return 1
    fi
}

# Показать статус сервисов
show_status() {
    echo ""
    print_header
    print_info "Статус контейнеров мониторинга:"
    echo ""
    
    docker ps -a --filter "name=prometheus" --filter "name=grafana" --filter "name=node_exporter" --filter "name=cadvisor" --filter "name=alertmanager" --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}" 2>/dev/null
    
    echo ""
    print_info "Открытые порты:"
    if command -v netstat &> /dev/null; then
        netstat -tlnp 2>/dev/null | grep -E "(9090|9091|9093|9100|9101|3000|3002)" | awk '{print $4, $7}'
    elif command -v ss &> /dev/null; then
        ss -tlnp 2>/dev/null | grep -E "(9090|9091|9093|9100|9101|3000|3002)"
    else
        print_warning "netstat/ss не установлены, невозможно показать открытые порты"
    fi
}

# Проверка firewall и вывод предупреждений
check_firewall() {
    print_info "Проверка firewall..."
    
    if systemctl is-active --quiet firewalld 2>/dev/null; then
        print_warning "Firewalld активен. Возможно, потребуется открыть порты:"
        print_info "firewall-cmd --permanent --add-port=9100/tcp  # Node Exporter"
        print_info "firewall-cmd --permanent --add-port=9101/tcp  # cAdvisor"
        print_info "firewall-cmd --permanent --add-port=9091/tcp  # Prometheus"
        print_info "firewall-cmd --permanent --add-port=9093/tcp  # Alertmanager"
        print_info "firewall-cmd --permanent --add-port=3002/tcp  # Grafana"
        print_info "firewall-cmd --reload"
        echo ""
    elif systemctl is-active --quiet ufw 2>/dev/null; then
        print_warning "UFW активен. Возможно, потребуется открыть порты:"
        print_info "ufw allow 9100/tcp  # Node Exporter"
        print_info "ufw allow 9101/tcp  # cAdvisor"
        print_info "ufw allow 9091/tcp  # Prometheus"
        print_info "ufw allow 9093/tcp  # Alertmanager"
        print_info "ufw allow 3002/tcp  # Grafana"
        echo ""
    fi
}

# Главное меню
main_menu() {
    while true; do
        clear
        print_header
        echo "Выберите действие:"
        echo ""
        echo "  1) Установить основной сервер мониторинга (Prometheus + Grafana)"
        echo "  2) Установить агенты на сервер (Node Exporter + cAdvisor)"
        echo "  3) Установить только Node Exporter (мониторинг ресурсов)"
        echo "  4) Установить только cAdvisor (мониторинг Docker)"
        echo "  5) Добавить сервер в конфигурацию Prometheus"
        echo "  6) Показать статус сервисов"
        echo "  7) Перезапустить все сервисы"
        echo "  8) Проверить firewall"
        echo "  9) Настроить алерты в Telegram (Alertmanager)"
        echo " 10) Отправить тестовый алерт"
        echo "  0) Выход"
        echo ""
        read -p "Ваш выбор: " choice
        
        case $choice in
            1)
                echo ""
                check_root
                install_netstat
                install_docker
                if [ $? -eq 0 ]; then
                    install_monitoring_server
                    check_firewall
                fi
                read -p "Нажмите Enter для продолжения..."
                ;;
            2)
                echo ""
                check_root
                install_netstat
                install_docker
                if [ $? -eq 0 ]; then
                    install_node_exporter
                    install_cadvisor
                    echo ""
                    print_success "Агенты успешно установлены!"
                    print_info "Не забудьте добавить этот сервер в конфигурацию Prometheus (опция 5)"
                    check_firewall
                fi
                read -p "Нажмите Enter для продолжения..."
                ;;
            3)
                echo ""
                check_root
                install_netstat
                install_docker
                if [ $? -eq 0 ]; then
                    install_node_exporter
                    check_firewall
                fi
                read -p "Нажмите Enter для продолжения..."
                ;;
            4)
                echo ""
                check_root
                install_netstat
                install_docker
                if [ $? -eq 0 ]; then
                    install_cadvisor
                    check_firewall
                fi
                read -p "Нажмите Enter для продолжения..."
                ;;
            5)
                echo ""
                add_server_to_config
                read -p "Нажмите Enter для продолжения..."
                ;;
            6)
                show_status
                read -p "Нажмите Enter для продолжения..."
                ;;
            7)
                echo ""
                print_info "Перезапуск всех сервисов..."
                docker restart prometheus grafana node_exporter cadvisor 2>/dev/null
                print_success "Сервисы перезапущены"
                read -p "Нажмите Enter для продолжения..."
                ;;
            8)
                echo ""
                check_firewall
                read -p "Нажмите Enter для продолжения..."
                ;;
            9)
                echo ""
                check_root
                install_alertmanager
                read -p "Нажмите Enter для продолжения..."
                ;;
            10)
                echo ""
                test_alert
                read -p "Нажмите Enter для продолжения..."
                ;;
            0)
                print_info "Выход..."
                exit 0
                ;;
            *)
                print_error "Неверный выбор"
                sleep 2
                ;;
        esac
    done
}

# Запуск главного меню
main_menu
