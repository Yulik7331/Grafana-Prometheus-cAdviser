# 📊 Система мониторинга серверов

Автоматическая установка полного стека мониторинга: **Grafana + Prometheus + Node Exporter + cAdvisor + Alertmanager**

## 🎯 Возможности

- ✅ Мониторинг ресурсов серверов (CPU, RAM, Disk, Network)
- ✅ Мониторинг Docker контейнеров
- ✅ Алерты в Telegram
- ✅ Красивые дашборды в Grafana
- ✅ Поддержка Ubuntu/Debian/CentOS/RHEL
- ✅ Установка в один клик

---

## 📋 Требования

- Linux сервер (Ubuntu/Debian/CentOS/RHEL)
- Root доступ (sudo)
- Интернет соединение
- Открытые порты (скрипт подскажет как настроить firewall)

---

## 🚀 Быстрый старт

### 1. Скачайте скрипт

```bash
# Скачайте скрипт на ваш сервер
wget https://github.com/Yulik7331/Grafana-Prometheus-cAdvisor/blob/main/monitoring_setup_script.sh

# Или создайте файл вручную
nano monitoring_setup.sh
# Вставьте содержимое скрипта и сохраните (Ctrl+X, Y, Enter)
```

### 2. Сделайте скрипт исполняемым

```bash
chmod +x monitoring_setup.sh
```

### 3. Запустите скрипт

```bash
sudo ./monitoring_setup.sh
```

---

## 📖 Пошаговая установка

### Сценарий 1: Один основной сервер + несколько серверов для мониторинга

#### На основном сервере (где будет Grafana):

```bash
sudo ./monitoring_setup.sh
# Выберите: 1 - Установить основной сервер мониторинга
# Введите порты (или оставьте по умолчанию)
# Дождитесь завершения установки
```

**Результат:**
- Prometheus на порту `9091`
- Grafana на порту `3002`
- Доступ к Grafana: `http://ВАШ_IP:3002`
  - Логин: `admin`
  - Пароль: `admin`

#### На каждом сервере для мониторинга:

```bash
sudo ./monitoring_setup.sh
# Выберите: 2 - Установить агенты на сервер
# Введите порт для cAdvisor (или оставьте 9101)
```

**Результат:**
- Node Exporter на порту `9100`
- cAdvisor на порту `9101`

#### Добавление серверов в Prometheus:

```bash
# На основном сервере
sudo ./monitoring_setup.sh
# Выберите: 5 - Добавить сервер в конфигурацию
# Введите IP адрес сервера: 92.38.34.113
# Введите имя сервера: server106
# Есть Docker? (y/n): y
```

Повторите для всех серверов.

---

## 🔔 Настройка алертов в Telegram

### Шаг 1: Создание Telegram бота

1. Откройте Telegram и найдите **@BotFather**
2. Отправьте команду `/newbot`
3. Придумайте имя бота (например: `My Monitoring Bot`)
4. Придумайте username (например: `mymonitoring_bot`)
5. Получите **Bot Token**: `1234567890:ABCdefGHIjklMNOpqrsTUVwxyz`

### Шаг 2: Получение Chat ID

1. Найдите бота **@userinfobot** в Telegram
2. Отправьте `/start`
3. Бот вернёт ваш **Chat ID**: `123456789`

### Шаг 3: Настройка Alertmanager

```bash
sudo ./monitoring_setup.sh
# Выберите: 9 - Настроить алерты в Telegram
# Введите Bot Token: 1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
# Введите Chat ID: 123456789
```

### Шаг 4: Тестирование

```bash
sudo ./monitoring_setup.sh
# Выберите: 10 - Отправить тестовый алерт
# Проверьте Telegram - должно прийти сообщение
```

---

## 📊 Настройка Grafana

### 1. Войдите в Grafana

Откройте браузер: `http://ВАШ_IP:3002`
- Логин: `admin`
- Пароль: `admin`
- При первом входе система попросит сменить пароль

### 2. Добавьте Prometheus как источник данных

1. Нажмите на **⚙ Configuration** → **Data Sources**
2. Нажмите **Add data source**
3. Выберите **Prometheus**
4. В поле **URL** введите: `http://localhost:9090`
5. Нажмите **Save & Test**

### 3. Импортируйте дашборды

#### Дашборд для мониторинга серверов:

1. Нажмите **+** → **Import**
2. Введите ID дашборда: `1860`
3. Нажмите **Load**
4. Выберите Prometheus как источник данных
5. Нажмите **Import**

#### Дашборд для Docker контейнеров:

1. Нажмите **+** → **Import**
2. Введите ID дашборда: `893`
3. Нажмите **Load**
4. Выберите Prometheus как источник данных
5. Нажмите **Import**

### 4. Готово! 🎉

Теперь у вас есть красивые дашборды с метриками всех серверов!

---

## 🔧 Структура портов

| Сервис | Порт | Описание |
|--------|------|----------|
| Grafana | 3002 | Веб-интерфейс визуализации |
| Prometheus | 9091 | Сервер сбора метрик |
| Alertmanager | 9093 | Система алертов |
| Node Exporter | 9100 | Метрики сервера (на каждом сервере) |
| cAdvisor | 9101 | Метрики Docker (на каждом сервере) |

---

## 📁 Важные файлы и директории

```
/opt/monitoring/
├── prometheus/
│   ├── prometheus.yml          # Конфигурация Prometheus
│   └── alerts.yml              # Правила алертов
├── grafana/                    # Данные Grafana
└── alertmanager/
    └── alertmanager.yml        # Конфигурация Alertmanager
```

---

## 🛠 Полезные команды

### Проверка статуса сервисов

```bash
sudo ./monitoring_setup.sh
# Выберите: 6 - Показать статус сервисов
```

Или вручную:

```bash
# Просмотр всех контейнеров
docker ps -a

# Просмотр логов
docker logs prometheus
docker logs grafana
docker logs node_exporter
docker logs cadvisor
docker logs alertmanager
```

### Перезапуск сервисов

```bash
sudo ./monitoring_setup.sh
# Выберите: 7 - Перезапустить все сервисы
```

Или вручную:

```bash
docker restart prometheus
docker restart grafana
docker restart node_exporter
docker restart cadvisor
docker restart alertmanager
```

### Редактирование конфигурации Prometheus

```bash
nano /opt/monitoring/prometheus/prometheus.yml
# После изменений:
docker restart prometheus
```

### Редактирование правил алертов

```bash
nano /opt/monitoring/prometheus/alerts.yml
# После изменений:
docker restart prometheus
```

---

## 🔥 Настройка Firewall

### Ubuntu/Debian (UFW)

```bash
sudo ufw allow 9100/tcp   # Node Exporter
sudo ufw allow 9101/tcp   # cAdvisor
sudo ufw allow 9091/tcp   # Prometheus
sudo ufw allow 9093/tcp   # Alertmanager
sudo ufw allow 3002/tcp   # Grafana
```

### CentOS/RHEL (firewalld)

```bash
sudo firewall-cmd --permanent --add-port=9100/tcp
sudo firewall-cmd --permanent --add-port=9101/tcp
sudo firewall-cmd --permanent --add-port=9091/tcp
sudo firewall-cmd --permanent --add-port=9093/tcp
sudo firewall-cmd --permanent --add-port=3002/tcp
sudo firewall-cmd --reload
```

Или используйте скрипт:

```bash
sudo ./monitoring_setup.sh
# Выберите: 8 - Проверить firewall
```

---

## 🚨 Настройка алертов

Алерты автоматически создаются при установке Alertmanager. Они включают:

### Критические алерты (🔴 Critical):
- Сервер недоступен более 1 минуты
- CPU > 95% более 3 минут
- RAM > 95% более 3 минут
- Диск > 90% более 3 минут

### Предупреждения (⚠️ Warning):
- CPU > 80% более 5 минут
- RAM > 80% более 5 минут
- Диск > 80% более 5 минут
- Контейнер использует много ресурсов
- Контейнер перезапускается

### Изменение порогов

Отредактируйте файл с правилами:

```bash
nano /opt/monitoring/prometheus/alerts.yml
```

Пример изменения порога CPU:

```yaml
- alert: HighCPUUsage
  expr: 100 - (avg by(instance, nodename) (rate(node_cpu_seconds_total{mode="idle"}[5m])) * 100) > 70  # Было 80
  for: 5m
```

После изменений:

```bash
docker restart prometheus
```

---

## 📱 Примеры алертов в Telegram

```
🔴 CRITICAL

Alert: CriticalMemoryUsage
Severity: critical
Instance: 92.38.34.112 (server105)
Description: server105 (92.38.34.112) - критическое использование памяти: 96.5%
Time: 2025-10-08 14:30:22
```

```
⚠️ WARNING

Alert: HighDiskUsage
Severity: warning
Instance: 92.38.34.113 (server106)
Description: server106 (92.38.34.113) - мало места на диске /: 85.2%
Time: 2025-10-08 15:45:10
```

---

## ❓ Решение проблем

### Контейнер не запускается

```bash
# Просмотр логов
docker logs prometheus
docker logs grafana

# Проверка портов
netstat -tulnp | grep -E "9090|9091|3002"
```

### Grafana не показывает метрики

1. Проверьте, что Prometheus доступен: `http://ВАШ_IP:9091`
2. Проверьте targets в Prometheus: `http://ВАШ_IP:9091/targets`
3. Убедитесь, что все targets в статусе **UP**

### Алерты не приходят в Telegram

```bash
# Проверьте логи Alertmanager
docker logs alertmanager

# Отправьте тестовый алерт
sudo ./monitoring_setup.sh
# Выберите: 10 - Отправить тестовый алерт
```

### Node Exporter не собирает метрики

```bash
# Проверьте доступность
curl http://localhost:9100/metrics

# Проверьте логи
docker logs node_exporter

# Перезапустите
docker restart node_exporter
```

---

## 📈 Масштабирование

### Добавление нового сервера

```bash
# 1. На новом сервере установите агенты
sudo ./monitoring_setup.sh
# Выберите: 2

# 2. На основном сервере добавьте в конфигурацию
sudo ./monitoring_setup.sh
# Выберите: 5
```

### Массовая установка на множество серверов

Создайте скрипт для автоматизации:

```bash
#!/bin/bash
# deploy_monitoring.sh

SERVERS=(
  "92.38.34.12:server001"
  "92.38.34.13:server002"
  "92.38.34.14:server003"
)

for server in "${SERVERS[@]}"; do
  IP="${server%%:*}"
  NAME="${server##*:}"
  
  echo "Установка на $NAME ($IP)..."
  
  # Копирование скрипта
  scp monitoring_setup.sh root@$IP:/tmp/
  
  # Установка
  ssh root@$IP "cd /tmp && chmod +x monitoring_setup.sh && echo '2' | ./monitoring_setup.sh"
  
  echo "Добавление в Prometheus..."
  # Добавление в конфигурацию
  # ... ваш код ...
done
```

---

## 🔒 Безопасность

### Рекомендации:

1. **Измените пароль Grafana** после первого входа
2. **Ограничьте доступ** к портам через firewall
3. **Используйте VPN** для доступа к Grafana
4. **Регулярно обновляйте** контейнеры:

```bash
docker pull prom/prometheus:latest
docker pull grafana/grafana:latest
docker pull prom/node-exporter:latest
docker pull gcr.io/cadvisor/cadvisor:latest
docker pull prom/alertmanager:latest

# Затем пересоздайте контейнеры через скрипт
```

---

## 📞 Поддержка

### Полезные ссылки:

- [Документация Prometheus](https://prometheus.io/docs/)
- [Документация Grafana](https://grafana.com/docs/)
- [Дашборды Grafana](https://grafana.com/grafana/dashboards/)
- [Node Exporter](https://github.com/prometheus/node_exporter)
- [cAdvisor](https://github.com/google/cadvisor)

### Логи для диагностики:

```bash
# Все логи
docker logs prometheus
docker logs grafana
docker logs node_exporter
docker logs cadvisor
docker logs alertmanager

# Следить за логами в реальном времени
docker logs -f prometheus
```

---

## 🎓 Дополнительные возможности

### Настройка SSL для Grafana

```bash
# Используйте nginx как reverse proxy
# Или настройте встроенный SSL в Grafana
```

### Длительное хранение метрик

По умолчанию Prometheus хранит метрики 15 дней. Для увеличения:

```bash
# Остановите Prometheus
docker stop prometheus

# Запустите с параметром retention
docker run -d \
  --name=prometheus \
  --restart=always \
  -p 9091:9090 \
  -v /opt/monitoring/prometheus:/etc/prometheus \
  prom/prometheus:latest \
  --config.file=/etc/prometheus/prometheus.yml \
  --storage.tsdb.retention.time=90d
```

### Экспорт метрик в другие системы

Prometheus поддерживает remote write для экспорта в:
- InfluxDB
- Thanos
- VictoriaMetrics
- И другие

---

## ✅ Чек-лист после установки

- [ ] Prometheus доступен и собирает метрики
- [ ] Grafana открывается и показывает дашборды
- [ ] Все серверы в статусе UP в Prometheus Targets
- [ ] Импортированы дашборды 1860 и 893
- [ ] Настроены алерты в Telegram
- [ ] Получен тестовый алерт в Telegram
- [ ] Firewall настроен
- [ ] Пароль Grafana изменён

---

## 📝 Changelog

**v1.0** - Первая версия
- Установка Grafana + Prometheus
- Поддержка Node Exporter и cAdvisor
- Алерты в Telegram
- Интерактивное меню

---

**Удачного мониторинга! 🚀📊**
