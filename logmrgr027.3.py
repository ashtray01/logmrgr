import tkinter as tk
import heapq
from tkinter import filedialog, messagebox, ttk
import json
import os
import re
import threading
import tempfile
import shutil
import time
import logging
from datetime import datetime
from dateutil.parser import parse
import chardet
#import psutil
from multiprocessing import Pool, cpu_count
from functools import partial
import pytz

# Для поддержки multiprocessing на Windows
from multiprocessing import freeze_support

# Настройка логгера
logging.basicConfig(
    filename='log_merger_errors.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Кэш для парсинга дат — ускорение
DATE_PARSE_CACHE = {}

def cached_parse(dt_str):
    if dt_str not in DATE_PARSE_CACHE:
        try:
            # Обработка специфичных форматов времени
            if ',' in dt_str and '.' not in dt_str:
                dt_str = dt_str.replace(',', '.')
            dt = parse(dt_str)
            if dt.tzinfo is None:
                dt = pytz.utc.localize(dt)
            DATE_PARSE_CACHE[dt_str] = dt
        except Exception as e:
            logging.warning(f"Failed to cache parse {dt_str}: {e}")
            dt = datetime.now(pytz.utc)  # fallback на текущее UTC время
            DATE_PARSE_CACHE[dt_str] = dt
    return DATE_PARSE_CACHE[dt_str]

def sanitize_filename(filename):
    """Заменяет недопустимые символы в имени файла на подчеркивания."""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename

def extract_version_from_text(text):
    """Извлекает версию из текста."""
    if not text:
        return "unknown"
    # Сначала ищем версию в квадратных скобках
    match = re.search(r'\[(\d+\.\d+\.\d+(?:\.\d+)?)\]', text)
    if match:
        return match.group(1)
    # Затем ищем версию в формате "version":"..."
    match = re.search(r'"version"\s*:\s*"([^"]+)"', text)
    if match:
        return match.group(1)
    # Затем ищем версию в формате "module":"...Version=..."
    match = re.search(r'"module"\s*:\s*"([^"]*Version=([^",]+)[^"]*)"', text)
    if match:
        return match.group(2)
    # Затем ищем версию в формате "Version":"..."
    match = re.search(r'"Version"\s*:\s*"([^"]+)"', text)
    if match:
        return match.group(1)
    # Затем ищем версию в формате version= или version:
    match = re.search(r'version[=:]\s*["\']?([^"\'>\s,]+)', text)
    if match:
        return match.group(1)
    # Затем ищем версию в формате elasticsearch-7.17.13.jar
    match = re.search(r'[-_]v?(\d+\.\d+\.\d+(?:\.\d+)?)', text)
    if match:
        return match.group(1)
    # Затем ищем версию в формате 7.17.13
    match = re.search(r'\b(\d+\.\d+\.\d+(?:\.\d+)?)\b', text)
    if match:
        return match.group(1)
    return "unknown"

def extract_service_name_from_path(file_path):
    """Извлекает имя сервиса из имени файла или пути."""
    filename = os.path.basename(file_path).lower()
    candidates = [
        'elasticsearch', 'kibana', 'logstash', 'nginx', 'apache', 'redis', 'postgres',
        'mysql', 'mongo', 'rabbitmq', 'rabbit', 'kafka', 'zookeeper', 'traefik', 'haproxy',
        'grafana', 'prometheus', 'alertmanager', 'consul', 'vault', 'nomad',
        'beats', 'filebeat', 'metricbeat', 'auditbeat', 'journalbeat', 'winlogbeat',
        'fluentd', 'vector', 'telegraf', 'cadvisor', 'node_exporter', 'blackbox_exporter',
        'gateway', 'auth', 'payment', 'user', 'catalog', 'search', 'cache', 'queue',
        'worker', 'scheduler', 'report', 'backup', 'monitor', 'health', 'api', 'web'
    ]
    for candidate in candidates:
        if candidate in filename:
            return candidate.title()
    name = os.path.splitext(filename)[0]
    return sanitize_filename(name).title() or "Unknown"

def extract_tenant(entry):
    """Извлекает имя тенанта из записи."""
    # Проверяем tn напрямую
    if "tn" in entry:
        return entry["tn"]
    # Проверяем host.name
    if "host" in entry and isinstance(entry["host"], dict) and "name" in entry["host"]:
        return entry["host"]["name"]
    # Проверяем cluster.name и node.name
    cluster_name = entry.get("cluster.name")
    node_name = entry.get("node.name")
    if cluster_name and node_name:
        return f"{cluster_name}-{node_name}"
    if node_name:
        return node_name
    if cluster_name:
        return cluster_name
    return None

def extract_logger(entry):
    """Извлекает имя логгера из записи."""
    # Проверяем lg напрямую
    if "lg" in entry:
        return entry["lg"]
    # Проверяем logger
    if "logger" in entry:
        if isinstance(entry["logger"], str):
            return entry["logger"]
        elif isinstance(entry["logger"], dict) and "name" in entry["logger"]:
            return entry["logger"]["name"]
    # Проверяем component
    if "component" in entry:
        return entry["component"]
    # Проверяем service.name
    if "service" in entry and isinstance(entry["service"], dict) and "name" in entry["service"]:
        return entry["service"]["name"]
    # Проверяем app_id
    if "app_id" in entry:
        return entry["app_id"]
    return None

def format_timestamp(dt):
    """Форматирует дату в эталонный формат."""
    t_formatted = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + dt.strftime("%z")
    if len(t_formatted) == 26:  # +0000 → +00:00
        t_formatted = t_formatted[:-2] + ":" + t_formatted[-2:]
    return t_formatted

def parse_log_line(line, file_path):
    """Парсит строку лога в зависимости от её формата."""
    line = line.strip()
    if not line:
        return None
    # Поиск JSON-объекта в строке
    json_start = line.find('{')
    if json_start != -1:
        try:
            json_part = line[json_start:]
            entry = json.loads(json_part)
            time_keys = ['t', '@timestamp', 'timestamp', 'date', 'time']
            dt_str = next((entry.get(k) for k in time_keys if k in entry), None)
            if dt_str:
                try:
                    cached_parse(dt_str)
                    return transform_generic_json(entry, file_path)
                except Exception:
                    pass
            return transform_generic_json(entry, file_path)
        except (json.JSONDecodeError, ValueError):
            pass
    # Проверяем на известные текстовые форматы
    ecs_pattern = re.compile(r'^\{"@timestamp":"')
    procrun_pattern = re.compile(r'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[info\]')
    elasticsearch_pattern = re.compile(r'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d{3})\]\[([A-Z]+)\]\[(.*?)\] \[([A-Z0-9_-]+)\] \[(.*?)\] (.*)')
    linux_syslog_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}\+\d{2}:\d{2} [a-zA-Z0-9_-]+ \w+\[\d+\]:')
    elasticsearch_json_pattern = re.compile(r'^\{"type":\s*"[^"]*",\s*"timestamp":\s*"[^"]*"')
    # Новый шаблон для обработки "смешанных" форматов
    mixed_log_pattern = re.compile(r'^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}.\d{3} .*?\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d{3})\](.*)')
    try:
        if ecs_pattern.match(line):
            return transform_ecs(json.loads(line))
        if elasticsearch_json_pattern.match(line):
            return transform_elasticsearch_json_log(json.loads(line))
        if procrun_pattern.match(line):
            return transform_procrun_log(line, file_path)
        mixed_match = mixed_log_pattern.match(line)
        if mixed_match:
            partial_line = f"[{mixed_match.group(1)}]{mixed_match.group(2)}"
            return transform_elasticsearch_log(partial_line, file_path)
        if elasticsearch_pattern.match(line):
            return transform_elasticsearch_log(line, file_path)
        if linux_syslog_pattern.match(line):
            return transform_linux_syslog_to_etalon(line, file_path)
    except (json.JSONDecodeError, ValueError, Exception) as e:
        logging.warning(f"Failed to parse line in {file_path}: {line[:100]}... Error: {e}")
    return create_minimal_entry(line, file_path)

def transform_elasticsearch_json_log(entry):
    transformed = {}
    dt_str = entry.get("timestamp", "").replace(',', '.')
    try:
        dt = cached_parse(dt_str)
        transformed["t"] = format_timestamp(dt)
    except Exception:
        transformed["t"] = format_timestamp(datetime.now(pytz.utc))
    transformed["pid"] = str(entry.get("process.id", "1"))
    level = entry.get("level", "INFO")
    transformed["l"] = level.title().replace("Critical", "Fatal")
    transformed["lg"] = entry.get("component", "Elasticsearch")
    transformed["mt"] = entry.get("message", "")
    transformed["args"] = {}
    excluded_keys = {"timestamp", "level", "component", "message", "type", "cluster.name", "node.name", "process.id"}
    for key, value in entry.items():
        if key not in excluded_keys:
            transformed["args"][key] = value
    transformed["tn"] = entry.get("node.name", "Elasticsearch")
    transformed["v"] = extract_version_from_text(transformed["mt"])
    return transformed

def transform_ecs(entry):
    transformed = {}
    try:
        dt_str = entry.pop("@timestamp")
        dt = cached_parse(dt_str)
        transformed["t"] = format_timestamp(dt)
    except Exception:
        transformed["t"] = format_timestamp(datetime.now(pytz.utc))
    level = entry.pop("log", {}).get("level", "information").title()
    transformed["l"] = level.replace("Information", "Info").replace("Warning", "Warn").replace("Critical", "Fatal")
    log_info = entry.pop("log", {})
    service = entry.pop("service", {})
    service_name = service.get("name", "UnknownService")
    transformed["lg"] = log_info.get("logger", service_name)
    process = entry.pop("process", {})
    pid = process.get("pid", "1")
    transformed["pid"] = str(pid)
    message = entry.pop("message", "")
    transformed["mt"] = message
    transformed["args"] = {}
    for key, value in entry.items():
        if key not in ["labels", "ecs", "host"]:
            transformed["args"][key] = value
    if 'host' in entry:
        transformed["args"]['host'] = entry['host']
    if 'original' in log_info:
        transformed["args"]['original_log_info'] = log_info['original']
    transformed["tn"] = service.get("name", "UnknownService")
    transformed["v"] = extract_version_from_text(message)
    return transformed

def transform_procrun_log(line, file_path):
    transformed = {}
    parts = re.split(r'\[(.*?)\]', line.strip())
    try:
        dt = cached_parse(parts[1].strip())
        transformed["t"] = format_timestamp(dt)
    except Exception:
        transformed["t"] = format_timestamp(datetime.now(pytz.utc))
    level = parts[3].strip()
    transformed["l"] = "Info" if level.lower() == "info" else level.title().replace("Critical", "Fatal")
    service_name = extract_service_name_from_path(file_path)
    transformed["lg"] = "Commons Daemon"
    transformed["pid"] = parts[5].strip() if len(parts) > 5 else "1"
    rest = " ".join(parts[6:]).strip()
    transformed["mt"] = rest
    transformed["args"] = {}
    transformed["tn"] = service_name
    transformed["v"] = extract_version_from_text(rest)
    return transformed

def transform_elasticsearch_log(line, file_path):
    transformed = {}
    match = re.search(r'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d{3})\]\[([A-Z]+)\]\[(.*?)\] \[([A-Z0-9_-]+)\] \[(.*?)\] (.*)', line)
    if match:
        dt_str, level, logger, pid, service_name, message = match.groups()
        dt_str = dt_str.replace(',', '.')
        try:
            dt = cached_parse(dt_str)
            transformed["t"] = format_timestamp(dt)
        except Exception:
            transformed["t"] = format_timestamp(datetime.now(pytz.utc))
        transformed["pid"] = pid
        transformed["l"] = level.title().replace("Critical", "Fatal")
        transformed["lg"] = logger
        transformed["mt"] = message.strip()
        transformed["tn"] = service_name
        transformed["v"] = extract_version_from_text(message)
        transformed["args"] = {}
        return transformed
    return create_minimal_entry(line, file_path)

def transform_linux_syslog(line, file_path):
    transformed = {}
    match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}\+\d{2}:\d{2}) ([a-zA-Z0-9_-]+) (\w+)\[(\d+)\]: (.*)', line)
    if match:
        dt_str, host, service_name, pid, message = match.groups()
        try:
            dt = cached_parse(dt_str)
            transformed["t"] = format_timestamp(dt)
        except Exception:
            transformed["t"] = format_timestamp(datetime.now(pytz.utc))
        transformed["pid"] = pid
        transformed["l"] = "Info"
        transformed["lg"] = host
        transformed["mt"] = message.strip()
        transformed["tn"] = service_name
        transformed["v"] = extract_version_from_text(message)
        transformed["args"] = {}
        return transformed
    return create_minimal_entry(line, file_path)

def transform_generic_json(entry, file_path):
    # Начинаем с КОПИИ исходного объекта — НИЧЕГО НЕ УДАЛЯЕМ
    transformed = entry.copy() if isinstance(entry, dict) else {}
    
    # 1. Время (t) — нормализуем формат
    dt_str = None
    if "t" in entry:
        dt_str = entry["t"]
    elif "@timestamp" in entry:
        dt_str = entry["@timestamp"]
    elif "timestamp" in entry:
        dt_str = entry["timestamp"]
    elif "date" in entry:
        dt_str = entry["date"]
    elif "time" in entry:
        dt_str = entry["time"]
    
    if dt_str:
        try:
            if isinstance(dt_str, str) and dt_str.endswith("Z"):
                dt_str = dt_str.replace("Z", "+00:00")
            dt = cached_parse(dt_str)
            transformed["t"] = format_timestamp(dt)
        except Exception:
            transformed["t"] = dt_str  # оставляем как есть
    else:
        # Если t вообще нет — добавляем
        transformed["t"] = format_timestamp(datetime.now(pytz.utc))
    
    # 2. PID — если не задан, добавим
    if "pid" not in transformed:
        if "process" in entry and isinstance(entry["process"], dict) and "pid" in entry["process"]:
            transformed["pid"] = str(entry["process"]["pid"])
        else:
            transformed["pid"] = "1"
    
    # 3. Trace (tr) — поднимаем из вложенных объектов, если нужно
    if "tr" not in transformed:
        if "trace" in entry and isinstance(entry["trace"], dict) and "id" in entry["trace"]:
            transformed["tr"] = entry["trace"]["id"]
        elif "transaction" in entry and isinstance(entry["transaction"], dict) and "id" in entry["transaction"]:
            transformed["tr"] = entry["transaction"]["id"]
    
    # 4. Уровень (l) — если не задан, извлекаем
    if "l" not in transformed:
        level = None
        if "log" in entry and isinstance(entry["log"], dict) and "level" in entry["log"]:
            level = entry["log"]["level"]
        elif "level" in entry:
            level = entry["level"]
        elif "log.level" in entry:
            level = entry["log.level"]
        # Проверяем текстовые уровни
        if not level:
            entry_str = json.dumps(entry)
            lower_entry = entry_str.lower()
            if '"level":"error"' in lower_entry or '"log.level":"error"' in lower_entry or '[error]' in lower_entry:
                level = "Error"
            elif '"level":"warn"' in lower_entry or '"log.level":"warn"' in lower_entry or '[warn]' in lower_entry or '[warning]' in lower_entry:
                level = "Warn"
            elif '"level":"debug"' in lower_entry or '"log.level":"debug"' in lower_entry or '[debug]' in lower_entry:
                level = "Debug"
            elif '"level":"fatal"' in lower_entry or '"log.level":"fatal"' in lower_entry or '[fatal]' in lower_entry:
                level = "Fatal"
            elif '"level":"info"' in lower_entry or '"log.level":"info"' in lower_entry or '[info]' in lower_entry:
                level = "Info"
        
        if level:
            level_title = level.title()
            transformed["l"] = level_title.replace("Information", "Info").replace("Warning", "Warn").replace("Critical", "Fatal")
        else:
            transformed["l"] = "Info"
    
    # 5. Логгер (lg) — если не задан
    if "lg" not in transformed:
        logger = extract_logger(entry)
        if logger:
            transformed["lg"] = logger
        else:
            transformed["lg"] = extract_service_name_from_path(file_path)
    
    # 6. Сообщение (mt) — если не задано, пытаемся извлечь
    if "mt" not in transformed:
        if "message" in entry:
            transformed["mt"] = entry["message"]
        elif "msg" in entry:
            transformed["mt"] = entry["msg"]
    
    # 7. Transaction name (tn) — нормализуем, если есть
    if "tn" not in transformed:
        tenant = extract_tenant(entry)
        if tenant:
            transformed["tn"] = tenant
        else:
            transformed["tn"] = extract_service_name_from_path(file_path)
    
    # 8. Версия (v) — если не задана
    if "v" not in transformed:
        # Пытаемся извлечь из service.version
        if "service" in entry and isinstance(entry["service"], dict) and "version" in entry["service"]:
            transformed["v"] = entry["service"]["version"]
        else:
            # Пытаемся извлечь из сообщения или других полей
            msg = str(entry.get("message", "")) if "message" in entry else str(entry)
            transformed["v"] = extract_version_from_text(msg)
    
    # 9. Ошибки (ex) — если есть
    if "ex" not in transformed:
        # Проверяем наличие типичных полей ошибок
        error_fields = ["exception", "error", "err", "stacktrace", "stack_trace"]
        for field in error_fields:
            if field in entry:
                if "ex" not in transformed:
                    transformed["ex"] = {}
                transformed["ex"][field] = entry[field]
    
    # ➤➤➤ САМОЕ ВАЖНОЕ: НИЧЕГО НЕ УДАЛЯЕМ.
    # Все исходные поля остаются.
    # Мы только ДОБАВЛЯЕМ или НОРМАЛИЗУЕМ обязательные поля эталона.
    return transformed

def transform_linux_syslog_to_etalon(line, file_path):
    """Преобразует syslog в эталонный формат"""
    match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2}) ([a-zA-Z0-9_-]+) (\w+)\[(\d+)\]: (.*)', line)
    if not match:
        return create_minimal_entry(line, file_path)
    dt_str, host, service_name, pid, message = match.groups()
    # Парсим время
    try:
        dt = cached_parse(dt_str)
        t_formatted = format_timestamp(dt)
    except Exception:
        t_formatted = format_timestamp(datetime.now(pytz.utc))
    # Извлекаем название сервиса из сообщения, если возможно
    lg = service_name
    if "DocumentAssemblerService" in message:
        lg = "DocumentAssemblerService"
    elif "TextExtractorService" in message:
        lg = "TextExtractorService"
    else:
        # Пытаемся найти сервис в тексте
        services = ["DocumentAssemblerService", "TextExtractorService", "RabbitMqSubscriber", "GenericService"]
        for svc in services:
            if svc in message:
                lg = svc
                break
    # Создаем span из сообщения
    span_name = "SystemLog"
    if "AMQP connection" in message:
        span_name = "AMQP connection"
    elif "closing" in message:
        span_name = "Closing connection"
    # Упрощаем сообщение — удаляем избыточные данные
    clean_message = message
    clean_message = re.sub(r'<[^>]+>', '', clean_message)  # удаляем <0.123.0>
    clean_message = re.sub(r'vhost:.*?,', '', clean_message)
    clean_message = re.sub(r'\s+', ' ', clean_message).strip()
    return {
        "t": t_formatted,
        "pid": pid,
        "l": "Info",
        "lg": lg,
        "span": {
            "status": "Info",
            "name": span_name,
            "messageType": "SystemLog",
            "message": clean_message
        },
        "tn": lg,
        # "v" не добавляем — в syslog обычно нет версии
    }

def create_minimal_entry(line, file_path):
    """Создаёт запись, сохраняя ВСЮ строку. Ищет истинное время события внутри строки. НИЧЕГО НЕ УДАЛЯЕМ."""
    transformed = {
        "_raw_line": line.strip(),  # 🔥 ОРИГИНАЛ — свято храним
    }
    raw_line = line.strip()
    # Шаблоны для поиска времени СОБЫТИЯ (не времени записи лога)
    # Формат: "03.04.2025 0:10:19" или "03.04.2025 00:10:19"
    event_time_patterns = [
        r'(\d{2})\.(\d{2})\.(\d{4})\s+(\d{1,2}):(\d{2}):(\d{2})',  # DD.MM.YYYY H:M:S
        r'(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})(?:\.(\d{3,6}))?',  # YYYY-MM-DD HH:MM:SS[.mmm]
    ]
    event_time = None
    for pattern in event_time_patterns:
        match = re.search(pattern, raw_line)
        if match:
            try:
                if pattern.startswith(r'(\d{2})\.'):  # DD.MM.YYYY
                    day, month, year, hour, minute, second = match.groups()[:6]
                    dt = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
                else:  # YYYY-MM-DD
                    year, month, day, hour, minute, second, ms = match.groups()
                    dt = datetime(int(year), int(month), int(day), int(hour), int(minute), int(second))
                    if ms:
                        microsecond = int(ms.ljust(6, '0')[:6])
                        dt = dt.replace(microsecond=microsecond)
                # Локализуем в UTC, если нет таймзоны
                if dt.tzinfo is None:
                    dt = pytz.utc.localize(dt)
                event_time = dt
                break
            except Exception as e:
                logging.warning(f"Failed to parse event time with pattern {pattern}: {e}")
                continue
    # Если нашли время события — используем его
    if event_time:
        t_formatted = format_timestamp(event_time)
        transformed["t"] = t_formatted
    else:
        # Иначе — берём время из начала строки (fallback)
            # Сохраняем время записи лога отдельно, если оно отличается
        start_time_match = re.search(r'^\s*(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,})?)', raw_line)
        if start_time_match:
            dt_str = start_time_match.group(1).replace(',', '.')
            try:
                dt = cached_parse(dt_str)
                logged_at = format_timestamp(dt)
                if logged_at != transformed.get("t", ""):  # если отличается от времени события
                    transformed["_logged_at"] = logged_at
            except Exception:
                pass
        else:
            transformed["t"] = format_timestamp(datetime.now(pytz.utc))
    # ➤➤➤ ВСЁ ОСТАЛЬНОЕ — БЕЗ ИЗМЕНЕНИЙ — НИЧЕГО НЕ УДАЛЯЕМ
    # Извлекаем уровень
    level = "Info"
    lower_line = raw_line.lower()

    if re.search(r'\b(error|err)\b', lower_line):
        level = "Error"
    elif re.search(r'\b(warn|warning)\b', lower_line):
        level = "Warn"
    elif re.search(r'\b(debug)\b', lower_line):
        level = "Debug"
    elif re.search(r'\b(fatal|crit|critical)\b', lower_line):
        level = "Fatal"
    elif re.search(r'\b(info|information)\b', lower_line):
        level = "Info"

    transformed["l"] = level
    # Извлекаем PID
    pid = "1"
    pid_match = re.search(r'[<\(]([^>)]+)[>\)]', raw_line)
    if pid_match:
        pid = pid_match.group(1)
    else:
        parts = raw_line.split()
        if len(parts) >= 2:
            last_part = parts[-1]
            if re.match(r'^\d+\+\d+$', last_part) or last_part.isdigit():
                pid = last_part
    transformed["pid"] = pid
    # Извлекаем версию
    ver_match = re.search(r'(\d+\.\d+\.\d+(?:\.\d+)?)', raw_line)
    transformed["v"] = ver_match.group(1) if ver_match else "unknown"
    # Извлекаем логгер
    logger = extract_service_name_from_path(file_path)
    if "|" in raw_line:
        before_pipe = raw_line.split("|", 1)[0].strip()
        parts = before_pipe.split()
        if len(parts) >= 2:
            logger = parts[-1]
    transformed["lg"] = logger
    # Transaction name
    transformed["tn"] = extract_service_name_from_path(file_path)
    # Сохраняем ВСЁ в span.message
    clean_message = re.sub(r'<[^>]+>', '', raw_line) # Убираем <...> из сообщения
    clean_message = re.sub(r'\s+', ' ', clean_message).strip() # Нормализуем пробелы
    transformed["span"] = {
        "status": "Info",
        "name": "RawLogLine",
        "messageType": "Text",
        "message": clean_message
    }
    return transformed

def process_file_and_sort_chunk(args):
    file_path, temp_dir = args
    sorted_entries = []
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(4096)
            result = chardet.detect(raw_data)
            encoding = result['encoding'] or 'utf-8'
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            for line in f:
                entry = parse_log_line(line, file_path)
                if entry:
                    sorted_entries.append(entry)
        # Сортировка по 't'
        sorted_entries.sort(key=lambda x: x.get('t', ''))
        temp_file = os.path.join(temp_dir, f"chunk_{sanitize_filename(os.path.basename(file_path))}.tmp")
        with open(temp_file, 'w', encoding='utf-8') as tf:
            for entry in sorted_entries:
                tf.write(json.dumps(entry, ensure_ascii=False) + '\n')
        return temp_file
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")
        return None

def resource_path(relative_path):
    """Возвращает правильный путь к ресурсам, работает и в PyInstaller, и в обычном Python"""
    try:
        # PyInstaller создает временную папку _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

class LogMergerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("logmrgr v027.3")
        icon_path = resource_path("icon/icon.ico")
        self.root.iconbitmap(icon_path)
        self.root.geometry("250x350")
        self.root.resizable(False, False)
        self.root.configure(bg="#2E2E2E")
        self.loaded_files = []
        self.temp_dir = tempfile.mkdtemp()
        self.temp_files = []
        self.after_id = None
        self.progress_value = 0
        self.progress_lock = threading.Lock()
        self.total_lines = 0
        self.current_line = 0
        self.last_update_time = 0
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('Fixed.TButton', background='#4A4A4A', foreground='white', bordercolor='#555555', padding=5)
        self.style.map('Fixed.TButton', background=[('active', '#006400')], foreground=[('active', 'white')])
        # стиль обычной кнопки
        self.style.configure('Fixed.TButton',
                             background='#4A4A4A', foreground='white',
                             bordercolor='#555555', padding=5)
        self.style.map('Fixed.TButton',
                       background=[('active', '#006400')],
                       foreground=[('active', 'white')])
        # стиль подсвеченной кнопки
        self.style.configure('Highlight.TButton',
                             background='#228B22', foreground='white',
                             bordercolor='#00FF00', padding=5)
        self.style.map('Highlight.TButton',
                       background=[('active', '#32CD32')],
                       foreground=[('active', 'white')])

        self.main_frame = tk.Frame(root, bg="#2E2E2E")
        self.main_frame.pack(expand=True)
        tk.Frame(self.main_frame, bg="#2E2E2E", height=10).pack()
        button_width = 25  # одинаковая ширина
        self.load_button = ttk.Button(self.main_frame, text="Загрузить файлы 📄", command=self.load_logs, style='Fixed.TButton', width=button_width)
        self.load_button.pack(fill='x', pady=5, padx=15)
        self.load_folder_button = ttk.Button(self.main_frame, text="Загрузить папку 📂", command=self.load_folder, style='Fixed.TButton', width=button_width)
        self.load_folder_button.pack(fill='x', pady=5, padx=15)
        self.merge_button = ttk.Button(self.main_frame, text="Соединить логи 🧩", command=self.start_merge_logs, style='Fixed.TButton', width=button_width)
        self.merge_button.pack(fill='x', pady=5, padx=15)
        self.save_button = ttk.Button(self.main_frame, text="Сохранить всё 💾", command=self.save_logs, state='disabled', style='Fixed.TButton', width=button_width)
        self.save_button.pack(fill='x', pady=5, padx=15)
        self.open_folder_button = ttk.Button(self.main_frame, text="Открыть папку 📁", command=self.open_folder, state='disabled', style='Fixed.TButton', width=button_width)
        self.open_folder_button.pack(fill='x', pady=5, padx=15)
        self.progress_label = tk.Label(self.main_frame, text="Загрузите логи", bg="#2E2E2E", fg="white", font=("Arial", 9))
        self.progress_label.pack(pady=2)
        self.animation_label = tk.Label(self.main_frame, text="", bg="#2E2E2E", fg="#00FF00", font=("Courier", 10, "bold"))
        self.animation_label.pack(pady=2)
        self.progress_bar = ttk.Progressbar(
            self.main_frame,
            orient='horizontal',
            length=200,
            mode='determinate',
            style="Green.Horizontal.TProgressbar"
        )
        self.progress_bar.pack(pady=5)
        self.animation_frames = ["|", "/", "-", "\\"]
        self.animation_index = 0
        self.is_animating = False
        self.lines_processed = 0
        self.saved_file_path = None
        # стиль прогресс-бара (зелёный)
        self.style.configure(
            "Green.Horizontal.TProgressbar",
            troughcolor="#2E2E2E",   # фон канавки (тёмный серый)
            background="#00FF00",   # основной зелёный
            bordercolor="#2E2E2E",
            lightcolor="#33FF33",   # подсветка сверху
            darkcolor="#009900"     # затемнение снизу
        )
        self.highlight_step("load")

    def highlight_step(self, step):
        """Подсвечивает кнопку в зависимости от этапа работы"""
        # сбрасываем все кнопки в обычный стиль
        for btn in [self.load_button, self.load_folder_button,
                    self.merge_button, self.save_button, self.open_folder_button]:
            btn.configure(style="Fixed.TButton")
        if step == "load":  # ожидаем загрузку файлов
            self.load_button.configure(style="Highlight.TButton")
            self.load_folder_button.configure(style="Highlight.TButton")
        elif step == "merge":  # готовы соединять
            self.merge_button.configure(style="Highlight.TButton")
        elif step == "save":  # готовы сохранять
            self.save_button.configure(style="Highlight.TButton")
        elif step == "open":  # всё готово, можно открыть папку
            self.open_folder_button.configure(style="Highlight.TButton")

    def update_progress(self, start_time, progress=0, bytes_processed=0, lines_processed=None):
        current_time = time.time()
        if current_time - self.last_update_time < 0.2:
            return
        with self.progress_lock:
            elapsed = time.time() - start_time
            # memory = psutil.Process().memory_info().rss / 1024 / 1024
            self.progress_value = min(progress, 100)
            self.progress_bar['value'] = self.progress_value
            if bytes_processed > 0:
                mb_processed = bytes_processed / (1024 * 1024)
                self.progress_label.config(text=f"⏱ {elapsed:.1f}с | 📦 {mb_processed:.1f}МБ")
            elif lines_processed is not None:
                self.progress_label.config(text=f"⏱ {elapsed:.1f}с | 📝 {lines_processed} строк")
            else:
                self.progress_label.config(text=f"⏱ {elapsed:.1f}с")
            self.last_update_time = current_time
            try:
                self.root.update_idletasks()
            except:
                pass

    def start_animation(self):
        if not self.is_animating:
            self.is_animating = True
            self.animate()

    def animate(self):
        if self.is_animating:
            self.animation_label.config(text=f"🚀 Работа в процессе {self.animation_frames[self.animation_index]}")
            self.animation_index = (self.animation_index + 1) % len(self.animation_frames)
            self.after_id = self.root.after(150, self.animate)

    def stop_animation(self):
        if self.after_id:
            self.root.after_cancel(self.after_id)
            self.after_id = None
        self.is_animating = False
        self.animation_label.config(text="")
        # Не очищаем progress_label здесь, чтобы сохранить информацию

    def load_logs(self):
        files = filedialog.askopenfilenames(
            title="Выберите .log файлы", 
            filetypes=[("Log files", "*.log *.json *.ndjson")]
        )
        if files:
            self.loaded_files.extend(list(files))
            self.progress_label.config(text=f"Загружено {len(self.loaded_files)} файлов")
        self.highlight_step("merge")

    def load_folder(self):
        folder = filedialog.askdirectory(title="Выберите папку")
        if folder:
            log_files = []
            for root_dir, _, files in os.walk(folder):
                for file in files:
                    if file.endswith((".log", ".json", ".ndjson")):
                        log_files.append(os.path.join(root_dir, file))
            if log_files:
                self.loaded_files.extend(log_files)
                self.progress_label.config(text=f"Загружено {len(self.loaded_files)} файлов")
            else:
                self.progress_label.config(text="Нет .log, .json или .ndjson файлов")
        self.highlight_step("merge")

    def start_merge_logs(self):
        if not self.loaded_files:
            messagebox.showerror("Ошибка", "Сначала загрузите файлы.")
            return
        self.merge_button.config(state='disabled')
        self.start_animation()
        start_time = time.time()
        threading.Thread(target=self.merge_logs_task, args=(start_time,), daemon=True).start()

    def merge_logs_task(self, start_time):
        self.temp_files = []
        self.lines_processed = 0
        total_files = len(self.loaded_files)  # всего файлов
        try:
            with Pool(cpu_count()) as pool:
                args = [(f, self.temp_dir) for f in self.loaded_files]
                for i, temp_file in enumerate(pool.imap_unordered(process_file_and_sort_chunk, args), start=1):
                    if temp_file:
                        self.temp_files.append(temp_file)
                        # Подсчет строк в обработанном файле
                        try:
                            with open(temp_file, 'r', encoding='utf-8') as tf:
                                lines_count = sum(1 for _ in tf)
                                self.lines_processed += lines_count
                        except Exception:
                            pass

                    # вычисляем прогресс (% от числа файлов)
                    percent = (i / total_files) * 100
                    self.root.after(
                        0,
                        lambda p=percent, lp=self.lines_processed: 
                            self.update_progress(start_time, progress=p, lines_processed=lp)
                    )
        except Exception as e:
            self.root.after(0, lambda e=e: self.handle_merge_error(e, start_time))
            return

        self.root.after(0, lambda: self.finish_merge_logs(start_time))


    def handle_merge_error(self, error, start_time):
        self.stop_animation()
        self.merge_button.config(state='normal')
        self.progress_label.config(text=f"Ошибка: {error}")
        self.progress_bar['value'] = 0

    def finish_merge_logs(self, start_time):
        self.stop_animation()
        elapsed = time.time() - start_time
        self.progress_label.config(text=f"✅ {self.lines_processed} строк за {elapsed:.1f} сек")
        self.progress_bar['value'] = 100
        self.merge_button.config(state='normal')
        self.save_button.config(state='normal' if self.temp_files else 'disabled')
        self.highlight_step("save")

    def save_logs(self):
        if not self.temp_files:
            messagebox.showerror("Ошибка", "Сначала соедините логи.")
            return
        self.save_button.config(state='disabled')
        self.start_animation()
        start_time = time.time()
        threading.Thread(target=self.save_final_file_thread, args=(start_time,), daemon=True).start()

    def save_final_file_thread(self, start_time):
        current_date = datetime.now().strftime("%Y-%m-%d")
        default_filename = f"mrgd({current_date}).log"
        save_path = filedialog.asksaveasfilename(
            title="Сохранить как",
            defaultextension=".log",
            initialfile=default_filename
        )
        if not save_path:
            self.root.after(0, self.stop_animation)
            self.root.after(0, lambda: self.save_button.config(state='normal'))
            return
        self.saved_file_path = save_path
        try:
            # Подсчет общего количества строк
            self.total_lines = 0
            for f in self.temp_files:
                with open(f, 'r', encoding='utf-8') as temp_f:
                    self.total_lines += sum(1 for line in temp_f if line.strip())
            
            # Открытие итераторов для всех временных файлов
            iterators = []
            for f in self.temp_files:
                try:
                    it = (json.loads(line) for line in open(f, 'r', encoding='utf-8') if line.strip())
                    iterators.append(it)
                except Exception as e:
                    logging.warning(f"Cannot read temp file {f}: {e}")
            
            # Запись отсортированного результата
            bytes_written = 0
            with open(save_path, 'w', encoding='utf-8') as final_file:
                self.current_line = 0
                for entry in heapq.merge(*iterators, key=lambda x: x.get('t', '')):
                    line = json.dumps(entry, ensure_ascii=False) + '\n'
                    final_file.write(line)
                    bytes_written += len(line.encode('utf-8'))
                    self.current_line += 1
                    if self.current_line % 1000 == 0 or self.current_line == self.total_lines:
                        percent = (self.current_line / self.total_lines) * 100
                        self.root.after(0, lambda b=bytes_written, p=percent: 
                            self.update_progress(start_time, progress=p, bytes_processed=b))
            self.root.after(0, lambda: self.finish_save_logs(start_time, save_path))
        except Exception as e:
            logging.error(f"Error saving final file: {e}")
            self.root.after(0, lambda e=e: self.handle_save_error(e))

    def handle_save_error(self, error):
        self.stop_animation()
        self.save_button.config(state='normal')
        self.progress_label.config(text=f"Ошибка сохранения: {error}")

    def finish_save_logs(self, start_time, save_path):
        self.stop_animation()
        elapsed = time.time() - start_time
        # Получаем реальный размер файла
        try:
            file_size = os.path.getsize(save_path)
            mb_written = file_size / (1024 * 1024)
        except:
            mb_written = 0
        self.progress_label.config(text=f"✅ Сохранено {mb_written:.1f} МБ за {elapsed:.1f} сек")
        self.progress_bar['value'] = 100
        self.save_button.config(state='normal')
        self.open_folder_button.config(state='normal')
        self.highlight_step("open")

    def open_folder(self):
        if self.saved_file_path and os.path.exists(self.saved_file_path):
            folder_path = os.path.dirname(self.saved_file_path)
            try:
                if os.name == 'nt':  # Windows
                    os.startfile(folder_path)
                elif os.name == 'posix':  # macOS или Linux
                    os.system(f'open "{folder_path}"' if 'darwin' in os.sys.platform else f'xdg-open "{folder_path}"')
            except Exception as e:
                messagebox.showerror("Ошибка", f"Не удалось открыть папку: {e}")
        else:
            messagebox.showwarning("Предупреждение", "Файл не найден.")

    def __del__(self):
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except Exception as e:
            logging.error(f"Error removing temp dir: {e}")

if __name__ == "__main__":
    freeze_support()
    root = tk.Tk()
    app = LogMergerApp(root)
    root.mainloop()