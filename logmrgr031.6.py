import tkinter as tk
import heapq
from tkinter import filedialog, messagebox, ttk
import json
import os
import sys
import re
import threading
import tempfile
import shutil
import time
import logging
from datetime import datetime
from dateutil.parser import parse
import chardet
from multiprocessing import Pool, cpu_count
from functools import partial
import pytz
import hashlib

# Для поддержки multiprocessing на Windows
from multiprocessing import freeze_support

# Кэш для парсинга дат — ускорение (но для эталонных не используем)
DATE_PARSE_CACHE = {}

def cached_parse(dt_str):
    if dt_str not in DATE_PARSE_CACHE:
        try:
            # Обработка специфичных форматов времени
            if ',' in dt_str and '.' not in dt_str:
                dt_str = dt_str.replace(',', '.')
            if dt_str.endswith("Z"):
                dt_str = dt_str.replace("Z", "+00:00")
            dt = parse(dt_str)
            if dt.tzinfo is None:
                dt = pytz.utc.localize(dt)
            # Округление микросекунд до 3 знаков (для .148 из .1482032)
            dt = dt.replace(microsecond=(dt.microsecond // 1000) * 1000)
            DATE_PARSE_CACHE[dt_str] = dt
        except Exception as e:
            logging.warning(f"Failed to cache parse {dt_str}: {e}")
            dt = datetime.now(pytz.utc)  # fallback на текущее UTC время
            DATE_PARSE_CACHE[dt_str] = dt
    return DATE_PARSE_CACHE[dt_str]

def transform_log(original_json_str: str) -> str:
    """
    Модульная функция для преобразования одного JSON-лога.
    Использует transform_generic_json для ECS-формата.
    """
    try:
        entry = json.loads(original_json_str)
        if is_etalon_format(entry):
            return json.dumps(entry, ensure_ascii=False)
        transformed = transform_generic_json(entry, "")  # file_path не нужен для одиночного
        return json.dumps(transformed, ensure_ascii=False)
    except json.JSONDecodeError as e:
        logging.warning(f"Invalid JSON: {e}")
        return json.dumps({"t": format_timestamp(datetime.now(pytz.utc)), "mt": original_json_str, "l": "Error"}, ensure_ascii=False)

def sanitize_filename(filename):
    """Заменяет недопустимые символы в имени файла на подчеркивания."""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename

def get_unique_filename(temp_dir, base_name):
    """Генерирует уникальное имя файла на основе хэша, чтобы избежать коллизий."""
    # Хэшируем base_name для уникальности
    hash_obj = hashlib.md5(base_name.encode())
    short_hash = hash_obj.hexdigest()[:8]
    unique_name = f"chunk_{short_hash}_{sanitize_filename(os.path.basename(base_name))}.tmp"
    return os.path.join(temp_dir, unique_name)

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
    """Форматирует дату в эталонный формат YYYY-MM-DD HH:MM:SS.mmm+HH:MM."""
    # Убедимся, что dt - datetime с таймзоной
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    # Форматируем как YYYY-MM-DD HH:MM:SS.mmm+HHMM
    t_formatted = dt.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3] + dt.strftime("%z")
    # Добавляем двоеточие в таймзону: +HHMM -> +HH:MM
    if len(t_formatted) == 28: # 23 (база) + 5 (HHMM)
        t_formatted = t_formatted[:-2] + ":" + t_formatted[-2:]
    return t_formatted

def is_etalon_format(entry):
    """
    Проверяет, соответствует ли запись эталонному формату.
    Проверяет только обязательные поля и формат времени 't'.
    """
    if not isinstance(entry, dict):
        return False

    # Обязательные поля эталона
    required_keys = {'t', 'pid', 'l', 'lg', 'tn', 'v'}
    # Проверяем, что все обязательные ключи присутствуют
    if not required_keys.issubset(entry.keys()):
        return False

    # Проверяем, что 't' - строка с похожим форматом времени
    t_val = entry.get('t')
    if not isinstance(t_val, str) or not re.match(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d{3}[+-]\d{2}:\d{2}$', t_val):
        return False

    # Другие проверки можно добавить, но для быстрой проверки хватит и этих
    return True

def parse_log_line(line, file_path):
    line = line.strip()
    if not line:
        return None

    # --- Проверка на JSON ---
    if line.startswith('{'):
        try:
            entry = json.loads(line)
            # --- Проверка на эталонный формат ---
            if is_etalon_format(entry):
                # Возвращаем копию идеальной строки БЕЗ дополнительного парсинга времени
                # (поскольку regex уже подтвердил правильный формат 't')
                return dict(entry)
            # --- Конец проверки ---
            # Если не эталон, обрабатываем как обычно
            return transform_generic_json(entry, file_path)
        except json.JSONDecodeError:
            # невалидный JSON — дальше пробуем текстовые форматы
            pass

    # --- Текстовые форматы ---
    procrun_pattern = re.compile(r'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[info\]', re.IGNORECASE)
    elasticsearch_pattern = re.compile(
        r'.*\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d{3})\]\[([A-Z]+)\]\[.*?\]',
        re.IGNORECASE
    )
    linux_syslog_pattern = re.compile(
        r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}\+\d{2}:\d{2} [a-zA-Z0-9_-]+ \w+\[\d+\]:'
    )

    try:
        if procrun_pattern.match(line):
            return transform_procrun_log(line, file_path)
        if elasticsearch_pattern.match(line):
            return transform_elasticsearch_log(line, file_path)
        if linux_syslog_pattern.match(line):
            return transform_linux_syslog_to_etalon(line, file_path)
    except Exception as e:
        logging.warning(f"Failed to parse line in {file_path}: {line[:200]}... Error: {e}")

    return create_minimal_entry(line, file_path)

def transform_generic_json(entry, file_path):
    """
    Универсальный JSON-трансформер.
    НЕ проверяет эталонный формат - это делает parse_log_line.
    Только нормализует. Улучшено: сохранение ID и потерянных полей в args.
    """
    if not isinstance(entry, dict):
        return create_minimal_entry(json.dumps(entry), file_path)

    # --- Нормализация не-эталонных записей ---
    standard_out = {"t", "pid", "tr", "l", "lg", "mt", "tn", "v", "args", "ex", "trace_id", "transaction_id"}
    original = entry
    transformed = {}

    # 1. Время
    dt_candidates = ["t", "@timestamp", "timestamp", "date", "time"]
    dt_str = None
    for k in dt_candidates:
        if k in original and original.get(k):
            dt_str = original.get(k)
            break
    if dt_str:
        try:
            s = str(dt_str)
            transformed["t"] = format_timestamp(cached_parse(s))
        except Exception as e:
            logging.warning(f"Failed to parse timestamp {dt_str}: {e}")
            transformed["t"] = format_timestamp(datetime.now(pytz.utc))
    else:
        transformed["t"] = format_timestamp(datetime.now(pytz.utc))

    # 2. Уровень
    try:
        level = None
        if isinstance(original.get("log"), dict):
            level = original["log"].get("level")
        if not level and "level" in original:
            level = original.get("level")
        if not level and "log.level" in original:
            level = original.get("log.level")
        if not level:
            s = json.dumps(original).lower()
            if '"level":"error"' in s or '[error]' in s:
                level = "Error"
            elif '"level":"warn"' in s or '[warn]' in s or '[warning]' in s:
                level = "Warn"
            elif '"level":"debug"' in s or '[debug]' in s:
                level = "Debug"
            elif '"level":"fatal"' in s or '[fatal]' in s:
                level = "Fatal"
            elif '"level":"info"' in s or '[info]' in s:
                level = "Information"
            else:
                level = "Information"
        full_level = str(level)
        short_level = full_level if full_level != "Information" else "Info"
        transformed["l"] = short_level
    except Exception as e:
        logging.warning(f"Failed to extract level: {e}")
        transformed["l"] = "Info"
        full_level = "Information"

    # 3. PID
    try:
        if "pid" in original and original["pid"]:
            transformed["pid"] = str(original["pid"])
        else:
            pid = None
            if isinstance(original.get("process"), dict):
                pid = original["process"].get("pid") or original["process"].get("id")
            if not pid:
                pid = original.get("process.id") or original.get("process.pid")
            transformed["pid"] = str(pid) if pid is not None else "1"
    except Exception as e:
        logging.warning(f"Failed to extract PID: {e}")
        transformed["pid"] = "1"

    # 4. Trace ID (критично для отладки)
    try:
        if "trace" in original and isinstance(original["trace"], dict) and "id" in original["trace"]:
            transformed["trace_id"] = original["trace"]["id"]
        elif "tr" in original and original["tr"]:
            transformed["trace_id"] = original["tr"]
    except Exception as e:
        logging.warning(f"Failed to extract trace_id: {e}")

    # 5. Transaction ID (критично для отладки)
    try:
        if "transaction" in original and isinstance(original["transaction"], dict) and "id" in original["transaction"]:
            transformed["transaction_id"] = original["transaction"]["id"]
    except Exception as e:
        logging.warning(f"Failed to extract transaction_id: {e}")

    # 6. Logger
    try:
        if "lg" in original and original["lg"]:
            transformed["lg"] = original["lg"]
        else:
            logger = extract_logger(original)
            transformed["lg"] = logger if logger else extract_service_name_from_path(file_path)
    except Exception as e:
        logging.warning(f"Failed to extract logger: {e}")
        transformed["lg"] = extract_service_name_from_path(file_path)

    # 7. Message
    try:
        if "mt" in original and original["mt"]:
            transformed["mt"] = original["mt"]
        else:
            transformed["mt"] = original.get("message") or original.get("msg", "")
    except Exception as e:
        logging.warning(f"Failed to extract message: {e}")
        transformed["mt"] = ""

    # 8. Tenant
    try:
        if "tn" in original and original["tn"]:
            transformed["tn"] = original["tn"]
        else:
            tenant = extract_tenant(original)
            transformed["tn"] = tenant if tenant else extract_service_name_from_path(file_path)
    except Exception as e:
        logging.warning(f"Failed to extract tenant: {e}")
        transformed["tn"] = extract_service_name_from_path(file_path)

    # 9. Version
    try:
        if "v" in original and original["v"]:
            transformed["v"] = original["v"]
        else:
            if isinstance(original.get("service"), dict) and original["service"].get("version"):
                transformed["v"] = original["service"]["version"]
            else:
                msg = transformed["mt"] if "mt" in transformed else str(original)
                transformed["v"] = extract_version_from_text(msg)
    except Exception as e:
        logging.warning(f"Failed to extract version: {e}")
        transformed["v"] = "unknown"

    # 10. Span
    try:
        if "span" in original:
            transformed["span"] = original["span"]
    except Exception as e:
        logging.warning(f"Failed to extract span: {e}")

    # 11. Errors
    try:
        error_fields = ["exception", "error", "err", "stacktrace", "stack_trace"]
        ex_dict = {}
        for fld in error_fields:
            if fld in original:
                ex_dict[fld] = original[fld]
        if ex_dict:
            transformed["ex"] = ex_dict
    except Exception as e:
        logging.warning(f"Failed to extract errors: {e}")

    # 12. Args - собираем оставшиеся поля + восстановленные потерянные
    args = {}
    try:
        # Оставшиеся поля (исключая стандартные)
        for k, v in original.items():
            if k in standard_out or k in ["log", "process", "service", "host", "trace", "transaction", "logger", "component", "app_id", "cluster.name", "node.name"]:
                continue
            args[k] = v

        # Восстановление потерянных полей в args
        # Trace (полностью, id уже вынесен)
        if "trace" in original:
            args["trace"] = original["trace"]

        # Transaction (полностью, id уже вынесен)
        if "transaction" in original:
            args["transaction"] = original["transaction"]

        # Host.user
        if "host" in original and isinstance(original["host"], dict) and "user" in original["host"] and isinstance(original["host"]["user"], dict):
            if "host" not in args:
                args["host"] = {}
            args["host"]["user"] = original["host"]["user"]

        # Log (с logger, original, level)
        if "log" in original:
            log_data = original["log"].copy()
            log_data["level"] = full_level  # Полная версия level
            args["log"] = log_data

        # Process (с thread.id, name, executable; pid уже вынесен)
        if "process" in original:
            process = original["process"].copy()
            process.pop("pid", None)  # Не дублируем
            args["process"] = process

        # Удаляем дубликаты времени из args
        args = remove_time_duplicates_from_args(args, transformed.get("t"))

        if args:
            transformed["args"] = args
    except Exception as e:
        logging.warning(f"Failed to build args: {e}")

    return transformed

def transform_ecs(entry):
    transformed = {}

    # --- 1. Время ---
    dt_str = entry.pop("@timestamp", None)
    if dt_str:
        try:
            dt = cached_parse(dt_str)
            transformed["t"] = format_timestamp(dt)
        except Exception:
            transformed["t"] = format_timestamp(datetime.now(pytz.utc))
    else:
        transformed["t"] = format_timestamp(datetime.now(pytz.utc))

    # --- 2. Уровень ---
    log_info = entry.pop("log", {})
    level = log_info.get("level", "information").title()
    level = (
        level.replace("Information", "Info")
             .replace("Warning", "Warn")
             .replace("Critical", "Fatal")
    )
    transformed["l"] = level

    # --- 3. Сервис и логгер ---
    service = entry.pop("service", {})
    service_name = service.get("name", "UnknownService")
    transformed["lg"] = log_info.get("logger", service_name)

    # --- 4. Процесс ---
    process = entry.pop("process", {})
    pid = process.get("pid", "1")
    transformed["pid"] = str(pid)

    # --- 5. Сообщение ---
    message = entry.pop("message", "")
    transformed["mt"] = message

    # --- 6. Аргументы (оставшееся содержимое) ---
    transformed["args"] = {}
    for key, value in entry.items():
        if key not in ["labels", "ecs", "host"]:
            transformed["args"][key] = value

    if "host" in entry:
        transformed["args"]["host"] = entry["host"]

    # --- 7. Host и оригинальный лог ---
    if "original" in log_info:
        transformed["args"]["original_log_info"] = log_info["original"]

    # --- 8. Transaction name + версия ---
    transformed["tn"] = service_name
    transformed["v"] = extract_version_from_text(message)

    return transformed

def transform_elasticsearch_log(entry):
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
    """Создаёт запись, сохраняя строку только если она не была JSON или не распознана. Ищет истинное время события внутри строки. Убирает `_raw_line` если возможно."""
    # Проверяем, является ли строка валидным JSON
    stripped_line = line.strip()
    is_json = False
    original_json_obj = None
    if stripped_line.startswith('{'):
        try:
            original_json_obj = json.loads(stripped_line)
            is_json = True
        except json.JSONDecodeError:
            pass # Это не валидный JSON

    transformed = {}

    raw_line = line.strip()
    # Шаблоны для поиска времени СОБЫТИЯ (не времени записи лога)
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
        start_time_match = re.search(r'^\s*(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,})?)', raw_line)
        if start_time_match:
            dt_str = start_time_match.group(1).replace(',', '.')
            try:
                dt = cached_parse(dt_str)
                t_formatted = format_timestamp(dt)
                transformed["t"] = t_formatted
            except Exception:
                transformed["t"] = format_timestamp(datetime.now(pytz.utc))
        else:
            transformed["t"] = format_timestamp(datetime.now(pytz.utc))

    # ➤➤➤ ВСЁ ОСТАЛЬНОЕ — БЕЗ ИЗМЕНЕНИЙ — НИЧЕГО НЕ УДАЛЯЕМ
    # Извлекаем уровень
    level = "Info"
    lower_line = raw_line.lower()
    if re.search(r'\b(error|err|не удалось|исключение)\b', lower_line):
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

    # Парсинг метаданных для текстовых логов
    un_match = re.search(r'UserName:\s*(.+?)(?:\n|$)', raw_line, re.IGNORECASE)
    if un_match:
        transformed["un"] = un_match.group(1).strip()

    tr_match = re.search(r'Trace:\s*(.+?)(?:\n|$)', raw_line, re.IGNORECASE)
    if tr_match:
        transformed["tr"] = tr_match.group(1).strip()

    # --- ИЗМЕНЕНИЕ ---
    # Если строка была JSON, но не распознана, и не была преобразована в transform_generic_json (например, ошибка),
    # то добавляем её как сообщение или в args, но НЕ добавляем _raw_line.
    # Если строка была просто текстом, добавляем его в span.message.
    if is_json and original_json_obj:
         # Считаем, что JSON-строка была "обработана" как структурированная информация
         # Помещаем оригинальный JSON-объект в args под ключом _original_json, если он не пустой
         # Это позволяет сохранить исходные данные, но не дублировать их в _raw_line
         # Однако, чтобы не увеличивать размер ещё больше, и если основные поля уже извлечены,
         # можно не добавлять _original_json. Оставим на усмотрение.
         # Для уменьшения размера: НЕ добавляем _raw_line и _original_json в этом случае.
         # Сообщение можно извлечь из JSON, если оно было.
         # Но в минимальной записи оно может быть не представлено явно.
         # Просто не добавляем _raw_line.
         pass # Просто не добавляем _raw_line
    else:
        # Это была текстовая строка, которую мы не смогли распознать как специфический формат.
        # Раньше добавляли _raw_line, теперь добавим в span.message.
        clean_message = re.sub(r'<[^>]+>', '', raw_line).strip()  # Только удаляем теги и trim краёв, БЕЗ сжатия пробелов
        transformed["span"] = {
            "status": "Info",
            "name": "RawLogLine",
            "messageType": "Text",
            "message": clean_message
        }

    return transformed

def clean_nested_duplicates(nested_dict, transformed_entry):
    """Рекурсивно удаляет дубликаты из вложенного словаря на основе transformed_entry."""
    if not isinstance(nested_dict, dict):
        return nested_dict

    cleaned = {}
    normalized_time = transformed_entry.get("t")

    for k, v in nested_dict.items():
        # Проверяем, является ли текущий ключ дубликатом верхнего уровня
        if k in {"@timestamp", "timestamp", "time", "date"}:
            if normalized_time:
                try:
                    sval = str(v)
                    if sval.endswith("Z"):
                        sval = sval.replace("Z", "+00:00")
                    dt2 = cached_parse(sval)
                    if format_timestamp(dt2) == normalized_time:
                        continue # Пропускаем дубликат времени
                except Exception:
                    pass # Если не распозналось, всё равно добавим
        # Проверяем, является ли текущий ключ дубликатом уровня l, pid, mt, tn, v
        elif k == "level" and transformed_entry.get("l") and str(v).title() == transformed_entry["l"]:
            continue
        elif k == "pid" and transformed_entry.get("pid") and str(v) == transformed_entry["pid"]:
            continue
        elif k == "message" and transformed_entry.get("mt") and v == transformed_entry["mt"]:
            continue
        elif k == "name" and transformed_entry.get("tn") and v == transformed_entry["tn"]:
            continue
        elif k == "version" and transformed_entry.get("v") and v == transformed_entry["v"]:
            continue
        # Рекурсивно обрабатываем вложенные словари
        elif isinstance(v, dict):
            cleaned_v = clean_nested_duplicates(v, transformed_entry)
            if cleaned_v: # Добавляем только непустые словари
                cleaned[k] = cleaned_v
        # Для вложенных списков, проверим элементы, если они словари
        elif isinstance(v, list):
            cleaned_list = []
            for item in v:
                if isinstance(item, dict):
                     cleaned_item = clean_nested_duplicates(item, transformed_entry)
                     if cleaned_item:
                         cleaned_list.append(cleaned_item)
                else:
                     cleaned_list.append(item)
            if cleaned_list: # Добавляем только непустые списки
                cleaned[k] = cleaned_list
        else:
            cleaned[k] = v

    return cleaned

def remove_time_duplicates_from_args(args_dict, normalized_time_str):
    """Рекурсивно удаляет дубликаты времени из словаря args."""
    if not normalized_time_str or not isinstance(args_dict, dict):
        return args_dict

    def _clean_time_recursive(d):
        if isinstance(d, dict):
            new_d = {}
            for k, v in d.items():
                if k in {"@timestamp", "timestamp", "time", "date"}:
                    if isinstance(v, str):
                        try:
                            sval = v
                            if sval.endswith("Z"):
                                sval = sval.replace("Z", "+00:00")
                            dt2 = cached_parse(sval)
                            if format_timestamp(dt2) == normalized_time_str:
                                continue # Пропускаем дубликат
                        except Exception:
                            pass # Не распознано, добавим
                elif isinstance(v, dict):
                    new_d[k] = _clean_time_recursive(v)
                elif isinstance(v, list):
                    new_d[k] = [_clean_time_recursive(item) if isinstance(item, dict) else item for item in v]
                else:
                    new_d[k] = v
            return new_d
        return d

    return _clean_time_recursive(args_dict)

def process_file_and_sort_chunk(args):
    i, file_path, temp_dir = args
    sorted_entries = []
    detected_encoding = None
    try:
        # --- 1. Определение кодировки ---
        with open(file_path, 'rb') as f:
            raw_data = f.read(8192)  # Читаем больше данных для точности
            result = chardet.detect(raw_data)
            chardet_encoding = result['encoding']
            confidence = result['confidence']
            logging.info(f"Chardet: {chardet_encoding} (conf: {confidence:.2f}) for {file_path}")

        # Кандидаты: сначала chardet, потом cp1251, utf-8-sig, utf-8
        encodings_to_try = []
        if chardet_encoding and confidence > 0.6:
            encodings_to_try.append(chardet_encoding)
        encodings_to_try.extend(['cp1251', 'utf-8-sig', 'utf-8'])

        # Убираем дубликаты, сохраняя порядок
        seen = set()
        encodings_to_try = [e for e in encodings_to_try if e and not (e in seen or seen.add(e))]

        content_lines = None
        for enc in encodings_to_try:
            try:
                with open(file_path, 'r', encoding=enc, errors='strict') as f:
                    content_lines = f.readlines()
                detected_encoding = enc
                logging.info(f"Successfully read {file_path} with encoding: {enc}")
                break
            except (UnicodeDecodeError, LookupError) as e:
                logging.debug(f"Failed to read {file_path} with {enc}: {e}")
                continue

        if content_lines is None:
            # Последний шанс: читаем с errors='replace'
            logging.warning(f"Fallback to cp1251 with errors='replace' for {file_path}")
            with open(file_path, 'r', encoding='cp1251', errors='replace') as f:
                content_lines = f.readlines()
            detected_encoding = 'cp1251 (fallback)'

        # --- 2. Обработка строк ---
        for line in content_lines:
            entry = parse_log_line(line, file_path)
            if entry:
                sorted_entries.append(entry)

        # Сортировка по времени
        sorted_entries.sort(key=lambda x: x.get('t', ''))

        # --- 3. Запись во временный файл в UTF-8 ---
        temp_file = get_unique_filename(temp_dir, file_path)
        with open(temp_file, 'w', encoding='utf-8', errors='replace') as tf:
            for entry in sorted_entries:
                json_line = json.dumps(entry, ensure_ascii=False, indent=None)
                tf.write(json_line + '\n')

        return temp_file

    except Exception as e:
        logging.error(f"Critical error processing {file_path}: {e}", exc_info=True)
        return None

def resource_path(relative_path):
    """Возвращает правильный путь к ресурсам, работает и в PyInstaller, и в обычном Python"""
    try:
        # PyInstaller создает временную папку _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# Функция для активации тёмной темы title bar на Windows (если возможно)
def setup_windows_dark_titlebar(root):
    if os.name == 'nt':  # Windows
        try:
            import ctypes
            from ctypes import wintypes
            # Получаем handle окна
            hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
            # Устанавливаем DWMWA_USE_IMMERSIVE_DARK_MODE = 20 (Windows 10+)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(ctypes.c_int(1)), ctypes.sizeof(ctypes.c_int))
        except Exception:
            pass  # Если не удалось, игнорируем

class LogMergerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("logmrgr v031.6")
        icon_path = resource_path("icon/icon.ico")
        self.root.iconbitmap(icon_path)
        self.root.geometry("250x350")
        self.root.resizable(False, False)
        self.root.configure(bg="#2E2E2E")
        # Активируем тёмную тему для title bar на Windows
        setup_windows_dark_titlebar(root)
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
        # Используем 'clam' для кастомизации, но настраиваем под тёмную тему
        self.style.theme_use('clam')
        # Тёмная тема для всех элементов
        self.style.configure('TFrame', background='#2E2E2E')
        self.style.configure('TLabel', background='#2E2E2E', foreground='white', font=('Arial', 9))
        self.style.configure('Fixed.TButton', background='#4A4A4A', foreground='white', bordercolor='#555555', padding=5, focuscolor='none')
        self.style.map('Fixed.TButton', background=[('active', '#006400'), ('pressed', '#004d00')], foreground=[('active', 'white')])
        # стиль подсвеченной кнопки
        self.style.configure('Highlight.TButton',
                             background='#228B22', foreground='white',
                             bordercolor='#00FF00', padding=5)
        self.style.map('Highlight.TButton',
                       background=[('active', '#32CD32')],
                       foreground=[('active', 'white')])
        # Тёмная прогресс-бар
        self.style.configure(
            "Green.Horizontal.TProgressbar",
            troughcolor="#2E2E2E",   # фон канавки (тёмный серый)
            background="#00FF00",   # основной зелёный
            bordercolor="#2E2E2E",
            lightcolor="#33FF33",   # подсветка сверху
            darkcolor="#009900"     # затемнение снизу
        )
        self.style.configure('TNotebook', background='#2E2E2E')
        self.style.configure('TNotebook.Tab', background='#4A4A4A', foreground='white', padding=[10, 5])

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
                # Добавляем индекс для уникальности
                args = [(i, f, self.temp_dir) for i, f in enumerate(self.loaded_files)]
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
            with open(save_path, 'w', encoding='utf-8', errors='replace') as final_file:
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

# Version: 031.6

if __name__ == "__main__":
    freeze_support()
    root = tk.Tk()
    app = LogMergerApp(root)
    root.mainloop()