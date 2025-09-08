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
import psutil
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
    """Извлекает версию из текста вида [7.17.13] или elasticsearch-7.17.13.jar"""
    if not text:
        return "unknown"
    match = re.search(r'\[?(\d+\.\d+\.\d+(?:\.\d+)?)\]?', text)
    if match:
        return match.group(1)
    match = re.search(r'[-_]v?(\d+\.\d+\.\d+(?:\.\d+)?)', text)
    if match:
        return match.group(1)
    return "unknown"

def extract_service_name_from_path(file_path):
    """Извлекает имя сервиса из имени файла или пути."""
    filename = os.path.basename(file_path).lower()
    candidates = [
        'elasticsearch', 'kibana', 'logstash', 'nginx', 'apache', 'redis', 'postgres',
        'mysql', 'mongo', 'rabbitmq', 'kafka', 'zookeeper', 'traefik', 'haproxy',
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
            return transform_linux_syslog(line, file_path)
    except (json.JSONDecodeError, ValueError, Exception) as e:
        logging.warning(f"Failed to parse line in {file_path}: {line[:100]}... Error: {e}")

    return create_minimal_entry(line, file_path)

def transform_elasticsearch_json_log(entry):
    transformed = {}
    dt_str = entry.get("timestamp", "").replace(',', '.')
    try:
        dt = cached_parse(dt_str)
        transformed["t"] = dt.isoformat(timespec='milliseconds')
    except Exception:
        transformed["t"] = datetime.now(pytz.utc).isoformat(timespec='milliseconds')
    
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
        transformed["t"] = dt.isoformat(timespec='milliseconds')
    except Exception:
        transformed["t"] = datetime.now(pytz.utc).isoformat(timespec='milliseconds')
    
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
        transformed["t"] = dt.isoformat(timespec='milliseconds')
    except Exception:
        transformed["t"] = datetime.now(pytz.utc).isoformat(timespec='milliseconds')
    
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
            transformed["t"] = dt.isoformat(timespec='milliseconds')
        except Exception:
            transformed["t"] = datetime.now(pytz.utc).isoformat(timespec='milliseconds')
        
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
            transformed["t"] = dt.isoformat(timespec='milliseconds')
        except Exception:
            transformed["t"] = datetime.now(pytz.utc).isoformat(timespec='milliseconds')
        
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
    transformed = {}
    
    time_keys = ['t', '@timestamp', 'timestamp', 'date', 'time']
    dt_str = next((entry.get(k) for k in time_keys if k in entry), None)
    if dt_str:
        try:
            dt = cached_parse(dt_str)
            transformed["t"] = dt.isoformat(timespec='milliseconds')
        except Exception:
            transformed["t"] = datetime.now(pytz.utc).isoformat(timespec='milliseconds')
    else:
        transformed["t"] = datetime.now(pytz.utc).isoformat(timespec='milliseconds')
    
    pid = "1"
    if "process" in entry and isinstance(entry["process"], dict):
        pid = str(entry["process"].get("pid", "1"))
    elif "pid" in entry:
        pid = str(entry["pid"])
    transformed["pid"] = pid
    
    level = entry.get("log.level") or entry.get("level") or "Info"
    transformed["l"] = level.title().replace("Information", "Info").replace("Warning", "Warn").replace("Critical", "Fatal")
    
    service_name = extract_service_name_from_path(file_path)
    transformed["lg"] = entry.get("logger") or entry.get("component") or service_name
    
    message = entry.get("message", "")
    transformed["mt"] = message
    
    transformed["tn"] = entry.get("service") or entry.get("serviceName") or service_name
    transformed["v"] = entry.get("v", extract_version_from_text(message))
    
    transformed["args"] = {}
    excluded_keys = {"t", "@timestamp", "timestamp", "date", "time", "level", "log.level", "logger", "component", "message", "service", "serviceName", "process", "pid", "tn", "v"}
    for key, value in entry.items():
        if key not in excluded_keys:
            transformed["args"][key] = value

    return transformed

def create_minimal_entry(line, file_path):
    transformed = {}
    match = re.search(r'^\s*(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,})?)', line)
    if match:
        dt_str = match.group(1).replace(',', '.')
        try:
            dt = cached_parse(dt_str)
            transformed["t"] = dt.isoformat(timespec='milliseconds')
        except Exception:
            transformed["t"] = datetime.now(pytz.utc).isoformat(timespec='milliseconds')
    else:
        transformed["t"] = datetime.now(pytz.utc).isoformat(timespec='milliseconds')
    
    service_name = extract_service_name_from_path(file_path)
    transformed["pid"] = "1"
    transformed["l"] = "Info"
    transformed["lg"] = service_name
    transformed["mt"] = line.strip()
    transformed["tn"] = service_name
    transformed["v"] = extract_version_from_text(line)
    transformed["args"] = {}
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

class LogMergerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("logmrgr v25.024.8")
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
        self.style.configure('TButton', background='#4A4A4A', foreground='white', bordercolor='#555555', padding=5)
        self.style.map('TButton', background=[('active', '#006400')], foreground=[('active', 'white')])
        self.style.configure('TProgressbar', background='#006400', troughcolor='#2E2E2E')
        self.main_frame = tk.Frame(root, bg="#2E2E2E")
        self.main_frame.pack(expand=True)
        tk.Frame(self.main_frame, bg="#2E2E2E", height=10).pack()
        self.load_button = ttk.Button(self.main_frame, text="Загрузить файлы 📄", command=self.load_logs)
        self.load_button.pack(fill='x', pady=5, padx=15)
        self.load_folder_button = ttk.Button(self.main_frame, text="Загрузить папку 📂", command=self.load_folder)
        self.load_folder_button.pack(fill='x', pady=5, padx=15)
        self.merge_button = ttk.Button(self.main_frame, text="Соединить логи 🧩", command=self.start_merge_logs)
        self.merge_button.pack(fill='x', pady=5, padx=15)
        self.save_button = ttk.Button(self.main_frame, text="Сохранить всё 💾", command=self.start_save_logs, state='disabled')
        self.save_button.pack(fill='x', pady=5, padx=15)
        self.progress_label = tk.Label(self.main_frame, text="", bg="#2E2E2E", fg="white", font=("Arial", 9))
        self.progress_label.pack(pady=2)
        self.animation_label = tk.Label(self.main_frame, text="", bg="#2E2E2E", fg="#00FF00", font=("Courier", 10, "bold"))
        self.animation_label.pack(pady=2)
        self.progress_bar = ttk.Progressbar(self.main_frame, orient='horizontal', length=200, mode='determinate')
        self.progress_bar.pack(pady=5)
        self.animation_frames = ["|", "/", "-", "\\"]
        self.animation_index = 0
        self.is_animating = False

    def update_progress(self, start_time, progress=0):
        current_time = time.time()
        if current_time - self.last_update_time < 0.2:
            return
        with self.progress_lock:
            elapsed = time.time() - start_time
            memory = psutil.Process().memory_info().rss / 1024 / 1024
            self.progress_value = min(progress, 100)
            self.progress_bar['value'] = self.progress_value
            self.progress_label.config(text=f"⏱ {elapsed:.1f}с | 🧠 {memory:.1f}МБ | 📊 {self.progress_value:.1f}%")
            self.last_update_time = current_time
            self.root.update_idletasks()

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
        self.progress_label.config(text="")

    def load_logs(self):
        files = filedialog.askopenfilenames(title="Выберите .log файлы", filetypes=[("Log files", "*.log"), ("JSON files", "*.json")])
        if files:
            self.loaded_files.extend(list(files))
            messagebox.showinfo("Инфо", f"Загружено {len(files)} файлов.")

    def load_folder(self):
        folder = filedialog.askdirectory(title="Выберите папку")
        if folder:
            log_files = []
            for root_dir, _, files in os.walk(folder):
                for file in files:
                    if file.endswith((".log", ".json")):
                        log_files.append(os.path.join(root_dir, file))
            if log_files:
                self.loaded_files.extend(log_files)
                messagebox.showinfo("Инфо", f"Загружено {len(log_files)} файлов из папки.")
            else:
                messagebox.showinfo("Инфо", "Нет .log или .json файлов в папке.")

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
        try:
            with Pool(cpu_count()) as pool:
                args = [(f, self.temp_dir) for f in self.loaded_files]
                for i, temp_file in enumerate(pool.imap_unordered(process_file_and_sort_chunk, args)):
                    if temp_file:
                        self.temp_files.append(temp_file)
                    progress = (i + 1) / len(self.loaded_files) * 100
                    self.root.after(0, lambda p=progress: self.update_progress(start_time, p))
        except Exception as e:
            self.root.after(0, lambda e=e: self.handle_merge_error(e, start_time))
            return
        self.root.after(0, lambda: self.finish_merge_logs(start_time))

    def handle_merge_error(self, error, start_time):
        self.stop_animation()
        self.merge_button.config(state='normal')
        self.progress_label.config(text="")
        self.progress_bar['value'] = 0
        messagebox.showerror("Ошибка", f"Произошла ошибка при слиянии: {error}")

    def finish_merge_logs(self, start_time):
        self.stop_animation()
        elapsed = time.time() - start_time
        self.update_progress(start_time, 100)
        self.merge_button.config(state='normal')
        self.save_button.config(state='normal' if self.temp_files else 'disabled')
        messagebox.showinfo("Инфо", f"✅ Логи соединены и отсортированы за {elapsed:.1f} сек. Теперь можно сохранить.")

    def start_save_logs(self):
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

        try:
            self.total_lines = 0
            for f in self.temp_files:
                with open(f, 'r', encoding='utf-8') as temp_f:
                    self.total_lines += sum(1 for line in temp_f if line.strip())

            iterators = []
            for f in self.temp_files:
                try:
                    it = (json.loads(line) for line in open(f, 'r', encoding='utf-8') if line.strip())
                    iterators.append(it)
                except Exception as e:
                    logging.warning(f"Cannot read temp file {f}: {e}")

            with open(save_path, 'w', encoding='utf-8') as final_file:
                self.current_line = 0
                for entry in heapq.merge(*iterators, key=lambda x: x.get('t', '')):
                    final_file.write(json.dumps(entry, ensure_ascii=False) + '\n')
                    self.current_line += 1
                    if self.current_line % 1000 == 0 or self.current_line == self.total_lines:
                        progress = self.current_line * 100 / (self.total_lines or 1)
                        self.root.after(0, lambda p=progress: self.update_progress(start_time, p))

            self.root.after(0, lambda: self.finish_save_logs(start_time))
        except Exception as e:
            logging.error(f"Error saving final file: {e}")
            self.root.after(0, lambda e=e: self.handle_save_error(e))

    def handle_save_error(self, error):
        self.stop_animation()
        self.save_button.config(state='normal')
        messagebox.showerror("Ошибка", f"Ошибка сохранения: {error}")

    def finish_save_logs(self, start_time):
        self.stop_animation()
        elapsed = time.time() - start_time
        self.progress_bar['value'] = 100
        self.progress_label.config(text=f"✅ Готово! {elapsed:.1f} сек.")
        self.save_button.config(state='normal')
        messagebox.showinfo("Инфо", f"Файл сохранён за {elapsed:.1f} сек.")

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