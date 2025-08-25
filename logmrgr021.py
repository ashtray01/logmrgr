# logmrgr.py - Объединение логов с поддержкой разных форматов
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
from multiprocessing import Manager, Pool
from functools import partial

# Для поддержки multiprocessing на Windows
from multiprocessing import freeze_support

# Настройка логгера
logging.basicConfig(
    filename='log_merger_errors.log',
    level=logging.WARNING,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def sanitize_filename(filename):
    """Заменяет недопустимые символы в имени файла на подчеркивания."""
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename

def get_timezone_from_file(file_path):
    """Определяет временную зону из файла."""
    timezone = None
    sample_size = 20
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(4096)
            result = chardet.detect(raw_data)
            encoding = result['encoding'] or 'utf-8'
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            for i, line in enumerate(f):
                if i >= sample_size:
                    break
                match = re.search(r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6,}([-+]\d{2}:\d{2})', line)
                if match:
                    timezone = match.group(1)
                    break
    except Exception as e:
        logging.warning(f"Error reading timezone from {file_path}: {e}")
    return timezone or "+00:00"

def parse_log_line(line, file_path, service_map, service_counter):
    """Парсит строку лога в зависимости от её формата."""
    line = line.strip()
    if not line:
        return None

    ecs_pattern = re.compile(r'^\{"@timestamp":"')
    procrun_pattern = re.compile(r'^\[\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\] \[info\]')
    elasticsearch_pattern = re.compile(r'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d{3})\]\[([A-Z]+)\]\[(.*?)\] \[([A-Z0-9_-]+)\] \[(.*?)\] (.*)')
    linux_syslog_pattern = re.compile(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}\+\d{2}:\d{2} [a-zA-Z0-9_-]+ \w+\[\d+\]:')

    try:
        if line.startswith('{') and '"t":' in line:
            return json.loads(line)
        if ecs_pattern.match(line):
            return transform_ecs(json.loads(line), service_map, service_counter)
        if line.startswith('{'):
            return transform_generic_json(json.loads(line), file_path, service_map, service_counter)
        if procrun_pattern.match(line):
            return transform_procrun_log(line, file_path)
        if elasticsearch_pattern.match(line):
            return transform_elasticsearch_log(line, file_path)
        if linux_syslog_pattern.match(line):
            return transform_linux_syslog(line, file_path)
        return transform_catch_all(line, file_path, service_map, service_counter)
    except (json.JSONDecodeError, ValueError) as e:
        logging.warning(f"Failed to parse line in {file_path}: {line[:100]}... Error: {e}")
        return create_generic_entry(line, file_path, service_map, service_counter)

def transform_ecs(entry, service_map, service_counter):
    """Трансформирует запись в формате ECS."""
    transformed = {}
    try:
        dt_str = entry.pop("@timestamp")
        dt = parse(dt_str)
        transformed["t"] = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + dt.strftime('%z')
    except (KeyError, ValueError):
        transformed["t"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + "+00:00"

    service = entry.pop("service", {})
    service_name = service.get("name")
    if not service_name:
        service_counter['value'] += 1
        service_name = f"DUNNOSERVICE{service_counter['value']}"
    transformed["service"] = service_name

    level = entry.pop("log.level", "Information")
    transformed["l"] = level.replace("Information", "Info").replace("Warning", "Warn").replace("CRITICAL", "FATAL")
    log_info = entry.pop("log", {})
    transformed["lg"] = log_info.get("logger", service_name)

    process = entry.pop("process", {})
    pid = process.get("pid", "1")
    thread_id = process.get("thread", {}).get("id", "1")
    transformed["pid"] = f"{pid}+{thread_id}"

    span_data = {}
    for key, value in entry.items():
        if key not in ["message", "labels", "ecs", "host", "log", "process", "service"]:
            span_data[key] = value
    message = entry.pop("message", "")
    if message:
        span_data["name"] = message

    if 'original' in log_info:
        span_data['original_log_info'] = log_info['original']
    if 'host' in entry:
        span_data['host'] = entry['host']

    transformed["span"] = span_data
    return transformed

def transform_procrun_log(line, file_path):
    """Трансформирует запись в формате Procrun."""
    transformed = {}
    parts = re.split(r'\[(.*?)\]', line.strip())
    try:
        dt = parse(parts[1].strip())
        timezone = get_timezone_from_file(file_path)
        transformed["t"] = dt.strftime('%Y-%m-%d %H:%M:%S.000') + timezone
    except (ValueError, IndexError):
        transformed["t"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + "+00:00"
    level = parts[3].strip()
    transformed["l"] = "Info" if level == "info" else level.replace("CRITICAL", "FATAL")
    transformed["pid"] = parts[5].strip()
    transformed["service"] = "procrun"
    transformed["lg"] = "Commons Daemon"
    rest = " ".join(parts[6:]).strip()
    if rest:
        transformed["span"] = {"name": rest}
    return transformed

def transform_elasticsearch_log(line, file_path):
    """Трансформирует запись в формате Elasticsearch."""
    transformed = {}
    match = re.search(r'^\[(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2},\d{3})\]\[([A-Z]+)\]\[(.*?)\] \[([A-Z0-9_-]+)\] \[(.*?)\] (.*)', line)
    if match:
        dt_str, level, logger, pid, service_name, message = match.groups()
        dt_str = dt_str.replace(',', '.')
        dt = parse(dt_str)
        timezone = get_timezone_from_file(file_path)
        transformed["t"] = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + timezone
        transformed["l"] = level.title().replace("CRITICAL", "FATAL")
        transformed["service"] = service_name
        transformed["lg"] = logger
        transformed["pid"] = pid
        transformed["span"] = {"name": message.strip()}
    return transformed or create_generic_entry(line, file_path, {}, {'value': 0})

def transform_linux_syslog(line, file_path):
    """Трансформирует запись в формате Linux Syslog."""
    transformed = {}
    match = re.search(r'(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}.\d{6}\+\d{2}:\d{2}) ([a-zA-Z0-9_-]+) (\w+)\[(\d+)\]: (.*)', line)
    if match:
        dt_str, host, service_name, pid, message = match.groups()
        dt = parse(dt_str)
        transformed["t"] = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + dt.strftime('%z')
        transformed["service"] = service_name
        transformed["pid"] = pid
        transformed["lg"] = host
        transformed["l"] = "Info"
        transformed["span"] = {"name": message.strip()}
    return transformed or create_generic_entry(line, file_path, {}, {'value': 0})

def transform_generic_json(entry, file_path, service_map, service_counter):
    """Трансформирует общую JSON-запись."""
    transformed = {}
    time_keys = ['@timestamp', 'timestamp', 'date', 'time']
    dt_str = next((entry.get(k) for k in time_keys if k in entry), None)
    if dt_str:
        try:
            dt = parse(dt_str)
            timezone = get_timezone_from_file(file_path)
            transformed["t"] = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + timezone
        except ValueError:
            transformed["t"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + "+00:00"
    else:
        transformed["t"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + "+00:00"

    service_name = entry.get("service", {}).get("name") or entry.get("serviceName")
    if not service_name:
        if file_path not in service_map:
            service_counter['value'] += 1
            service_map[file_path] = f"DUNNOSERVICE{service_counter['value']}"
        service_name = service_map[file_path]
    transformed["service"] = service_name

    level = entry.get("log.level") or entry.get("level") or "Info"
    transformed["l"] = level.replace("Information", "Info").replace("Warning", "Warn").replace("CRITICAL", "FATAL")
    transformed["lg"] = entry.get("logger") or transformed["service"]
    transformed["span"] = entry
    return transformed

def transform_catch_all(line, file_path, service_map, service_counter):
    """Трансформирует запись, если её формат не распознан."""
    return create_generic_entry(line, file_path, service_map, service_counter)

def create_generic_entry(line, file_path, service_map, service_counter):
    """Создает обобщенную запись для нераспознанных форматов."""
    transformed = {}
    match = re.search(r'\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d{3,})?', line)
    if match:
        dt_str = match.group(0).replace(',', '.')
        try:
            dt = parse(dt_str)
            timezone = get_timezone_from_file(file_path)
            transformed["t"] = dt.strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + timezone
        except ValueError:
            transformed["t"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + "+00:00"
    else:
        transformed["t"] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3] + "+00:00"

    if file_path not in service_map:
        service_counter['value'] += 1
        service_map[file_path] = f"DUNNOSERVICE{service_counter['value']}"

    transformed["service"] = service_map[file_path]
    transformed["l"] = "Info"
    transformed["lg"] = transformed["service"]
    transformed["span"] = {"name": line.strip()}
    return transformed

def process_file(args):
    """Обрабатывает один файл и возвращает список временных файлов (чанков)."""
    file_path, temp_dir, service_map, service_counter = args
    temp_files = []
    chunk_size = 666 * 1024 * 1024  # 666 MB
    chunk_entries = []
    current_chunk_size = 0
    temp_file_counter = 0

    # Определяем кодировку
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read(4096)
            result = chardet.detect(raw_data)
            encoding = result['encoding'] or 'utf-8'
    except Exception:
        encoding = 'utf-8'

    try:
        with open(file_path, 'r', encoding=encoding, errors='ignore') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                entry = parse_log_line(line, file_path, service_map, service_counter)
                if entry and 't' in entry:
                    entry_str = json.dumps(entry, ensure_ascii=False) + '\n'
                    entry_size = len(entry_str.encode('utf-8'))

                    if current_chunk_size + entry_size > chunk_size and chunk_entries:
                        # Сохраняем чанк
                        sorted_entries = sorted(chunk_entries, key=lambda x: parse(x['t']))
                        sanitized_name = sanitize_filename(os.path.basename(file_path))
                        temp_file = os.path.join(temp_dir, f"chunk_{sanitized_name}_{temp_file_counter}.log")
                        with open(temp_file, 'w', encoding='utf-8') as tf:
                            for e in sorted_entries:
                                tf.write(json.dumps(e, ensure_ascii=False) + '\n')
                        temp_files.append(temp_file)
                        chunk_entries = [entry]
                        current_chunk_size = entry_size
                        temp_file_counter += 1
                    else:
                        chunk_entries.append(entry)
                        current_chunk_size += entry_size

            # Последний чанк
            if chunk_entries:
                sorted_entries = sorted(chunk_entries, key=lambda x: parse(x['t']))
                sanitized_name = sanitize_filename(os.path.basename(file_path))
                temp_file = os.path.join(temp_dir, f"chunk_{sanitized_name}_{temp_file_counter}.log")
                with open(temp_file, 'w', encoding='utf-8') as tf:
                    for e in sorted_entries:
                        tf.write(json.dumps(e, ensure_ascii=False) + '\n')
                temp_files.append(temp_file)
    except Exception as e:
        logging.error(f"Error processing {file_path}: {e}")

    return temp_files


class LogMergerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("logmrgr v021")
        self.root.geometry("250x300")
        self.root.resizable(False, False)
        self.root.configure(bg="#2E2E2E")

        self.loaded_files = []
        self.temp_dir = tempfile.mkdtemp()
        self.service_map = Manager().dict()
        self.service_counter = Manager().dict({'value': 0})
        self.after_id = None
        self.progress_value = 0
        self.progress_lock = threading.Lock()

        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', background='#4A4A4A', foreground='white', bordercolor='#555555', padding=5)
        self.style.map('TButton', background=[('active', '#006400')], foreground=[('active', 'white')])
        self.style.configure('TProgressbar', background='#006400', troughcolor='#2E2E2E')

        self.main_frame = tk.Frame(root, bg="#2E2E2E")
        self.main_frame.pack(expand=True)

        tk.Frame(self.main_frame, bg="#2E2E2E", height=20).pack()

        self.load_button = ttk.Button(self.main_frame, text="Загрузить файлы 📄", command=self.load_logs)
        self.load_button.pack(fill='x', pady=5, padx=15)

        self.load_folder_button = ttk.Button(self.main_frame, text="Загрузить папку 📂", command=self.load_folder)
        self.load_folder_button.pack(fill='x', pady=5, padx=15)

        self.merge_button = ttk.Button(self.main_frame, text="Соединить логи 🧩", command=self.start_merge_logs)
        self.merge_button.pack(fill='x', pady=5, padx=15)

        self.save_button = ttk.Button(self.main_frame, text="Сохранить всё 💾", command=self.start_save_logs, state='disabled')
        self.save_button.pack(fill='x', pady=5, padx=15)

        self.progress_label = tk.Label(self.main_frame, text="", bg="#2E2E2E", fg="white")
        self.progress_label.pack(pady=5)

        self.progress_bar = ttk.Progressbar(self.main_frame, orient='horizontal', length=200, mode='determinate')
        self.progress_bar.pack(pady=5)

        self.animation_frames = ["|", "/", "-", "\\"]
        self.animation_index = 0
        self.is_animating = False

    def update_progress(self, start_time, progress=0):
        with self.progress_lock:
            elapsed = time.time() - start_time
            memory = psutil.Process().memory_info().rss / 1024 / 1024
            self.progress_value = min(progress, 100)
            self.progress_bar['value'] = self.progress_value
            self.progress_label.config(text=f"Обработка: {elapsed:.1f} сек, Память: {memory:.1f} МБ")
            self.root.update_idletasks()

    def start_animation(self):
        if not self.is_animating:
            self.is_animating = True
            self.animate()

    def animate(self):
        if self.is_animating:
            self.progress_label.config(text=f"Работа в процессе {self.animation_frames[self.animation_index]} ({self.progress_value:.1f}%)")
            self.animation_index = (self.animation_index + 1) % len(self.animation_frames)
            self.after_id = self.root.after(200, self.animate)

    def stop_animation(self):
        if self.after_id:
            self.root.after_cancel(self.after_id)
            self.after_id = None
        self.is_animating = False
        self.progress_label.config(text="")
        self.progress_bar['value'] = 0

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
        threading.Thread(target=self.merge_logs, args=(start_time,), daemon=True).start()

    def merge_logs(self, start_time):
        try:
            with Pool() as pool:
                args = [(f, self.temp_dir, self.service_map, self.service_counter) for f in self.loaded_files]
                all_temp_files = []
                for i, file_temp_files in enumerate(pool.imap_unordered(process_file, args)):
                    all_temp_files.extend(file_temp_files)
                    progress = (i + 1) / len(self.loaded_files) * 100
                    self.root.after(0, lambda p=progress: self.update_progress(start_time, p))
            self.root.after(0, lambda: self.finish_merge_logs(start_time, all_temp_files))
        except Exception as e:
            self.root.after(0, lambda e=e: self.finish_merge_with_error(e, start_time))

    def finish_merge_logs(self, start_time, temp_files):
        self.stop_animation()
        elapsed = time.time() - start_time
        self.update_progress(start_time, 100)
        self.merge_button.config(state='normal')
        self.save_button.config(state='normal' if temp_files else 'disabled')
        self.temp_files = temp_files
        messagebox.showinfo("Инфо", f"Логи успешно соединены за {elapsed:.1f} сек.")

    def finish_merge_with_error(self, error, start_time):
        self.stop_animation()
        self.merge_button.config(state='normal')
        self.progress_label.config(text="")
        self.progress_bar['value'] = 0
        messagebox.showerror("Ошибка", f"Произошла ошибка: {error}")

    def start_save_logs(self):
        if not hasattr(self, 'temp_files') or not self.temp_files:
            messagebox.showerror("Ошибка", "Сначала соедините логи.")
            return
        self.save_button.config(state='disabled')
        self.start_animation()
        start_time = time.time()
        threading.Thread(target=self.save_logs, args=(start_time,), daemon=True).start()

    def save_logs(self, start_time):
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
            # Собираем итераторы для всех временных файлов
            iterators = []
            for f in self.temp_files:
                try:
                    it = (json.loads(line) for line in open(f, 'r', encoding='utf-8'))
                    iterators.append(it)
                except Exception as e:
                    logging.warning(f"Cannot read temp file {f}: {e}")

            # Сливаем все записи по времени
            with open(save_path, 'w', encoding='utf-8') as final_file:
                count = 0
                for entry in heapq.merge(*iterators, key=lambda x: x.get('t', '')):
                    json.dump(entry, final_file, ensure_ascii=False)
                    final_file.write('\n')
                    count += 1
                    if count % 500 == 0:  # Обновляем прогресс каждые 500 строк
                        self.root.after(0, lambda c=count: self.update_progress(start_time, min(c / 1000, 100)))

            # Успешно сохранили
            self.root.after(0, lambda: self.finish_save_logs(start_time))
        except Exception as e:
            logging.error(f"Error saving final file: {e}")
            self.root.after(0, lambda e=e: self.handle_save_error(e))
            return

    def handle_save_error(self, error):
        self.stop_animation()
        self.save_button.config(state='normal')
        messagebox.showerror("Ошибка", f"Ошибка сохранения: {error}")

    def finish_save_logs(self, start_time):
        self.stop_animation()
        elapsed = time.time() - start_time
        self.progress_bar['value'] = 100
        self.progress_label.config(text=f"Готово! Заняло {elapsed:.1f} сек.")
        self.save_button.config(state='normal')
        messagebox.showinfo("Инфо", f"Файл успешно сохранен за {elapsed:.1f} сек.")

    try:
        shutil.rmtree(self.temp_dir, ignore_errors=True)
        self.temp_dir = tempfile.mkdtemp()
    except Exception as e:
        logging.error(f"Error removing temp dir: {e}")

        # Удаляем временные файлы
        try:
            shutil.rmtree(self.temp_dir, ignore_errors=True)
            self.temp_dir = tempfile.mkdtemp()  # Новый временный каталог
        except Exception as e:
            logging.error(f"Error removing temp dir: {e}")


if __name__ == "__main__":
    freeze_support()  # Для Windows и multiprocessing
    root = tk.Tk()
    app = LogMergerApp(root)
    root.mainloop()