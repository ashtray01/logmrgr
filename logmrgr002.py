import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import json
from datetime import datetime
import os
import re

class LogMergerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("logmrgr")
        self.root.geometry("200x200")
        self.root.resizable(False, False)
        self.root.configure(bg="#2E2E2E")
        
        self.loaded_files = []
        self.merged_logs = []
        
        self.style = ttk.Style()
        self.style.theme_use('clam')
        self.style.configure('TButton', background='#4A4A4A', foreground='white', bordercolor='#555555', padding=5)
        self.style.map('TButton', background=[('active', '#666666')])
        
        # Create a frame to center buttons vertically
        self.main_frame = tk.Frame(root, bg="#2E2E2E")
        self.main_frame.pack(expand=True)
        
        # Add some padding at the top
        tk.Frame(self.main_frame, bg="#2E2E2E", height=20).pack()
        
        self.load_button = ttk.Button(self.main_frame, text="Загрузить логи", command=self.load_logs)
        self.load_button.pack(fill='x', pady=5, padx=15)
        
        self.merge_button = ttk.Button(self.main_frame, text="Соединить логи", command=self.merge_logs)
        self.merge_button.pack(fill='x', pady=5, padx=15)
        
        self.save_button = ttk.Button(self.main_frame, text="Сохранить всё", command=self.save_logs)
        self.save_button.pack(fill='x', pady=5, padx=15)

    def load_logs(self):
        files = filedialog.askopenfilenames(title="Выберите .log файлы", filetypes=[("Log files", "*.log")])
        if files:
            self.loaded_files = list(files)
            messagebox.showinfo("Инфо", f"Загружено {len(self.loaded_files)} файлов.")

    def merge_logs(self):
        if not self.loaded_files:
            messagebox.showerror("Ошибка", "Сначала загрузите файлы.")
            return
        
        all_entries = []
        for file_path in self.loaded_files:
            file_name = os.path.basename(file_path)
            match = re.search(r'(?<=op-gankov-pp-)([a-z]+)', file_name, re.IGNORECASE)
            service_name = match.group(1) if match else "unknown"
            
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            if 't' in entry:
                                entry['service'] = service_name
                                all_entries.append(entry)
                        except json.JSONDecodeError:
                            pass
        
        all_entries.sort(key=lambda x: datetime.fromisoformat(x['t']))
        
        self.merged_logs = all_entries
        messagebox.showinfo("Инфо", "Логи успешно соединены.")

    def save_logs(self):
        if not self.merged_logs:
            messagebox.showerror("Ошибка", "Сначала соедините логи.")
            return
        
        current_date = datetime.now().strftime("%Y-%m-%d")
        default_filename = f"mrgd({current_date}).log"
        save_path = filedialog.asksaveasfilename(title="Сохранить как", defaultextension=".log", initialfile=default_filename)
        
        if save_path:
            with open(save_path, 'w', encoding='utf-8') as f:
                for entry in self.merged_logs:
                    f.write(json.dumps(entry) + '\n')
            messagebox.showinfo("Инфо", "Файл сохранен.")

if __name__ == "__main__":
    root = tk.Tk()
    app = LogMergerApp(root)
    root.mainloop()