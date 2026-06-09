#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Simple GUI launcher for Ingram scanner.

Provides a basic panel for users who don't want to run from terminal.
- Top: scrolling text area that shows the animated logo and console logs ("mini terminal").
- Bottom: basic settings mapped to existing CLI options (in_file/target, out_dir, ports, threads, timeout, debug, disable_snapshot).

This script wraps the same logic as run_ingram.run(), but drives it from a Tkinter GUI
and runs the core scan in a background process, streaming stdout/stderr into the GUI.
"""

import os
import sys
import threading
import queue
import subprocess
import shlex
import re
import fcntl
import select

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from Ingram.utils import logo as ingram_logo


PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


LANG_TEXTS = {
    'en': {
        'title': "Ingram Scanner GUI",
        'mini_terminal': "Modified by: Pravoslavni Bes && Tg: SniffCam",
        'target_file': "Target file:",
        'browse': "Browse",
        'single_target': "Single target (IP / range / IP:port):",
        'out_dir': "Output directory:",
        'ports': "Ports (comma separated):",
        'threads': "Threads (-t):",
        'timeout': "Timeout (-T):",
        'debug': "Debug logging",
        'disable_snapshot': "Disable snapshots",
        'start': "Start scan",
        'stop': "Stop",
        'initial_hint': "Ingram GUI launcher ready. Configure options below and press 'Start scan'...\n",
        'err_title': "Error",
        'err_both_inputs': "Specify either a file with targets or a single target, not both.",
        'err_no_input': "You must specify either a target file or a single target.",
        'warn_running_title': "Running",
        'warn_running': "Scan is already running.",
        'log_starting': "[+] Starting Ingram: ",
        'log_stopping': "[!] Stopping scan...\n",
        'log_finished': "\n[+] Scan finished.\n",
    },
    'ru': {
        'title': "Ingram Scanner GUI",
        'mini_terminal': "Модифицировал Православный Бес && ТГ: SniffCam",
        'target_file': "Файл с целями:",
        'browse': "Обзор",
        'single_target': "Одна цель (IP / диапазон / IP:port):",
        'out_dir': "Папка для результатов:",
        'ports': "Порты (через запятую):",
        'threads': "Потоки (-t):",
        'timeout': "Таймаут (-T):",
        'debug': "Отладочный лог",
        'disable_snapshot': "Отключить скриншот",
        'start': "Запустить сканирование",
        'stop': "Стоп",
        'initial_hint': "Ingram GUI ready",
        'err_title': "Ошибка",
        'err_both_inputs': "Укажите файл с целями",
        'err_no_input': "Нужно указать либо файл с целями",
        'warn_running_title': "Выполняется",
        'warn_running': "Сканирование уже запущенно.",
        'log_starting': "[+] Запуск Ingram: ",
        'log_stopping': "[!] Остановка скананирования...\n",
        'log_finished': "\n[+] Сканирование завершено.\n",
    },
}


class IngramGUILauncher(tk.Tk):
    def __init__(self):
        super().__init__()
        self.current_lang = 'ru'

        # Modern dark theme
        self.bg_primary = "#0d1117"
        self.bg_secondary = "#161b22"
        self.bg_tertiary = "#21262d"
        self.fg_primary = "#e6edf3"
        self.fg_secondary = "#8b949e"
        self.accent = "#58a6ff"
        self.accent_hover = "#79c0ff"
        self.success = "#3fb950"
        self.danger = "#f85149"

        self.configure(bg=self.bg_primary)

        # Apply modern dark ttk style
        style = ttk.Style(self)
        try:
            style.theme_use('clam')
        except Exception:
            pass
        
        style.configure('TFrame', background=self.bg_primary)
        style.configure('TLabel', background=self.bg_primary, foreground=self.fg_primary)
        style.configure('TButton', background=self.bg_tertiary, foreground=self.fg_primary, 
                       borderwidth=1, relief='solid', padding=6)
        style.map('TButton', 
                 background=[('active', self.accent), ('pressed', self.accent_hover)],
                 foreground=[('active', self.bg_primary)])
        style.configure('TCheckbutton', background=self.bg_primary, foreground=self.fg_primary)
        style.map('TCheckbutton', background=[('active', self.bg_primary)])
        style.configure('TEntry', fieldbackground=self.bg_tertiary, foreground=self.fg_primary,
                       borderwidth=1, relief='solid', padding=4)
        style.configure('TOptionMenu', background=self.bg_tertiary, foreground=self.fg_primary)

        self.title(LANG_TEXTS[self.current_lang]['title'])
        self.geometry("1000x700")

        # Queue for background process output
        self.output_queue: "queue.Queue[str]" = queue.Queue()
        self.process = None
        self.widgets = {}
        self.lang_buttons = {}
        self.stream_buf = ""
        self._build_ui()
        self._poll_output()

    # ---------------- UI BUILD -----------------
    def _build_ui(self):
        # Header bar with title and language switch
        header = tk.Frame(self, bg=self.bg_secondary, height=50)
        header.pack(side=tk.TOP, fill=tk.X)
        header.pack_propagate(False)

        title_label = tk.Label(
            header,
            text="Ingram-modified (v1.1 Beta)",
            font=("Segoe UI", 16, "bold"),
            bg=self.bg_secondary,
            fg=self.accent
        )
        title_label.pack(side=tk.LEFT, padx=15, pady=10)

        # Language switch (right side)
        lang_frame = tk.Frame(header, bg=self.bg_secondary)
        lang_frame.pack(side=tk.RIGHT, padx=15, pady=10)
        lang_label = tk.Label(lang_frame, text="🌐", font=("Segoe UI", 15), bg=self.bg_secondary, fg=self.fg_secondary)
        lang_label.pack(side=tk.LEFT, padx=(0, 8))
        # Map language to flag emoji
        self.lang_var = tk.StringVar(value=self.current_lang)
        for code, text in (("ru", "RU"), ("en", "EN")):
            btn = tk.Button(
                lang_frame,
                text=text,
                font=("Segoe UI", 10, "bold"),
                bg=self.accent if code == self.current_lang else self.bg_tertiary,
                fg=self.bg_primary if code == self.current_lang else self.fg_secondary,
                bd=0,
                relief=tk.FLAT,
                activebackground=self.accent_hover,
                activeforeground=self.bg_primary,
                cursor="hand2",
                padx=6,
                pady=2,
            )
            btn.config(command=lambda c=code: self._on_lang_change(c))
            btn.pack(side=tk.LEFT, padx=(0, 4))
            self.lang_buttons[code] = btn

        # Main content area
        content = ttk.Frame(self)
        content.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=10, pady=10)

        # Top: mini terminal / logo area with border
        terminal_frame = tk.Frame(content, bg=self.bg_secondary, relief=tk.FLAT, bd=1)
        terminal_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, pady=(0, 10))

        terminal_label = tk.Label(
            terminal_frame,
            font=("Segoe UI", 10, "bold"),
            bg=self.bg_secondary,
            fg=self.accent
        )
        terminal_label.pack(side=tk.TOP, fill=tk.X, padx=10, pady=8)

        text_frame = ttk.Frame(terminal_frame)
        text_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))

        self.text = tk.Text(
            text_frame,
            height=16,
            bg="#010409",  # Very dark terminal background
            fg=self.fg_primary,
            insertbackground=self.accent,
            highlightthickness=0,
            bd=0,
            font=("Courier New", 10)
        )
        self.text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scroll = ttk.Scrollbar(text_frame, command=self.text.yview)
        scroll.pack(side=tk.RIGHT, fill=tk.Y, padx=(4, 0))
        self.text.configure(yscrollcommand=scroll.set)

        # Status Bar at the bottom of the terminal frame
        self.status_var = tk.StringVar(value="⏳ Ожидание запуска...")
        status_label = tk.Label(
            terminal_frame,
            textvariable=self.status_var,
            font=("Courier New", 10, "bold"),
            bg="#010409",
            fg=self.success,
            anchor="w"
        )
        status_label.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=(0, 8))

        # Configure color tags for text widget
        self._configure_color_tags()

        # Bottom: settings panel with border
        settings_frame = tk.Frame(content, bg=self.bg_secondary, relief=tk.FLAT, bd=1)
        settings_frame.pack(side=tk.BOTTOM, fill=tk.X)

        settings_label = tk.Label(
            settings_frame,
            text="⚙️  " + LANG_TEXTS[self.current_lang]['mini_terminal'],
            font=("Segoe UI", 10, "bold"),
            bg=self.bg_secondary,
            fg=self.accent
        )
        settings_label.pack(side=tk.TOP, fill=tk.X, padx=10, pady=8)

        settings_inner = ttk.Frame(settings_frame)
        settings_inner.pack(side=tk.TOP, fill=tk.X, padx=10, pady=(0, 10))

        # Row 0: input mode (file or single target)
        row = 0
        self.widgets['lbl_target_file'] = ttk.Label(settings_inner, text=LANG_TEXTS[self.current_lang]['target_file'])
        self.widgets['lbl_target_file'].grid(row=row, column=0, sticky=tk.W, pady=5)
        self.in_file_var = tk.StringVar()
        entry_in_file = ttk.Entry(settings_inner, textvariable=self.in_file_var, width=50)
        entry_in_file.grid(row=row, column=1, sticky=tk.EW, pady=5, padx=(10, 5))
        self.widgets['btn_browse_file'] = ttk.Button(settings_inner, text=LANG_TEXTS[self.current_lang]['browse'], command=self._browse_in_file)
        self.widgets['btn_browse_file'].grid(row=row, column=2, padx=5)

        row += 1
        self.widgets['lbl_single_target'] = ttk.Label(settings_inner, text=LANG_TEXTS[self.current_lang]['single_target'])
        self.widgets['lbl_single_target'].grid(row=row, column=0, sticky=tk.W, pady=5)
        self.target_var = tk.StringVar()
        ttk.Entry(settings_inner, textvariable=self.target_var, width=50).grid(row=row, column=1, sticky=tk.EW, pady=5, padx=(10, 5))

        # Row 2: out_dir
        row += 1
        self.widgets['lbl_out_dir'] = ttk.Label(settings_inner, text=LANG_TEXTS[self.current_lang]['out_dir'])
        self.widgets['lbl_out_dir'].grid(row=row, column=0, sticky=tk.W, pady=5)
        self.out_dir_var = tk.StringVar(value=os.path.join(PROJECT_ROOT, "results"))
        ttk.Entry(settings_inner, textvariable=self.out_dir_var, width=50).grid(row=row, column=1, sticky=tk.EW, pady=5, padx=(10, 5))
        self.widgets['btn_browse_out'] = ttk.Button(settings_inner, text=LANG_TEXTS[self.current_lang]['browse'], command=self._browse_out_dir)
        self.widgets['btn_browse_out'].grid(row=row, column=2, padx=5)

        # Row 3: ports and threads (side by side)
        row += 1
        self.widgets['lbl_ports'] = ttk.Label(settings_inner, text=LANG_TEXTS[self.current_lang]['ports'])
        self.widgets['lbl_ports'].grid(row=row, column=0, sticky=tk.W, pady=5)
        self.ports_var = tk.StringVar()
        ttk.Entry(settings_inner, textvariable=self.ports_var, width=50).grid(row=row, column=1, sticky=tk.EW, pady=5, padx=(10, 5))

        # Row 4: threads
        row += 1
        self.widgets['lbl_threads'] = ttk.Label(settings_inner, text=LANG_TEXTS[self.current_lang]['threads'])
        self.widgets['lbl_threads'].grid(row=row, column=0, sticky=tk.W, pady=5)
        self.threads_var = tk.StringVar(value="150")
        ttk.Entry(settings_inner, textvariable=self.threads_var, width=15).grid(row=row, column=1, sticky=tk.W, pady=5, padx=(10, 5))

        # Row 5: flags
        row += 1
        self.debug_var = tk.BooleanVar(value=False)
        self.disable_snapshot_var = tk.BooleanVar(value=False)
        flags_frame = ttk.Frame(settings_inner)
        flags_frame.grid(row=row, column=0, columnspan=3, sticky=tk.W, pady=5)
        self.widgets['chk_debug'] = ttk.Checkbutton(flags_frame, text=LANG_TEXTS[self.current_lang]['debug'], variable=self.debug_var)
        self.widgets['chk_debug'].pack(side=tk.LEFT, padx=(0, 20))
        self.widgets['chk_disable_snap'] = ttk.Checkbutton(flags_frame, text=LANG_TEXTS[self.current_lang]['disable_snapshot'], variable=self.disable_snapshot_var)
        self.widgets['chk_disable_snap'].pack(side=tk.LEFT)

        # Row 6: Start/Stop buttons
        row += 1
        button_frame = ttk.Frame(settings_inner)
        button_frame.grid(row=row, column=0, columnspan=3, sticky=tk.W, pady=10)
        self.start_btn = ttk.Button(button_frame, text="▶ " + LANG_TEXTS[self.current_lang]['start'], command=self._on_start)
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        self.stop_btn = ttk.Button(button_frame, text="⏹ " + LANG_TEXTS[self.current_lang]['stop'], command=self._on_stop, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT)

        # Stretch columns
        settings_inner.columnconfigure(1, weight=1)

        # Draw Ingram ASCII logo at the top of the mini-terminal
        self._draw_logo()
        # Print initial hint below logo
        self._write(LANG_TEXTS[self.current_lang]['initial_hint'] + "\n")

    # ------------- UTILS -------------
    def _configure_color_tags(self):
        """Configure ANSI color tags for the text widget."""
        self.current_ansi_tag = None
        # ANSI color mapping
        ansi_colors = {
            '30': '#808080',  # black -> dark gray
            '31': '#ff5555',  # red
            '32': '#55ff55',  # green
            '33': '#ffff55',  # yellow
            '34': '#5555ff',  # blue
            '35': '#ff55ff',  # magenta
            '36': '#55ffff',  # cyan
            '37': '#ffffff',  # white
            '90': '#808080',  # bright black
            '91': '#ff8888',  # bright red
            '92': '#88ff88',  # bright green
            '93': '#ffff88',  # bright yellow
            '94': '#8888ff',  # bright blue
            '95': '#ff88ff',  # bright magenta
            '96': '#88ffff',  # bright cyan
            '97': '#ffffff',  # bright white
        }
        
        for code, color in ansi_colors.items():
            self.text.tag_config(f'ansi_{code}', foreground=color)
        
        # Special tags
        self.text.tag_config('logo_icon', foreground='#FFFF55')
        self.text.tag_config('logo_font', foreground='#FF55FF')

    def _insert_ansi_parts(self, text: str):
        """Insert text while parsing ANSI codes into tags."""
        ansi_pattern = r'\x1b\[([0-9;]+)m'
        parts = re.split(ansi_pattern, text)
        
        for i, part in enumerate(parts):
            if i % 2 == 0:
                if part:
                    self.text.insert(tk.END, part, self.current_ansi_tag)
            else:
                codes = part.split(';')
                for code in codes:
                    if code == '0':
                        self.current_ansi_tag = None
                    elif code in ['30', '31', '32', '33', '34', '35', '36', '37',
                                 '90', '91', '92', '93', '94', '95', '96', '97']:
                        self.current_ansi_tag = f'ansi_{code}'

    def _write(self, text: str):
        """Write text to widget, parsing ANSI color codes."""
        self._insert_ansi_parts(text)
        self.text.see(tk.END)

    def _browse_in_file(self):
        path = filedialog.askopenfilename(title="Select targets file")
        if path:
            self.in_file_var.set(path)

    def _browse_out_dir(self):
        path = filedialog.askdirectory(title="Select output directory")
        if path:
            self.out_dir_var.set(path)

    # ------------- PROCESS CONTROL -------------
    def _build_cmd(self):
        """Build command line for run_ingram.py based on GUI settings."""
        py = shlex.quote(sys.executable)
        script = os.path.join(PROJECT_ROOT, "run_ingram.py")

        args = [py, script]

        in_file = self.in_file_var.get().strip()
        target = self.target_var.get().strip()
        out_dir = self.out_dir_var.get().strip()
        ports = self.ports_var.get().strip()
        threads = self.threads_var.get().strip()

        if in_file and target:
            messagebox.showerror(LANG_TEXTS[self.current_lang]['err_title'], LANG_TEXTS[self.current_lang]['err_both_inputs'])
            return None

        if not in_file and not target:
            messagebox.showerror(LANG_TEXTS[self.current_lang]['err_title'], LANG_TEXTS[self.current_lang]['err_no_input'])
            return None

        if in_file:
            args += ["-i", in_file]
        if target:
            args += ["--target", target]

        if out_dir:
            args += ["-o", out_dir]

        if ports:
            # ports can be separated by commas and/or spaces
            for p in ports.replace(',', ' ').split():
                args += ["-p", p]

        if threads:
            args += ["-t", threads]

        if self.disable_snapshot_var.get():
            args.append("-D")

        if self.debug_var.get():
            args.append("--debug")

        return args

    def _on_start(self):
        if self.process is not None:
            messagebox.showwarning(LANG_TEXTS[self.current_lang]['warn_running_title'], LANG_TEXTS[self.current_lang]['warn_running'])
            return

        cmd = self._build_cmd()
        if not cmd:
            return

        self._write("\n" + LANG_TEXTS[self.current_lang]['log_starting'] + " ".join(cmd) + "\n\n")
        try:
            # Start subprocess; inherit env, run from project root
            env = os.environ.copy()
            env['INGRAM_NO_LOGO'] = '1'
            env['PYTHONUNBUFFERED'] = '1'  # Force unbuffered output to fix lag
            self.process = subprocess.Popen(
                cmd,
                cwd=PROJECT_ROOT,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=False,  # Read in binary mode to capture \r accurately
                bufsize=0,   # Fully unbuffered
                env=env
            )
        except Exception as e:
            self._write(f"[!] Failed to start Ingram: {e}\n")
            self.process = None
            return

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status_var.set("🚀 Запуск сканирования...")

        t = threading.Thread(target=self._reader_thread, daemon=True)
        t.start()

    def _on_stop(self):
        if self.process is None:
            return
        try:
            self._write("\n" + LANG_TEXTS[self.current_lang]['log_stopping'])
            self.process.terminate()
        except Exception:
            pass
        self.process = None
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status_var.set("🛑 Сканирование остановлено")

    def _reader_thread(self):
        """Read subprocess output and push into queue in chunks without blocking."""
        if self.process is None or self.process.stdout is None:
            return
            
        fd = self.process.stdout.fileno()
        fl = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, fl | os.O_NONBLOCK)
        
        while self.process is not None and self.process.poll() is None:
            ready, _, _ = select.select([fd], [], [], 0.1)
            if ready:
                try:
                    chunk = self.process.stdout.read()
                    if chunk:
                        self.output_queue.put(chunk)
                    else:
                        break  # EOF
                except Exception:
                    pass
                    
        # Read any remaining data
        try:
            while True:
                chunk = self.process.stdout.read()
                if not chunk:
                    break
                self.output_queue.put(chunk)
        except Exception:
            pass

        # Process finished
        self.output_queue.put(b"\n" + LANG_TEXTS[self.current_lang]['log_finished'].encode('utf-8'))
        self.process = None

    def _poll_output(self):
        """Periodically pull from queue and write to text widget."""
        try:
            while True:
                chunk = self.output_queue.get_nowait()
                if isinstance(chunk, bytes):
                    chunk = chunk.decode('utf-8', errors='replace')
                
                if chunk.endswith(LANG_TEXTS[self.current_lang]['log_finished']):
                    self._write(chunk)
                    self.status_var.set("✅ " + LANG_TEXTS[self.current_lang]['log_finished'].strip())
                    # Scan finished naturally: allow starting a new one
                    self.start_btn.config(state=tk.NORMAL)
                    self.stop_btn.config(state=tk.DISABLED)
                    self.stream_buf = ""
                else:
                    self._process_chunk(chunk)
        except queue.Empty:
            pass
        self.after(50, self._poll_output)

    def _process_chunk(self, chunk: str):
        self.stream_buf += chunk
        
        # We need to separate normal logs (\n) from status bar updates (\r)
        
        # 1. Process normal logs (ending with \n)
        while '\n' in self.stream_buf:
            line, self.stream_buf = self.stream_buf.split('\n', 1)
            
            # If line has \r, the part BEFORE \r is a status bar update, 
            # and the part AFTER \r is the normal log.
            # Example: "[status]\r[log msg]"
            if '\r' in line:
                parts = line.split('\r')
                status_part = parts[-2] if len(parts) >= 2 else ""
                log_part = parts[-1]
                
                if status_part.strip():
                    clean_status = re.sub(r'\x1b\[[0-9;]*m', '', status_part)
                    self.status_var.set("⚡ " + clean_status.strip())
                    
                if log_part.strip():
                    self._write(log_part + '\n')
            else:
                if line.strip():
                    self._write(line + '\n')
            
        # 2. Process remaining status bar updates (ending with \r)
        if '\r' in self.stream_buf:
            parts = self.stream_buf.split('\r')
            # The last element is incomplete (doesn't end with \r or \n), keep it in buffer
            self.stream_buf = parts[-1]
            
            # The second to last element is our latest complete status update
            latest_status = parts[-2]
            if latest_status.strip():
                clean_status = re.sub(r'\x1b\[[0-9;]*m', '', latest_status)
                self.status_var.set("⚡ " + clean_status.strip())

    # ------------- UTILS -------------
    def _draw_logo(self):
        """Render the Ingram ASCII logo with colors at the top of the text area."""
        try:
            # Ingram.utils exports `logo` as a ready-made [icon_lines, font_lines] list
            icon_lines, font_lines = ingram_logo
        except Exception:
            return

        # Draw logo with direct tag application
        # Yellow for icon, magenta for font
        for left, right in zip(icon_lines, font_lines):
            # Left (icon) in yellow
            self.text.insert(tk.END, left, 'ansi_33')
            # Separator
            self.text.insert(tk.END, "  ")
            # Right (font) in magenta
            self.text.insert(tk.END, right, 'ansi_35')
            # Newline
            self.text.insert(tk.END, "\n")
        
        # Add separator line after logo
        self.text.insert(tk.END, "\n" + "="*80 + "\n\n")

    def _on_lang_change(self, value):
        """Update UI texts when language is changed."""
        # Map emoji flags to language codes
        flag_to_lang = {'🇷🇺': 'ru', '🇺🇸': 'en'}
        lang = flag_to_lang.get(value, value) or self.lang_var.get()

        if lang not in LANG_TEXTS:
            return
        self.current_lang = lang
        t = LANG_TEXTS[lang]
        self.title(t['title'])
        # Update widgets texts
        self.widgets['lbl_target_file'].config(text=t['target_file'])
        self.widgets['btn_browse_file'].config(text=t['browse'])
        self.widgets['lbl_single_target'].config(text=t['single_target'])
        self.widgets['lbl_out_dir'].config(text=t['out_dir'])
        self.widgets['btn_browse_out'].config(text=t['browse'])
        self.widgets['lbl_ports'].config(text=t['ports'])
        self.widgets['lbl_threads'].config(text=t['threads'])
        self.widgets['chk_debug'].config(text=t['debug'])
        self.widgets['chk_disable_snap'].config(text=t['disable_snapshot'])
        self.start_btn.config(text="▶ " + t['start'])
        self.stop_btn.config(text="⏹ " + t['stop'])

        # Update language buttons appearance
        for code, btn in self.lang_buttons.items():
            if code == self.current_lang:
                btn.config(bg=self.accent, fg=self.bg_primary)
            else:
                btn.config(bg=self.bg_tertiary, fg=self.fg_secondary)


def main():
    app = IngramGUILauncher()
    app.mainloop()


if __name__ == "__main__":
    main()
