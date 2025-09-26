import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Menu
import threading
import hashlib
import zlib
import os
import queue
import time
import pefile
import pystray
from PIL import Image, ImageDraw

LANGUAGES = {
    "ru": {
        "title": "Hashfile",
        "tab_text": "Текст",
        "tab_file": "Файл",
        "enter_text": "Введите текст:",
        "choose_file": "Выберите файл:",
        "browse": "Обзор...",
        "calc_hashes": "Вычислить хэши",
        "copy_all": "Копировать все",
        "copy_selected": "Копировать",
        "minimize_tray": "Свернуть в трей",
        "progress_size": "Размер файла: {mb:.2f} МБ",
        "hashing_done": "Хэширование завершено",
        "select_file_warning": "Выберите файл",
        "enter_text_warning": "Введите текст для вычисления хэшей",
        "error": "Ошибка",
        "settings": "Настройки",
        "language": "Язык",
        "exit": "Выход",
        "show": "Показать"
    },
    "en": {
        "title": "Hashfile",
        "tab_text": "Text",
        "tab_file": "File",
        "enter_text": "Enter text:",
        "choose_file": "Choose file:",
        "browse": "Browse...",
        "calc_hashes": "Calculate Hashes",
        "copy_all": "Copy All",
        "copy_selected": "Copy",
        "minimize_tray": "Minimize to tray",
        "progress_size": "File size: {mb:.2f} MB",
        "hashing_done": "Hashing completed",
        "select_file_warning": "Select a file",
        "enter_text_warning": "Enter text to calculate hashes",
        "error": "Error",
        "settings": "Settings",
        "language": "Language",
        "exit": "Exit",
        "show": "Show"
    },
    "ua": {
        "title": "Hashfile",
        "tab_text": "Текст",
        "tab_file": "Файл",
        "enter_text": "Введіть текст:",
        "choose_file": "Виберіть файл:",
        "browse": "Огляд...",
        "calc_hashes": "Обчислити хеші",
        "copy_all": "Копіювати все",
        "copy_selected": "Копіювати",
        "minimize_tray": "Згорнути в трей",
        "progress_size": "Розмір файлу: {mb:.2f} МБ",
        "hashing_done": "Хешування завершено",
        "select_file_warning": "Оберіть файл",
        "enter_text_warning": "Введіть текст для обчислення хешів",
        "error": "Помилка",
        "settings": "Налаштування",
        "language": "Мова",
        "exit": "Вихід",
        "show": "Показати"
    }
}


class HashCalculatorApp:
    def __init__(self, root):
        self.root = root
        self.language = "en"
        self.lang = LANGUAGES[self.language]
        self.root.title(self.lang["title"])
        self.root.geometry("920x720")
        self._stop_event = threading.Event()
        self._worker_lock = threading.Lock()
        self.queue = queue.Queue()
        self.current_worker = None
        self.tray_icon = None
        self.tray_thread = None
        self.create_widgets()
        self.setup_context_menu()
        self.setup_menu()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(200, self._poll_queue)
        self.root.bind("<Unmap>", self._on_minimize)

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        self.text_tab = ttk.Frame(self.notebook)
        self.file_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.text_tab, text=self.lang["tab_text"])
        self.notebook.add(self.file_tab, text=self.lang["tab_file"])

        self.create_text_tab()
        self.create_file_tab()

    def create_text_tab(self):
        self.text_label = ttk.Label(self.text_tab, text=self.lang["enter_text"])
        self.text_label.pack(pady=6, anchor="w", padx=10)

        self.text_input = tk.Text(self.text_tab, height=10, wrap=tk.WORD)
        self.text_input.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0,6))

        btn_frame = ttk.Frame(self.text_tab)
        btn_frame.pack(pady=6, padx=10, anchor="w")

        self.calculate_text_btn = ttk.Button(
            btn_frame, text=self.lang["calc_hashes"], command=self.start_text_hash_thread
        )
        self.calculate_text_btn.pack(side=tk.LEFT, padx=(0,6))

        self.copy_all_text_btn = ttk.Button(
            btn_frame, text=self.lang["copy_all"],
            command=lambda: self.copy_to_clipboard(self.text_results)
        )
        self.copy_all_text_btn.pack(side=tk.LEFT)

        self.text_results = tk.Text(self.text_tab, height=14, state=tk.DISABLED)
        self.text_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=(6,10))
        self.text_results.bind("<Button-3>", self.show_context_menu)

    def create_file_tab(self):
        file_select_frame = ttk.Frame(self.file_tab)
        file_select_frame.pack(pady=8, fill=tk.X, padx=10)

        self.file_label = ttk.Label(file_select_frame, text=self.lang["choose_file"])
        self.file_label.pack(side=tk.LEFT, padx=(0,6))

        self.file_path = tk.StringVar()
        self.file_entry = ttk.Entry(file_select_frame, textvariable=self.file_path, width=60)
        self.file_entry.pack(side=tk.LEFT, padx=(0,6), expand=True, fill=tk.X)

        self.browse_btn = ttk.Button(file_select_frame, text=self.lang["browse"], command=self.browse_file)
        self.browse_btn.pack(side=tk.LEFT)

        btn_frame = ttk.Frame(self.file_tab)
        btn_frame.pack(pady=8, padx=10, anchor="w")

        self.calculate_file_btn = ttk.Button(
            btn_frame, text=self.lang["calc_hashes"], command=self.start_file_hash_thread
        )
        self.calculate_file_btn.pack(side=tk.LEFT, padx=(0,6))

        self.copy_all_file_btn = ttk.Button(
            btn_frame, text=self.lang["copy_all"],
            command=lambda: self.copy_to_clipboard(self.file_results)
        )
        self.copy_all_file_btn.pack(side=tk.LEFT)

        self.minimize_tray_btn = ttk.Button(btn_frame, text=self.lang["minimize_tray"], command=self.hide_to_tray)
        self.minimize_tray_btn.pack(side=tk.LEFT, padx=(6,0))

        self.progress = ttk.Progressbar(self.file_tab, mode="determinate")
        self.progress.pack(fill=tk.X, padx=10, pady=(6,0))

        self.progress_label = ttk.Label(self.file_tab, text="")
        self.progress_label.pack(anchor="w", padx=10, pady=(4,6))

        self.file_results = tk.Text(self.file_tab, height=14, state=tk.DISABLED)
        self.file_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0,10))
        self.file_results.bind("<Button-3>", self.show_context_menu)

    def setup_context_menu(self):
        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label=self.lang["copy_selected"], command=self.copy_selected)
        self.context_menu.add_command(label=self.lang["copy_all"], command=self.copy_all_from_active)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Select All", command=self.select_all)

    def setup_menu(self):
        menubar = Menu(self.root)
        settings_menu = Menu(menubar, tearoff=0)
        lang_menu = Menu(settings_menu, tearoff=0)
        lang_menu.add_command(label="Русский", command=lambda: self.set_language("ru"))
        lang_menu.add_command(label="English", command=lambda: self.set_language("en"))
        lang_menu.add_command(label="Українська", command=lambda: self.set_language("ua"))
        settings_menu.add_cascade(label=self.lang["language"], menu=lang_menu)
        menubar.add_cascade(label=self.lang["settings"], menu=settings_menu)
        self.root.config(menu=menubar)

    def set_language(self, code):
        if code not in LANGUAGES:
            return
        self.language = code
        self.lang = LANGUAGES[code]
        self._refresh_ui_texts()

    def _refresh_ui_texts(self):
        self.root.title(self.lang["title"])
        self.notebook.tab(0, text=self.lang["tab_text"])
        self.notebook.tab(1, text=self.lang["tab_file"])
        self.text_label.config(text=self.lang["enter_text"])
        self.file_label.config(text=self.lang["choose_file"])
        self.browse_btn.config(text=self.lang["browse"])
        self.calculate_text_btn.config(text=self.lang["calc_hashes"])
        self.calculate_file_btn.config(text=self.lang["calc_hashes"])
        self.copy_all_text_btn.config(text=self.lang["copy_all"])
        self.copy_all_file_btn.config(text=self.lang["copy_all"])
        self.minimize_tray_btn.config(text=self.lang["minimize_tray"])
        self.setup_context_menu()
        self.setup_menu()

    def show_context_menu(self, event):
        try:
            self.context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.context_menu.grab_release()

    def copy_selected(self):
        active_widget = self.root.focus_get()
        if isinstance(active_widget, tk.Text):
            try:
                text = active_widget.get("sel.first", "sel.last")
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
            except tk.TclError:
                messagebox.showwarning(self.lang["error"], "No selection")

    def copy_all_from_active(self):
        active_widget = self.root.focus_get()
        if isinstance(active_widget, tk.Text):
            self.copy_to_clipboard(active_widget)

    def select_all(self):
        active_widget = self.root.focus_get()
        if isinstance(active_widget, tk.Text):
            active_widget.tag_add(tk.SEL, "1.0", tk.END)
            active_widget.mark_set(tk.INSERT, "1.0")
            active_widget.see(tk.INSERT)

    def copy_to_clipboard(self, text_widget):
        text_widget.config(state=tk.NORMAL)
        text = text_widget.get("1.0", tk.END).strip()
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        text_widget.config(state=tk.DISABLED)
        messagebox.showinfo(self.lang["title"], self.lang["copy_all"] + " ✓")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def start_text_hash_thread(self):
        text = self.text_input.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning(self.lang["error"], self.lang["enter_text_warning"])
            return
        if self._is_worker_busy():
            messagebox.showinfo(self.lang["title"], "Worker busy")
            return
        t = threading.Thread(target=self._text_worker, args=(text,), daemon=True)
        with self._worker_lock:
            self.current_worker = t
        t.start()

    def start_file_hash_thread(self):
        filepath = self.file_path.get()
        if not filepath or not os.path.isfile(filepath):
            messagebox.showwarning(self.lang["error"], self.lang["select_file_warning"])
            return
        if self._is_worker_busy():
            messagebox.showinfo(self.lang["title"], "Worker busy")
            return
        t = threading.Thread(target=self._file_worker, args=(filepath,), daemon=True)
        with self._worker_lock:
            self.current_worker = t
        t.start()

    def _is_worker_busy(self):
        with self._worker_lock:
            return self.current_worker is not None and self.current_worker.is_alive()

    def _text_worker(self, text):
        try:
            data = text.encode("utf-8")
            result = {"Размер текста (байт)": str(len(data))}
            result.update(self._calc_hashes_bytes(data))
            self.queue.put(("text_result", result))
        except Exception as e:
            self.queue.put(("error", str(e)))
        finally:
            with self._worker_lock:
                self.current_worker = None

    def _file_worker(self, filepath):
        try:
            filesize = os.path.getsize(filepath)
            self.queue.put(("progress_set_max", filesize))
            chunk_size = 8 * 1024 * 1024
            hashes = {
                "MD5": hashlib.md5(),
                "SHA-1": hashlib.sha1(),
                "SHA-256": hashlib.sha256(),
                "SHA-512": hashlib.sha512(),
                "SHA3-256": hashlib.sha3_256(),
                "SHA3-512": hashlib.sha3_512(),
                "BLAKE2b": hashlib.blake2b(),
                "BLAKE2s": hashlib.blake2s(),
            }
            crc32 = 0
            shake128 = hashlib.shake_128()
            shake256 = hashlib.shake_256()
            processed = 0
            progress_update_threshold = 4 * 1024 * 1024
            last_update = 0
            with open(filepath, "rb") as f:
                while not self._stop_event.is_set():
                    chunk = f.read(chunk_size)
                    if not chunk:
                        break
                    for h in hashes.values():
                        h.update(chunk)
                    crc32 = zlib.crc32(chunk, crc32)
                    shake128.update(chunk)
                    shake256.update(chunk)
                    processed += len(chunk)
                    if processed - last_update >= progress_update_threshold:
                        last_update = processed
                        self.queue.put(("progress_update", processed))
            result = {k: v.hexdigest() for k, v in hashes.items()}
            result["SHAKE128 (64)"] = shake128.hexdigest(64)
            result["SHAKE256 (64)"] = shake256.hexdigest(64)
            result["CRC32"] = format(crc32 & 0xFFFFFFFF, "08x")
            if filepath.lower().endswith(('.exe', '.dll', '.sys')):
                try:
                    pe_hashes = self._calculate_pe_hashes(filepath)
                    result.update(pe_hashes)
                except Exception as e:
                    result["PE-hashes"] = f"Error: {str(e)}"
            result["File path"] = filepath
            result["File size (bytes)"] = str(filesize)
            self.queue.put(("file_result", result))
            self.queue.put(("progress_update", filesize))
        except Exception as e:
            self.queue.put(("error", str(e)))
        finally:
            with self._worker_lock:
                self.current_worker = None
            self.queue.put(("done", None))

    def _calculate_pe_hashes(self, filepath):
        pe_hashes = {}
        pe = pefile.PE(filepath)
        try:
            security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
            if security_dir.VirtualAddress != 0:
                try:
                    raw = pe.write()
                    start = security_dir.VirtualAddress + 8
                    if start < len(raw):
                        pe_hashes["Authentihash"] = hashlib.sha256(raw[start:]).hexdigest()
                    else:
                        pe_hashes["Authentihash"] = "Not found"
                except Exception:
                    pe_hashes["Authentihash"] = "Error"
            else:
                pe_hashes["Authentihash"] = "Not found"
        except Exception:
            pe_hashes["Authentihash"] = "Error"
        try:
            pe_hashes["Imphash"] = pe.get_imphash()
        except Exception:
            pe_hashes["Imphash"] = "Error"
        try:
            pe_hashes["Vhash"] = hashlib.sha256(pe.__data__).hexdigest()
        except Exception:
            pe_hashes["Vhash"] = "Error"
        if hasattr(pe, "RICH_HEADER") and pe.RICH_HEADER:
            try:
                pe_hashes["Rich Header MD5"] = hashlib.md5(pe.RICH_HEADER.raw_data).hexdigest()
            except Exception:
                pe_hashes["Rich Header MD5"] = "Error"
        pe.close()
        return pe_hashes

    def _calc_hashes_bytes(self, data):
        return {
            "MD5": hashlib.md5(data).hexdigest(),
            "SHA-1": hashlib.sha1(data).hexdigest(),
            "SHA-256": hashlib.sha256(data).hexdigest(),
            "SHA-512": hashlib.sha512(data).hexdigest(),
            "SHA3-256": hashlib.sha3_256(data).hexdigest(),
            "SHA3-512": hashlib.sha3_512(data).hexdigest(),
            "BLAKE2b": hashlib.blake2b(data).hexdigest(),
            "BLAKE2s": hashlib.blake2s(data).hexdigest(),
            "SHAKE128 (64)": hashlib.shake_128(data).hexdigest(64),
            "SHAKE256 (64)": hashlib.shake_256(data).hexdigest(64),
            "CRC32": format(zlib.crc32(data) & 0xFFFFFFFF, "08x"),
        }

    def _poll_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                kind, payload = item
                if kind == "text_result":
                    self._display_results(self.text_results, payload)
                elif kind == "file_result":
                    self._display_results(self.file_results, payload)
                    self.progress_label.config(text=self.lang["hashing_done"])
                elif kind == "progress_set_max":
                    self.progress["maximum"] = payload
                    self.progress["value"] = 0
                    self.progress_label.config(text=self.lang["progress_size"].format(mb=payload / (1024 ** 2)))
                elif kind == "progress_update":
                    self.progress["value"] = payload
                elif kind == "done":
                    self.progress_label.config(text=self.lang["hashing_done"])
                elif kind == "error":
                    messagebox.showerror(self.lang["error"], payload)
        except queue.Empty:
            pass
        if not self._stop_event.is_set():
            self.root.after(150, self._poll_queue)

    def _display_results(self, text_widget, results: dict):
        text_widget.config(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)
        for name, value in results.items():
            text_widget.insert(tk.END, f"{name}:\n{value}\n\n")
        text_widget.config(state=tk.DISABLED)

    def on_close(self):
        self.hide_to_tray()

    def hide_to_tray(self):
        if self.tray_icon is None:
            self._start_tray_icon()
        self.root.withdraw()

    def _on_minimize(self, event):
        if self.root.state() == "iconic":
            self.hide_to_tray()

    def _start_tray_icon(self):
        image = Image.new("RGB", (64, 64), color=(40, 40, 40))
        dc = ImageDraw.Draw(image)
        dc.rectangle((12, 12, 52, 52), fill=(30, 150, 30))

        def on_show(icon, item):
            self.root.after(0, self._restore_window)

        def on_exit(icon, item):
            icon.stop()
            self._stop_event.set()
            self.root.after(0, self._final_exit)

        menu = pystray.Menu(
            pystray.MenuItem(self.lang["show"], on_show),
            pystray.MenuItem(self.lang["exit"], on_exit)
        )
        self.tray_icon = pystray.Icon("hashfile", image, "Hashfile", menu)

        def tray_run():
            try:
                self.tray_icon.run()
            except Exception:
                pass

        self.tray_thread = threading.Thread(target=tray_run, daemon=True)
        self.tray_thread.start()

    def _restore_window(self):
        try:
            self.root.deiconify()
            self.root.lift()
            self.root.focus_force()
        except Exception:
            pass

    def _final_exit(self):
        try:
            if self.tray_icon:
                try:
                    self.tray_icon.stop()
                except Exception:
                    pass
            self._stop_event.set()
            time.sleep(0.15)
        finally:
            try:
                self.root.quit()
            except Exception:
                os._exit(0)


if __name__ == "__main__":
    root = tk.Tk()
    app = HashCalculatorApp(root)
    root.mainloop()
