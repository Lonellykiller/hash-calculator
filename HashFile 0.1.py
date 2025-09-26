import tkinter as tk
from tkinter import ttk, filedialog, messagebox, Menu
import hashlib
import pefile
import os
import threading
import zlib

class HashCalculatorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("HashFile")
        self.root.geometry("1280x1024")
        
        self.create_widgets()
        self.setup_context_menu()

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.text_tab = ttk.Frame(self.notebook)
        self.file_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.text_tab, text="Текст")
        self.notebook.add(self.file_tab, text="Файл")

        self.create_text_tab()
        self.create_file_tab()

    def create_text_tab(self):
        self.text_label = ttk.Label(self.text_tab, text="Введите текст:")
        self.text_label.pack(pady=5)

        self.text_input = tk.Text(self.text_tab, height=10, wrap=tk.WORD)
        self.text_input.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        btn_frame = ttk.Frame(self.text_tab)
        btn_frame.pack(pady=5)

        self.calculate_text_btn = ttk.Button(
            btn_frame, text="Вычислить хэши", command=self.calculate_text_hashes
        )
        self.calculate_text_btn.pack(side=tk.LEFT, padx=5)

        self.copy_all_text_btn = ttk.Button(
            btn_frame, text="Копировать все",
            command=lambda: self.copy_to_clipboard(self.text_results)
        )
        self.copy_all_text_btn.pack(side=tk.LEFT, padx=5)

        self.text_results = tk.Text(self.text_tab, height=15, state=tk.DISABLED)
        self.text_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.text_results.bind("<Button-3>", self.show_context_menu)

    def create_file_tab(self):
        file_select_frame = ttk.Frame(self.file_tab)
        file_select_frame.pack(pady=5, fill=tk.X)

        self.file_label = ttk.Label(file_select_frame, text="Выберите файл:")
        self.file_label.pack(side=tk.LEFT, padx=5)

        self.file_path = tk.StringVar()
        self.file_entry = ttk.Entry(file_select_frame, textvariable=self.file_path, width=50)
        self.file_entry.pack(side=tk.LEFT, padx=5, expand=True, fill=tk.X)

        self.browse_btn = ttk.Button(file_select_frame, text="Обзор...", command=self.browse_file)
        self.browse_btn.pack(side=tk.LEFT, padx=5)

        btn_frame = ttk.Frame(self.file_tab)
        btn_frame.pack(pady=5)

        self.calculate_file_btn = ttk.Button(
            btn_frame, text="Вычислить хэши", command=self.run_hash_thread
        )
        self.calculate_file_btn.pack(side=tk.LEFT, padx=5)

        self.copy_all_file_btn = ttk.Button(
            btn_frame, text="Копировать все",
            command=lambda: self.copy_to_clipboard(self.file_results)
        )
        self.copy_all_file_btn.pack(side=tk.LEFT, padx=5)

        self.progress = ttk.Progressbar(self.file_tab, mode='determinate')
        self.progress.pack(fill=tk.X, padx=10, pady=(0, 5))

        self.progress_label = ttk.Label(self.file_tab, text="")
        self.progress_label.pack()

        self.file_results = tk.Text(self.file_tab, height=15, state=tk.DISABLED)
        self.file_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        self.file_results.bind("<Button-3>", self.show_context_menu)

    def setup_context_menu(self):
        self.context_menu = Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Копировать", command=self.copy_selected)
        self.context_menu.add_command(label="Копировать все", command=self.copy_all_from_active)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Выделить все", command=self.select_all)

    def show_context_menu(self, event):
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def copy_selected(self):
        active_widget = self.root.focus_get()
        if isinstance(active_widget, tk.Text):
            try:
                text = active_widget.get("sel.first", "sel.last")
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
            except tk.TclError:
                messagebox.showwarning("Ошибка", "Не выделен текст для копирования")

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
        text = text_widget.get("1.0", tk.END)
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        text_widget.config(state=tk.DISABLED)
        messagebox.showinfo("Копирование", "Все хэши скопированы в буфер обмена")

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def calculate_text_hashes(self):
        text = self.text_input.get("1.0", tk.END).encode('utf-8')
        if not text.strip():
            messagebox.showwarning("Ошибка", "Введите текст для вычисления хэшей")
            return

        size = len(text)
        results = {"Размер текста (байт)": str(size)}
        results.update(self.calculate_hashes(text))
        self.display_results(self.text_results, results)

    def run_hash_thread(self):
        threading.Thread(target=self.calculate_file_hashes, daemon=True).start()

    def calculate_file_hashes(self):
        filepath = self.file_path.get()
        if not filepath:
            messagebox.showwarning("Ошибка", "Выберите файл")
            return

        try:
            filesize = os.path.getsize(filepath)
            self.progress["maximum"] = filesize
            self.progress["value"] = 0
            self.progress_label.config(text=f"Размер файла: {filesize / (1024**2):.2f} МБ")

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

            chunk_size = 16 * 1024 * 1024
            with open(filepath, 'rb') as f:
                while chunk := f.read(chunk_size):
                    for h in hashes.values():
                        h.update(chunk)
                    crc32 = zlib.crc32(chunk, crc32)
                    shake128.update(chunk)
                    shake256.update(chunk)
                    self.progress["value"] += len(chunk)
                    self.root.update_idletasks()

            result = {k: v.hexdigest() for k, v in hashes.items()}
            result["SHAKE128 (64 байта)"] = shake128.hexdigest(64)
            result["SHAKE256 (64 байта)"] = shake256.hexdigest(64)
            result["CRC32"] = format(crc32 & 0xFFFFFFFF, '08x')

            if filepath.lower().endswith(('.exe', '.dll', '.sys')):
                try:
                    pe_hashes = self.calculate_pe_hashes(filepath)
                    result.update(pe_hashes)
                except Exception as e:
                    result["PE-хэши"] = f"Ошибка: {str(e)}"

            self.display_results(self.file_results, result)
            self.progress_label.config(text="Хэширование завершено")
        except Exception as e:
            messagebox.showerror("Ошибка", str(e))
            self.progress_label.config(text="Ошибка")

    def calculate_hashes(self, data):
        return {
            "MD5": hashlib.md5(data).hexdigest(),
            "SHA-1": hashlib.sha1(data).hexdigest(),
            "SHA-256": hashlib.sha256(data).hexdigest(),
            "SHA-512": hashlib.sha512(data).hexdigest(),
            "SHA3-256": hashlib.sha3_256(data).hexdigest(),
            "SHA3-512": hashlib.sha3_512(data).hexdigest(),
            "BLAKE2b": hashlib.blake2b(data).hexdigest(),
            "BLAKE2s": hashlib.blake2s(data).hexdigest(),
            "SHAKE128 (64 байта)": hashlib.shake_128(data).hexdigest(64),
            "SHAKE256 (64 байта)": hashlib.shake_256(data).hexdigest(64),
            "CRC32": format(zlib.crc32(data) & 0xFFFFFFFF, '08x'),
        }

    def calculate_pe_hashes(self, filepath):
        pe_hashes = {}
        pe = pefile.PE(filepath)
        security_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_SECURITY']]
        if security_dir.VirtualAddress != 0:
            pe_hashes["Authentihash"] = hashlib.sha256(pe.write()[security_dir.VirtualAddress + 8:]).hexdigest()
        else:
            pe_hashes["Authentihash"] = "Не найден"
        try:
            pe_hashes["Imphash"] = pe.get_imphash()
        except:
            pe_hashes["Imphash"] = "Ошибка"
        pe_hashes["Vhash"] = hashlib.sha256(pe.__data__).hexdigest()
        if hasattr(pe, 'RICH_HEADER'):
            pe_hashes["Rich Header Hash"] = hashlib.md5(pe.RICH_HEADER.raw_data).hexdigest()
        pe.close()
        return pe_hashes

    def display_results(self, text_widget, results):
        text_widget.config(state=tk.NORMAL)
        text_widget.delete("1.0", tk.END)
        for name, value in results.items():
            text_widget.insert(tk.END, f"{name}:\n{value}\n\n")
        text_widget.config(state=tk.DISABLED)

if __name__ == "__main__":
    root = tk.Tk()
    app = HashCalculatorApp(root)
    root.mainloop()
