import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import os
import threading
import queue

class HashCheckerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("文件哈希校验工具")
        self.root.geometry("600x450")
        
        self.file_path = tk.StringVar()
        self.selected_hash = tk.StringVar(value="sha256")
        self.calculated_hash = tk.StringVar()
        self.expected_hash = tk.StringVar()
        self.progress = tk.DoubleVar()
        self.running = False
        
        self.create_widgets()
        self.progress_queue = queue.Queue()
        self.check_progress()

    def create_widgets(self):
        # 文件选择部分
        file_frame = ttk.Frame(self.root, padding="10")
        file_frame.pack(fill=tk.X)
        
        ttk.Label(file_frame, text="选择文件:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(file_frame, textvariable=self.file_path, width=50).grid(row=0, column=1)
        ttk.Button(file_frame, text="浏览...", command=self.select_file).grid(row=0, column=2)
        
        # 哈希算法选择
        hash_frame = ttk.Frame(self.root, padding="10")
        hash_frame.pack(fill=tk.X)
        
        ttk.Label(hash_frame, text="哈希算法:").grid(row=0, column=0, sticky=tk.W)
        hash_combo = ttk.Combobox(
            hash_frame,
            textvariable=self.selected_hash,
            values=["md5", "sha1", "sha256", "sha512"],
            state="readonly"
        )
        hash_combo.grid(row=0, column=1, sticky=tk.W)
        
        # 进度条
        progress_frame = ttk.Frame(self.root, padding="10")
        progress_frame.pack(fill=tk.X)
        
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress,
            maximum=100,
            mode="determinate"
        )
        self.progress_bar.pack(fill=tk.X)
        
        # 计算哈希部分
        calc_frame = ttk.Frame(self.root, padding="10")
        calc_frame.pack(fill=tk.X)
        
        self.calc_button = ttk.Button(calc_frame, text="计算哈希值", command=self.start_calculation)
        self.calc_button.pack(side=tk.LEFT)
        ttk.Entry(calc_frame, textvariable=self.calculated_hash, width=70, state="readonly").pack(side=tk.LEFT, padx=10)
        
        # 校验哈希部分
        verify_frame = ttk.Frame(self.root, padding="10")
        verify_frame.pack(fill=tk.X)
        
        ttk.Label(verify_frame, text="预期哈希值:").pack(side=tk.LEFT)
        ttk.Entry(verify_frame, textvariable=self.expected_hash, width=50).pack(side=tk.LEFT, padx=5)
        ttk.Button(verify_frame, text="校验", command=self.verify_hash).pack(side=tk.LEFT)
        
        # 信息提示
        self.status_label = ttk.Label(self.root, text="", foreground="red")
        self.status_label.pack(pady=10)

    def select_file(self):
        if self.running:
            return
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)
            self.calculated_hash.set("")
            self.status_label.config(text="")

    def start_calculation(self):
        if self.running:
            return
        
        file_path = self.file_path.get()
        if not os.path.exists(file_path):
            self.status_label.config(text="错误：文件不存在！")
            return
        
        self.running = True
        self.calc_button.config(state=tk.DISABLED)
        self.progress.set(0)
        self.status_label.config(text="开始计算...")
        
        threading.Thread(
            target=self.calculate_hash,
            args=(file_path, self.selected_hash.get()),
            daemon=True
        ).start()

    def calculate_hash(self, file_path, hash_type):
        try:
            hash_func = getattr(hashlib, hash_type)()
            total_size = os.path.getsize(file_path)
            processed = 0
            chunk_size = 1024*1024  # 1MB chunks

            with open(file_path, "rb") as f:
                while chunk := f.read(chunk_size):
                    hash_func.update(chunk)
                    processed += len(chunk)
                    progress = processed / total_size * 100
                    self.progress_queue.put(progress)

            self.progress_queue.put(("result", hash_func.hexdigest()))
        except Exception as e:
            self.progress_queue.put(("error", str(e)))

    def check_progress(self):
        while not self.progress_queue.empty():
            data = self.progress_queue.get()
            if isinstance(data, float):
                self.progress.set(data)
                self.status_label.config(text=f"计算进度: {data:.1f}%")
            elif data[0] == "result":
                self.calculated_hash.set(data[1])
                self.status_label.config(text="计算完成！")
                self.running = False
                self.calc_button.config(state=tk.NORMAL)
            elif data[0] == "error":
                self.status_label.config(text=f"错误：{data[1]}")
                self.running = False
                self.calc_button.config(state=tk.NORMAL)
        self.root.after(100, self.check_progress)

    def verify_hash(self):
        if self.running:
            return
        
        expected = self.expected_hash.get().strip().lower()
        actual = self.calculated_hash.get().lower()
        
        if not expected:
            self.status_label.config(text="错误：请输入预期哈希值！")
            return
        if not actual:
            self.status_label.config(text="错误：请先计算文件哈希值！")
            return
        
        if expected == actual:
            messagebox.showinfo("校验结果", "哈希值匹配！")
            self.status_label.config(text="校验成功：哈希值匹配！")
        else:
            messagebox.showerror("校验结果", "哈希值不匹配！")
            self.status_label.config(text="校验失败：哈希值不匹配！")

if __name__ == "__main__":
    root = tk.Tk()
    app = HashCheckerApp(root)
    root.mainloop()