import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from queue import Queue
import os
import sys
import threading
from .core import HashCalculator

class HashCheckerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("文件哈希校验工具")
        self.root.geometry("650x480")
        
        # 初始化变量
        self.file_path = tk.StringVar()
        self.selected_hash = tk.StringVar(value="sha256")
        self.calculated_hash = tk.StringVar()
        self.expected_hash = tk.StringVar(value="在此输入哈希值（如：b94d27b...）")
        self.progress = tk.DoubleVar()
        self.running = False
        
        # 初始化组件
        self._setup_ui()
        self.hash_calculator = HashCalculator()
        self.progress_queue = Queue()
        self._setup_bindings()
        self._setup_placeholder_style()
        self._setup_hash_events()
        
        # 启动进度检查
        self.check_progress()

    def _setup_ui(self):
        """初始化用户界面组件"""
        # 文件选择部分
        file_frame = ttk.Frame(self.root, padding=10)
        file_frame.pack(fill=tk.X)
        
        ttk.Label(file_frame, text="选择文件:").grid(row=0, column=0, sticky=tk.W)
        ttk.Entry(file_frame, textvariable=self.file_path, width=50).grid(row=0, column=1)
        ttk.Button(file_frame, text="浏览...", command=self.select_file).grid(row=0, column=2)
        
        # 哈希算法选择
        hash_frame = ttk.Frame(self.root, padding=10)
        hash_frame.pack(fill=tk.X)
        
        ttk.Label(hash_frame, text="哈希算法:").grid(row=0, column=0, sticky=tk.W)
        self.hash_combo = ttk.Combobox(
            hash_frame,
            textvariable=self.selected_hash,
            values=["md5", "sha1", "sha256", "sha512"],
            state="readonly"
        )
        self.hash_combo.grid(row=0, column=1, sticky=tk.W)
        
        # 进度条
        progress_frame = ttk.Frame(self.root, padding=10)
        progress_frame.pack(fill=tk.X)
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress,
            maximum=100,
            mode="determinate"
        )
        self.progress_bar.pack(fill=tk.X)
        
        # 计算哈希部分
        calc_frame = ttk.Frame(self.root, padding=10)
        calc_frame.pack(fill=tk.X)
        self.calc_button = ttk.Button(calc_frame, text="计算哈希值", command=self.start_calculation)
        self.calc_button.pack(side=tk.LEFT)
        ttk.Entry(calc_frame, textvariable=self.calculated_hash, width=70, state="readonly").pack(side=tk.LEFT, padx=10)
        
        # 校验哈希部分
        verify_frame = ttk.Frame(self.root, padding=10)
        verify_frame.pack(fill=tk.X)
        ttk.Label(verify_frame, text="预期哈希值:").pack(side=tk.LEFT)
        self.verify_entry = ttk.Entry(
            verify_frame,
            textvariable=self.expected_hash,
            width=50,
            style="Placeholder.TEntry"
        )
        self.verify_entry.pack(side=tk.LEFT, padx=5)
        ttk.Button(verify_frame, text="校验", command=self.verify_hash).pack(side=tk.LEFT)
        
        # 状态提示
        self.status_label = ttk.Label(self.root, text="", foreground="red")
        self.status_label.pack(pady=10)

    def _setup_bindings(self):
        """设置事件绑定"""
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.verify_entry.bind("<FocusIn>", self._clear_placeholder)
        self.verify_entry.bind("<FocusOut>", self._restore_placeholder)

    def _setup_placeholder_style(self):
        """配置输入框提示文本样式"""
        style = ttk.Style()
        style.configure("Placeholder.TEntry", foreground="gray60")
        style.map(
            "Placeholder.TEntry",
            foreground=[("!focus", "gray60"), ("focus", "black")]
        )

    def _setup_hash_events(self):
        """绑定哈希算法选择事件"""
        self.hash_combo.bind("<<ComboboxSelected>>", self._update_hash_example)

    def _update_hash_example(self, event=None):
        """更新哈希示例"""
        if self.expected_hash.get() in ["", "在此输入哈希值（如：b94d27b...）"]:
            example = self.hash_calculator.get_example_hash(
                self.selected_hash.get()
            )
            self.expected_hash.set(f"示例：{example[:12]}...")

    def _clear_placeholder(self, event):
        """清除占位文本"""
        current_value = self.expected_hash.get()
        if current_value.startswith("示例：") or current_value == "在此输入哈希值（如：b94d27b...）":
            self.expected_hash.set("")

    def _restore_placeholder(self, event):
        """恢复占位文本"""
        if not self.expected_hash.get().strip():
            self.expected_hash.set("在此输入哈希值（如：b94d27b...）")

    def on_close(self):
        """处理窗口关闭事件"""
        if self.running:
            messagebox.showwarning("警告", "请等待当前计算完成！")
            return
        self.root.destroy()

    def select_file(self):
        """选择文件"""
        if self.running:
            return
        file_path = filedialog.askopenfilename()
        if file_path:
            self.file_path.set(file_path)
            self.calculated_hash.set("")
            self.status_label.config(text="")

    def start_calculation(self):
        """启动计算线程"""
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
        
        self.hash_calculator.progress_callback = self.update_progress
        
        threading.Thread(
            target=self._calculate_hash_thread,
            args=(file_path, self.selected_hash.get()),
            daemon=True
        ).start()

    def _calculate_hash_thread(self, file_path: str, hash_type: str):
        """计算哈希值的线程函数"""
        try:
            result = self.hash_calculator.calculate_hash(file_path, hash_type)
            self.progress_queue.put(("result", result))
        except Exception as e:
            self.progress_queue.put(("error", str(e)))

    def update_progress(self, value: float):
        """更新进度（由核心模块调用）"""
        self.progress_queue.put(("progress", value))

    def check_progress(self):
        """定期检查进度更新"""
        while not self.progress_queue.empty():
            data = self.progress_queue.get()
            
            if data[0] == "progress":
                self.progress.set(data[1])
                self.status_label.config(text=f"计算进度: {data[1]:.1f}%")
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
        """校验哈希值"""
        if self.running:
            return
        
        expected = self.expected_hash.get().strip().lower()
        actual = self.calculated_hash.get().lower()
        
        # 检查无效输入
        if expected in ["", "在此输入哈希值（如：b94d27b...）"]:
            self.status_label.config(text="错误：请输入有效的哈希值！")
            return
        if expected.startswith("示例："):
            self.status_label.config(text="错误：请替换示例哈希值！")
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