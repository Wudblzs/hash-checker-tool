import tkinter as tk
from tkinter import ttk

class ProgressWindow(tk.Toplevel):
    """进度条窗口组件"""
    def __init__(self, parent):
        super().__init__(parent)
        self.progress_var = tk.DoubleVar()
        self._setup_ui()

    def _setup_ui(self):
        self.title("处理进度")
        self.geometry("300x80")
        ttk.Label(self, text="计算进度:").pack(pady=5)
        ttk.Progressbar(
            self,
            variable=self.progress_var,
            maximum=100
        ).pack(fill=tk.X, padx=10)