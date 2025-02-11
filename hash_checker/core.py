import hashlib
import os
from typing import Optional, Callable

class HashCalculator:
    def __init__(self):
        self.chunk_size = 1024 * 1024  # 1MB chunks
        self.progress_callback: Optional[Callable] = None

    def calculate_hash(self, file_path: str, hash_type: str = "sha256") -> str:
        """计算文件哈希值"""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"文件不存在: {file_path}")

        hash_func = getattr(hashlib, hash_type)()
        total_size = os.path.getsize(file_path)
        processed = 0

        with open(file_path, "rb") as f:
            while chunk := f.read(self.chunk_size):
                hash_func.update(chunk)
                processed += len(chunk)
                if self.progress_callback:
                    self.progress_callback(processed / total_size * 100)

        return hash_func.hexdigest()

    @staticmethod
    def get_example_hash(hash_type: str) -> str:
        """获取示例哈希值"""
        examples = {
            "md5": "d41d8cd98f00b204e9800998ecf8427e",  # 空文件
            "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",  # 空文件
            "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # 空文件
            "sha512": "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"  # 空文件
        }
        return examples.get(hash_type, "")