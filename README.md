# 文件哈希校验工具

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

专业的文件完整性校验工具，支持多种哈希算法和大型文件处理。

## 功能特性

- 多哈希算法支持（MD5, SHA1, SHA256, SHA512）
- 大文件处理优化
- 实时进度显示
- 多线程计算
- 跨平台支持

## 安装使用

```bash
# 克隆仓库
git clone https://github.com/Wudblzs/hash-checker-tool.git

# 运行程序
python src/app/main.py

# 打包exe
pyinstaller -F -w \
--icon=resources/app_icon.ico \
main.py