# 🧹 C盘清理大师 Pro (C Drive Cleaner Pro)

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![UI](https://img.shields.io/badge/UI-CustomTkinter-orange.svg)](https://github.com/TomSchimansky/CustomTkinter)

一个专为 Windows 打造的现代化、专业级磁盘空间清理工具。基于 Python + CustomTkinter 开发，提供极速扫描、深度清理和极简的交互体验。

![C盘清理大师 Pro 预览](./preview.png)

## ✨ Pro 版核心功能

- � **全盘扫描支持** - 不止是 C 盘！现已支持扫描所有本地磁盘（D:, E: 等）及一键进行“全盘大扫除”。
- 🧠 **开发者智能清理** - 专为程序员打造！自动识别并清理超过 180 天未变动的开发项目冗余文件（如 `node_modules`, `venv`, `target`, `bin/obj` 等）。
- 📊 **可视化存储状态** - 实时显示磁盘占用比例、可用空间及预计清理后的空间，状态一目了然。
- 🛡️ **安全风险分级** - 每个清理项都标记了风险等级（低/中/高），并默认仅选中安全项，保护重要系统数据。
- 🎨 **极致现代 UI** - 采用深色模式设计，配备平滑的进度条、动态日志控制台和毛玻璃质感界面。
- 📝 **实时操作日志** - 详细记录每一个文件的清理状态，确保过程透明可追溯。

## 🗂️ 深度清理覆盖范围

| 分类 | 清理项目 | 风险等级 | 说明 |
|------|----------|----------|------|
| **基础清理** | 用户/系统临时文件 | 🟢 低 | 释放应用缓存和系统残留 |
| **浏览器** | Chrome/Edge/Firefox | 🟢 低 | 清理缓存、代码缓存和 GPU 缓存 |
| **系统维护** | Windows 更新缓存 | 🟡 中 | 移除已过期的系统更新安装包 |
| **视觉缓存** | 缩略图/预读取文件 | 🟢 低 | 刷新图标和系统预加载数据 |
| **个人痕迹** | 最近文件/回收站 | 🟡 中 | 彻底清除已删除数据和访问历史 |
| **开发者** | **Stale Dev Materials** | � 高 | 智能识别半年未动过的 node_modules/venv 等 |

## � 快速开始

### 1. 环境准备
确保已安装 Python 3.10 或更高版本。

### 2. 安装依赖
```bash
pip install -r requirements.txt
```

### 3. 运行程序
**建议以管理员身份运行**，以确保能够清理系统目录：
```bash
python main.py
```

## 🛠️ 打包为独立程序 (EXE)

如果你想在其他没有 Python 环境的电脑上使用，可以使用 PyInstaller 打包：

```bash
pip install pyinstaller
pyinstaller --noconfirm --onefile --windowed --icon=icon.ico --name="C盘清理大师Pro" --add-data "ui;ui" --add-data "utils;utils" main.py
```

## � 项目结构

```text
c_drive_cleaner/
├── main.py              # 程序启动入口
├── config.py            # 全局配置中心 (包含清理规则 & UI 样式)
├── scanner.py           # 核心扫描引擎 (支持正则匹配 & 深度检测)
├── cleaner.py           # 安全清理执行器 (支持文件占用重试)
├── ui/                  # UI 组件库
│   └── main_window.py   # 现代化的 CustomTkinter 主窗口
├── utils/               # 通用工具类
└── requirements.txt     # 项目依赖
```

## 🔧 技术选型

- **Frontend**: CustomTkinter (现代化 GUI)
- **Engine**: Python OS/Stat API & Windows Shell API
- **Monitoring**: psutil (磁盘实时状态监控)

## ⚠️ 免责声明

本工具旨在帮助用户通过清理冗余文件来释放空间。虽然我们设置了严格的安全规则，但在清理标记为 **[!] 高风险** 的项目（如开发者模式清理）时，请务必确认相关项目不再需要。作者对因误删导致的数据丢失不承担责任。

---

**C盘清理大师 Pro** —— 让你的 Windows 运行如飞。
