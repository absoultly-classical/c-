# -*- coding: utf-8 -*-
"""
C盘清理工具 - 配置文件
定义清理规则和路径
"""

import os
from pathlib import Path

# 获取环境变量路径
TEMP_PATH = os.environ.get('TEMP', r'C:\Users\Default\AppData\Local\Temp')
LOCALAPPDATA = os.environ.get('LOCALAPPDATA', r'C:\Users\Default\AppData\Local')
USERPROFILE = os.environ.get('USERPROFILE', r'C:\Users\Default')

# 清理项目配置
# 每个项目包含: name(名称), paths(路径列表), description(描述), risk(风险等级), enabled(默认启用)
CLEANUP_ITEMS = [
    {
        "id": "user_temp",
        "name": "用户临时文件",
        "description": "应用程序生成的临时文件",
        "paths": [TEMP_PATH],
        "extensions": None,  # None表示所有文件
        "risk": "low",
        "enabled": True
    },
    {
        "id": "system_temp",
        "name": "系统临时文件",
        "description": "Windows 系统临时文件",
        "paths": [r"C:\Windows\Temp"],
        "extensions": None,
        "risk": "low",
        "enabled": True
    },
    {
        "id": "chrome_cache",
        "name": "Chrome 浏览器缓存",
        "description": "Google Chrome 缓存文件",
        "paths": [
            os.path.join(LOCALAPPDATA, r"Google\Chrome\User Data\Default\Cache"),
            os.path.join(LOCALAPPDATA, r"Google\Chrome\User Data\Default\Code Cache"),
            os.path.join(LOCALAPPDATA, r"Google\Chrome\User Data\Default\GPUCache"),
        ],
        "extensions": None,
        "risk": "low",
        "enabled": True
    },
    {
        "id": "edge_cache",
        "name": "Edge 浏览器缓存",
        "description": "Microsoft Edge 缓存文件",
        "paths": [
            os.path.join(LOCALAPPDATA, r"Microsoft\Edge\User Data\Default\Cache"),
            os.path.join(LOCALAPPDATA, r"Microsoft\Edge\User Data\Default\Code Cache"),
            os.path.join(LOCALAPPDATA, r"Microsoft\Edge\User Data\Default\GPUCache"),
        ],
        "extensions": None,
        "risk": "low",
        "enabled": True
    },
    {
        "id": "firefox_cache",
        "name": "Firefox 浏览器缓存",
        "description": "Mozilla Firefox 缓存文件",
        "paths": [
            os.path.join(LOCALAPPDATA, r"Mozilla\Firefox\Profiles"),
        ],
        "extensions": None,
        "risk": "low",
        "enabled": True,
        "pattern": "cache2"  # 只清理cache2目录下的内容
    },
    {
        "id": "windows_update",
        "name": "Windows 更新缓存",
        "description": "已下载的 Windows 更新安装包",
        "paths": [r"C:\Windows\SoftwareDistribution\Download"],
        "extensions": None,
        "risk": "medium",
        "enabled": False  # 默认不启用，因为可能需要管理员权限
    },
    {
        "id": "thumbnail_cache",
        "name": "缩略图缓存",
        "description": "Windows 资源管理器缩略图缓存",
        "paths": [
            os.path.join(LOCALAPPDATA, r"Microsoft\Windows\Explorer"),
        ],
        "extensions": [".db"],
        "pattern": "thumbcache",
        "risk": "low",
        "enabled": True
    },
    {
        "id": "windows_logs",
        "name": "Windows 日志文件",
        "description": "系统和应用程序日志",
        "paths": [
            r"C:\Windows\Logs",
            os.path.join(LOCALAPPDATA, r"Temp"),
        ],
        "extensions": [".log", ".txt", ".etl"],
        "risk": "medium",
        "enabled": False
    },
    {
        "id": "prefetch",
        "name": "预读取文件",
        "description": "Windows 预读取缓存",
        "paths": [r"C:\Windows\Prefetch"],
        "extensions": [".pf"],
        "risk": "medium",
        "enabled": False
    },
    {
        "id": "recycle_bin",
        "name": "回收站",
        "description": "已删除的文件",
        "paths": [],  # 回收站需要特殊处理
        "extensions": None,
        "risk": "low",
        "enabled": True,
        "special": "recycle_bin"
    },
    {
        "id": "recent_files",
        "name": "最近文件记录",
        "description": "最近访问的文件快捷方式",
        "paths": [
            os.path.join(USERPROFILE, r"AppData\Roaming\Microsoft\Windows\Recent"),
        ],
        "extensions": [".lnk"],
        "risk": "low",
        "enabled": False
    },
    {
        "id": "error_reports",
        "name": "错误报告",
        "description": "Windows 错误报告文件",
        "paths": [
            os.path.join(LOCALAPPDATA, r"Microsoft\Windows\WER"),
            r"C:\ProgramData\Microsoft\Windows\WER",
        ],
        "extensions": None,
        "risk": "low",
        "enabled": True
    },
    {
        "id": "developer_junk",
        "name": "过期开发项目(node_modules/target等)",
        "description": "识别超过半年未变动的开发项目中间件",
        "paths": [], # 由扫描器动态全盘搜索
        "extensions": None,
        "risk": "high",
        "enabled": False,
        "special": "developer_mode"
    },
]

# 风险等级颜色
RISK_COLORS = {
    "low": "#4CAF50",      # 绿色
    "medium": "#FF9800",   # 橙色
    "high": "#F44336",     # 红色
}

# 开发者智能清理配置
# 定义需要扫描的项目中间文件夹
DEVELOPER_CLEAN_RULES = {
    "node_modules": "Node.js 依赖",
    "venv": "Python 虚拟环境",
    ".venv": "Python 虚拟环境",
    "target": "Java/Rust 编译产物",
    "bin": "C#/C++ 编译产物",
    "obj": "C#/C++ 编译中间件",
    ".gradle": "Gradle 缓存",
    ".idea": "JetBrains 项目配置",
}

# 时间阈值：天数（默认180天，即半年未动过的项目）
AGE_THRESHOLD_DAYS = 180

# UI 配置
UI_CONFIG = {
    "window_title": "C盘清理大师 Pro",
    "window_size": "850x750",
    "theme": "dark-blue",
    "accent_color": "#1f538d",
}
