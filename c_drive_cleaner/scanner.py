# -*- coding: utf-8 -*-
"""
C盘清理工具 - 扫描模块
负责扫描系统垃圾文件
"""

import os
import ctypes
from pathlib import Path
from typing import Dict, List, Callable, Optional
from dataclasses import dataclass, field
import winreg

from config import CLEANUP_ITEMS, DEVELOPER_CLEAN_RULES, AGE_THRESHOLD_DAYS
import time


@dataclass
class ScanResult:
    """扫描结果数据类"""
    item_id: str
    item_name: str
    total_size: int = 0
    file_count: int = 0
    files: List[str] = field(default_factory=list)
    error: Optional[str] = None


class Scanner:
    """垃圾文件扫描器"""
    
    def __init__(self, progress_callback: Callable[[str, int], None] = None, drive: str = "C:"):
        """
        初始化扫描器
        
        Args:
            progress_callback: 进度回调函数，参数为(当前扫描项名称, 进度百分比)
            drive: 要扫描的盘符 (如 "C:", "D:", 或 "ALL")
        """
        self.progress_callback = progress_callback
        self.drive = drive.upper().replace("\\", "")
        self.results: Dict[str, ScanResult] = {}
        self._cancelled = False
    
    @staticmethod
    def get_available_drives() -> List[str]:
        """获取所有可用本地驱动器"""
        try:
            import psutil
            drives = []
            for part in psutil.disk_partitions(all=False):
                if 'fixed' in part.opts.lower() or part.fstype:
                    drives.append(part.device.replace("\\", ""))
            return sorted(drives)
        except:
            return ["C:"]

    def cancel(self):
        """取消扫描"""
        self._cancelled = True
    
    def scan_all(self) -> Dict[str, ScanResult]:
        """
        扫描所有配置的清理项目
        
        Returns:
            包含所有扫描结果的字典
        """
        self._cancelled = False
        self.results.clear()
        
        total_items = len(CLEANUP_ITEMS)
        
        for index, item in enumerate(CLEANUP_ITEMS):
            if self._cancelled:
                break
                
            item_id = item["id"]
            item_name = item["name"]
            
            # 如果不是全盘扫描，且路径不属于该盘符，可能需要跳过或重定向
            # 但这里我们保持逻辑：如果是 ALL，则为每个盘符执行规则；如果是特定盘，则只执行该盘的规则
            
            if self.progress_callback:
                progress = int((index / total_items) * 100)
                self.progress_callback(item_name, progress)
            
            # 特殊处理回收站
            if item.get("special") == "recycle_bin":
                if self.drive == "ALL":
                    result = self._scan_recycle_bin(item_id, item_name, None)
                else:
                    result = self._scan_recycle_bin(item_id, item_name, self.drive + "\\")
            elif item.get("special") == "developer_mode":
                result = self._scan_developer_junk(item_id, item_name)
            else:
                result = self._scan_item(item)
            
            self.results[item_id] = result
        
        if self.progress_callback:
            self.progress_callback("扫描完成", 100)
        
        return self.results
    
    def _scan_item(self, item: dict) -> ScanResult:
        """
        扫描单个清理项目
        
        Args:
            item: 清理项目配置
            
        Returns:
            扫描结果
        """
        result = ScanResult(
            item_id=item["id"],
            item_name=item["name"]
        )
        
        paths = item.get("paths", [])
        extensions = item.get("extensions")
        pattern = item.get("pattern")
        
        for path_template in paths:
            if self._cancelled:
                break
            
            # 处理路径盘符：如果配置是硬编码的 C:\，在扫描其他盘时需要转换
            target_paths = []
            if self.drive == "ALL":
                # 对于 ALL，如果路径包含盘符，尝试替换为所有可用盘符
                if path_template.lower().startswith("c:"):
                    for d in self.get_available_drives():
                        target_paths.append(d + path_template[2:])
                else:
                    target_paths.append(path_template)
            else:
                # 对于特定盘，如果是 C:\ 开头的路径，替换为目标盘符
                if path_template.lower().startswith("c:"):
                    target_paths.append(self.drive + path_template[2:])
                else:
                    target_paths.append(path_template)

            for path in target_paths:
                if not os.path.exists(path):
                    continue
                
                try:
                    self._scan_directory(
                        path, 
                        result, 
                        extensions=extensions,
                        pattern=pattern
                    )
                except PermissionError:
                    result.error = "权限不足，需要管理员权限"
                except Exception as e:
                    result.error = str(e)
        
        return result
    
    def _scan_directory(
        self, 
        directory: str, 
        result: ScanResult,
        extensions: List[str] = None,
        pattern: str = None
    ):
        """
        递归扫描目录
        
        Args:
            directory: 目录路径
            result: 扫描结果对象
            extensions: 文件扩展名过滤
            pattern: 路径模式匹配
        """
        try:
            for entry in os.scandir(directory):
                if self._cancelled:
                    return
                    
                try:
                    if entry.is_file(follow_symlinks=False):
                        # 检查扩展名过滤
                        if extensions:
                            ext = Path(entry.path).suffix.lower()
                            if ext not in extensions:
                                continue
                        
                        # 检查模式匹配
                        if pattern and pattern.lower() not in entry.path.lower():
                            continue
                        
                        size = entry.stat().st_size
                        result.total_size += size
                        result.file_count += 1
                        result.files.append(entry.path)
                        
                    elif entry.is_dir(follow_symlinks=False):
                        # 检查模式匹配（目录级别）
                        if pattern and pattern.lower() not in entry.path.lower():
                            # 继续递归，但不统计此目录下的文件
                            self._scan_directory(entry.path, result, extensions, pattern)
                        else:
                            self._scan_directory(entry.path, result, extensions, None if pattern else None)
                            
                except (PermissionError, OSError):
                    # 跳过无权限访问的文件
                    continue
                    
        except (PermissionError, OSError):
            pass
    
    def _scan_recycle_bin(self, item_id: str, item_name: str, drive_path: Optional[str] = None) -> ScanResult:
        """
        扫描回收站
        
        Args:
            item_id: 项目ID
            item_name: 项目名称
            drive_path: 特定盘符路径 (如 "C:\\")，None 表示所有盘
            
        Returns:
            扫描结果
        """
        result = ScanResult(item_id=item_id, item_name=item_name)
        
        try:
            # 使用 Windows Shell API 获取回收站大小
            shell32 = ctypes.windll.shell32
            
            # SHQUERYRBINFO 结构体
            class SHQUERYRBINFO(ctypes.Structure):
                _fields_ = [
                    ("cbSize", ctypes.c_ulong),
                    ("i64Size", ctypes.c_longlong),
                    ("i64NumItems", ctypes.c_longlong),
                ]
            
            info = SHQUERYRBINFO()
            info.cbSize = ctypes.sizeof(SHQUERYRBINFO)
            
            # 查询回收站 (None 表示所有驱动器)
            ret = shell32.SHQueryRecycleBinW(drive_path, ctypes.byref(info))
            
            if ret == 0:  # S_OK
                result.total_size = info.i64Size
                result.file_count = info.i64NumItems
            else:
                result.error = "无法获取回收站信息"
                
        except Exception as e:
            result.error = str(e)
        
        return result
    
    def _scan_developer_junk(self, item_id: str, item_name: str) -> ScanResult:
        """
        深度扫描开发者相关的过期项目文件
        """
        result = ScanResult(item_id=item_id, item_name=item_name)
        now = time.time()
        threshold_seconds = AGE_THRESHOLD_DAYS * 24 * 3600
        
        # 确定扫描盘符
        drives = self.get_available_drives() if self.drive == "ALL" else [self.drive]
        
        # 排除目录
        skip_dirs = {
            "windows", "program files", "program files (x86)", 
            "programdata", "appdata", ".git", ".svn", "system volume information",
            "$recycle.bin", "recovery", "msocache"
        }

        for drive in drives:
            drive_path = drive + "\\"
            if not os.path.exists(drive_path):
                continue
            
            # 限制递归深度以保证性能
            self._depth_search(drive_path, result, now, threshold_seconds, skip_dirs, depth=0, max_depth=6)
            
            if self._cancelled:
                break
                
        return result

    def _depth_search(self, path: str, result: ScanResult, now: float, threshold: float, skip_dirs: set, depth: int, max_depth: int):
        """递归深度搜索开发者垃圾"""
        if self._cancelled or depth > max_depth:
            return
            
        try:
            for entry in os.scandir(path):
                if self._cancelled:
                    return
                
                try:
                    if entry.is_dir(follow_symlinks=False):
                        name_lower = entry.name.lower()
                        
                        # 检查是否为目标清理目录
                        if name_lower in DEVELOPER_CLEAN_RULES:
                            mtime = entry.stat().st_mtime
                            # 如果文件夹超过阈值未更新，记录
                            if (now - mtime) > threshold:
                                size = self._get_dir_size_for_scan(entry.path)
                                result.total_size += size
                                result.file_count += 1
                                result.files.append(entry.path)
                                # 识别到目标后，不再进入该目录深层
                                continue
                        
                        # 如果不是目标目录，检查是否需要跳过并继续递归
                        if name_lower in skip_dirs or entry.name.startswith('.'):
                            continue
                            
                        self._depth_search(entry.path, result, now, threshold, skip_dirs, depth + 1, max_depth)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass

    def _get_dir_size_for_scan(self, path: str) -> int:
        """扫描期间专用的目录大小获取逻辑"""
        total = 0
        try:
            for entry in os.scandir(path):
                try:
                    if entry.is_file(follow_symlinks=False):
                        total += entry.stat().st_size
                    elif entry.is_dir(follow_symlinks=False):
                        total += self._get_dir_size_for_scan(entry.path)
                except (PermissionError, OSError):
                    continue
        except (PermissionError, OSError):
            pass
        return total

    def get_total_size(self) -> int:
        """获取所有扫描结果的总大小"""
        return sum(r.total_size for r in self.results.values())
    
    def get_selected_size(self, selected_ids: List[str]) -> int:
        """获取选中项目的总大小"""
        return sum(
            self.results[id].total_size 
            for id in selected_ids 
            if id in self.results
        )


def format_size(size_bytes: int) -> str:
    """
    格式化文件大小显示
    
    Args:
        size_bytes: 字节大小
        
    Returns:
        格式化后的字符串
    """
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.2f} GB"
