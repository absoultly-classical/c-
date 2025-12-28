# -*- coding: utf-8 -*-
"""
C盘清理工具 - 主窗口 (优化版)
"""

import customtkinter as ctk
import threading
from typing import Dict, List
import sys
import os

# 添加父目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from scanner import Scanner, ScanResult, format_size
from cleaner import Cleaner, CleanResult, get_disk_usage
from config import CLEANUP_ITEMS, RISK_COLORS, UI_CONFIG


class MainWindow(ctk.CTk):
    """主窗口类"""
    
    def __init__(self):
        super().__init__()
        
        # 窗口配置
        self.title(UI_CONFIG["window_title"])
        self.geometry("850x750")  # 增加高度到 750，平衡可见性和空间
        self.resizable(False, False)
        
        # 设置主题
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # 数据
        self.scan_results: Dict[str, ScanResult] = {}
        self.scanner: Scanner = None
        self.cleaner: Cleaner = None
        self.is_scanning = False
        self.is_cleaning = False
        self.current_drive = "C:"
        self.available_drives = Scanner.get_available_drives()
        
        # 创建UI
        self._create_widgets()
        self._layout_widgets()
        
        # 初始化磁盘信息
        self._update_disk_info()
    
    def _create_widgets(self):
        """创建所有UI组件"""
        
        # ===== 顶部标题 =====
        self.header_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.title_label = ctk.CTkLabel(
            self.header_frame,
            text="🧹 C盘清理大师 Pro",
            font=ctk.CTkFont(size=28, weight="bold")
        )
        self.admin_label = ctk.CTkLabel(
            self.header_frame,
            text="管理员模式",
            font=ctk.CTkFont(size=12),
            text_color="#4CAF50",
            fg_color="#1E3A1E",
            corner_radius=5,
            padx=10
        )
        
        # ===== 驱动器选择区域 =====
        self.drive_select_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.drive_label = ctk.CTkLabel(
            self.drive_select_frame,
            text="选择清理对象:",
            font=ctk.CTkFont(size=13, weight="bold")
        )
        
        drive_options = self.available_drives + ["全部磁盘"]
        self.drive_menu = ctk.CTkOptionMenu(
            self.drive_select_frame,
            values=drive_options,
            command=self._on_drive_change,
            width=120
        )
        self.drive_menu.set("C:")
        
        # ===== 磁盘状态卡片 =====
        self.stats_frame = ctk.CTkFrame(self)
        
        self.disk_title = ctk.CTkLabel(
            self.stats_frame,
            text="存储状态",
            font=ctk.CTkFont(size=16, weight="bold")
        )
        
        self.disk_progress = ctk.CTkProgressBar(
            self.stats_frame,
            width=800,
            height=24,
            corner_radius=12
        )
        
        self.disk_info_label = ctk.CTkLabel(
            self.stats_frame,
            text="计算中...",
            font=ctk.CTkFont(size=13)
        )
        
        # ===== 核心进度条 (最显眼位置) =====
        self.progress_section = ctk.CTkFrame(self, fg_color="#2B2B2B", corner_radius=15)
        
        self.progress_title = ctk.CTkLabel(
            self.progress_section,
            text="当前操作进度",
            font=ctk.CTkFont(size=14, weight="bold")
        )
        
        self.operation_progress = ctk.CTkProgressBar(
            self.progress_section,
            width=750,
            height=15,
            corner_radius=10,
            progress_color="#3B8ED0"
        )
        self.operation_progress.set(0)
        
        self.progress_detail_label = ctk.CTkLabel(
            self.progress_section,
            text="准备就绪",
            font=ctk.CTkFont(size=12),
            text_color="#BBBBBB"
        )
        
        self.progress_percent_label = ctk.CTkLabel(
            self.progress_section,
            text="0%",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#3B8ED0"
        )
        
        # ===== 扫描结果滚动列表 =====
        self.results_frame = ctk.CTkFrame(self)
        
        self.results_header = ctk.CTkFrame(self.results_frame, fg_color="transparent")
        self.results_title_label = ctk.CTkLabel(
            self.results_header,
            text="发现的垃圾分类",
            font=ctk.CTkFont(size=15, weight="bold")
        )
        self.results_size_label = ctk.CTkLabel(
            self.results_header,
            text="共计: 0 B",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#4CAF50"
        )
        
        self.scrollable_frame = ctk.CTkScrollableFrame(
            self.results_frame,
            width=840,
            height=280
        )
        
        self.cleanup_checkboxes: Dict[str, ctk.CTkCheckBox] = {}
        
        # ===== 日志控制台 (反馈清理是否有用) =====
        self.log_textbox = ctk.CTkTextbox(
            self,
            height=100,
            font=ctk.CTkFont(size=11),
            text_color="#AAAAAA",
            fg_color="#1E1E1E"
        )
        self.log_textbox.insert("0.0", "--- 系统日志 ---\n等待操作...\n")
        self.log_textbox.configure(state="disabled")

        # ===== 底部控制栏 =====
        self.control_frame = ctk.CTkFrame(self, fg_color="transparent")
        
        self.scan_button = ctk.CTkButton(
            self.control_frame,
            text="🔍 开始全面扫描",
            command=self._on_scan_click,
            width=150,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold")
        )
        
        self.clean_button = ctk.CTkButton(
            self.control_frame,
            text="🗑️ 立即清理垃圾",
            command=self._on_clean_click,
            width=150,
            height=40,
            font=ctk.CTkFont(size=14, weight="bold"),
            fg_color="#E53935",
            hover_color="#C62828",
            state="disabled"
        )

        self.select_all_btn = ctk.CTkButton(
            self.control_frame,
            text="全选",
            command=self._select_all,
            width=80,
            height=40
        )

        self.deselect_all_btn = ctk.CTkButton(
            self.control_frame,
            text="全不选",
            command=self._deselect_all,
            width=80,
            height=40
        )
        
        self.tip_label = ctk.CTkLabel(
            self,
            text="💡 提示: 清理前请先手动关闭浏览器，清理后磁盘可用空间将即时更新。",
            font=ctk.CTkFont(size=11, slant="italic"),
            text_color="#FFA726"
        )
    
    def _layout_widgets(self):
        """缩减间距的布局组件"""
        self.header_frame.pack(pady=(10, 5), fill="x", padx=30)
        self.title_label.pack(side="left")
        self.admin_label.pack(side="right")
        
        self.drive_select_frame.pack(padx=30, pady=2, fill="x")
        self.drive_label.pack(side="left", padx=(5, 10))
        self.drive_menu.pack(side="left")
        
        self.stats_frame.pack(padx=30, pady=5, fill="x")
        self.disk_title.pack(pady=(5, 2))
        self.disk_progress.pack(pady=2, padx=20)
        self.disk_info_label.pack(pady=(2, 5))
        
        self.progress_section.pack(padx=30, pady=5, fill="x")
        self.progress_title.pack(pady=(5, 0))
        self.operation_progress.pack(pady=2)
        self.progress_percent_label.place(relx=0.9, rely=0.3)
        self.progress_detail_label.pack(pady=(0, 5))
        
        self.results_frame.pack(padx=30, pady=5, fill="x")
        self.results_header.pack(fill="x", padx=10, pady=2)
        self.results_title_label.pack(side="left")
        self.results_size_label.pack(side="right")
        self.scrollable_frame.configure(height=200)  # 稍微增加列表高度
        self.scrollable_frame.pack(padx=10, pady=(0, 5), fill="x")
        
        self.log_textbox.configure(height=150)  # 显著增加日志框高度，方便用户查看
        self.log_textbox.pack(padx=30, pady=5, fill="x")
        
        self.control_frame.pack(padx=30, pady=5)
        self.scan_button.pack(side="left", padx=5)
        self.clean_button.pack(side="left", padx=5)
        self.select_all_btn.pack(side="left", padx=5)
        self.deselect_all_btn.pack(side="left", padx=5)
        
        self.tip_label.pack(pady=(0, 5))

    def _log(self, message: str):
        """添加日志到输出框"""
        self.log_textbox.configure(state="normal")
        self.log_textbox.insert("end", f"> {message}\n")
        self.log_textbox.see("end")
        self.log_textbox.configure(state="disabled")

    def _update_disk_info(self):
        if self.current_drive == "ALL":
            # 如果是全部磁盘，汇总信息
            total_cleaned, used_cleaned, free_cleaned = 0, 0, 0
            for d in self.available_drives:
                usage = get_disk_usage(d)
                total_cleaned += usage["total"]
                used_cleaned += usage["used"]
                free_cleaned += usage["free"]
            
            if total_cleaned > 0:
                percent = used_cleaned / total_cleaned
                self.disk_progress.set(percent)
                self.disk_info_label.configure(
                    text=f"[ALL] 已用: {used_cleaned/(1024**3):.1f}GB | 可用: {free_cleaned/(1024**3):.1f}GB | 总计: {total_cleaned/(1024**3):.1f}GB"
                )
        else:
            usage = get_disk_usage(self.current_drive)
            if usage["total"] > 0:
                percent = usage["percent"] / 100
                self.disk_progress.set(percent)
                self.disk_info_label.configure(
                    text=f"[{self.current_drive}] 已使用: {usage['used']/(1024**3):.1f}GB  |  可用: {usage['free']/(1024**3):.1f}GB  |  总量: {usage['total']/(1024**3):.1f}GB"
                )

    def _on_drive_change(self, value):
        """驱动器切换处理"""
        if value == "全部磁盘":
            self.current_drive = "ALL"
            self._log("已切换到: 全部本地磁盘")
        else:
            self.current_drive = value
            self._log(f"已切换到: 磁盘 {value}")
        
        self._update_disk_info()
        # 清空之前的扫描结果，强制重新扫描
        self.scan_results.clear()
        self._create_cleanup_items()
        self.results_size_label.configure(text="共计: 0 B")

    def _create_cleanup_items(self):
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.cleanup_checkboxes.clear()
        
        for item in CLEANUP_ITEMS:
            item_id = item["id"]
            scan_result = self.scan_results.get(item_id)
            if not scan_result: continue
            
            frame = ctk.CTkFrame(self.scrollable_frame, fg_color="transparent")
            frame.pack(fill="x", padx=10, pady=2)
            
            # 复选框部分
            risk_tag = ""
            if item.get("risk") == "high":
                risk_tag = " [!] 高风险"
            elif item.get("risk") == "medium":
                risk_tag = " [?] 中风险"
                
            cb = ctk.CTkCheckBox(frame, text=f"{item['name']} ({item['description']}){risk_tag}")
            if item.get("enabled", True) and scan_result.total_size > 0:
                cb.select()
            cb.pack(side="left", pady=5)
            cb.configure(command=self._update_selected_size)
            
            size_lbl = ctk.CTkLabel(frame, text=format_size(scan_result.total_size), 
                                    text_color=RISK_COLORS.get(item['risk'], "white"),
                                    font=ctk.CTkFont(weight="bold"))
            size_lbl.pack(side="right")
            self.cleanup_checkboxes[item_id] = cb

    def _update_selected_size(self):
        total = 0
        for iid, cb in self.cleanup_checkboxes.items():
            if cb.get():
                total += self.scan_results[iid].total_size
        self.results_size_label.configure(text=f"已选中: {format_size(total)}")

    def _on_scan_click(self):
        self.is_scanning = True
        self.scan_button.configure(state="disabled")
        self.clean_button.configure(state="disabled")
        self.results_size_label.configure(text="正在扫描...")
        
        # 清理旧的扫描结果界面
        for widget in self.scrollable_frame.winfo_children():
            widget.destroy()
        self.cleanup_checkboxes.clear()
        
        drive_name = "全部磁盘" if self.current_drive == "ALL" else f"{self.current_drive} 盘"
        self._log(f"开始扫描 {drive_name} 垃圾文件...")
        threading.Thread(target=self._scan_thread, daemon=True).start()

    def _scan_thread(self):
        try:
            self.scanner = Scanner(
                progress_callback=self._on_scan_progress,
                drive=self.current_drive
            )
            self.scan_results = self.scanner.scan_all()
            self.after(0, self._on_scan_complete)
        except Exception as e:
            self.after(0, lambda: self._log(f"扫描出错: {e}"))

    def _select_all(self):
        """全选所有项目"""
        for cb in self.cleanup_checkboxes.values():
            cb.select()
        self._update_selected_size()
        self._log("已全选所有扫描项目")

    def _deselect_all(self):
        """取消全选"""
        for cb in self.cleanup_checkboxes.values():
            cb.deselect()
        self._update_selected_size()
        self._log("已取消选择所有项目")

    def _on_scan_progress(self, name: str, progress: int):
        self.after(0, lambda: self._update_progress(name, progress))

    def _update_progress(self, name: str, progress: int):
        self.operation_progress.set(progress / 100)
        self.progress_percent_label.configure(text=f"{progress}%")
        self.progress_detail_label.configure(text=f"正在扫描: {name}")

    def _on_scan_complete(self):
        self.is_scanning = False
        self.scan_button.configure(state="normal", text="🔍 重新扫描")
        self.clean_button.configure(state="normal")
        self._create_cleanup_items()
        self._update_selected_size()
        self.operation_progress.set(0)
        self.progress_percent_label.configure(text="0%")
        self.progress_detail_label.configure(text="扫描完毕，请选择项目清理")
        self._log("扫描完成！")

    def _on_clean_click(self):
        selected = [id for id, cb in self.cleanup_checkboxes.items() if cb.get()]
        if not selected: return
        
        self.is_cleaning = True
        self.scan_button.configure(state="disabled")
        self.clean_button.configure(state="disabled")
        self._log("启动清理任务...")
        threading.Thread(target=self._clean_thread, args=(selected,), daemon=True).start()

    def _clean_thread(self, selected):
        try:
            self.cleaner = Cleaner(
                progress_callback=self._on_clean_progress,
                log_callback=self._log  # 将日志重定向到UI
            )
            results = self.cleaner.clean(self.scan_results, selected)
            self.after(0, lambda: self._on_clean_complete(results))
        except Exception as e:
            self.after(0, lambda: self._log(f"清理失败: {e}"))

    def _on_clean_progress(self, name: str, current: int, total: int):
        percent = int((current / total) * 100) if total > 0 else 0
        self.after(0, lambda: self._update_progress_clean(current, total, percent))

    def _update_progress_clean(self, current, total, percent):
        self.operation_progress.set(current / total if total > 0 else 0)
        self.progress_percent_label.configure(text=f"{percent}%")
        self.progress_detail_label.configure(text=f"清理进度: {current} / {total} 文件")

    def _on_clean_complete(self, results):
        self.is_cleaning = False
        total_cleaned = sum(r.cleaned_size for r in results.values())
        self._log(f"清理完毕！释放空间: {format_size(total_cleaned)}")
        for r in results.values():
            if r.failed_count > 0:
                self._log(f"  - {r.item_name}: {r.failed_count} 个文件因占用无法删除")
        
        self._update_disk_info()
        self.operation_progress.set(0)
        self.progress_percent_label.configure(text="0%")
        self.progress_detail_label.configure(text="清理完成")
        self.scan_button.configure(state="normal")
        self._on_scan_click()

def main():
    MainWindow().mainloop()

if __name__ == "__main__":
    main()
