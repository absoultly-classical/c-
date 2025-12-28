  # C盘清理大师

一个现代化的 Windows C盘垃圾清理工具，使用 Python + CustomTkinter 开发。

## ✨ 功能特点

- 🔍 **智能扫描** - 自动检测多种类型的垃圾文件
- 🗑️ **安全清理** - 选择性清理，不会误删重要文件
- 📊 **可视化界面** - 直观显示磁盘使用情况和垃圾文件分布
- 🛡️ **权限保护** - 清理前需要确认，防止误操作
- 🎨 **现代UI** - 基于 CustomTkinter 的美观界面

## 🗂️ 支持清理的项目

| 清理项目 | 说明 | 风险等级 |
|---------|------|----------|
| 用户临时文件 | 应用程序临时文件 | 🟢 低 |
| 系统临时文件 | Windows 系统临时文件 | 🟢 低 |
| Chrome 浏览器缓存 | Google Chrome 缓存 | 🟢 低 |
| Edge 浏览器缓存 | Microsoft Edge 缓存 | 🟢 低 |
| Firefox 浏览器缓存 | Mozilla Firefox 缓存 | 🟢 低 |
| Windows 更新缓存 | 已下载的更新包 | 🟡 中 |
| 缩略图缓存 | 图片预览缓存 | 🟢 低 |
| Windows 日志 | 系统日志文件 | 🟡 中 |
| 预读取文件 | Windows 预加载数据 | 🟡 中 |
| 回收站 | 已删除的文件 | 🟢 低 |
| 最近文件记录 | 最近访问记录 | 🟢 低 |
| 错误报告 | Windows 错误报告 | 🟢 低 |

## 📦 安装依赖

```bash
pip install -r requirements.txt
```

或手动安装：

```bash
pip install customtkinter psutil
```

## 🚀 使用方法

### 方法一：直接运行（推荐）

以管理员身份运行：

```bash
python main.py
```

### 方法二：打包成 exe

使用 PyInstaller 打包：

```bash
pip install pyinstaller
pyinstaller --onefile --windowed --icon=icon.ico --name="C盘清理大师" main.py
```

生成的 exe 文件在 `dist` 目录下。

## 📖 使用说明

1. **启动程序** - 建议以管理员身份运行以获得完整权限
2. **点击扫描** - 程序会自动扫描所有垃圾文件
3. **选择项目** - 勾选想要清理的项目（默认已选中安全项）
4. **开始清理** - 点击清理按钮，输入 `YES` 确认
5. **查看结果** - 清理完成后会显示释放的空间

## ⚠️ 注意事项

1. **管理员权限** - 某些系统文件需要管理员权限才能清理
2. **浏览器缓存** - 清理前请关闭相关浏览器
3. **回收站** - 清空回收站后文件无法恢复
4. **系统文件** - 标记为"中"风险的项目请谨慎清理

## 🛠️ 项目结构

```
c_drive_cleaner/
├── main.py              # 程序入口
├── config.py            # 配置文件
├── scanner.py           # 扫描模块
├── cleaner.py           # 清理模块
├── ui/
│   ├── __init__.py
│   └── main_window.py   # 主窗口
├── utils/
│   └── __init__.py
├── requirements.txt     # 依赖列表
└── README.md           # 说明文档
```

## 🔧 技术栈

- **Python 3.10+**
- **CustomTkinter** - 现代化 GUI 框架
- **psutil** - 系统信息获取
- **Windows API** - 回收站操作

## 📝 开发计划

- [ ] 添加定时清理功能
- [ ] 支持自定义清理规则
- [ ] 添加清理历史记录
- [ ] 支持多语言
- [ ] 添加系统托盘图标

## 📄 许可证

MIT License

## 🤝 贡献

欢迎提交 Issue 和 Pull Request！

---

**注意**: 本工具仅用于清理垃圾文件，不会删除任何重要数据。使用前请仔细阅读说明。
