# R3Term - 为逆向工程师打造的终极终端环境

R3Term 是一个专为逆向工程师、恶意软件分析师和安全研究人员精心打造的专业终端环境。它将各种必备的逆向工程工具无缝集成到一个统一的、强大的命令行界面中。

## 🎯 为什么选择 R3Term？

R3Term 通过以下方式将您的终端转变为全面的逆向工程工作台：
- **统一关键工具** - 将 Frida、ADB、Scrcpy 和 Termux 无缝集成到一个统一的界面中
- **优化工作流程** - 专为逆向工程工作流程设计，快速访问常用任务
- **提升生产力** - 提供智能命令建议和自动化任务序列

### 🔧 集成工具和功能

- **动态分析套件**
  - Frida 集成与高级脚本管理
  - 实时进程操作和监控
  - 常见保护机制的自动化绕过方案
  - 加密操作深度检测
  - 快速部署的自定义 Hook 模板

- **Android 分析工具集**
  - 简化的 ADB 命令界面
  - 智能包管理
  - 高级日志记录和监控
  - 自动化证据收集
  - 一键 Root 检测绕过

- **增强的终端功能**
  - 通过 tmux 集成实现多窗格工作区
  - 智能命令历史
  - 上下文感知自动补全
  - 为逆向工程工作流定制的快捷键
  - 会话持久化和恢复



[![asciicast](https://asciinema.org/a/EGg4uh4OHNikw3owBepj8JuEf.svg)](https://asciinema.org/a/EGg4uh4OHNikw3owBepj8JuEf)


## 安装

1. 克隆仓库：
```bash
git clone https://github.com/overkazaf/r3term.git
cd r3term
```

2. 创建并激活虚拟环境：
```bash
python -m venv venv
source venv/bin/activate  # Windows 系统使用：venv\Scripts\activate
```

3. 安装依赖：
```bash
pip install -r requirements.txt
```

4. 安装系统依赖：
```bash
# macOS
brew install adb scrcpy tmux

# Linux (Ubuntu/Debian)
sudo apt install android-tools-adb scrcpy tmux
```

## 使用方法

### 基本命令

1. 启动工具：
```bash
python src/cli.py
```

2. 列出可用设备：
```bash
devices
```

3. 查看运行中的进程：
```bash
ps
```

### Frida 脚本

1. 列出可用脚本：
```bash
list
```

2. 显示脚本内容：
```bash
show <script_id>
```

3. 注入脚本：
```bash
inject <script_id> [device_id] [process_name/package_name]
```

### 高级用法

#### 动态分析

1. 快速脚本注入：
```bash
inject bypass_ssl com.target.app
```

2. 自定义 Hook 部署：
```bash
hook crypto com.target.app --method AES
```

3. 实时监控：
```bash
monitor network com.target.app
```

#### 工作区管理

1. 创建逆向工程工作区：
```bash
workspace create target_app
```

2. 分屏执行并行任务：
```bash
split frida logs network
```

## 项目结构

```
r3term/
├── src/
│   ├── cli.py              # 命令行界面
│   ├── frida_manager.py    # Frida 集成
│   ├── network_manager.py  # 网络操作
│   └── ...
├── scripts/
│   └── frida/             # Frida 脚本
├── docs/
│   └── guides/            # 使用指南
└── requirements.txt       # Python 依赖
```

## 依赖项

- Python 3.8+
- Frida
- ADB
- Scrcpy
- tmux
- Rich (终端 UI)

## 贡献

1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/amazing-feature`)
3. 提交更改 (`git commit -m '添加某个很棒的特性'`)
4. 推送到分支 (`git push origin feature/amazing-feature`)
5. 提交 Pull Request

## 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件。

## 致谢

- [Frida](https://frida.re/) - 动态插桩工具包
- [Scrcpy](https://github.com/Genymobile/scrcpy) - Android 屏幕镜像
- [Rich](https://github.com/Textualize/rich) - 终端格式化库

## 支持

如需支持，请在 GitHub 仓库中提出 issue 或联系维护者。

## 安全

如果您发现任何与安全相关的问题，请发送邮件至 security@yourdomain.com，而不是使用 issue 追踪器。

## 赞助

如果您觉得这个项目有用，请考虑支持它的发展：

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-lightgrey?logo=github)](https://github.com/sponsors/overkazaf)

您的支持有助于维护和改进这个项目！ 