# R3Term - The Ultimate Terminal Environment for Reverse Engineers

R3Term is a specialized terminal environment meticulously crafted for reverse engineers, malware analysts, and security researchers. It seamlessly integrates essential reverse engineering tools into a unified, powerful command-line interface.

## 🎯 Why R3Term?

R3Term transforms your terminal into a comprehensive reverse engineering workbench by:
- **Unifying Critical Tools** - Seamlessly integrates Frida, ADB, Scrcpy, and Termux into a single, cohesive interface
- **Optimizing Workflow** - Designed specifically for reverse engineering workflows with quick access to common tasks
- **Enhancing Productivity** - Provides intelligent command suggestions and automated task sequences

### 🔧 Integrated Tools & Features

- **Dynamic Analysis Suite**
  - Frida integration with advanced script management
  - Real-time process manipulation and monitoring
  - Automated bypass solutions for common protections
  - Deep inspection of crypto operations
  - Custom hooking templates for rapid deployment

- **Android Analysis Toolkit**
  - Streamlined ADB command interface
  - Intelligent package management
  - Advanced logging and monitoring
  - Automated artifact collection
  - One-click root detection bypass

- **Enhanced Terminal Features**
  - Multi-pane workspace via tmux integration
  - Intelligent command history
  - Context-aware autocompletion
  - Custom keybindings for RE workflows
  - Session persistence and recovery

## Features

### 🔧 Core Features
- **Frida Integration**
  - Script management (quick scripts and custom scripts)
  - Process injection and monitoring
  - SSL/Root detection bypass
  - Crypto operations monitoring
  - Dynamic instrumentation

- **ADB Command Suite**
  - Device management
  - App installation and management
  - Screen capture and recording
  - System information monitoring
  - File operations
  - Network management

- **Screen Mirroring & Control**
  - Scrcpy integration with optimized settings
  - Interactive shell sessions
  - Split-screen terminal support via tmux
  - Touch event visualization

### 🛠 Advanced Features
- **Termux Integration**
  - SSH access management
  - API command support
  - System information retrieval
  - Hardware control (camera, sensors, etc.)

- **Debugging Tools**
  - Process monitoring
  - Memory analysis
  - Network traffic inspection
  - System logs access
  - Bug report generation

- **Scripting**
  - Easy to use script editor
  - Easy to use script runner   

- **AI**
  - Easy to use AI assistant    

- **Reverse Engineering**
  - Easy to use reverse engineering tools

## Sponsor

If you find this project useful, please consider supporting its development:

[![GitHub Sponsors](https://img.shields.io/badge/Sponsor%20on%20GitHub-%E2%9D%A4-lightgrey?logo=github)](https://github.com/sponsors/overkazaf)

Your support helps maintain and improve this project!

[![asciicast](https://asciinema.org/a/EGg4uh4OHNikw3owBepj8JuEf.svg)](https://asciinema.org/a/EGg4uh4OHNikw3owBepj8JuEf)


## Installation

1. Clone the repository:
```bash
git clone https://github.com/overkazaf/r3term.git
cd r3term
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install additional system dependencies:
```bash
# For macOS
brew install adb scrcpy tmux

# For Linux (Ubuntu/Debian)
sudo apt install android-tools-adb scrcpy tmux
```

## Usage

### Basic Commands

1. Start the tool:
```bash
python src/cli.py
```

2. List available devices:
```bash
devices
```

3. View running processes:
```bash
ps
```

### Frida Scripts

1. List available scripts:
```bash
list
```

2. Show script content:
```bash
show <script_id>
```

3. Inject script:
```bash
inject <script_id> [device_id] [process_name/package_name]
```

### Screen Control

1. Start screen mirroring:
```bash
scrcpy [device_id]
```

2. Start interactive shell:
```bash
screen_shell [device_id]
```

### ADB Commands

1. Install APK:
```bash
adb install <path_to_apk>
```

2. Take screenshot:
```bash
adb screenshot
```

3. Record screen:
```bash
adb screenrecord
```

## Advanced Usage

### Dynamic Analysis

1. Quick Script Injection:
```bash
inject bypass_ssl com.target.app
```

2. Custom Hook Deployment:
```bash
hook crypto com.target.app --method AES
```

3. Real-time Monitoring:
```bash
monitor network com.target.app
```

### Workspace Management

1. Create RE workspace:
```bash
workspace create target_app
```

2. Split terminal for parallel tasks:
```bash
split frida logs network
```

## Project Structure

```
r3term/
├── src/
│   ├── cli.py              # Command-line interface
│   ├── frida_manager.py    # Frida integration
│   ├── network_manager.py  # Network operations
│   └── ...
├── scripts/
│   └── frida/             # Frida scripts
├── docs/
│   └── guides/            # Usage guides
└── requirements.txt       # Python dependencies
```

## Dependencies

- Python 3.8+
- Frida
- ADB
- Scrcpy
- tmux
- Rich (for terminal UI)

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- [Frida](https://frida.re/) - Dynamic instrumentation toolkit
- [Scrcpy](https://github.com/Genymobile/scrcpy) - Android screen mirroring
- [Rich](https://github.com/Textualize/rich) - Terminal formatting library

## Support

For support, please open an issue in the GitHub repository or contact the maintainers.

## Security

If you discover any security-related issues, please email security@yourdomain.com instead of using the issue tracker. 