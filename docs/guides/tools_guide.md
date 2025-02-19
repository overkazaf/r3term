# Tools Guide

## Core Tools

### 1. Radare2
- **Installation**: `brew install radare2` (macOS) or `apt install radare2` (Linux)
- **Basic Commands**:
  - `r2 <binary>` - Open binary in radare2
  - `aaa` - Analyze all
  - `afl` - List all functions
  - `pdf @<function>` - Print disassembly of function
  - `s <address>` - Seek to address
  - `V` - Enter visual mode
  - `VV` - Enter graph mode
- **Tips**:
  - Use `?` in any mode to get help
  - Use `q` to exit current mode
  - Use `w` to write changes

### 2. Pwntools
- **Installation**: `pip install pwntools`
- **Basic Usage**:
```python
from pwn import *

# Start process
p = process('./binary')
# Or connect to remote
p = remote('host', port)

# Send/Receive
p.sendline(payload)
p.recvline()
p.interactive()

# Pattern creation
cyclic(100)
cyclic_find('aaaa')
```
- **Features**:
  - ELF manipulation
  - ROP chain building
  - Pattern generation
  - Shellcode generation

### 3. Frida
- **Installation**: 
  - `pip install frida-tools`
  - `npm install frida`
- **Basic Usage**:
  - List processes: `frida-ps -U`
  - Attach to process: `frida -U <process>`
  - Spawn and attach: `frida -U -f <package>`
- **Script Example**:
```javascript
Java.perform(() => {
    const MainActivity = Java.use('com.example.app.MainActivity');
    MainActivity.checkPassword.implementation = function(password) {
        console.log('Password:', password);
        return true;
    };
});
```

### 4. ADB (Android Debug Bridge)
- **Installation**: Via Android SDK or package manager
- **Device Management**:
  - `adb devices` - List connected devices
  - `adb shell` - Enter device shell
  - `adb root` - Restart adbd with root permissions
- **App Management**:
  - `adb install <apk>` - Install app
  - `adb uninstall <package>` - Remove app
  - `adb shell pm list packages` - List installed packages
- **File Operations**:
  - `adb pull <remote> [local]` - Copy from device
  - `adb push <local> <remote>` - Copy to device
- **Debugging**:
  - `adb logcat` - View device logs
  - `adb shell dumpsys` - Dump system info

### 5. Scrcpy
- **Installation**: `brew install scrcpy` (macOS)
- **Basic Usage**:
  - `scrcpy` - Mirror default device
  - `scrcpy -s <device>` - Select specific device
  - `scrcpy --record file.mp4` - Record screen
- **Options**:
  - `--max-size 1024` - Limit size
  - `--bit-rate 2M` - Change bitrate
  - `--no-audio` - Disable audio
  - `--stay-awake` - Keep device awake

## Additional Tools

### Static Analysis
- IDA Pro
- Ghidra
- Hopper

### Dynamic Analysis
- x64dbg
- GDB
- LLDB

### Network Tools
- Wireshark
- Burp Suite
- Charles Proxy

## Best Practices
- Keep tools updated for security
- Practice in a controlled environment
- Document your findings
- Use version control for scripts
- Regular backups of important data

## Tips for Beginners
1. Start with basic tools and gradually advance
2. Follow tool-specific documentation
3. Join reverse engineering communities
4. Practice with CTF challenges
5. Keep security in mind while testing

## Installation Guide
- Each tool has specific installation requirements
- Check system compatibility before installation
- Follow vendor-specific installation guides
- Keep tools updated for security

## Usage Tips
- Start with basic tools for learning
- Practice in a controlled environment
- Follow security guidelines
- Keep tools updated
- Document your findings 