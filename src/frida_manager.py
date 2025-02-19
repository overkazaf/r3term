from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
from rich import box
from pathlib import Path
from datetime import datetime
from db_manager import DBManager
import subprocess
import platform
import os
import frida
import json
import tempfile
import time
import re
from base_manager import BaseManager
import sys

console = Console()

class FridaManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.scripts_dir = Path("data/frida/scripts")  # Convert to Path object
        self.hooks_dir = Path("data/frida/hooks")      # Convert to Path object
        self._ensure_dirs()
        self.db = DBManager()
        self.cached_device_id = None  # 添加设备ID缓存
        self.quick_scripts = {
            "ssl_bypass": {
                "name": "SSL Pinning Bypass",
                "tags": ["ssl", "security", "bypass"],
                "description": "Universal SSL certificate pinning bypass script",
                "filename": "ssl_bypass.js"
            },
            "root_bypass": {
                "name": "Root Detection Bypass",
                "tags": ["root", "security", "bypass"],
                "description": "Basic root detection bypass script",
                "filename": "root_bypass.js"
            },
            "md5_hook": {
                "name": "MD5 Hook",
                "tags": ["crypto", "hash", "hook"],
                "description": "Hook MD5 calculation functions",
                "filename": "md5_hook.js"
            },
            "aes_hook": {
                "name": "AES Hook",
                "tags": ["crypto", "encryption", "hook"],
                "description": "Hook AES encryption/decryption functions",
                "filename": "aes_hook.js"
            }
        }
        # ADB 命令列表
        self.adb_commands = [
            # 应用管理
            "install", "uninstall", "grant", "revoke", "clear", "start", "stop",
            # 界面操作
            "input_text", "tap", "swipe", "back", "home", "menu", "power",
            "screenshot", "screenrecord",
            # 应用信息
            "current_activity", "dump_layout", "permissions", "app_info",
            "memory_info", "battery_info",
            # 文件操作
            "pull", "push", "ls", "rm", "mkdir",
            # 系统操作
            "reboot", "shell", "logcat", "bugreport", "dumpsys", "dmesg",
            # 网络相关
            "tcpip", "connect", "disconnect", "forward", "reverse", "ifconfig",
            # 设备信息
            "devices", "get-state", "get-serialno", "get-devpath",
            # 性能分析
            "top", "cpuinfo", "meminfo", "netstat", "procstats"
        ]
        self.init_quick_scripts()
        self.import_local_scripts()
        self.index_file = os.path.join(self.scripts_dir, "index.json")
        
        # 检查环境变量
        self.termux_ssh_host = os.getenv('TERMUX_SSH_HOST', 'localhost')
        self.termux_ssh_port = os.getenv('TERMUX_SSH_PORT', '8022')
        self.termux_ssh_user = os.getenv('TERMUX_SSH_USER', 'u0_a287')
        
        # 验证 SSH 连接
        if not self._check_ssh_connection():
            self.console.print("[yellow]Warning: Cannot connect to Termux via SSH. Some features may be unavailable.[/yellow]")

    def _check_ssh_connection(self):
        """Check SSH connection to Termux"""
        try:
            check_cmd = [
                'ssh',
                '-p', self.termux_ssh_port,
                f'{self.termux_ssh_user}@{self.termux_ssh_host}',
                'echo test'
            ]
            
            result = subprocess.run(
                check_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5  # 5秒超时
            )
            
            return result.returncode == 0
        except Exception:
            return False

    def init_quick_scripts(self):
        """Initialize quick scripts if they don't exist"""
        for script_id, script_info in self.quick_scripts.items():
            script_path = self.scripts_dir / script_info["filename"]
            if not script_path.exists():
                self._create_quick_script(script_id, script_path)
                # Add to database if not exists
                self.db.add_script(
                    script_info["name"],
                    script_info["description"],
                    script_info["filename"],
                    "quick",
                    script_info["tags"]
                )

    def _create_quick_script(self, script_id, script_path):
        """Create quick script files with template content"""
        templates = {
            "ssl_bypass": '''
Java.perform(function() {
    console.log("[*] SSL Pinning Bypass Script Loaded");
    
    var TrustManager = {
        verify: function() {
            console.log("[+] Certificate check bypassed");
        }
    };

    // Create a new TrustManager that trusts everything
    var TrustManagers = [TrustManager];
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var init = SSLContext.init.overload(
        "[Ljavax.net.ssl.KeyManager;", "[Ljavax.net.ssl.TrustManager;", "java.security.SecureRandom");
    
    init.implementation = function(keyManager, trustManager, secureRandom) {
        console.log("[*] Bypassing SSL Pinning...");
        init.call(this, keyManager, TrustManagers, secureRandom);
    };
});''',
            "root_bypass": '''
Java.perform(function() {
    console.log("[*] Root Detection Bypass Loaded");
    
    var RootPackages = ["com.noshufou.android.su", "com.thirdparty.superuser", "eu.chainfire.supersu",
                        "com.topjohnwu.magisk"];
    
    var RootBinary = ["su", "busybox"];
    var RootProperties = ["ro.build.selinux"];
    
    var Build = Java.use("android.os.Build");
    var File = Java.use("java.io.File");
    var String = Java.use("java.lang.String");
    
    // Bypass file-based checks
    File.exists.implementation = function() {
        var name = this.getAbsolutePath();
        for (var i = 0; i < RootBinary.length; i++) {
            if (name.indexOf(RootBinary[i]) > -1) {
                console.log("[+] Bypassing root check for: " + name);
                return false;
            }
        }
        return this.exists.call(this);
    };
});''',
            "md5_hook": '''
Java.perform(function() {
    console.log("[*] MD5 Hook Loaded");
    
    // Hook MessageDigest
    var MessageDigest = Java.use("java.security.MessageDigest");
    MessageDigest.getInstance.overload("java.lang.String").implementation = function(algorithm) {
        console.log("[+] MessageDigest.getInstance(" + algorithm + ") called");
        return this.getInstance.call(this, algorithm);
    };
    
    MessageDigest.digest.overload().implementation = function() {
        var ret = this.digest.call(this);
        console.log("[+] MessageDigest.digest() called");
        console.log("[*] Input: " + this.toString());
        console.log("[*] Output: " + ret);
        return ret;
    };
});''',
            "aes_hook": '''
Java.perform(function() {
    console.log("[*] AES Hook Loaded");
    
    var cipher = Java.use("javax.crypto.Cipher");
    cipher.doFinal.overload("[B").implementation = function(buffer) {
        console.log("[+] Cipher.doFinal([B]) called");
        console.log("[*] Algorithm: " + this.getAlgorithm());
        console.log("[*] Input: " + buffer);
        var ret = this.doFinal.call(this, buffer);
        console.log("[*] Output: " + ret);
        return ret;
    };
});'''
        }
        
        with open(script_path, 'w') as f:
            f.write(templates.get(script_id, "// Template not found"))

    def display_scripts(self, filter_tag=None):
        table = Table(
            title="Frida Scripts",
            show_header=True,
            header_style="bold magenta",
            box=box.SIMPLE
        )
        
        table.add_column("ID", style="cyan", justify="right")
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Tags", style="yellow")
        table.add_column("Type", style="blue")

        scripts = self.db.get_all_scripts(filter_tag)
        for script in scripts:
            table.add_row(
                str(script['id']),
                script['name'],
                script['description'],
                ", ".join(script['tags']),
                script['type'].title()
            )

        self.console.print(table)

    def show_script_content(self, script_id):
        try:
            script_id = int(script_id)
            script = self.db.get_script_by_id(script_id)
            
            if script:
                script_path = self.scripts_dir / script['filename']
                if script_path.exists():
                    with open(script_path, 'r') as f:
                        content = f.read()
                    syntax = Syntax(content, "javascript", theme="monokai")
                    self.console.print(f"\n[bold cyan]Script #{script['id']}: {script['name']}[/bold cyan]")
                    self.console.print(f"[yellow]Tags: {', '.join(script['tags'])}[/yellow]")
                    self.console.print(f"Description: {script['description']}\n")
                    self.console.print(syntax)
                    return True
            
            self.console.print("[red]Script not found[/red]")
            return False
        except ValueError:
            self.console.print("[red]Invalid script ID[/red]")
            return False

    def add_script(self, name, description, tags, content):
        filename = f"{name.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d%H%M%S')}.js"
        script_path = self.scripts_dir / filename
        
        # Save script content
        with open(script_path, 'w') as f:
            f.write(content)
        
        # Add to database
        script_id = self.db.add_script(
            name,
            description,
            filename,
            "custom",
            [tag.strip() for tag in tags.split(',')]
        )
        
        self.console.print(f"[green]Script added successfully with ID: {script_id}[/green]")

    def delete_script(self, script_id):
        try:
            script_id = int(script_id)
            script = self.db.get_script_by_id(script_id)
            
            if script and script['type'] != 'quick':  # Cannot delete quick scripts
                script_path = self.scripts_dir / script['filename']
                if script_path.exists():
                    script_path.unlink()
                
                if self.db.delete_script(script_id):
                    self.console.print("[green]Script deleted successfully[/green]")
                    return True
            
            self.console.print("[red]Script not found or is a quick script (cannot be deleted)[/red]")
            return False
        except ValueError:
            self.console.print("[red]Invalid script ID[/red]")
            return False

    def show_usage_guide(self):
        """Show usage guide for all available commands"""
        self.console.print("\n[bold cyan]Frida Manager Usage Guide[/bold cyan]")
        
        # Basic Commands
        self.console.print("\n[yellow]Basic Commands:[/yellow]")
        self.console.print("  list       - List all available scripts")
        self.console.print("  devices    - List connected devices")
        self.console.print("  ps         - List processes on device")
        self.console.print("  show       - Show script content")
        self.console.print("  search     - Search scripts")
        self.console.print("  edit       - Edit script")
        self.console.print("  delete     - Delete script")
        self.console.print("  inject     - Inject script into process")
        self.console.print("  spawn      - Spawn and inject")
        
        # Objection Tools
        self.console.print("\n[yellow]Objection Tools:[/yellow]")
        self.console.print("  explore    - Start objection explorer")
        self.console.print("  memory     - Memory operations")
        self.console.print("  android    - Android specific commands")
        self.console.print("  ios        - iOS specific commands")
        self.console.print("  heap       - Heap operations")
        self.console.print("  stalker    - Function stalking")
        
        # Android Tools
        self.console.print("\n[yellow]Android Tools:[/yellow]")
        self.console.print("  scrcpy     - Screen mirroring")
        self.console.print("  screen     - Interactive screen and shell session")
        self.console.print("  adb        - Run ADB commands")
        self.console.print("  jnitrace   - Trace JNI calls")
        
        # Termux Tools
        self.console.print("\n[yellow]Termux Tools:[/yellow]")
        self.console.print("  termux-api - Run Termux API commands")
        self.console.print("  termux-ssh - Setup and manage SSH")
        
        # Usage Examples
        self.console.print("\n[yellow]Usage Examples:[/yellow]")
        self.console.print("1. List all scripts:")
        self.console.print("   > list")
        self.console.print("\n2. Inject script into process:")
        self.console.print("   > inject <script_id> [device_id] [process_name]")
        self.console.print("\n3. Start objection explorer:")
        self.console.print("   > explore [device_id] [package_name]")
        self.console.print("\n4. Screen mirroring:")
        self.console.print("   > scrcpy [device_id]")
        self.console.print("\n5. Run Termux API command:")
        self.console.print("   > termux-api <command> [device_id] [params...]")
        
        # Tips
        self.console.print("\n[yellow]Tips:[/yellow]")
        self.console.print("1. Use 'devices' to list available devices")
        self.console.print("2. Most commands support optional device_id parameter")
        self.console.print("3. Use 'guide' to show this help message")
        
        # Basic Commands
        self.console.print("\n[yellow]Basic Commands:[/yellow]")
        self.console.print("1. List processes:")
        self.console.print("   frida-ps -U")
        self.console.print("2. Attach to process:")
        self.console.print("   frida -U -l script.js <process_name>")
        self.console.print("3. Spawn and attach:")
        self.console.print("   frida -U -l script.js -f <package_name>")
        
        # Common Scenarios
        self.console.print("\n[yellow]Common Scenarios:[/yellow]")
        self.console.print("1. SSL Pinning Bypass:")
        self.console.print("   frida -U -l ssl_bypass.js -f com.example.app")
        self.console.print("2. Root Detection Bypass:")
        self.console.print("   frida -U -l root_bypass.js -f com.example.app")
        self.console.print("3. Crypto Monitoring:")
        self.console.print("   frida -U -l crypto_monitor.js -f com.example.app")
        
        # Tips
        self.console.print("\n[yellow]Tips:[/yellow]")
        self.console.print("1. Use --no-pause with -f to avoid waiting for resume")
        self.console.print("2. Use -o output.txt to save output to file")
        self.console.print("3. Use -q for quiet mode (less output)")

    def handle_command(self, command: str, *args):
        """Handle frida commands"""
        try:
            # 首先检查是否是shell命令
            if self.handle_shell_command(command):
                return
                
            if command == "devices":
                self._list_devices()
            elif command == "ps":
                device_id = args[0] if args else None
                self._list_processes(device_id)
            elif command == "list":
                filter_tag = args[0] if args else None
                self._list_scripts(filter_tag)
            elif command == "show":
                script_id = args[0] if args else None
                if script_id:
                    self._show_script(script_id)
                else:
                    console.print("[red]Please provide a script ID[/red]")
            elif command == "search":
                keyword = args[0] if args else None
                tag = args[1] if len(args) > 1 else None
                self._search_scripts(keyword, tag)
            elif command == "add":
                if len(args) >= 2:
                    name, description = args[0], args[1]
                    tags = args[2].split(',') if len(args) > 2 else []
                    content = args[3] if len(args) > 3 else ""
                    self._add_script(name, description, tags, content)
                else:
                    console.print("[red]Please provide script name and description[/red]")
            elif command == "edit":
                script_id = args[0] if args else None
                if script_id:
                    self._edit_script(script_id)
                else:
                    console.print("[red]Please provide a script ID[/red]")
            elif command == "delete":
                script_id = args[0] if args else None
                if script_id:
                    self._delete_script(script_id)
                else:
                    console.print("[red]Please provide a script ID[/red]")
            elif command == "inject":
                if len(args) >= 1:
                    script_id = args[0]
                    device_id = args[1] if len(args) > 1 else None
                    target = args[2] if len(args) > 2 else None
                    self._inject_script(script_id, device_id, target)  # Ensure correct number of arguments
                else:
                    console.print("[red]Please provide a script ID[/red]")
            elif command == "spawn":
                if len(args) >= 2:
                    script_id, package = args[0], args[1]
                    device_id = args[2] if len(args) > 2 else None
                    self._spawn_and_inject(script_id, device_id, package)
                else:
                    console.print("[red]Please provide script ID and package name[/red]")
            elif command == "jnitrace":
                device_id = args[0] if args else None
                target = args[1] if len(args) > 1 else None
                lib_name = args[2] if len(args) > 2 else None
                self._jnitrace(device_id, target, lib_name)
            elif command == "objection":
                if len(args) >= 1:
                    subcommand = args[0]
                    device_id = args[1] if len(args) > 1 else None
                    target = args[2] if len(args) > 2 else None
                    self._run_objection(subcommand, device_id, target)
                else:
                    console.print("[red]Please provide objection subcommand[/red]")
            elif command in ["explore", "memory", "android", "ios", "heap", "stalker"]:
                device_id = args[0] if args else None
                target = args[1] if len(args) > 1 else None
                self._run_objection(command, device_id, target)
            elif command == "adb":
                if len(args) >= 1:
                    subcommand = args[0]
                    device_id = args[1] if len(args) > 1 else None
                    params = args[2:] if len(args) > 2 else []
                    self._run_adb_command(subcommand, device_id, *params)
                else:
                    console.print("[red]Please provide ADB subcommand[/red]")
            elif command == "scrcpy":
                device_id = args[0] if args else None
                self._run_scrcpy(device_id)
            elif command == "screen_shell":
                device_id = args[0] if args else None
                self._run_screen_shell(device_id)
            elif command == "termux-ssh":
                device_id = args[0] if args else None
                self._run_termux_ssh(device_id)
            elif command == "termux-api":
                if len(args) >= 1:
                    subcommand = args[0]
                    device_id = args[1] if len(args) > 1 else None
                    params = args[2:] if len(args) > 2 else []
                    self._run_termux_api(subcommand, device_id, *params)
                else:
                    console.print("[red]Please provide Termux API subcommand[/red]")
            elif command == "guide":
                self.show_usage_guide()
            else:
                console.print("[red]Unknown command[/red]")
                self.show_usage_guide()
                
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

    def _handle_termux_api_commands(self):
        """Handle termux-api commands in an interactive sub-shell"""
        self.console.print("\n[bold cyan]Termux API Commands[/bold cyan]")
        self.console.print("Type 'help' for available commands, 'exit' to quit\n")
        
        while True:
            try:
                cmd = self.console.input("[bold cyan]termux-api#[/bold cyan] ").strip()
                
                if not cmd:
                    continue
                if cmd == 'exit':
                    break
                if cmd == 'help':
                    self._show_termux_api_help()
                    continue
                
                # 移除可能的 termux- 前缀
                cmd = cmd.replace('termux-', '')
                self._run_termux_command(cmd)
                    
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Termux API shell stopped by user[/yellow]")
                break
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")

    def import_local_scripts(self):
        """Import existing scripts from the scripts directory into the database"""
        self.console.print("[yellow]Scanning for local scripts...[/yellow]")
        
        # Get all .js files in the scripts directory
        js_files = list(self.scripts_dir.glob("*.js"))
        imported_count = 0
        
        for script_path in js_files:
            filename = script_path.name
            
            # Skip if script already exists in database
            if self.db.script_exists(filename):
                continue
            
            # Check if it's a quick script
            quick_script_info = None
            for info in self.quick_scripts.values():
                if info["filename"] == filename:
                    quick_script_info = info
                    break
            
            if quick_script_info:
                # Add quick script to database if not exists
                if not self.db.get_script_by_name(quick_script_info["name"]):
                    self.db.add_script(
                        quick_script_info["name"],
                        quick_script_info["description"],
                        filename,
                        "quick",
                        quick_script_info["tags"]
                    )
                    imported_count += 1
            else:
                # Import as custom script
                # Try to extract name from filename (remove timestamp if exists)
                name = filename.rsplit('_', 1)[0].replace('_', ' ').title()
                
                # Add to database
                self.db.add_script(
                    name,
                    "Imported local script",
                    filename,
                    "custom",
                    ["imported"]
                )
                imported_count += 1
        
        if imported_count > 0:
            self.console.print(f"[green]Imported {imported_count} new scripts[/green]")

    def search_scripts(self, keyword=None, tag=None):
        scripts = self.db.search_scripts(keyword, tag)
        if scripts:
            table = Table(
                title=f"Search Results",
                show_header=True,
                header_style="bold magenta",
                box=box.SIMPLE
            )
            
            table.add_column("ID", style="cyan", justify="right")
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="green")
            table.add_column("Tags", style="yellow")
            table.add_column("Type", style="blue")

            for script in scripts:
                table.add_row(
                    str(script['id']),
                    script['name'],
                    script['description'],
                    ", ".join(script['tags']),
                    script['type'].title()
                )
            
            self.console.print(table)
        else:
            self.console.print("[yellow]No scripts found[/yellow]")

    def _inject_script(self, script_id, device_id, target):
        """Inject script into target process"""
        try:
            # 验证脚本ID
            script = self.db.get_script_by_id(int(script_id))
            if not script:
                self.console.print("[red]Script not found[/red]")
                return

            # 统一收集所有需要的输入
            # device_id = self.console.input("Device ID (leave empty for current/USB): ").strip()
            # target = self.console.input("Target process/package: ").strip()
            device_id = device_id or self.cached_device_id
            if not target:
                self.console.print("[red]Please provide a target process/package[/red]")
                return

            # 询问是否使用spawn模式
            spawn_mode = self.console.input("Use spawn mode? (y/N): ").strip().lower() == 'y'
            
            # 构建frida命令
            cmd = ['frida']
            if device_id:
                cmd.extend(['-D', device_id])
            else:
                cmd.append('-U')
                
            script_path = self.scripts_dir / script['filename']
            cmd.extend(['-l', str(script_path)])
            
            if spawn_mode:
                if target.isdigit():
                    cmd.extend(['-p', target])
                else:
                    cmd.extend(['-f', target])
            else:
                # 如果是进程ID 则使用-p
                if target.isdigit():
                    cmd.extend(['-p', target])
                else:
                    cmd.extend(['-n', target])
            
            # 显示执行的命令
            self.console.print(f"\n[cyan]Running command:[/cyan]")
            self.console.print(f"[yellow]{' '.join(cmd)}[/yellow]\n")
            
            # 创建新的tmux会话并执行命令
            tmux_session_name = f"frida_command_{int(time.time())}"
            tmux_cmd = ["tmux", "new-session", "-d", "-s", tmux_session_name, "bash", "-c", " ".join(cmd)]
            # 直接attach到tmux会话
            tmux_attach_cmd = ["tmux", "attach", "-t", tmux_session_name]
            subprocess.run(tmux_cmd)
            subprocess.run(tmux_attach_cmd)

            self.console.print(f"[green]Command is running in a new tmux session: {tmux_session_name}[/green]")
            self.console.print("[cyan]Press Ctrl+b then d to detach from the session.[/cyan]")
            self.console.print("[cyan]To reattach later, use: tmux attach -t {tmux_session_name}[/cyan]")

        except ValueError:
            self.console.print("[red]Invalid script ID[/red]")
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Injection stopped by user[/yellow]")
        except Exception as e:
            self.console.print(f"[red]Error injecting script: {str(e)}[/red]")

    def _edit_script_enhanced(self, script_id):
        """增强的脚本编辑功能"""
        try:
            script_id = int(script_id)
            script = self.db.get_script_by_id(script_id)
            
            if not script:
                self.console.print("[red]Script not found[/red]")
                return
            
            if script['type'] == 'quick':
                self.console.print("[red]Cannot edit quick scripts[/red]")
                return
            
            script_path = self.scripts_dir / script['filename']
            if not script_path.exists():
                self.console.print("[red]Script file not found[/red]")
                return
            
            # 显示当前脚本信息
            self.console.print(f"\n[bold cyan]Editing Script #{script_id}[/bold cyan]")
            self.console.print("Current values:")
            self.console.print(f"Name: {script['name']}")
            self.console.print(f"Description: {script['description']}")
            self.console.print(f"Tags: {', '.join(script['tags'])}")
            
            while True:
                self.console.print("\n[cyan]Edit options:[/cyan]")
                self.console.print("1. Edit metadata (name/description/tags)")
                self.console.print("2. Edit script content")
                self.console.print("3. Show current content")
                self.console.print("4. Save and exit")
                
                choice = self.console.input("\n[bold cyan]edit#[/bold cyan] ").strip()
                
                if choice == "1":
                    self._edit_script_metadata(script_id)
                elif choice == "2":
                    self._edit_script_content(script_path)
                elif choice == "3":
                    self._show_current_content(script_path)
                elif choice == "4":
                    break
                else:
                    self.console.print("[red]Invalid choice[/red]")

        except ValueError:
            self.console.print("[red]Invalid script ID[/red]")
        except Exception as e:
            self.console.print(f"[red]Error editing script: {str(e)}[/red]")

    def _edit_script_metadata(self, script_id):
        """编辑脚本元数据"""
        while True:
            self.console.print("\n[cyan]Metadata edit options:[/cyan]")
            self.console.print("1. Edit name")
            self.console.print("2. Edit description")
            self.console.print("3. Add tag")
            self.console.print("4. Remove tag")
            self.console.print("5. Back")
            
            choice = self.console.input("\n[bold cyan]metadata#[/bold cyan] ").strip()
            
            if choice == "1":
                name = self.console.input("New name: ").strip()
                if name:
                    self.db.update_script_metadata(script_id, name=name)
                    self.console.print("[green]Name updated[/green]")
            elif choice == "2":
                desc = self.console.input("New description: ").strip()
                if desc:
                    self.db.update_script_metadata(script_id, description=desc)
                    self.console.print("[green]Description updated[/green]")
            elif choice == "3":
                tag = self.console.input("New tag: ").strip()
                if tag:
                    if self.db.add_script_tag(script_id, tag):
                        self.console.print("[green]Tag added[/green]")
                    else:
                        self.console.print("[yellow]Tag already exists[/yellow]")
            elif choice == "4":
                tag = self.console.input("Tag to remove: ").strip()
                if tag:
                    if self.db.remove_script_tag(script_id, tag):
                        self.console.print("[green]Tag removed[/green]")
                    else:
                        self.console.print("[yellow]Tag not found[/yellow]")
            elif choice == "5":
                break

    def _edit_script_content(self, script_path):
        """编辑脚本内容"""
        # 检测系统默认编辑器
        editor = os.environ.get('EDITOR', 'vim')
        
        try:
            # 打开编辑器编辑文件
            subprocess.run([editor, script_path])
            self.console.print("[green]Script content updated[/green]")
        except Exception as e:
            self.console.print(f"[red]Error opening editor: {str(e)}[/red]")
            
            # 如果打开编辑器失败，提供内置编辑选项
            self.console.print("\n[yellow]Editor failed to open. Using built-in editor...[/yellow]")
            
            # 读取当前内容
            with open(script_path, 'r') as f:
                current_content = f.read()
            
            # 显示当前内容
            self.console.print("\n[cyan]Current content:[/cyan]")
            self.console.print(Syntax(current_content, "javascript", theme="monokai"))
            
            # 提示用户输入新内容
            self.console.print("\n[cyan]Enter new content (type 'END' on a new line to finish):[/cyan]")
            new_content = []
            while True:
                line = input()
                if line.strip() == 'END':
                    break
                new_content.append(line)
            
            # 保存新内容
            if new_content:
                with open(script_path, 'w') as f:
                    f.write('\n'.join(new_content))
                self.console.print("[green]Script content updated[/green]")
            else:
                self.console.print("[yellow]Content unchanged[/yellow]")

    def _show_current_content(self, script_path):
        """显示当前脚本内容"""
        try:
            with open(script_path, 'r') as f:
                content = f.read()
            self.console.print("\n[cyan]Current content:[/cyan]")
            self.console.print(Syntax(content, "javascript", theme="monokai"))
        except Exception as e:
            self.console.print(f"[red]Error reading script: {str(e)}[/red]")

    def _list_devices(self):
        """列出所有连接的设备"""
        try:
            devices = frida.enumerate_devices()
            
            table = Table(title="Connected Devices")
            table.add_column("ID", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Type", style="magenta")
            table.add_column("Status", style="yellow")  # 添加状态列
            
            for device in devices:
                # 检查是否是当前缓存的设备
                status = "[bright_yellow]Current[/bright_yellow]" if device.id == self.cached_device_id else ""
                table.add_row(
                    str(device.id),
                    device.name,
                    device.type,
                    status
                )
            
            self.console.print(table)
            
            # 显示当前设备信息
            if self.cached_device_id:
                self.console.print(f"\n[cyan]Current device: {self.cached_device_id}[/cyan]")
            
        except frida.InvalidArgumentError as e:
            self.console.print(f"[red]Error listing devices: {str(e)}[/red]")
    
    def _list_processes(self, device_id: str = None, filter_type: str = "all", filter_value: str = None):
        """列出指定设备上的进程，支持过滤"""
        try:
            device = self._get_device(device_id)
            processes = device.enumerate_processes()
            
            # 应用过滤
            filtered_processes = []
            for process in processes:
                if filter_type == "all":
                    filtered_processes.append(process)
                elif filter_type == "name" and filter_value.lower() in process.name.lower():
                    filtered_processes.append(process)
                elif filter_type == "pid" and str(process.pid) == filter_value:
                    filtered_processes.append(process)
                elif filter_type == "user" and hasattr(process, 'user') and filter_value.lower() in str(process.user).lower():
                    filtered_processes.append(process)

            # 创建表格
            table = Table(title=f"Processes on {device.name}")
            table.add_column("PID", style="cyan", justify="right")
            table.add_column("Name", style="green")
            if any(hasattr(p, 'user') for p in processes):
                table.add_column("User", style="yellow")
            
            # 添加进程信息到表格
            for process in filtered_processes:
                row = [str(process.pid), process.name]
                if hasattr(process, 'user'):
                    row.append(str(process.user))
                table.add_row(*row)
            
            # 显示结果
            self.console.print(table)
            self.console.print(f"\n[cyan]Total processes: {len(filtered_processes)}[/cyan]")
            
        except frida.InvalidArgumentError as e:
            self.console.print(f"[red]Error listing processes: {str(e)}[/red]")
    
    def _jnitrace(self, device_id: str = None, target: str = None, lib_name: str = None):
        """使用jnitrace跟踪JNI调用"""
        try:
            # 构建jnitrace命令
            cmd = ["jnitrace"]
            
            if device_id:
                cmd.extend(["-d", device_id])
            
            if lib_name:
                cmd.extend(["-l", lib_name])
            
            cmd.append(target)
            
            # 执行jnitrace
            self.console.print(f"[cyan]Starting JNI trace for {target}...[/cyan]")
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # 实时输出结果
            try:
                while True:
                    output = process.stdout.readline()
                    if output == '' and process.poll() is not None:
                        break
                    if output:
                        self.console.print(output.strip())
            except KeyboardInterrupt:
                process.terminate()
                self.console.print("\n[yellow]JNI trace stopped[/yellow]")
            
        except Exception as e:
            self.console.print(f"[red]Error running jnitrace: {str(e)}[/red]")
    
    def _get_device(self, device_id: str = None):
        """获取指定设备，如果未指定则返回缓存的设备或本地设备"""
        try:
            if device_id:
                device = frida.get_device(device_id)
                self.cached_device_id = device_id  # 更新缓存
                return device
            elif self.cached_device_id:
                try:
                    return frida.get_device(self.cached_device_id)
                except frida.InvalidArgumentError:
                    # 如果缓存的设备不可用，清除缓存并返回本地设备
                    self.cached_device_id = None
                    return frida.get_local_device()
            return frida.get_local_device()
        except frida.InvalidArgumentError:
            self.console.print(f"[red]Device {device_id} not found[/red]")
            return None

    def _list_scripts(self, filter_tag=None):
        table = Table(
            title="Frida Scripts",
            show_header=True,
            header_style="bold magenta",
            box=box.SIMPLE
        )
        
        table.add_column("ID", style="cyan", justify="right")
        table.add_column("Name", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Tags", style="yellow")
        table.add_column("Type", style="blue")

        scripts = self.db.get_all_scripts(filter_tag)
        for script in scripts:
            table.add_row(
                str(script['id']),
                script['name'],
                script['description'],
                ", ".join(script['tags']),
                script['type'].title()
            )

        self.console.print(table)

    def _show_script(self, script_id):
        """显示脚本内容"""
        try:
            script_id = int(script_id)
            script = self.db.get_script_by_id(script_id)
            
            if not script:
                self.console.print("[red]Script not found in database[/red]")
                return False
            
            script_path = self.scripts_dir / script['filename']
            if not script_path.exists():
                # 尝试在默认脚本目录中查找
                default_script_path = Path(__file__).parent / 'scripts' / script['filename']
                if default_script_path.exists():
                    script_path = default_script_path
                else:
                    self.console.print(f"[red]Script file not found in either:[/red]")
                    self.console.print(f"- {script_path}")
                    self.console.print(f"- {default_script_path}")
                    self.console.print("\n[yellow]Available scripts:[/yellow]")
                    self._list_scripts()  # 显示可用的脚本列表
                    return False
            
            with open(script_path, 'r') as f:
                content = f.read()
            
            # 显示脚本信息和内容
            self.console.print(f"\n[bold cyan]Script #{script['id']}: {script['name']}[/bold cyan]")
            self.console.print(f"[yellow]Tags: {', '.join(script['tags'])}[/yellow]")
            self.console.print(f"Description: {script['description']}")
            self.console.print(f"File: {script_path}\n")
            self.console.print(Syntax(content, "javascript", theme="monokai"))
            return True
            
        except ValueError:
            self.console.print("[red]Invalid script ID[/red]")
            return False
        except Exception as e:
            self.console.print(f"[red]Error showing script: {str(e)}[/red]")
            return False

    def _search_scripts(self, keyword=None, tag=None):
        scripts = self.db.search_scripts(keyword, tag)
        if scripts:
            table = Table(
                title=f"Search Results",
                show_header=True,
                header_style="bold magenta",
                box=box.SIMPLE
            )
            
            table.add_column("ID", style="cyan", justify="right")
            table.add_column("Name", style="cyan")
            table.add_column("Description", style="green")
            table.add_column("Tags", style="yellow")
            table.add_column("Type", style="blue")

            for script in scripts:
                table.add_row(
                    str(script['id']),
                    script['name'],
                    script['description'],
                    ", ".join(script['tags']),
                    script['type'].title()
                )
            
            self.console.print(table)
        else:
            self.console.print("[yellow]No scripts found[/yellow]")

    def _add_script(self, name, description, tags, content):
        filename = f"{name.lower().replace(' ', '_')}_{datetime.now().strftime('%Y%m%d%H%M%S')}.js"
        script_path = self.scripts_dir / filename
        
        # Save script content
        with open(script_path, 'w') as f:
            f.write(content)
        
        # Add to database
        script_id = self.db.add_script(
            name,
            description,
            filename,
            "custom",
            [tag.strip() for tag in tags.split(',')]
        )
        
        self.console.print(f"[green]Script added successfully with ID: {script_id}[/green]")

    def _delete_script(self, script_id):
        try:
            script_id = int(script_id)
            script = self.db.get_script_by_id(script_id)
            
            if script and script['type'] != 'quick':  # Cannot delete quick scripts
                script_path = self.scripts_dir / script['filename']
                if script_path.exists():
                    script_path.unlink()
                
                if self.db.delete_script(script_id):
                    self.console.print("[green]Script deleted successfully[/green]")
                    return True
            
            self.console.print("[red]Script not found or is a quick script (cannot be deleted)[/red]")
            return False
        except ValueError:
            self.console.print("[red]Invalid script ID[/red]")
            return False

    def _edit_script(self, script_id):
        script = self.db.get_script_by_id(script_id)
        if not script:
            self.console.print("[red]Script not found[/red]")
            return
        
        if script['type'] == 'quick':
            self.console.print("[red]Cannot edit quick scripts[/red]")
            return
        
        self.console.print(f"\n[bold cyan]Editing Script #{script_id}[/bold cyan]")
        self.console.print("Current values:")
        self.console.print(f"Name: {script['name']}")
        self.console.print(f"Description: {script['description']}")
        self.console.print(f"Tags: {', '.join(script['tags'])}")
        
        while True:
            self.console.print("\n[cyan]Edit options:[/cyan]")
            self.console.print("1. Edit name")
            self.console.print("2. Edit description")
            self.console.print("3. Add tag")
            self.console.print("4. Remove tag")
            self.console.print("5. Done")
            
            choice = self.console.input("\n[bold cyan]edit#[/bold cyan] ").strip()
            
            if choice == "1":
                name = self.console.input("New name: ").strip()
                if name:
                    self.db.update_script_metadata(script_id, name=name)
            elif choice == "2":
                desc = self.console.input("New description: ").strip()
                if desc:
                    self.db.update_script_metadata(script_id, description=desc)
            elif choice == "3":
                tag = self.console.input("New tag: ").strip()
                if tag:
                    if self.db.add_script_tag(script_id, tag):
                        self.console.print("[green]Tag added[/green]")
                    else:
                        self.console.print("[yellow]Tag already exists[/yellow]")
            elif choice == "4":
                tag = self.console.input("Tag to remove: ").strip()
                if tag:
                    if self.db.remove_script_tag(script_id, tag):
                        self.console.print("[green]Tag removed[/green]")
                    else:
                        self.console.print("[yellow]Tag not found[/yellow]")
            elif choice == "5":
                break

    def _spawn_and_inject(self, script_id: str, device_id: str = None, package: str = None):
        """生成新进程并注入脚本"""
        try:
            # 获取脚本内容
            script_data = self._get_script(script_id)
            if not script_data:
                return
            
            script_path = os.path.join(self.scripts_dir, script_data['filename'])
            with open(script_path, 'r') as f:
                script_content = f.read()
            
            # 获取设备
            device = self._get_device(device_id)
            if not device:
                return
            
            # 生成新进程
            pid = device.spawn([package])
            self.console.print(f"[green]Spawned {package} with PID {pid}[/green]")
            
            # 附加到进程
            session = device.attach(pid)
            
            # 创建脚本
            script = session.create_script(script_content)
            
            # 设置消息处理
            def on_message(message, data):
                if message['type'] == 'send':
                    self.console.print(f"[green]{message['payload']}[/green]")
                elif message['type'] == 'error':
                    self.console.print(f"[red]Script Error: {message['description']}[/red]")
            
            script.on('message', on_message)
            
            # 加载脚本
            script.load()
            self.console.print(f"[green]Script {script_id} injected successfully![/green]")
            
            # 恢复进程执行
            device.resume(pid)
            
            # 保持会话活跃
            self.console.print("[cyan]Press Ctrl+C to stop...[/cyan]")
            while True:
                time.sleep(1)
                
        except frida.ProcessNotFoundError:
            self.console.print(f"[red]Package {package} not found[/red]")
        except frida.InvalidArgumentError as e:
            self.console.print(f"[red]Error spawning process: {str(e)}[/red]")
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Script injection stopped[/yellow]")

    def _run_objection(self, subcommand: str, device_id: str = None, target: str = None):
        """运行objection命令"""
        try:
            # 构建基本命令
            cmd = ["objection"]
            
            if device_id:
                cmd.extend(["-d", device_id])
            
            # 处理不同的子命令
            if subcommand == "explore":
                cmd.extend(["-g", target, "explore"])
            elif subcommand == "memory":
                cmd.extend(["-g", target, "memory", "list", "modules"])
                self._run_interactive_objection(cmd)
                return
            elif subcommand == "android":
                cmd.extend(["-g", target, "android"])
                self._show_android_menu(cmd)
                return
            elif subcommand == "ios":
                cmd.extend(["-g", target, "ios"])
                self._show_ios_menu(cmd)
                return
            elif subcommand == "heap":
                cmd.extend(["-g", target, "heap"])
                self._show_heap_menu(cmd)
                return
            elif subcommand == "stalker":
                cmd.extend(["-g", target, "stalker"])
                self._show_stalker_menu(cmd)
                return
            
            # 执行命令
            self.console.print(f"[cyan]Running objection command: {' '.join(cmd)}[/cyan]")
            subprocess.run(cmd)
            
        except Exception as e:
            self.console.print(f"[red]Error running objection: {str(e)}[/red]")
    
    def _run_interactive_objection(self, base_cmd: list):
        """运行交互式objection命令"""
        try:
            process = subprocess.Popen(
                base_cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            self.console.print("[cyan]Interactive objection session started. Type 'exit' to quit.[/cyan]")
            
            while True:
                command = self.console.input("[cyan]objection> [/cyan]").strip()
                
                if command.lower() == "exit":
                    break
                
                process.stdin.write(command + "\n")
                process.stdin.flush()
                
                # 读取输出
                while True:
                    output = process.stdout.readline()
                    if not output or output.strip() == "objection>":
                        break
                    self.console.print(output.strip())
            
            process.terminate()
            
        except Exception as e:
            self.console.print(f"[red]Error in interactive session: {str(e)}[/red]")
    
    def _show_android_menu(self, base_cmd: list):
        """显示Android特定命令菜单"""
        while True:
            self.console.print("\n[yellow]Android Commands:[/yellow]")
            self.console.print("1. List activities")
            self.console.print("2. List services")
            self.console.print("3. List receivers")
            self.console.print("4. List providers")
            self.console.print("5. Dump manifest")
            self.console.print("6. List permissions")
            self.console.print("7. Start activity")
            self.console.print("8. Back")
            
            choice = self.console.input("[cyan]android> [/cyan]").strip()
            
            if choice == "8":
                break
            
            cmd = base_cmd.copy()
            if choice == "1":
                cmd.extend(["hooking", "list", "activities"])
            elif choice == "2":
                cmd.extend(["hooking", "list", "services"])
            elif choice == "3":
                cmd.extend(["hooking", "list", "receivers"])
            elif choice == "4":
                cmd.extend(["hooking", "list", "providers"])
            elif choice == "5":
                cmd.extend(["android", "hooking", "dump", "manifest"])
            elif choice == "6":
                cmd.extend(["android", "hooking", "list", "permissions"])
            elif choice == "7":
                activity = self.console.input("[cyan]Enter activity name: [/cyan]").strip()
                cmd.extend(["android", "intent", "launch_activity", activity])
            
            subprocess.run(cmd)
    
    def _show_ios_menu(self, base_cmd: list):
        """显示iOS特定命令菜单"""
        while True:
            self.console.print("\n[yellow]iOS Commands:[/yellow]")
            self.console.print("1. List keychain items")
            self.console.print("2. List cookies")
            self.console.print("3. List binary cookies")
            self.console.print("4. Dump UI")
            self.console.print("5. List modules")
            self.console.print("6. Back")
            
            choice = self.console.input("[cyan]ios> [/cyan]").strip()
            
            if choice == "6":
                break
            
            cmd = base_cmd.copy()
            if choice == "1":
                cmd.extend(["keychain", "dump"])
            elif choice == "2":
                cmd.extend(["cookies", "get"])
            elif choice == "3":
                cmd.extend(["cookies", "dump"])
            elif choice == "4":
                cmd.extend(["ui", "dump"])
            elif choice == "5":
                cmd.extend(["list", "modules"])
            
            subprocess.run(cmd)
    
    def _show_heap_menu(self, base_cmd: list):
        """显示堆操作菜单"""
        while True:
            self.console.print("\n[yellow]Heap Operations:[/yellow]")
            self.console.print("1. List instances")
            self.console.print("2. Search instances")
            self.console.print("3. Print instance")
            self.console.print("4. Back")
            
            choice = self.console.input("[cyan]heap> [/cyan]").strip()
            
            if choice == "4":
                break
            
            cmd = base_cmd.copy()
            if choice == "1":
                class_name = self.console.input("[cyan]Enter class name: [/cyan]").strip()
                cmd.extend(["print", "instances", class_name])
            elif choice == "2":
                pattern = self.console.input("[cyan]Enter search pattern: [/cyan]").strip()
                cmd.extend(["search", "instances", pattern])
            elif choice == "3":
                instance_id = self.console.input("[cyan]Enter instance id: [/cyan]").strip()
                cmd.extend(["print", "instance", instance_id])
            
            subprocess.run(cmd)
    
    def _show_stalker_menu(self, base_cmd: list):
        """显示函数追踪菜单"""
        while True:
            self.console.print("\n[yellow]Function Stalker:[/yellow]")
            self.console.print("1. Stalk function")
            self.console.print("2. Stalk module")
            self.console.print("3. Stop stalking")
            self.console.print("4. Back")
            
            choice = self.console.input("[cyan]stalker> [/cyan]").strip()
            
            if choice == "4":
                break
            
            cmd = base_cmd.copy()
            if choice == "1":
                function = self.console.input("[cyan]Enter function name: [/cyan]").strip()
                cmd.extend(["stalk", "function", function])
            elif choice == "2":
                module = self.console.input("[cyan]Enter module name: [/cyan]").strip()
                cmd.extend(["stalk", "module", module])
            elif choice == "3":
                cmd.extend(["stop"])
            
            subprocess.run(cmd)

    def _get_script(self, script_id: str):
        """获取脚本数据"""
        try:
            script_id = int(script_id)
            script = self.db.get_script_by_id(script_id)
            
            if script:
                return script
            
            self.console.print(f"[red]Script {script_id} not found[/red]")
            return None
        except ValueError:
            self.console.print("[red]Invalid script ID[/red]")
            return None

    def _run_adb_command(self, subcommand: str, device_id: str = None, *params):
        """运行ADB命令"""
        try:
            base_cmd = ["adb"]
            if device_id:
                base_cmd.extend(["-s", device_id])

            if subcommand == "current_activity":
                # 获取当前Activity
                cmd = base_cmd + ["shell", "dumpsys", "window", "windows", "|", "grep", "-E", "'mCurrentFocus|mFocusedApp'"]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "input_text":
                # 模拟文本输入
                if not params:
                    text = self.console.input("[cyan]Enter text to input:[/cyan] ")
                else:
                    text = params[0]
                cmd = base_cmd + ["shell", "input", "text", text]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "tap":
                # 模拟点击
                if len(params) < 2:
                    x = self.console.input("[cyan]Enter x coordinate:[/cyan] ")
                    y = self.console.input("[cyan]Enter y coordinate:[/cyan] ")
                else:
                    x, y = params[0], params[1]
                cmd = base_cmd + ["shell", "input", "tap", str(x), str(y)]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "swipe":
                # 模拟滑动
                if len(params) < 4:
                    x1 = self.console.input("[cyan]Enter start x coordinate:[/cyan] ")
                    y1 = self.console.input("[cyan]Enter start y coordinate:[/cyan] ")
                    x2 = self.console.input("[cyan]Enter end x coordinate:[/cyan] ")
                    y2 = self.console.input("[cyan]Enter end y coordinate:[/cyan] ")
                    duration = self.console.input("[cyan]Enter duration (ms, default 300):[/cyan] ") or "300"
                else:
                    x1, y1, x2, y2 = params[0:4]
                    duration = params[4] if len(params) > 4 else "300"
                cmd = base_cmd + ["shell", "input", "swipe", str(x1), str(y1), str(x2), str(y2), str(duration)]
                self._run_command(" ".join(cmd))
            
            elif subcommand in ["back", "home", "menu", "power"]:
                # 模拟系统按键
                key_map = {
                    "back": "KEYCODE_BACK",
                    "home": "KEYCODE_HOME",
                    "menu": "KEYCODE_MENU",
                    "power": "KEYCODE_POWER"
                }
                cmd = base_cmd + ["shell", "input", "keyevent", key_map[subcommand]]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "screenshot":
                # 截图
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                remote_path = f"/sdcard/screenshot_{timestamp}.png"
                local_path = f"screenshots/screenshot_{timestamp}.png"
                os.makedirs("screenshots", exist_ok=True)
                
                # 截图到设备
                cmd1 = base_cmd + ["shell", "screencap", "-p", remote_path]
                self._run_command(" ".join(cmd1))
                
                # 拉取到本地
                cmd2 = base_cmd + ["pull", remote_path, local_path]
                self._run_command(" ".join(cmd2))
                
                # 删除设备上的文件
                cmd3 = base_cmd + ["shell", "rm", remote_path]
                self._run_command(" ".join(cmd3))
                
                self.console.print(f"[green]Screenshot saved to {local_path}[/green]")
            
            elif subcommand == "screenrecord":
                # 录屏
                if not params:
                    duration = self.console.input("[cyan]Enter recording duration in seconds (default 30):[/cyan] ") or "30"
                else:
                    duration = params[0]
                
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                remote_path = f"/sdcard/screenrecord_{timestamp}.mp4"
                local_path = f"screenrecords/screenrecord_{timestamp}.mp4"
                os.makedirs("screenrecords", exist_ok=True)
                
                self.console.print("[cyan]Recording screen... Press Ctrl+C to stop[/cyan]")
                cmd = base_cmd + ["shell", "screenrecord", "--time-limit", duration, remote_path]
                
                try:
                    subprocess.run(" ".join(cmd), shell=True)
                except KeyboardInterrupt:
                    self.console.print("\n[yellow]Stopping recording...[/yellow]")
                
                # 等待文件写入完成
                time.sleep(1)
                
                # 拉取到本地
                cmd2 = base_cmd + ["pull", remote_path, local_path]
                self._run_command(" ".join(cmd2))
                
                # 删除设备上的文件
                cmd3 = base_cmd + ["shell", "rm", remote_path]
                self._run_command(" ".join(cmd3))
                
                self.console.print(f"[green]Screen recording saved to {local_path}[/green]")
            
            elif subcommand == "install":
                # 安装APK
                if not params:
                    apk_path = self.console.input("[cyan]Enter APK path:[/cyan] ")
                else:
                    apk_path = params[0]
                cmd = base_cmd + ["install", "-r", "-d", apk_path]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "uninstall":
                # 卸载应用
                if not params:
                    package_name = self.console.input("[cyan]Enter package name:[/cyan] ")
                else:
                    package_name = params[0]
                cmd = base_cmd + ["uninstall", package_name]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "grant":
                # 授予权限
                if len(params) < 2:
                    package_name = self.console.input("[cyan]Enter package name:[/cyan] ")
                    permission = self.console.input("[cyan]Enter permission:[/cyan] ")
                else:
                    package_name, permission = params[0:2]
                cmd = base_cmd + ["shell", "pm", "grant", package_name, permission]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "revoke":
                # 撤销权限
                if len(params) < 2:
                    package_name = self.console.input("[cyan]Enter package name:[/cyan] ")
                    permission = self.console.input("[cyan]Enter permission:[/cyan] ")
                else:
                    package_name, permission = params[0:2]
                cmd = base_cmd + ["shell", "pm", "revoke", package_name, permission]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "permissions":
                # 查看应用权限
                if not params:
                    package_name = self.console.input("[cyan]Enter package name:[/cyan] ")
                else:
                    package_name = params[0]
                cmd = base_cmd + ["shell", "dumpsys", "package", package_name, "|", "grep", "permission"]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "app_info":
                # 查看应用信息
                if not params:
                    package_name = self.console.input("[cyan]Enter package name:[/cyan] ")
                else:
                    package_name = params[0]
                cmd = base_cmd + ["shell", "dumpsys", "package", package_name]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "memory_info":
                # 查看内存信息
                if not params:
                    package_name = self.console.input("[cyan]Enter package name:[/cyan] ")
                else:
                    package_name = params[0]
                cmd = base_cmd + ["shell", "dumpsys", "meminfo", package_name]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "battery_info":
                # 查看电池信息
                cmd = base_cmd + ["shell", "dumpsys", "battery"]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "logcat":
                # 查看日志
                filter_str = f"*:{params[0]}" if params else "*:D"
                cmd = base_cmd + ["logcat", filter_str]
                self.console.print("[cyan]Press Ctrl+C to stop logging...[/cyan]")
                process = subprocess.Popen(" ".join(cmd), shell=True)
                try:
                    process.wait()
                except KeyboardInterrupt:
                    process.terminate()
            
            elif subcommand == "bugreport":
                # 生成错误报告
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"bugreport_{timestamp}"
                os.makedirs("bugreports", exist_ok=True)
                cmd = base_cmd + ["bugreport", f"bugreports/{filename}"]
                self.console.print("[cyan]Generating bug report... This may take a while.[/cyan]")
                self._run_command(" ".join(cmd))
            
            elif subcommand == "dumpsys":
                # 系统信息
                service = params[0] if params else self.console.input("[cyan]Enter service name (e.g., battery, wifi):[/cyan] ")
                cmd = base_cmd + ["shell", "dumpsys", service]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "dmesg":
                # 内核日志
                cmd = base_cmd + ["shell", "dmesg"]
                self._run_command(cmd)
            
            elif subcommand == "top":
                # 进程资源占用
                cmd = base_cmd + ["shell", "top", "-n", "1"]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "cpuinfo":
                # CPU 信息
                cmd = base_cmd + ["shell", "cat", "/proc/cpuinfo"]
                self._run_command(cmd)
            
            elif subcommand == "meminfo":
                # 内存信息
                cmd = base_cmd + ["shell", "cat", "/proc/meminfo"]
                self._run_command(cmd)
            
            elif subcommand == "netstat":
                # 网络统计
                cmd = base_cmd + ["shell", "netstat"]
                self._run_command(cmd)
            
            elif subcommand == "procstats":
                # 进程统计
                cmd = base_cmd + ["shell", "dumpsys", "procstats"]
                self._run_command(cmd)
            
            elif subcommand == "forward":
                # 端口转发
                if len(params) < 2:
                    local_port = self.console.input("[cyan]Enter local port:[/cyan] ")
                    remote_port = self.console.input("[cyan]Enter remote port:[/cyan] ")
                else:
                    local_port, remote_port = params[0:2]
                cmd = base_cmd + ["forward", f"tcp:{local_port}", f"tcp:{remote_port}"]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "reverse":
                # 反向端口转发
                if len(params) < 2:
                    remote_port = self.console.input("[cyan]Enter remote port:[/cyan] ")
                    local_port = self.console.input("[cyan]Enter local port:[/cyan] ")
                else:
                    remote_port, local_port = params[0:2]
                cmd = base_cmd + ["reverse", f"tcp:{remote_port}", f"tcp:{local_port}"]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "ifconfig":
                # 网络配置
                cmd = base_cmd + ["shell", "ifconfig"]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "get-state":
                # 获取设备状态
                cmd = base_cmd + ["get-state"]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "get-serialno":
                # 获取序列号
                cmd = base_cmd + ["get-serialno"]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "get-devpath":
                # 获取设备路径
                cmd = base_cmd + ["get-devpath"]
                self._run_command(" ".join(cmd))
            
            elif subcommand == "call":
                # 拨打电话
                if not params:
                    self.console.print("[red]Phone number required[/red]")
                    return
                cmd = base_cmd + ["shell", "run-as", "com.termux", "/data/data/com.termux/files/usr/bin/termux-telephony-call", params[0]]
                self._run_command(cmd)
            elif subcommand == "call-log":
                # 查看通话记录
                limit = params[0] if params else "10"
                offset = params[1] if len(params) > 1 else "0"
                cmd = base_cmd + ["shell", "run-as", "com.termux", "/data/data/com.termux/files/usr/bin/termux-telephony-calllog", "-l", limit, "-o", offset]
                self._run_command(cmd)
            elif subcommand == "contacts":
                # 获取联系人列表
                cmd = base_cmd + ["shell", "run-as", "com.termux", "/data/data/com.termux/files/usr/bin/termux-contact-list"]
                self._run_command(cmd)
            elif subcommand == "cellular-info":
                # 获取蜂窝网络信息
                cmd = base_cmd + ["shell", "run-as", "com.termux", "/data/data/com.termux/files/usr/bin/termux-telephony-cellinfo"]
                self._run_command(cmd)
            elif subcommand == "device-info":
                # 获取设备信息
                cmd = base_cmd + ["shell", "run-as", "com.termux", "/data/data/com.termux/files/usr/bin/termux-telephony-deviceinfo"]
                self._run_command(cmd)
            elif subcommand == "wifi-enable":
                # 启用WiFi
                cmd = base_cmd + ["shell", "settings", "put", "global", "airplane_mode_on", "1"]
                self._run_command(" ".join(cmd))
            elif subcommand == "wifi-disable":
                # 禁用WiFi
                cmd = base_cmd + ["shell", "settings", "put", "global", "airplane_mode_on", "0"]
                self._run_command(" ".join(cmd))
            elif subcommand == "wifi-status":
                # 获取WiFi状态
                cmd = base_cmd + ["shell", "settings", "get", "global", "airplane_mode"]
                self._run_command(" ".join(cmd))
            elif subcommand == "wifi-scaninfo":
                # 获取WiFi扫描信息
                cmd = base_cmd + ["shell", "dumpsys", "wifi", "scaninfo"]
                self._run_command(" ".join(cmd))
            else:
                self.console.print(f"[red]Unknown ADB command: {subcommand}[/red]")
                self.console.print(f"[yellow]Available commands: {', '.join(self.adb_commands)}[/yellow]")
        
        except Exception as e:
            self.console.print(f"[red]Error running ADB command: {str(e)}[/red]")

    def _run_scrcpy(self, device_id: str = None):
        """运行Scrcpy进行设备投屏"""
        try:
            cmd = ["scrcpy"]
            if device_id:
                cmd.extend(["-s", device_id])
            
            # 添加一些常用的优化选项
            cmd.extend([
                "--max-fps", "60",  # 限制帧率
                "--window-title", f"Scrcpy - {device_id if device_id else 'Default Device'}",  # 设置窗口标题
                "--show-touches",  # 显示触摸点
                "--turn-screen-off",  # 投屏时关闭设备屏幕
                "--stay-awake",  # 保持设备唤醒
                "--power-off-on-close"  # 关闭投屏时关闭设备屏幕
            ])
            
            self.console.print("[cyan]Starting Scrcpy...[/cyan]")
            self.console.print("[cyan]Press Ctrl+C to stop[/cyan]")
            
            process = subprocess.Popen(cmd)
            process.wait()
            
        except Exception as e:
            self.console.print(f"[red]Error running Scrcpy: {str(e)}[/red]")

    def _run_command(self, command: str):
        """运行命令并捕获输出"""
        try:
            # Split the command if it's a string
            if isinstance(command, str):
                command = command.split()
            
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=False  # Explicitly set shell to False for security
            )
            
            while True:
                output = process.stdout.readline()
                if output:
                    self.console.print(output.strip())
                if process.poll() is not None:
                    break
            
            # Check for any errors
            if process.returncode != 0:
                error = process.stderr.read()
                if error:
                    self.console.print(f"[red]{error.strip()}[/red]")
        
        except Exception as e:
            self.console.print(f"[red]Error running command: {str(e)}[/red]")

    def _run_screen_shell(self, device_id: str = None):
        """启动交互式投屏和shell会话"""
        try:
            # 检查tmux是否已安装
            if subprocess.run(['which', 'tmux'], capture_output=True).returncode != 0:
                self.console.print("[red]Error: tmux is not installed. Please install it first.[/red]")
                self.console.print("[yellow]For macOS: brew install tmux[/yellow]")
                self.console.print("[yellow]For Linux: sudo apt install tmux[/yellow]")
                return

            # 创建一个新的tmux会话
            session_name = f"android_control_{int(time.time())}"
            
            # 构建设备参数
            device_param = f"-s {device_id}" if device_id else ""
            
            # 创建tmux会话并分割窗口
            tmux_commands = [
                # 创建新会话，启动local shell
                f"tmux new-session -d -s {session_name}",
                f"tmux send-keys -t {session_name}.0 'scrcpy {device_param}' C-m",  # 确保在当前工作目录
                
                f"tmux split-window -h -t {session_name}.0",
                f"tmux send-keys -t {session_name}.1 'cd {os.getcwd()}' C-m",
                
                f"tmux split-window -v -t {session_name}.0",
                f"tmux send-keys -t {session_name}.2 'cd {os.getcwd()}' C-m",
                
                # 选择local shell窗格作为活动窗格
                f"tmux select-pane -t {session_name}.1",

                # 设置scrcpy窗格高度为10%
                f"tmux resize-pane -t {session_name}.0 -x 20%",
                # 附加到会话
                f"tmux attach-session -t {session_name}"
            ]
            # 执行tmux命令
            for cmd in tmux_commands:
                subprocess.run(cmd, shell=True)
            
        except Exception as e:
            self.console.print(f"[red]Error starting screen shell: {str(e)}[/red]")

    def _run_termux_ssh(self, device_id: str = None):
        """Setup and manage SSH connection in Termux using tmux"""
        try:
            # Get device info (returns tuple of (ip_address, username))
            device_info = self._get_target_device_info(device_id)
            
            if not device_info:
                return
            
            ssh_host, ssh_user = device_info  # Unpack the tuple
            ssh_port = "8022"  # Termux default SSH port
            
            # Create SSH command with explicit port
            ssh_cmd = f"ssh -p {ssh_port} {ssh_user}@{ssh_host}"
            
            # Create a unique session name using timestamp
            session_name = f"termux_ssh_{int(time.time())}"
            
            # Prepare tmux commands
            tmux_commands = [
                # Kill existing session if it exists
                f"tmux kill-session -t {session_name} 2>/dev/null || true",
                
                # Create new session
                f"tmux new-session -d -s {session_name}",
                
                # Set window name
                f"tmux rename-window -t {session_name} 'termux-ssh'",
                
                # Send SSH command to the session
                f"tmux send-keys -t {session_name} '{ssh_cmd}' Enter",
                
                # Attach to the session
                f"tmux attach-session -t {session_name}"
            ]
            
            # Execute tmux commands
            for cmd in tmux_commands:
                subprocess.run(cmd, shell=True)
            
            console.print(f"[green]SSH connection established in tmux session: {session_name}[/green]")
            console.print("[cyan]Use 'Ctrl+b d' to detach from the session[/cyan]")
            console.print(f"[cyan]To reattach later, use: tmux attach -t {session_name}[/cyan]")
            
        except Exception as e:
            self.console.print(f"[red]Error establishing SSH connection: {str(e)}[/red]")

    def _run_termux_api(self, subcommand: str, device_id: str = None, *params):
        """Execute Termux API commands via SSH"""
        try:
            # Get device info (returns tuple of (ip_address, username))
            device_info = self._get_target_device_info(device_id)
            if not device_info or len(device_info) != 2:
                self.console.print("[red]Failed to get device information[/red]")
                return

            ssh_host, ssh_user = device_info

            if not ssh_host or not ssh_user:
                self.console.print("[red]Failed to get SSH connection details[/red]")
                return

            # First, ensure Termux API is installed
            install_cmd = [
                "ssh",
                "-tt",
                "-p", "8022",
                f"{ssh_user}@{ssh_host}",
                "pkg install -y termux-api"
            ]
            
            subprocess.run(install_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

            # Map telephony commands to their proper Termux API equivalents
            command_map = {
                "call": "termux-telephony-call",
                "call-log": "termux-telephony-calllog",
                "call-info": "termux-telephony-deviceinfo",
                "cellular-info": "termux-telephony-cellinfo",
                "device-info": "termux-telephony-deviceinfo"
            }

            # Get the correct command name
            termux_cmd = command_map.get(subcommand, f"termux-{subcommand}")

            # Build command with parameters
            if subcommand == "call":
                # Ensure phone number is properly formatted
                phone_number = str(params[0]).strip()
                if not phone_number:
                    self.console.print("[red]Phone number is required[/red]")
                    return
                termux_cmd = f"{termux_cmd} {phone_number}"
            elif subcommand == "call-log":
                # Handle call log parameters
                if len(params) > 0:
                    termux_cmd = f"{termux_cmd} {' '.join(str(p) for p in params)}"
            else:
                # For other commands, just append parameters
                if params:
                    termux_cmd += " " + " ".join(str(p) for p in params)

            # Construct and execute SSH command with proper PATH
            ssh_cmd = [
                "ssh",
                "-tt",
                "-p", "8022",
                f"{ssh_user}@{ssh_host}",
                f"export PATH=/data/data/com.termux/files/usr/bin:$PATH && {termux_cmd}"
            ]

            # Execute command
            process = subprocess.Popen(
                ssh_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                universal_newlines=True
            )

            # Process output in real-time
            output_lines = []
            while True:
                line = process.stdout.readline()
                if not line and process.poll() is not None:
                    break
                if line:
                    # Clean ANSI escape sequences and control characters
                    clean_line = re.sub(r'\x1B\[[0-?]*[ -/]*[@-~]', '', line).strip()
                    if clean_line:
                        output_lines.append(clean_line)
                        self.console.print(clean_line)

            # Check for errors
            return_code = process.poll()
            if return_code != 0:
                error = process.stderr.read()
                if error:
                    self.console.print(f"[red]Error: {error}[/red]")
                return

            # Try to parse JSON output if present
            try:
                output_text = '\n'.join(output_lines)
                if output_text.strip().startswith('{') or output_text.strip().startswith('['):
                    json_data = json.loads(output_text)
                    # Create a table for JSON output
                    table = Table(title=f"termux-{subcommand} Result")
                    if isinstance(json_data, dict):
                        table.add_column("Key", style="cyan")
                        table.add_column("Value", style="green")
                        for key, value in json_data.items():
                            table.add_row(str(key), str(value))
                    elif isinstance(json_data, list):
                        if json_data and isinstance(json_data[0], dict):
                            # Get columns from first item
                            columns = list(json_data[0].keys())
                            for col in columns:
                                table.add_column(col, style="cyan")
                            # Add rows
                            for item in json_data:
                                table.add_row(*[str(item.get(col, '')) for col in columns])
                        else:
                            table.add_column("Value", style="green")
                            for item in json_data:
                                table.add_row(str(item))
                    self.console.print(table)
            except json.JSONDecodeError:
                # Output wasn't JSON, already printed line by line above
                pass

        except Exception as e:
            self.console.print(f"[red]Error: {str(e)}[/red]")

    def _get_target_device_info(self, device_id: str = None):
        """Get target device IP and user information"""
        try:
            # Check if device exists
            result = subprocess.run(
                ['adb', 'devices'],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                self.console.print("[red]Error listing adb devices[/red]")
                return None
            
            # Check if the specified device is in the list
            if device_id and device_id not in result.stdout:
                self.console.print(f"[red]Device {device_id} not found. Available devices:[/red]")
                self.console.print(result.stdout)
                return None
            
            # Get device IP address
            adb_cmd = ['adb']
            if device_id:
                adb_cmd.extend(['-s', device_id])
            adb_cmd.extend(['shell', 'ip', 'route'])
            
            result = subprocess.run(
                adb_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if result.returncode != 0:
                self.console.print(f"[red]Error getting device IP: {result.stderr}[/red]")
                return None
            
            # Extract IP address
            ip_match = re.search(r'src (\d+\.\d+\.\d+\.\d+)', result.stdout)
            if not ip_match:
                # Try alternative method
                adb_cmd = ['adb']
                if device_id:
                    adb_cmd.extend(['-s', device_id])
                adb_cmd.extend(['shell', 'settings', 'get', 'global', 'wifi_ip_address'])
                
                result = subprocess.run(
                    adb_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True
                )
                
                if result.returncode != 0 or not result.stdout.strip():
                    self.console.print("[red]Could not get device IP address[/red]")
                    return None
                
                device_ip = result.stdout.strip()
            else:
                device_ip = ip_match.group(1)
            
            # Get Termux username
            adb_cmd = ['adb']
            if device_id:
                adb_cmd.extend(['-s', device_id])
            adb_cmd.extend(['shell', 'run-as', 'com.termux', 'whoami'])
            
            result = subprocess.run(
                adb_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            termux_user = result.stdout.strip()
            if not termux_user:
                termux_user = 'u0_a287'  # Default Termux user if not found
            
            # Check SSH service
            adb_cmd = ['adb']
            if device_id:
                adb_cmd.extend(['-s', device_id])
            adb_cmd.extend(['shell', 'ps -ef | grep sshd'])
            
            result = subprocess.run(
                adb_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            if 'sshd' not in result.stdout:
                self.console.print("[yellow]Starting SSH service...[/yellow]")
                adb_cmd = ['adb']
                if device_id:
                    adb_cmd.extend(['-s', device_id])
                adb_cmd.extend(['shell', 'run-as', 'com.termux', 'sshd'])
                
                subprocess.run(adb_cmd)
                time.sleep(2)  # Wait for service to start
            
            self.console.print(f"[green]Connected to device at {device_ip} as {termux_user}[/green]")
            return device_ip, termux_user
            
        except Exception as e:
            self.console.print(f"[red]Error getting device info: {str(e)}[/red]")
            return None

    def _check_termux_command(self, command):
        """Check if termux command exists through SSH"""
        try:
            # 获取目标设备信息
            device_info = self._get_target_device_info()
            if not device_info:
                return False
                
            ssh_host, ssh_user = device_info
            ssh_port = os.getenv('TERMUX_SSH_PORT', '8022')
            
            check_cmd = [
                'ssh',
                '-tt',
                '-p', ssh_port,
                f'{ssh_user}@{ssh_host}',
                f'which termux-{command}'  # 检查 termux- 前缀的命令
            ]
            
            result = subprocess.run(
                check_cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            return result.returncode == 0
        except Exception:
            return False

    def _ensure_dirs(self):
        """Ensure required directories exist"""
        self.scripts_dir.mkdir(parents=True, exist_ok=True)
        self.hooks_dir.mkdir(parents=True, exist_ok=True)
