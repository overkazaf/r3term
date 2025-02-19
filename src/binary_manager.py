from base_manager import BaseManager
from rich.console import Console
from rich.table import Table
import subprocess
import os
import tempfile
import r2pipe
import json
from pathlib import Path

console = Console()

class BinaryManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.workspace_dir = Path("data/binary_workspace")
        self.workspace_dir.mkdir(parents=True, exist_ok=True)
        self.console = Console()
        self.current_file = None
        self.ida_path = "/Applications/IDA Professional 9.0.app/Contents/MacOS/ida"
    
    def handle_command(self, command: str, *args):
        """Handle binary analysis commands"""
        try:
            # 首先检查是否是shell命令
            if self.handle_shell_command(command):
                return
            if command == "open":
                if len(args) > 0:
                    self._open_file(args[0])
                else:
                    console.print("[red]Please provide a binary path[/red]")
            elif command == "analyze":
                if self.current_file:
                    self._analyze_file()
                else:
                    console.print("[red]Please open a file first[/red]")
            elif command == "strings":
                if self.current_file:
                    self._extract_strings(self.current_file)
                else:
                    console.print("[red]Please open a file first[/red]")
            elif command == "exports":
                if self.current_file:
                    self._list_exports(self.current_file)
                else:
                    console.print("[red]Please open a file first[/red]")
            elif command == "imports":
                if self.current_file:
                    self._list_imports(self.current_file)
                else:
                    console.print("[red]Please open a file first[/red]")
            elif command == "functions":
                if self.current_file:
                    self._list_functions()
                else:
                    console.print("[red]Please open a file first[/red]")
            elif command == "info":
                if self.current_file:
                    self._show_info()
                else:
                    console.print("[red]Please open a file first[/red]")
            elif command == "disasm":
                if self.current_file:
                    self._disassemble(args[0] if args else None)
                else:
                    console.print("[red]Please open a file first[/red]")
            elif command == "search":
                if len(args) > 0 and self.current_file:
                    self._search_pattern(args[0])
                else:
                    console.print("[red]Please provide a pattern and open a file first[/red]")
            elif command == "references":
                if len(args) > 0 and self.current_file:
                    self._find_references(args[0])
                else:
                    console.print("[red]Please provide a function name and open a file first[/red]")
            elif command == "shell":
                if self.current_file:
                    self._open_r2_shell()
                else:
                    console.print("[red]Please open a file first[/red]")
            elif command == "gdb":
                if self.current_file:
                    self._start_gdb_session(args)
                else:
                    console.print("[red]Please open a file first[/red]")
            elif command == "ida":
                if self.current_file:
                    self._start_ida_session(args)
                else:
                    console.print("[red]Please open a file first[/red]")
            else:
                console.print("[red]Unknown command[/red]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

    def handle_shell_command(self, command: str) -> bool:
        """处理shell命令"""
        if command.lower() in ['q', 'quit', 'exit', 'b', 'back']:
            self.console.print("[yellow]Returning to main menu...[/yellow]")
            return True
        elif command.lower() in ['h', 'help', '?']:
            self._show_help()
            return True
        return False

    def _show_help(self):
        """显示帮助信息"""
        self.console.print("\n[bold cyan]Binary Analysis Commands:[/bold cyan]")
        table = Table(show_header=False, box=None)
        table.add_column("Command", style="green")
        table.add_column("Description", style="white")
        
        table.add_row("open <file>", "Open a binary file for analysis")
        table.add_row("analyze", "Perform deep analysis on the current file")
        table.add_row("info", "Show file information")
        table.add_row("strings", "Extract strings from the binary")
        table.add_row("exports", "List export functions")
        table.add_row("imports", "List import functions")
        table.add_row("functions", "List all functions")
        table.add_row("disasm [function]", "Disassemble function or current position")
        table.add_row("search <pattern>", "Search for hex pattern")
        table.add_row("references <function>", "Find references to a function")
        table.add_row("shell", "Open interactive r2 shell")
        table.add_row("gdb [args]", "Start GDB debugging session")
        table.add_row("ida [args]", "Start IDA debugging session")
        table.add_row("help", "Show this help message")
        table.add_row("quit/back", "Return to main menu")
        
        self.console.print(table)

    def _list_exports(self, file_path: str):
        """列出导出函数"""
        try:
            r2 = r2pipe.open(file_path)
            r2.cmd('aaa')  # 分析所有内容
            exports = r2.cmdj('iEj')  # 获取导出函数的JSON格式
            r2.quit()
            
            if not exports:
                self.console.print("[yellow]No exports found[/yellow]")
                return
            
            # 创建表格显示导出函数
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Ordinal", style="dim")
            table.add_column("Address", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Size", style="blue")
            
            for exp in exports:
                table.add_row(
                    str(exp.get('ordinal', 'N/A')),
                    hex(exp.get('vaddr', 0)),
                    exp.get('name', 'Unknown'),
                    str(exp.get('size', 0))
                )
            
            self.console.print("\n[bold]Export Functions:[/bold]")
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error listing exports: {str(e)}[/red]")

    def _list_imports(self, file_path: str):
        """列出导入函数"""
        try:
            r2 = r2pipe.open(file_path)
            r2.cmd('aaa')  # 分析所有内容
            imports = r2.cmdj('iij')  # 获取导入函数的JSON格式
            r2.quit()
            
            if not imports:
                self.console.print("[yellow]No imports found[/yellow]")
                return
            
            # 创建表格显示导入函数
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Ordinal", style="dim")
            table.add_column("Address", style="cyan")
            table.add_column("Name", style="green")
            table.add_column("Library", style="blue")
            
            for imp in imports:
                table.add_row(
                    str(imp.get('ordinal', 'N/A')),
                    hex(imp.get('plt', 0)),
                    imp.get('name', 'Unknown'),
                    imp.get('libname', 'Unknown')
                )
            
            self.console.print("\n[bold]Import Functions:[/bold]")
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error listing imports: {str(e)}[/red]")
    
    def _extract_strings(self, file_path: str):
        """提取字符串"""
        try:
            r2 = r2pipe.open(file_path)
            r2.cmd('aaa')  # 分析所有内容
            strings = r2.cmdj('izj')  # 获取字符串的JSON格式
            r2.quit()
            
            if not strings:
                self.console.print("[yellow]No strings found[/yellow]")
                return
            
            # 创建表格显示字符串
            table = Table(show_header=True, header_style="bold magenta")
            table.add_column("Address", style="cyan")
            table.add_column("Type", style="dim")
            table.add_column("String", style="green")
            table.add_column("Length", style="blue")
            
            for s in strings:
                # 过滤掉太短的字符串（通常是噪音）
                if len(s.get('string', '')) < 4:
                    continue
                    
                table.add_row(
                    hex(s.get('vaddr', 0)),
                    s.get('type', 'Unknown'),
                    s.get('string', 'Unknown'),
                    str(s.get('length', 0))
                )
            
            self.console.print("\n[bold]Extracted Strings:[/bold]")
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error extracting strings: {str(e)}[/red]")

    def _open_file(self, file_path: str):
        """打开二进制文件"""
        if not os.path.exists(file_path):
            self.console.print(f"[red]Error: File {file_path} not found[/red]")
            return
        
        self.current_file = os.path.abspath(file_path)
        self.console.print(f"[green]Opened {self.current_file}[/green]")
    
    def _analyze_file(self):
        """分析当前文件"""
        if not self._check_file():
            return
        
        self.console.print("[cyan]Analyzing file...[/cyan]")
        cmd = f"r2 -c 'aaa' -q {self.current_file}"
        self._run_command(cmd)
    
    def _list_functions(self):
        """列出所有函数"""
        if not self._check_file():
            return
        
        self.console.print("[cyan]Listing functions...[/cyan]")
        cmd = f"r2 -c 'aaa;afl' -q {self.current_file}"
        self._run_command(cmd)
    
    def _find_strings(self):
        """查找字符串"""
        if not self._check_file():
            return
        
        self.console.print("[cyan]Finding strings...[/cyan]")
        cmd = f"r2 -c 'aaa;iz' -q {self.current_file}"
        self._run_command(cmd)
    
    def _show_info(self):
        """显示文件信息"""
        if not self._check_file():
            return
        
        self.console.print("[cyan]File information:[/cyan]")
        cmd = f"r2 -c 'i' -q {self.current_file}"
        self._run_command(cmd)
    
    def _disassemble(self, function_name: str = None):
        """反汇编指定函数或当前位置"""
        if not self._check_file():
            return
        
        if function_name:
            cmd = f"r2 -c 'aaa;pdf @sym.{function_name}' -q {self.current_file}"
        else:
            cmd = f"r2 -c 'aaa;pdf' -q {self.current_file}"
        self._run_command(cmd)
    
    def _search_pattern(self, pattern: str):
        """搜索特定模式"""
        if not self._check_file():
            return
        
        self.console.print(f"[cyan]Searching for pattern: {pattern}[/cyan]")
        cmd = f"r2 -c 'aaa;/x {pattern}' -q {self.current_file}"
        self._run_command(cmd)
    
    def _find_references(self, function_name: str):
        """查找函数引用"""
        if not self._check_file():
            return
        
        self.console.print(f"[cyan]Finding references to {function_name}[/cyan]")
        cmd = f"r2 -c 'aaa;axt @sym.{function_name}' -q {self.current_file}"
        self._run_command(cmd)
    
    def _open_r2_shell(self):
        """打开交互式r2 shell"""
        if not self._check_file():
            return
        
        self.console.print("[cyan]Opening r2 shell...[/cyan]")
        os.system(f"r2 {self.current_file}")
    
    def _check_file(self) -> bool:
        """检查是否已打开文件"""
        if not self.current_file:
            self.console.print("[red]Error: No file opened. Use 'open <file>' first.[/red]")
            return False
        return True
    
    def _run_command(self, cmd: str):
        """执行r2命令并显示输出"""
        try:
            result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
            if result.stdout:
                self.console.print(result.stdout)
            if result.stderr:
                self.console.print(f"[red]{result.stderr}[/red]")
        except Exception as e:
            self.console.print(f"[red]Error executing command: {str(e)}[/red]")

    def _start_gdb_session(self, args=None):
        """启动GDB调试会话"""
        try:
            # 检查GDB是否安装
            if not self._check_gdb_installed():
                self.console.print("[red]Error: GDB is not installed. Please install GDB first.[/red]")
                return

            # 准备GDB命令
            gdb_cmd = ["gdb", "-q"]  # -q 参数使GDB启动时不显示版本信息
            
            # 添加用户提供的参数
            if args:
                gdb_cmd.extend(args)
            
            # 添加目标文件
            gdb_cmd.append(self.current_file)
            
            # 创建GDB配置文件
            gdb_init_file = self._create_gdb_init_file()
            if gdb_init_file:
                gdb_cmd.extend(["-x", gdb_init_file])

            self.console.print("[cyan]Starting GDB session...[/cyan]")
            self.console.print("[dim]Type 'quit' or press Ctrl+D to exit GDB[/dim]")
            
            # 启动GDB会话
            process = subprocess.Popen(gdb_cmd)
            process.wait()
            
            # 清理临时文件
            if gdb_init_file and os.path.exists(gdb_init_file):
                os.remove(gdb_init_file)
                
        except Exception as e:
            self.console.print(f"[red]Error starting GDB session: {str(e)}[/red]")

    def _check_gdb_installed(self) -> bool:
        """检查GDB是否已安装"""
        try:
            subprocess.run(["gdb", "--version"], capture_output=True)
            return True
        except FileNotFoundError:
            return False

    def _create_gdb_init_file(self) -> str:
        """创建GDB初始化文件"""
        try:
            # 创建临时文件
            fd, path = tempfile.mkstemp(suffix='.gdbinit')
            
            # GDB配置内容
            gdb_init_content = """
# 设置输出不分页
set pagination off

# 设置断点时显示反汇编
set disassemble-next-line on

# 设置Intel语法
set disassembly-flavor intel

# 显示寄存器的值
define reg
    info registers
end

# 显示栈信息
define stack
    x/16xw $sp
end

# 显示帮助信息
define help-custom
    echo \\n
    echo Custom GDB commands:\\n
    echo reg - Display all registers\\n
    echo stack - Display stack contents\\n
    echo \\n
end

# 启动时显示帮助信息
help-custom
"""
            
            # 写入配置文件
            with os.fdopen(fd, 'w') as f:
                f.write(gdb_init_content)
            
            return path
            
        except Exception as e:
            self.console.print(f"[red]Error creating GDB init file: {str(e)}[/red]")
            return ""

    def _start_ida_session(self, args=None):
        """启动IDA Pro会话"""
        try:
            # 检查IDA Pro是否存在
            if not self._check_ida_installed():
                self.console.print("[red]Error: IDA Pro not found at the specified path.[/red]")
                return

            # 准备IDA命令
            ida_cmd = [self.ida_path]
            
            # 添加用户提供的参数
            if args:
                ida_cmd.extend(args)
            
            # 添加目标文件
            ida_cmd.append(self.current_file)

            self.console.print("[cyan]Starting IDA Pro...[/cyan]")
            
            # 启动IDA Pro（不等待关闭，让它在后台运行）
            process = subprocess.Popen(ida_cmd)
            self.console.print("[green]IDA Pro launched successfully[/green]")
                
        except Exception as e:
            self.console.print(f"[red]Error starting IDA Pro: {str(e)}[/red]")

    def _check_ida_installed(self) -> bool:
        """检查IDA Pro是否已安装"""
        return os.path.exists(self.ida_path) and os.access(self.ida_path, os.X_OK) 