from rich.console import Console
import subprocess
import os
import platform

console = Console()

class BaseManager:
    def __init__(self):
        self.console = Console()
        
    def execute_shell_command(self, cmd: str):
        """执行 shell 命令并显示输出"""
        try:
            result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
            if result.stdout:
                self.console.print("[green]Output:[/green]")
                for line in result.stdout.splitlines():
                    self.console.print(line)
            if result.stderr:
                self.console.print("[red]Error:[/red]")
                for line in result.stderr.splitlines():
                    self.console.print(line)
            return result.returncode == 0
        except Exception as e:
            self.console.print(f"[red]Error executing command: {str(e)}[/red]")
            return False

    def handle_command(self, cmd: str, *args):
        """处理命令"""
        if cmd.startswith("sh "):
            shell_cmd = cmd[3:].strip()
            return self.execute_shell_command(shell_cmd)
        return self._handle_specific_command(cmd, *args)

    def _handle_specific_command(self, cmd: str, *args):
        """子类需要实现的具体命令处理方法"""
        raise NotImplementedError("Subclasses must implement _handle_specific_command")

    def handle_shell_command(self, command: str) -> bool:
        """Handle shell command if present"""
        if command.startswith("sh "):
            self.execute_shell_command(command[3:])
            return True
        elif command == "sh":
            # 进入交互式shell模式
            shell = os.environ.get('SHELL', '/bin/bash')
            try:
                console.print("[yellow]Entering shell mode (type 'exit' to return)[/yellow]")
                subprocess.run(shell, shell=True)
            except Exception as e:
                console.print(f"[red]Error starting shell: {str(e)}[/red]")
            return True
        return False 