from rich.console import Console
from rich.table import Table
from rich import box
import subprocess
import os
import platform

console = Console()

class ToolsManager:
    def __init__(self):
        self.tools = {
            "adb": {
                "name": "Android Debug Bridge",
                "check_cmd": "adb version",
                "description": "Android device management tool"
            },
            "scrcpy": {
                "name": "Scrcpy",
                "check_cmd": "scrcpy --version",
                "description": "Display and control Android devices"
            },
            "jadx": {
                "name": "JADX",
                "check_cmd": "jadx --version",
                "description": "Dex to Java decompiler"
            },
            "apktool": {
                "name": "Apktool",
                "check_cmd": "apktool --version",
                "description": "APK reverse engineering tool"
            },
            "objection": {
                "name": "Objection",
                "check_cmd": "objection --version",
                "description": "Runtime mobile exploration toolkit"
            }
        }

    def check_tool_status(self, cmd):
        try:
            subprocess.run(cmd.split(), capture_output=True, text=True, check=True)
            return True
        except:
            return False

    def display_tools(self):
        table = Table(
            title="Reverse Engineering Tools",
            show_header=True,
            header_style="bold magenta",
            box=box.SIMPLE
        )
        
        table.add_column("Tool", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Status", style="yellow")

        for tool_id, tool_info in self.tools.items():
            status = "✓ Installed" if self.check_tool_status(tool_info["check_cmd"]) else "✗ Not Found"
            status_style = "green" if "Installed" in status else "red"
            table.add_row(
                tool_info["name"],
                tool_info["description"],
                f"[{status_style}]{status}[/{status_style}]"
            )

        console.print(table)

    def handle_command(self, command: str):
        if command == "list":
            self.display_tools()
            return

        if command == "install":
            self.show_install_guide()
            return

        console.print("[red]Unknown tools command. Available commands: list, install[/red]")

    def show_install_guide(self):
        system = platform.system().lower()
        
        console.print("\n[bold cyan]Installation Guide:[/bold cyan]")
        
        if system == "darwin":  # macOS
            console.print("\n[yellow]Using Homebrew on macOS:[/yellow]")
            console.print("brew install android-platform-tools")
            console.print("brew install scrcpy")
            console.print("brew install jadx")
            console.print("brew install apktool")
            console.print("pip install objection")
        
        elif system == "linux":
            console.print("\n[yellow]On Ubuntu/Debian:[/yellow]")
            console.print("sudo apt install android-tools-adb")
            console.print("sudo apt install scrcpy")
            console.print("sudo apt install jadx")
            console.print("sudo apt install apktool")
            console.print("pip install objection")
        
        elif system == "windows":
            console.print("\n[yellow]On Windows:[/yellow]")
            console.print("1. Install Android SDK Platform Tools for adb")
            console.print("2. Install scrcpy via Windows package managers")
            console.print("3. Download JADX from GitHub releases")
            console.print("4. Download Apktool from official website")
            console.print("5. pip install objection")
        
        console.print("\n[bold green]For more details, visit:[/bold green]")
        console.print("ADB: https://developer.android.com/studio/command-line/adb")
        console.print("Scrcpy: https://github.com/Genymobile/scrcpy")
        console.print("JADX: https://github.com/skylot/jadx")
        console.print("Apktool: https://ibotpeaches.github.io/Apktool/")
        console.print("Objection: https://github.com/sensepost/objection")

        console.print("\n[bold cyan]Analysis:[/bold cyan]")
        console.print("2. Analysis:") 