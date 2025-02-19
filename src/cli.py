import typer
import rich
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich import box
import os
import subprocess
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.styles import Style
from tools_manager import ToolsManager
from frida_manager import FridaManager
from ai_manager import AIManager
from search_manager import SearchManager
from guide_manager import GuideManager
from rich.markdown import Markdown
import tempfile
from binary_manager import BinaryManager
from snippets_manager import SnippetsManager
from network_manager import NetworkManager
from game_manager import GameManager
from crypto_manager import CryptoManager
from db_manager import DBManager
from music_manager import MusicManager
from remarks_manager import RemarksManager
import sys
import time


# 创建 Typer 应用并设置默认命令
app = typer.Typer(
    help="r3term - Ultimate Reverse Engineering CLI Tool",
    no_args_is_help=False,  # 没有参数时不显示帮助
    add_completion=False    # 不添加自动完成
)

# 创建子命令组
workspace_app = typer.Typer()
research_app = typer.Typer()
investment_app = typer.Typer()
entertainment_app = typer.Typer()

# 添加子命令组到主应用
app.add_typer(workspace_app, name="workspace", help="Workspace & Development Tools")
app.add_typer(research_app, name="research", help="Research & Analysis Tools")
app.add_typer(investment_app, name="investment", help="Investment & Trading Tools")
app.add_typer(entertainment_app, name="entertainment", help="Games & Entertainment")

console = Console()

# 定义命令补全器
def create_completer(commands):
    return WordCompleter(commands, ignore_case=True)

# 创建提示会话样式
style = Style.from_dict({
    'prompt': '#00FFFF',  # cyan color
    'completion-menu.completion': 'bg:#008888 #ffffff',
    'completion-menu.completion.current': 'bg:#00aaaa #000000',
})

# 创建提示会话
session = PromptSession(style=style)

def get_command_input(prompt_text: str, commands: list) -> str:
    """获取用户输入，支持命令补全"""
    # 添加 sh 命令到补全列表
    if "sh" not in commands:
        commands.append("sh")
        
    completer = create_completer(commands)
    try:
        result = session.prompt(f"{prompt_text} ", completer=completer, style=style).strip()
        play_keypress_sound()  # 添加按键音效
        return result
    except KeyboardInterrupt:
        play_error_sound()  # 添加中断音效
        return "back"
    except EOFError:
        play_error_sound()  # 添加退出音效
        return "exit"

def play_startup_sound():
    """播放启动音效"""
    try:
        print('\a', end='', flush=True)
        time.sleep(0.1)
    except Exception:
        pass

def play_error_sound():
    """错误提示音"""
    try:
        print('\a', end='', flush=True)
        time.sleep(0.1)
    except Exception:
        pass

def play_success_sound():
    """成功提示音"""
    try:
        print('\a', end='', flush=True)
        time.sleep(0.1)
    except Exception:
        pass

def play_keypress_sound():
    """按键音效"""
    try:
        print('\a', end='', flush=True)
    except Exception:
        pass

def create_header():
    # 播放启动音效
    play_startup_sound()
    
    # 创建动态加载效果
    for i in range(3):
        sys.stdout.write('\r[*] Initializing system ' + '.' * (i+1))
        sys.stdout.flush()
        time.sleep(0.3)
    print('\n')
    
    # 获取系统信息
    import platform
    import psutil
    
    os_name = platform.system()
    os_version = platform.release()
    cpu_usage = psutil.cpu_percent()
    memory = psutil.virtual_memory()
    disk = psutil.disk_usage('/')
    
    return Panel(
        f"""[bold bright_cyan]
    ╔════════════════════════════════════════════════╗
    ║ [bright_red]██████╗[/bright_red] [bright_yellow]██████╗[/bright_yellow][bright_green]████████╗[/bright_green][bright_white]███████╗██████╗ ███╗   ███╗[/bright_white] ║
    ║ [bright_red]██╔══██╗[/bright_red][bright_yellow]╚════██╗[/bright_yellow][bright_green]╚══██╔══╝[/bright_green][bright_white]██╔════╝██╔══██╗████╗ ████║[/bright_white] ║
    ║ [bright_red]██████╔╝[/bright_red][bright_yellow]█████╔╝[/bright_yellow] [bright_green]  ██║[/bright_green]   [bright_white]█████╗  ██████╔╝██╔████╔██║[/bright_white] ║
    ║ [bright_red]██╔══██╗[/bright_red][bright_yellow]╚═══██╗[/bright_yellow] [bright_green]  ██║[/bright_green]   [bright_white]██╔══╝  ██╔══██╗██║╚██╔╝██║[/bright_white] ║
    ║ [bright_red]██║  ██║[/bright_red][bright_yellow]██████╔╝[/bright_yellow][bright_green]  ██║[/bright_green]   [bright_white]███████╗██║  ██║██║ ╚═╝ ██║[/bright_white] ║
    ║ [bright_red]╚═╝  ╚═╝[/bright_red][bright_yellow]╚═════╝[/bright_yellow] [bright_green]  ╚═╝[/bright_green]   [bright_white]╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝[/bright_white] ║
    ╚════════════════════════════════════════════════╝[/bold bright_cyan]

    [bold bright_green]SOFTWARE INFO[/bold bright_green]
    [bright_white]>[/bright_white] Version: [bright_yellow]0.0.1-alpha[/bright_yellow]
    [bright_white]>[/bright_white] Author: [bright_yellow]overkazaf@gmail.com[/bright_yellow]
    [bright_white]>[/bright_white] License: [bright_yellow]MIT[/bright_yellow]
    [bright_white]>[/bright_white] Repository: [bright_yellow]github.com/overkazaf/r3term[/bright_yellow]

    [bold bright_green]SYSTEM INFO[/bold bright_green]
    [bright_white]>[/bright_white] OS: [bright_green]{os_name} {os_version}[/bright_green]
    [bright_white]>[/bright_white] CPU: [bright_green]{cpu_usage}% used[/bright_green]
    [bright_white]>[/bright_white] Memory: [bright_green]{memory.percent}% used[/bright_green] ([bright_green]{memory.used//1024//1024}MB[/bright_green] / [bright_green]{memory.total//1024//1024}MB[/bright_green])
    [bright_white]>[/bright_white] Disk: [bright_green]{disk.percent}% used[/bright_green] ([bright_green]{disk.used//1024//1024//1024}GB[/bright_green] / [bright_green]{disk.total//1024//1024//1024}GB[/bright_green])

    [bright_white][blink]>_[/blink][/bright_white] [bright_green]Session[/bright_green]: [bright_yellow]0x{hex(id(session))[2:].upper()}[/bright_yellow] | [bright_green]Mode[/bright_green]: [bright_red]ROOT[/bright_red]""",
        title="[bold bright_red]R3[/bold bright_red][bold bright_white]TERM[/bold bright_white]",
        subtitle="[bold bright_cyan]Reverse Engineering Terminal[/bold bright_cyan]",
        box=box.DOUBLE,
        padding=(0, 2),
        border_style="bright_blue"
    )

def execute_shell_command(cmd: str):
    """Execute shell command and display output"""
    try:
        result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
        if result.stdout:
            console.print("[green]Output:[/green]")
            for line in result.stdout.splitlines():
                console.print(line)
        if result.stderr:
            console.print("[red]Error:[/red]")
            for line in result.stderr.splitlines():
                console.print(line)
    except Exception as e:
        console.print(f"[red]Error executing command: {str(e)}[/red]")

def workspace_menu():
    """Workspace & Development Tools Menu"""
    workspace_commands = ["frida", "binary", "network", "back", "b"]
    
    try:
        while True:
            console.print("\n[bold cyan]Workspace Menu[/bold cyan]")
            console.print("1. frida    - Frida Script Management")
            console.print("2. binary   - Binary Analysis")
            console.print("3. network  - Network Analysis Tools")
            console.print("4. b/back   - Return to main menu")
            
            command = get_command_input("workspace#", workspace_commands)
            
            if command in ["back", "b"]:
                break
            
            if command.startswith("sh"):
                shell_cmd = command[3:].strip()
                execute_shell_command(shell_cmd)
                
            elif command == "frida":
                frida_cmd()
            elif command == "binary":
                binary_cmd()
            elif command == "network":
                network_cmd()
            else:
                console.print("[red]Unknown command[/red]")
            
            if command not in ["back", "b"]:
                console.print("\n" + "="*50 + "\n")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")

def research_menu():
    """Research & Analysis Tools Menu"""
    research_commands = ["ai", "search", "snippets", "remarks", "back", "b"]
    
    try:
        while True:
            console.print("\n[bold yellow]Research Menu[/bold yellow]")
            console.print("1. ai       - AI Q&A")
            console.print("2. search   - Search Engines")
            console.print("3. snippets - Code Snippets Management")
            console.print("4. remarks  - Bookmarks and Remarks Management")
            console.print("5. b/back   - Return to main menu")
            
            command = get_command_input("research#", research_commands)
            
            if command in ["back", "b"]:
                break

            if command.startswith("sh"):
                shell_cmd = command[3:].strip()
                execute_shell_command(shell_cmd)
            
            elif command == "ai":
                ai_cmd()
            elif command == "search":
                search_cmd()
            elif command == "snippets":
                snippets_cmd()
            elif command == "remarks":
                remarks_cmd()
            else:
                console.print("[red]Unknown command[/red]")
            
            if command not in ["back", "b"]:
                console.print("\n" + "="*50 + "\n")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")

def investment_menu():
    """Investment & Trading Tools Menu"""
    investment_commands = ["crypto", "back", "b"]
    
    try:
        while True:
            console.print("\n[bold green]Investment Menu[/bold green]")
            console.print("1. crypto   - Cryptocurrency Monitor")
            console.print("2. b/back   - Return to main menu")
            
            command = get_command_input("investment#", investment_commands)
            
            if command in ["back", "b"]:
                break

            if command.startswith("sh"):
                shell_cmd = command[3:].strip()
                execute_shell_command(shell_cmd)
            elif command == "crypto":
                crypto_cmd()
            else:
                console.print("[red]Unknown command[/red]")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")

@entertainment_app.command(name="music")
def music_cmd():
    """Music player and downloader"""
    music_manager = MusicManager()
    music_commands = [
        "search", "download", "play", "pause", "resume",
        "stop", "next", "prev", "list", "current", "playlist", "back", "b"
    ]
    
    try:
        while True:
            console.print("\n[yellow]Music Player Menu[/yellow]")
            console.print("1. search   - Search for music")
            console.print("2. download - Download a song")
            console.print("3. play     - Play a song")
            console.print("4. pause    - Pause playback")
            console.print("5. resume   - Resume playback")
            console.print("6. stop     - Stop playback")
            console.print("7. next     - Play next song")
            console.print("8. prev     - Play previous song")
            console.print("9. list     - List downloaded music")
            console.print("10. current  - Show current song")
            console.print("11. playlist - Playlist commands")
            console.print("    - playlist show    Show current playlist")
            console.print("    - playlist add     Add song to playlist")
            console.print("    - playlist remove  Remove from playlist")
            console.print("    - playlist clear   Clear playlist")
            console.print("    - playlist play    Play playlist")
            console.print("    - playlist mode    Set play mode")
            console.print("12. b/back   - Return to main menu")
            
            cmd = get_command_input("music#", music_commands)
            
            if cmd in ["back", "b"]:
                break

            if cmd.startswith("sh"):
                shell_cmd = cmd[3:].strip()
                execute_shell_command(shell_cmd)
                
            try:
                if cmd == "search":
                    query = console.input("[cyan]Enter search query: [/cyan]").strip()
                    if query:
                        music_manager.handle_command("search", query)
                elif cmd == "download":
                    song_id = console.input("[cyan]Enter song ID: [/cyan]").strip()
                    if song_id:
                        music_manager.handle_command("download", song_id)
                elif cmd == "play":
                    identifier = console.input("[cyan]Enter song name or number: [/cyan]").strip()
                    if identifier:
                        music_manager.handle_command("play", identifier)
                elif cmd == "playlist":
                    subcommand = console.input("[cyan]Enter playlist command (show/add/remove/clear/play): [/cyan]").strip()
                    if subcommand == "add":
                        identifier = console.input("[cyan]Enter song name or number to add: [/cyan]").strip()
                        music_manager.handle_command("playlist", "add", identifier)
                    elif subcommand == "remove":
                        number = console.input("[cyan]Enter playlist number to remove: [/cyan]").strip()
                        music_manager.handle_command("playlist", "remove", number)
                    elif subcommand in ["show", "clear", "play"]:
                        music_manager.handle_command("playlist", subcommand)
                    else:
                        console.print("[red]Invalid playlist command[/red]")
                elif cmd == "next":
                    music_manager.handle_command("next")
                elif cmd == "prev":
                    music_manager.handle_command("prev")
                else:
                    music_manager.handle_command(cmd)
                    
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")
    
    return True

def entertainment_menu():
    """Games & Entertainment Menu"""
    entertainment_commands = ["game", "music", "back", "b"]
    
    try:
        while True:
            console.print("\n[bold magenta]Entertainment Menu[/bold magenta]")
            console.print("1. game     - Classic Games Collection")
            console.print("2. music    - Music Player")
            console.print("3. b/back   - Return to main menu")
            
            command = get_command_input("entertainment#", entertainment_commands)
            
            if command in ["back", "b"]:
                break

            if command.startswith("sh"):
                shell_cmd = command[3:].strip()
                execute_shell_command(shell_cmd)
            
            if command == "game":
                game_cmd()
            elif command == "music":
                music_cmd()
            else:
                console.print("[red]Unknown command[/red]")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")

@app.callback(invoke_without_command=True)
def main(ctx: typer.Context):
    """Main Interface"""
    if ctx.invoked_subcommand is not None:
        return
        
    guide_manager = GuideManager()
    main_commands = [
        "workspace", "research", "investment", "entertainment",
        "sh", "clear", "exit", "quit", "q"
    ]
    
    try:
        while True:
            console.print(create_header())
            
            # Display available commands
            commands_table = Table(
                title="Available Commands",
                show_header=True,
                header_style="bold magenta",
                box=box.SIMPLE
            )
            commands_table.add_column("Command", style="cyan")
            commands_table.add_column("Description", style="green")
            
            # Workspace Category
            commands_table.add_row("[bold cyan]1. workspace[/bold cyan]", "[bold cyan]Workspace & Development Tools[/bold cyan]")
            commands_table.add_row("   frida", "Frida Script Management")
            commands_table.add_row("   binary", "Binary Analysis")
            commands_table.add_row("   network", "Network Analysis Tools")
            
            # Research Category
            commands_table.add_row("[bold yellow]2. research[/bold yellow]", "[bold yellow]Research & Analysis Tools[/bold yellow]")
            commands_table.add_row("   ai", "DeepSeek AI Q&A")
            commands_table.add_row("   search", "Awesome Search Engines")
            commands_table.add_row("   snippets", "Code Snippets Management")
            commands_table.add_row("   remarks", "Bookmarks and Remarks Management")
            
            # Investment Category
            commands_table.add_row("[bold green]3. investment[/bold green]", "[bold green]Investment & Trading Tools[/bold green]")
            commands_table.add_row("   crypto", "Cryptocurrency Monitor")
            
            # Entertainment Category
            commands_table.add_row("[bold magenta]4. entertainment[/bold magenta]", "[bold magenta]Games & Entertainment[/bold magenta]")
            commands_table.add_row("   game", "Classic Games Collection")
            commands_table.add_row("   music", "Music Player")
            
            # System Commands
            commands_table.add_row("[bold red]System[/bold red]", "[bold red]System Commands[/bold red]")
            commands_table.add_row("   sh", "Execute shell command")
            commands_table.add_row("   clear", "Clear screen")
            commands_table.add_row("   exit/quit/q", "Exit Program")
            
            console.print(commands_table)
            
            command = get_command_input("r3term#", main_commands)
            
            if command == "exit" or command == "quit" or command == "q":
                console.print("[yellow]Exiting program...[/yellow]")
                break
            elif command == "clear":
                os.system('cls' if os.name == 'nt' else 'clear')
                continue
            elif command.startswith("sh"):
                shell_cmd = command[3:].strip()
                execute_shell_command(shell_cmd)
            elif command == "workspace":
                workspace_menu()
            elif command == "research":
                research_menu()
            elif command == "investment":
                investment_menu()
            elif command == "entertainment":
                entertainment_menu()
            else:
                console.print("[red]Unknown command, please try again[/red]")
            
            if command != "clear":  # Don't show separator after clear
                console.print("\n" + "="*50 + "\n")
            
    except KeyboardInterrupt:
        console.print("\n[yellow]Exiting program...[/yellow]")

@workspace_app.command(name="frida")
def frida_cmd():
    """Frida reverse engineering tools"""
    frida_manager = FridaManager()
    frida_commands = [
        "devices", "ps", "list", "show", "search", "add", "edit", "delete",
        "inject", "spawn", "jnitrace", "explore", "memory", "android", "ios",
        "heap", "stalker", "adb", "scrcpy", "termux-api", "termux-ssh", "screen",
        "guide", "back", "b"
    ]
    
    # Termux API commands for completion
    termux_api_commands = [
        # Device Info
        "battery-status", "battery-temp", "device-info",
        "brightness", "camera-info", "camera-photo",
        
        # System Controls
        "clipboard-get", "clipboard-set",
        "volume", "torch", "vibrate",
        "notification", "toast",
        
        # Location & Sensors
        "location", "gps",
        "sensor-list", "sensor-read",
        "compass", "accelerometer",
        
        # Network
        "wifi-status", "wifi-scaninfo", 
        "wifi-enable", "wifi-disable",
        "data-status", "data-enable", "data-disable",
        
        # Telephony
        "telephony-info", "telephony-status",
        "contacts", "device-info", "cellular-info",
        "sms-list", "sms-send",
        "call-log", "call-info", "call",
        
        # Storage
        "storage-get", "storage-list",
        
        # Media
        "media-player", "media-scan",
        
        # System
        "wallpaper", "fingerprint",
        "battery", "dialog"
    ]
    
    try:
        while True:
            console.print("\n[yellow]Frida Tools Menu[/yellow]")
            
            # Device Management
            console.print("\n[cyan]Device Management:[/cyan]")
            console.print("  devices    - List connected devices")
            console.print("  ps         - List processes on device")
            
            # Script Management
            console.print("\n[cyan]Script Management:[/cyan]")
            console.print("  list       - List available scripts")
            console.print("  show       - Show script content")
            console.print("  search     - Search for scripts")
            console.print("  add        - Add new script")
            console.print("  edit       - Edit existing script")
            console.print("  delete     - Delete script")
            
            # Runtime Operations
            console.print("\n[cyan]Runtime Operations:[/cyan]")
            console.print("  inject     - Inject script into process")
            console.print("  spawn      - Spawn and inject into new process")
            console.print("  jnitrace   - Trace JNI calls")
            
            # Objection Tools
            console.print("\n[cyan]Objection Tools:[/cyan]")
            console.print("  explore    - Start objection explorer")
            console.print("  memory     - Memory operations")
            console.print("  android    - Android specific commands")
            console.print("  ios        - iOS specific commands")
            console.print("  heap       - Heap operations")
            console.print("  stalker    - Function stalking")
            
            # Android Tools
            console.print("\n[cyan]Android Tools:[/cyan]")
            console.print("  adb        - ADB command tool")
            console.print("  scrcpy     - Screen mirroring")
            console.print("  screen     - Interactive screen and shell session")
            
            # Termux Tools
            console.print("\n[cyan]Termux Tools:[/cyan]")
            console.print("  termux-api  - Run Termux API commands")
            console.print("  termux-ssh  - Setup and manage SSH")
            
            # Other Options
            console.print("\n[cyan]Other Options:[/cyan]")
            console.print("  guide      - Show usage guide")
            console.print("  b/back     - Return to main menu")
            
            cmd = get_command_input("frida#", frida_commands)
            
            if cmd in ["back", "b"]:
                break
                
            try:
                if frida_manager.handle_shell_command(cmd):
                    continue

                if cmd == "devices":
                    frida_manager.handle_command("devices")
                elif cmd == "ps":
                    device_id = console.input("[cyan]Device ID (leave empty for current/USB): [/cyan]").strip()
                    frida_manager.handle_command("ps", device_id if device_id else None)
                elif cmd == "list":
                    category = console.input("[cyan]Category (leave empty for all): [/cyan]").strip()
                    frida_manager.handle_command("list", category if category else None)
                elif cmd == "show":
                    script_id = console.input("[cyan]Script ID: [/cyan]").strip()
                    frida_manager.handle_command("show", script_id)
                elif cmd == "search":
                    keyword = console.input("[cyan]Search keyword: [/cyan]").strip()
                    category = console.input("[cyan]Category (leave empty for all): [/cyan]").strip()
                    frida_manager.handle_command("search", keyword, category if category else None)
                elif cmd == "inject":
                    script_id = console.input("[cyan]Script ID: [/cyan]").strip()
                    device_id = console.input("[cyan]Device ID (leave empty for current/USB): [/cyan]").strip()
                    target = console.input("[cyan]Target process/package: [/cyan]").strip()
                    frida_manager.handle_command("inject", script_id, device_id if device_id else None, target)
                elif cmd == "spawn":
                    script_id = console.input("[cyan]Script ID: [/cyan]").strip()
                    device_id = console.input("[cyan]Device ID (leave empty for current/USB): [/cyan]").strip()
                    package = console.input("[cyan]Package name: [/cyan]").strip()
                    frida_manager.handle_command("spawn", script_id, device_id if device_id else None, package)
                elif cmd == "edit":
                    script_id = console.input("[cyan]Script ID: [/cyan]").strip()
                    frida_manager.handle_command("edit", script_id)
                elif cmd == "add":
                    category = console.input("[cyan]Category: [/cyan]").strip()
                    name = console.input("[cyan]Script name: [/cyan]").strip()
                    frida_manager.handle_command("add", category, name)
                elif cmd == "delete":
                    script_id = console.input("[cyan]Script ID: [/cyan]").strip()
                    frida_manager.handle_command("delete", script_id)
                elif cmd == "jnitrace":
                    device_id = console.input("[cyan]Device ID (leave empty for current/USB): [/cyan]").strip()
                    target = console.input("[cyan]Target process/package: [/cyan]").strip()
                    lib_name = console.input("[cyan]Library name (leave empty for all): [/cyan]").strip()
                    frida_manager.handle_command("jnitrace", device_id if device_id else None, target, lib_name if lib_name else None)
                elif cmd in ["explore", "memory", "android", "ios", "heap", "stalker"]:
                    device_id = console.input("[cyan]Device ID (leave empty for current/USB): [/cyan]").strip()
                    target = console.input("[cyan]Target process/package: [/cyan]").strip()
                    frida_manager.handle_command("objection", cmd, device_id if device_id else None, target)
                elif cmd == "adb":
                    # Use command completion for ADB commands
                    subcommand = get_command_input("adb#", frida_manager.adb_commands)
                    if subcommand in frida_manager.adb_commands:
                        device_id = console.input("[cyan]Device ID (leave empty for current/USB): [/cyan]").strip()
                        params = console.input("[cyan]Additional parameters: [/cyan]").strip()
                        frida_manager.handle_command("adb", subcommand, device_id if device_id else None, *params.split())
                    else:
                        console.print("[red]Invalid ADB command[/red]")
                        console.print(f"[yellow]Available commands: {', '.join(frida_manager.adb_commands)}[/yellow]")
                elif cmd == "scrcpy":
                    device_id = console.input("[cyan]Device ID (leave empty for current/USB): [/cyan]").strip()
                    frida_manager.handle_command("scrcpy", device_id if device_id else None)
                elif cmd == "termux-api":
                    # Use command completion for Termux API commands
                    subcommand = get_command_input("termux-api#", termux_api_commands)
                    if subcommand in termux_api_commands:
                        device_id = console.input("[cyan]Device ID (leave empty for current/USB): [/cyan]").strip()
                        params = console.input("[cyan]Additional parameters (leave empty if none): [/cyan]").strip()
                        frida_manager.handle_command("termux-api", subcommand, device_id if device_id else None, *params.split() if params else [])
                    else:
                        console.print("[red]Invalid Termux API command[/red]")
                elif cmd == "termux-ssh":
                    device_id = console.input("[cyan]Device ID (leave empty for current/USB): [/cyan]").strip()
                    frida_manager.handle_command("termux-ssh", device_id if device_id else None)
                elif cmd == "screen":
                    device_id = console.input("[cyan]Device ID (leave empty for current/USB): [/cyan]").strip()
                    frida_manager.handle_command("screen_shell", device_id if device_id else None)
                elif cmd == "guide":
                    frida_manager.handle_command("guide")
                else:
                    console.print("[red]Unknown command[/red]")
                    
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")
    
    return True

@workspace_app.command(name="binary")
def binary_cmd():
    """Binary analysis tools"""
    binary_manager = BinaryManager()
    binary_commands = [
        "open", "analyze", "funcs", "strings", "info", "disasm",
        "search", "refs", "shell", "exports", "imports", "back", "b"
    ]
    
    try:
        while True:
            console.print("\n[yellow]Binary Analysis Menu[/yellow]")
            console.print("1. open     - Open binary file")
            console.print("2. analyze  - Analyze current file")
            console.print("3. funcs    - List functions")
            console.print("4. strings  - Find strings")
            console.print("5. info     - Show file info")
            console.print("6. disasm   - Disassemble function")
            console.print("7. search   - Search pattern")
            console.print("8. refs     - Find references")
            console.print("9. shell    - Open r2 shell")
            console.print("10. exports  - List exports")
            console.print("11. imports  - List imports")
            console.print("12. gdb      - Start GDB debugging session")
            console.print("13. ida      - Start IDA Pro debugging session")
            console.print("14. b/back  - Return to main menu")
            
            cmd = get_command_input("binary#", binary_commands)
            
            if cmd in ["back", "b"]:
                break
                
            try:
                if binary_manager.handle_shell_command(cmd):
                    continue

                if cmd == "open":
                    file_path = console.input("[cyan]Enter file path: [/cyan]").strip()
                    binary_manager.handle_command("open", file_path)
                elif cmd == "analyze":
                    binary_manager.handle_command("analyze")
                elif cmd == "funcs":
                    binary_manager.handle_command("functions")
                elif cmd == "strings":
                    binary_manager.handle_command("strings")
                elif cmd == "info":
                    binary_manager.handle_command("info")
                elif cmd == "disasm":
                    function = console.input("[cyan]Function name (leave empty for current): [/cyan]").strip()
                    binary_manager.handle_command("disasm", function if function else None)
                elif cmd == "search":
                    pattern = console.input("[cyan]Enter search pattern: [/cyan]").strip()
                    binary_manager.handle_command("search", pattern)
                elif cmd == "refs":
                    function = console.input("[cyan]Function name: [/cyan]").strip()
                    binary_manager.handle_command("references", function)
                elif cmd == "shell":
                    binary_manager.handle_command("shell")
                elif cmd == "exports":
                    binary_manager.handle_command("exports")
                elif cmd == "imports":
                    binary_manager.handle_command("imports")
                elif cmd == "gdb":
                    binary_manager.handle_command("gdb")
                elif cmd == "ida":
                    binary_manager.handle_command("ida")
                else:
                    console.print("[red]Unknown command[/red]")
                    
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")
    
    return True

@workspace_app.command(name="network")
def network_cmd():
    """Network analysis tools"""
    network_manager = NetworkManager()
    network_commands = [
        "scan", "capture", "stop", "analyze", "proxy", "pstop",
        "convert", "filter", "trace", "back"
    ]
    
    try:
        while True:
            console.print("\n[yellow]Network Analysis Menu[/yellow]")
            console.print("1. scan     - Network scanning")
            console.print("2. capture  - Start packet capture")
            console.print("3. stop     - Stop packet capture")
            console.print("4. analyze  - Analyze capture file")
            console.print("5. proxy    - Start HTTP proxy")
            console.print("6. pstop    - Stop HTTP proxy")
            console.print("7. convert  - Convert capture format")
            console.print("8. filter   - Filter capture file")
            console.print("9. trace    - Trace route")
            console.print("10. b/back    - Return to main menu")
            
            cmd = get_command_input("network#", network_commands)
            
            if cmd in ["back", "b"]:
                break
                
            try:
                if network_manager.handle_shell_command(cmd):
                    continue

                if cmd == "scan":
                    target = console.input("[cyan]Enter target: [/cyan]").strip()
                    options = console.input("[cyan]Enter options (leave empty for default): [/cyan]").strip()
                    network_manager.handle_command("scan", target, options if options else None)
                elif cmd == "capture":
                    interface = console.input("[cyan]Enter interface: [/cyan]").strip()
                    filter_str = console.input("[cyan]Enter filter (leave empty for all): [/cyan]").strip()
                    network_manager.handle_command("capture", interface, filter_str if filter_str else None)
                elif cmd == "stop":
                    network_manager.handle_command("stop")
                elif cmd == "analyze":
                    file_path = console.input("[cyan]Enter capture file: [/cyan]").strip()
                    filter_str = console.input("[cyan]Enter display filter (leave empty for all): [/cyan]").strip()
                    network_manager.handle_command("analyze", file_path, filter_str if filter_str else None)
                elif cmd == "proxy":
                    port = console.input("[cyan]Enter port (default: 8080): [/cyan]").strip()
                    options = console.input("[cyan]Enter options: [/cyan]").strip()
                    network_manager.handle_command("proxy", port if port else "8080", options)
                elif cmd == "pstop":
                    network_manager.handle_command("proxy_stop")
                elif cmd == "convert":
                    input_file = console.input("[cyan]Enter input file: [/cyan]").strip()
                    output_file = console.input("[cyan]Enter output file: [/cyan]").strip()
                    format_type = console.input("[cyan]Enter format (default: json): [/cyan]").strip()
                    network_manager.handle_command("convert", input_file, output_file, format_type if format_type else "json")
                elif cmd == "filter":
                    input_file = console.input("[cyan]Enter input file: [/cyan]").strip()
                    filter_str = console.input("[cyan]Enter filter: [/cyan]").strip()
                    output_file = console.input("[cyan]Enter output file: [/cyan]").strip()
                    network_manager.handle_command("filter", input_file, filter_str, output_file)
                elif cmd == "trace":
                    target = console.input("[cyan]Enter target: [/cyan]").strip()
                    max_hops = console.input("[cyan]Enter max hops (default: 16): [/cyan]").strip()
                    network_manager.handle_command("trace", target, max_hops if max_hops else "16")
                else:
                    console.print("[red]Unknown command[/red]")
                    
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")
    
    return True

@research_app.command(name="ai")
def ai_cmd():
    """AI assistant tools"""
    ai_manager = AIManager()
    ai_commands = ["chat", "config", "agent", "history", "logs", "back", "b"]
    
    try:
        while True:
            console.print("\n[yellow]AI Assistant Menu[/yellow]")
            console.print("1. chat     - Start chat session")
            console.print("2. config   - Configure settings")
            console.print("3. agent    - Start agent session    ")
            console.print("4. history  - View chat history")
            console.print("5. logs     - View API logs")
            console.print("6. b/back   - Return to main menu")
            
            cmd = get_command_input("ai#", ai_commands)
            
            if cmd in ["back", "b"]:
                break

            try:
                if ai_manager.handle_shell_command(cmd):
                    continue

                if cmd == "chat":
                    ai_manager.handle_command("chat")
                elif cmd == "config":
                    ai_manager.handle_command("config")
                elif cmd == "history":
                    ai_manager.handle_command("history")
                elif 'logs' in cmd:
                    ai_manager.handle_command(cmd)
                elif cmd == "agent":
                    ai_manager.handle_command("agent")
                else:
                    console.print("[red]Unknown command[/red]")
                    
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")
    
    return True

@research_app.command(name="search")
def search_cmd():
    """Knowledge base search tools"""
    search_manager = SearchManager()
    search_commands = ["all", "ddg", "so", "github", "history", "back", "b"]
    
    try:
        while True:
            console.print("\n[yellow]Search Menu[/yellow]")
            console.print("1. all      - Search all sources")
            console.print("2. ddg      - Search DuckDuckGo")
            console.print("3. so       - Search StackOverflow")
            console.print("4. github   - Search GitHub")
            console.print("5. history  - View search history")
            console.print("6. b/back   - Return to main menu")
            
            cmd = get_command_input("search#", search_commands)
            
            if cmd in ["back", "b"]:
                break
                
            try:
                if search_manager.handle_shell_command(cmd):
                    continue

                if cmd in ["all", "ddg", "so", "github"]:
                    query = console.input("[cyan]Enter search query: [/cyan]").strip()
                    if query:
                        search_manager.handle_command(cmd, query)
                    else:
                        console.print("[yellow]Search query cannot be empty[/yellow]")
                elif cmd == "history":
                    search_manager.handle_command("history")
                else:
                    console.print("[red]Unknown command[/red]")
                    
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")
    
    return True

@research_app.command(name="snippets")
def snippets_cmd():
    """Code snippets management"""
    snippets_manager = SnippetsManager()
    snippets_commands = ["list", "add", "show", "edit", "delete", "search", "back", "b"]
    
    try:
        while True:
            console.print("\n[yellow]Code Snippets Menu[/yellow]")
            console.print("1. list     - List snippets")
            console.print("2. add      - Add new snippet")
            console.print("3. show     - Show snippet")
            console.print("4. edit     - Edit snippet")
            console.print("5. delete   - Delete snippet")
            console.print("6. search   - Search snippets")
            console.print("7. b/back   - Return to main menu")
            
            cmd = get_command_input("snippets#", snippets_commands)
            
            if cmd in ["back", "b"]:
                break
                
            try:
                if snippets_manager.handle_shell_command(cmd):
                    continue

                if cmd == "list":
                    language = console.input("[cyan]Filter by language (leave empty for all): [/cyan]").strip()
                    snippets_manager.handle_command("list", language if language else None)
                elif cmd == "add":
                    snippets_manager.handle_command("add")
                elif cmd == "show":
                    snippet_id = console.input("[cyan]Enter snippet ID: [/cyan]").strip()
                    snippets_manager.handle_command("show", snippet_id)
                elif cmd == "edit":
                    snippet_id = console.input("[cyan]Enter snippet ID: [/cyan]").strip()
                    snippets_manager.handle_command("edit", snippet_id)
                elif cmd == "delete":
                    snippet_id = console.input("[cyan]Enter snippet ID: [/cyan]").strip()
                    snippets_manager.handle_command("delete", snippet_id)
                elif cmd == "search":
                    keyword = console.input("[cyan]Enter search keyword: [/cyan]").strip()
                    language = console.input("[cyan]Filter by language (leave empty for all): [/cyan]").strip()
                    snippets_manager.handle_command("search", keyword, language if language else None)
                else:
                    console.print("[red]Unknown command[/red]")
                    
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")
    
    return True

@research_app.command(name="remarks")
def remarks_cmd():
    """Bookmarks and remarks management"""
    remarks_manager = RemarksManager()
    remarks_commands = ["list", "add", "show", "edit", "delete", "search", "back", "b"]
    
    try:
        while True:
            console.print("\n[yellow]Remarks Menu[/yellow]")
            console.print("1. list     - List all remarks")
            console.print("2. add      - Add new remark")
            console.print("3. show     - Show remark details")
            console.print("4. edit     - Edit remark")
            console.print("5. delete   - Delete remark")
            console.print("6. search   - Search remarks")
            console.print("7. b/back   - Return to main menu")
            
            cmd = get_command_input("remarks#", remarks_commands)
            
            if cmd in ["back", "b"]:
                break
                
            try:
                if remarks_manager.handle_shell_command(cmd):
                    continue

                if cmd == "list":
                    category = console.input("[cyan]Filter by category (leave empty for all): [/cyan]").strip()
                    tag = console.input("[cyan]Filter by tag (leave empty for all): [/cyan]").strip()
                    remarks_manager.list_remarks(
                        category if category else None,
                        tag if tag else None
                    )
                elif cmd == "add":
                    title = console.input("[cyan]Enter title: [/cyan]").strip()
                    url = console.input("[cyan]Enter URL: [/cyan]").strip()
                    description = console.input("[cyan]Enter description (optional): [/cyan]").strip()
                    category = console.input("[cyan]Enter category (optional): [/cyan]").strip()
                    tags = console.input("[cyan]Enter tags (comma-separated, optional): [/cyan]").strip()
                    
                    if title and url:
                        remarks_manager.add_remark(
                            title,
                            url,
                            description if description else "",
                            category if category else "",
                            tags.split(",") if tags else None
                        )
                    else:
                        console.print("[red]Title and URL are required[/red]")
                        
                elif cmd == "show":
                    remark_id = console.input("[cyan]Enter remark ID: [/cyan]").strip()
                    if remark_id.isdigit():
                        remarks_manager.show_remark(int(remark_id))
                    else:
                        console.print("[red]Invalid remark ID[/red]")
                        
                elif cmd == "edit":
                    remark_id = console.input("[cyan]Enter remark ID: [/cyan]").strip()
                    if not remark_id.isdigit():
                        console.print("[red]Invalid remark ID[/red]")
                        continue
                        
                    title = console.input("[cyan]Enter new title (leave empty to keep current): [/cyan]").strip()
                    url = console.input("[cyan]Enter new URL (leave empty to keep current): [/cyan]").strip()
                    description = console.input("[cyan]Enter new description (leave empty to keep current): [/cyan]").strip()
                    category = console.input("[cyan]Enter new category (leave empty to keep current): [/cyan]").strip()
                    tags = console.input("[cyan]Enter new tags (comma-separated, leave empty to keep current): [/cyan]").strip()
                    
                    if title or url or description or category or tags:
                        remarks_manager.update_remark(
                            int(remark_id),
                            title if title else None,
                            url if url else None,
                            description if description else None,
                            category if category else None,
                            tags.split(",") if tags else None
                        )
                    else:
                        console.print("[yellow]No changes made[/yellow]")
                        
                elif cmd == "delete":
                    remark_id = console.input("[cyan]Enter remark ID: [/cyan]").strip()
                    if remark_id.isdigit():
                        remarks_manager.delete_remark(int(remark_id))
                    else:
                        console.print("[red]Invalid remark ID[/red]")
                        
                elif cmd == "search":
                    keyword = console.input("[cyan]Enter search keyword: [/cyan]").strip()
                    remarks_manager.search_remarks(keyword)
                    
                else:
                    console.print("[red]Unknown command[/red]")
                    
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")
    
    return True

@investment_app.command(name="crypto")
def crypto_cmd():
    """Cryptocurrency monitor"""
    crypto_manager = CryptoManager()
    crypto_commands = ["price", "markets", "watchlist", "add", "remove", "monitor", "info", "back", "b"]
    
    try:
        while True:
            console.print("\n[yellow]Cryptocurrency Menu[/yellow]")
            console.print("1. price    - Show cryptocurrency prices")
            console.print("2. markets  - Show market overview")
            console.print("3. watchlist- Manage watchlist")
            console.print("4. add      - Add to watchlist")
            console.print("5. remove   - Remove from watchlist")
            console.print("6. monitor  - Monitor prices")
            console.print("7. info     - Show coin information")
            console.print("8. b/back   - Return to main menu")
            
            cmd = get_command_input("crypto#", crypto_commands)
            
            if cmd in ["back", "b"]:
                break
                
            try:
                if crypto_manager.handle_shell_command(cmd):
                    continue

                if cmd == "price":
                    coins = console.input("[cyan]Enter coin IDs (comma-separated, press enter for watchlist): [/cyan]").strip()
                    crypto_manager.handle_command("price", coins.split(",") if coins else None)
                elif cmd == "markets":
                    crypto_manager.handle_command("markets")
                elif cmd == "watchlist":
                    crypto_manager.handle_command("watchlist")
                elif cmd == "add":
                    coin_id = console.input("[cyan]Enter coin ID to add: [/cyan]").strip()
                    crypto_manager.handle_command("add", coin_id)
                elif cmd == "remove":
                    coin_id = console.input("[cyan]Enter coin ID to remove: [/cyan]").strip()
                    crypto_manager.handle_command("remove", coin_id)
                elif cmd == "monitor":
                    crypto_manager.handle_command("monitor")
                elif cmd == "info":
                    coin_id = console.input("[cyan]Enter coin ID: [/cyan]").strip()
                    crypto_manager.handle_command("info", coin_id)
                else:
                    console.print("[red]Unknown command[/red]")
                    
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                
            if cmd not in ["back", "b"]:
                console.print("\n" + "="*50 + "\n")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")

@entertainment_app.command(name="game")
def game_cmd():
    """Classic Games Collection"""
    game_manager = GameManager()
    game_commands = ["2048", "tetris", "snake", "space", "list", "back", "b"]
    
    try:
        while True:
            console.print("\n[yellow]Classic Games Menu[/yellow]")
            console.print("1. 2048     - Classic 2048 puzzle game")
            console.print("2. tetris   - Classic Tetris game")
            console.print("3. snake    - Classic Snake game")
            console.print("4. space    - Space Shooter game")
            console.print("5. list     - List all available games")
            console.print("6. b/back   - Return to main menu")
            
            cmd = get_command_input("game#", game_commands)
            
            if cmd in ["back", "b"]:
                break
                
            try:
                if game_manager.handle_shell_command(cmd):
                    continue
                game_manager.handle_command(cmd)
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
                
            if cmd not in ["back", "b"]:
                console.print("\n" + "="*50 + "\n")
    
    except KeyboardInterrupt:
        console.print("\n[yellow]Returning to main menu...[/yellow]")
    
    return True

if __name__ == "__main__":
    app() 