from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.syntax import Syntax
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.live import Live
from rich.spinner import Spinner
from rich.console import Group
from rich.console import ConsoleOptions, RenderResult
from rich.padding import Padding
import httpx
import json
import os
from pathlib import Path
from datetime import datetime
import asyncio
import time
import base64
from base_manager import BaseManager
from rich.table import Table
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

console = Console()

class ScrollingMarkdown:
    """A custom renderable that shows the last N lines of markdown content"""
    def __init__(self, markdown_content: str, max_lines: int = 15):
        self.markdown_content = markdown_content
        self.max_lines = max_lines

    def __rich_console__(self, console: Console, options: ConsoleOptions) -> RenderResult:
        # 渲染 Markdown
        rendered = console.render_lines(Markdown(self.markdown_content), options)
        # 获取最后 N 行
        lines = list(rendered)
        if len(lines) > self.max_lines:
            lines = lines[-self.max_lines:]
        return lines

class AIManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.config_dir = Path("config")
        self.config_file = self.config_dir / "ai_config.json"
        self.history_dir = Path("data/ai_history")
        self.log_dir = Path("logs")
        self.log_file = self.log_dir / "ai_api.log"
        
        # Create necessary directories
        self.config_dir.mkdir(exist_ok=True)
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(exist_ok=True)
        
        self.console = Console()
        self.load_config()
        self.context = []
        self.api_key = os.getenv("DEEPSEEK_API_KEY")
        self.history_file = "data/ai/chat_history.json"
        self._ensure_data()

    def _handle_specific_command(self, cmd: str, *args):
        """处理 AI 相关的具体命令"""
        if cmd == "chat":
            return self._chat(args[0] if args else None)
        elif cmd == "history":
            return self._show_history()
        elif cmd == "clear":
            return self._clear_history()
        elif cmd == "config":
            return self._configure()
        elif cmd == "agent":
            return self._start_agent()
        elif cmd == "logs":
            return self._show_logs(int(args[0]) if args and args[0].isdigit() else 100)
        else:
            self.console.print("[red]Unknown command[/red]")
            return False

    def load_config(self):
        """Load API configuration"""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    config = json.load(f)
                    # 解码 API key
                    if config.get("api_key_encoded"):
                        config["api_key"] = base64.b64decode(config["api_key_encoded"]).decode('utf-8')
                        del config["api_key_encoded"]
                    self.config = config
            except Exception as e:
                console.print(f"[red]Error loading config: {str(e)}[/red]")
                self._create_default_config()
        else:
            self._create_default_config()

    def _create_default_config(self):
        """Create default configuration"""
        self.config = {
            "api_key": "",
            "api_base": "https://api.deepseek.com/v1",
            "model": "deepseek-chat",
            "temperature": 0.7,
            "max_tokens": 2000
        }
        self.save_config()

    def save_config(self):
        """Save API configuration"""
        try:
            # 创建配置的副本，避免修改原始配置
            config_to_save = self.config.copy()
            
            # 编码 API key
            if config_to_save.get("api_key"):
                config_to_save["api_key_encoded"] = base64.b64encode(
                    config_to_save["api_key"].encode('utf-8')
                ).decode('utf-8')
                del config_to_save["api_key"]
            
            with open(self.config_file, 'w') as f:
                json.dump(config_to_save, f, indent=2)
            
            return True
        except Exception as e:
            console.print(f"[red]Error saving config: {str(e)}[/red]")
            return False

    def set_api_key(self, api_key: str):
        """Set DeepSeek API key"""
        self.config["api_key"] = api_key
        if self.save_config():
            console.print("[green]API key saved successfully[/green]")
        else:
            console.print("[red]Failed to save API key[/red]")

    def log_api(self, message: str, level: str = "INFO"):
        """Log API related information"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] [{level}] {message}\n"
        
        try:
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(log_entry)
        except Exception as e:
            self.console.print(f"[red]Error writing to log file: {str(e)}[/red]")

    def chat(self, prompt: str, context: list = None):
        """Send chat request to DeepSeek API with streaming response"""
        if not self.config["api_key"]:
            self.console.print("[red]Please set your API key first using 'config' command[/red]")
            return None

        messages = []
        if context:
            messages.extend(context)
        messages.append({"role": "user", "content": prompt})

        self.console.print(Panel("[bold blue]Thinking...[/bold blue]", border_style="blue"))
        
        # Log API request
        self.log_api(f"API Request - Model: {self.config['model']}, Prompt: {prompt[:100]}...")
        
        try:
            with httpx.Client(timeout=30.0) as client:
                start_time = time.time()
                
                # Log request details
                request_data = {
                    "model": self.config["model"],
                    "messages": messages,
                    "temperature": self.config["temperature"],
                    "max_tokens": self.config["max_tokens"],
                    "stream": False
                }
                self.log_api(f"Request Data: {json.dumps(request_data, indent=2)}")
                
                response = client.post(
                    f"{self.config['api_base']}/chat/completions",
                    headers={
                        "Authorization": f"Bearer {self.config['api_key']}",
                        "Content-Type": "application/json",
                    },
                    json=request_data
                )

                # Log response status
                self.log_api(f"Response Status: {response.status_code}")
                
                if response.status_code == 200:
                    try:
                        data = response.json()
                        # Log response data (excluding sensitive information)
                        self.log_api(f"Response Data: {json.dumps({k:v for k,v in data.items() if k != 'id'}, indent=2)}")
                        
                        if not data:
                            error_msg = "Empty response from API"
                            self.log_api(error_msg, "ERROR")
                            self.console.print(f"[red]{error_msg}[/red]")
                            return None

                        if not data.get("choices"):
                            error_msg = "No choices in API response"
                            self.log_api(error_msg, "ERROR")
                            self.console.print(f"[red]{error_msg}[/red]")
                            return None

                        if not data["choices"] or len(data["choices"]) == 0:
                            error_msg = "Empty choices array in API response"
                            self.log_api(error_msg, "ERROR")
                            self.console.print(f"[red]{error_msg}[/red]")
                            return None

                        first_choice = data["choices"][0]
                        if not first_choice.get("message"):
                            error_msg = "No message in API response choice"
                            self.log_api(error_msg, "ERROR")
                            self.console.print(f"[red]{error_msg}[/red]")
                            return None

                        content = first_choice["message"].get("content")
                        if not content:
                            error_msg = "No content in API response message"
                            self.log_api(error_msg, "ERROR")
                            self.console.print(f"[red]{error_msg}[/red]")
                            return None
                            
                        # Format and display the response
                        self.console.print("\n")
                        self.console.print(
                            Panel(
                                Markdown(content, code_theme="monokai"),
                                title="AI Response",
                                border_style="green"
                            )
                        )
                        
                        # Log completion time
                        elapsed = time.time() - start_time
                        self.log_api(f"Request completed in {elapsed:.2f}s")
                        
                        # Save to history
                        self.save_to_history(prompt, content)
                        return content
                        
                    except json.JSONDecodeError as e:
                        error_msg = f"Error parsing API response: {str(e)}"
                        self.log_api(error_msg, "ERROR")
                        self.console.print(f"[red]{error_msg}[/red]")
                        return None
                else:
                    error_msg = f"API Error: {response.status_code} - {response.text}"
                    self.log_api(error_msg, "ERROR")
                    self.console.print(f"[red]{error_msg}[/red]")
                    return None

        except Exception as e:
            error_msg = f"Exception during API call: {str(e)}"
            self.log_api(error_msg, "ERROR")
            self.console.print(f"[red]{error_msg}[/red]")
            return None

    def save_to_history(self, prompt: str, answer: str):
        """Save chat history to file"""
        current_time = datetime.now()
        history_file = self.history_dir / f"chat_{current_time.strftime('%Y%m%d')}.md"
        
        with open(history_file, 'a', encoding='utf-8') as f:
            # 添加更详细的时间戳和格式化
            f.write(f"\n### {current_time.strftime('%H:%M:%S')}\n\n")
            f.write("#### Question:\n")
            f.write(f"{prompt}\n\n")
            f.write("#### Answer:\n")
            f.write(f"{answer}\n\n")
            f.write("---\n")

    def show_history(self, date=None):
        """Show chat history"""
        if date:
            # 显示指定日期的历史记录
            history_files = [self.history_dir / f"chat_{date}.md"]
        else:
            # 获取所有历史记录文件并按日期排序
            history_files = sorted(self.history_dir.glob("chat_*.md"), reverse=True)

        if not history_files:
            console.print("[yellow]No chat history found[/yellow]")
            return

        for history_file in history_files:
            if history_file.exists():
                # 从文件名提取日期
                date_str = history_file.stem.replace('chat_', '')
                try:
                    # 将日期字符串转换为格式化日期
                    formatted_date = datetime.strptime(date_str, '%Y%m%d').strftime('%Y-%m-%d')
                    # 创建日期分隔面板
                    console.print(Panel(
                        f"[bold cyan]Chat History for {formatted_date}[/bold cyan]",
                        border_style="cyan",
                        padding=(0, 2)
                    ))
                    
                    # 读取并显示内容
                    with open(history_file, 'r', encoding='utf-8') as f:
                        content = f.read().strip()
                        if content:
                            console.print(Markdown(content))
                        else:
                            console.print("[yellow]No conversations on this date[/yellow]")
                    
                    # 添加分隔线
                    console.print("=" * 80 + "\n")
                except ValueError:
                    console.print(f"[red]Invalid date format in filename: {history_file.name}[/red]")
            else:
                if date:  # 只有在指定日期时才显示未找到的消息
                    console.print(f"[yellow]No history found for {date}[/yellow]")

    def configure(self):
        """Configure AI settings"""
        self.console.print("\n[bold cyan]Current Configuration:[/bold cyan]")
        for key, value in self.config.items():
            if key == "api_key":
                # Show only first/last 4 characters of API key if it exists
                masked_key = value[:4] + "..." + value[-4:] if value else "Not set"
                self.console.print(f"[green]{key}:[/green] {masked_key}")
            else:
                self.console.print(f"[green]{key}:[/green] {value}")
        
        self.console.print("\n[bold cyan]Available settings to configure:[/bold cyan]")
        self.console.print("1. API Key")
        self.console.print("2. API Base URL")
        self.console.print("3. Model")
        self.console.print("4. Temperature")
        self.console.print("5. Max Tokens")
        self.console.print("6. Back to main menu\n")

        choice = self.console.input("[bold green]Enter your choice (1-6):[/bold green] ")
        
        if choice == "1":
            api_key = self.console.input("[bold green]Enter your API key:[/bold green] ")
            self.set_api_key(api_key)
        elif choice == "2":
            api_base = self.console.input("[bold green]Enter API base URL:[/bold green] ")
            self.config["api_base"] = api_base
            self.save_config()
        elif choice == "3":
            model = self.console.input("[bold green]Enter model name:[/bold green] ")
            self.config["model"] = model
            self.save_config()
        elif choice == "4":
            temp = self.console.input("[bold green]Enter temperature (0.0-1.0):[/bold green] ")
            try:
                temp = float(temp)
                if 0 <= temp <= 1:
                    self.config["temperature"] = temp
                    self.save_config()
                else:
                    self.console.print("[red]Temperature must be between 0 and 1[/red]")
            except ValueError:
                self.console.print("[red]Invalid temperature value[/red]")
        elif choice == "5":
            tokens = self.console.input("[bold green]Enter max tokens:[/bold green] ")
            try:
                tokens = int(tokens)
                if tokens > 0:
                    self.config["max_tokens"] = tokens
                    self.save_config()
                else:
                    self.console.print("[red]Max tokens must be positive[/red]")
            except ValueError:
                self.console.print("[red]Invalid max tokens value[/red]")
        elif choice == "6":
            return
        else:
            self.console.print("[red]Invalid choice[/red]") 

    def show_logs(self, num_lines: int = 100):
        """Show API logs with optional filtering"""
        if not self.log_file.exists():
            self.console.print("[yellow]No logs found[/yellow]")
            return

        try:
            with open(self.log_file, 'r', encoding='utf-8') as f:
                lines = f.readlines()

            # 获取最后N行
            last_lines = lines[-num_lines:] if len(lines) > num_lines else lines

            # 创建一个面板显示日志
            self.console.print("\n[bold cyan]API Logs:[/bold cyan]")
            
            for line in last_lines:
                # 根据日志级别添加颜色
                if "[ERROR]" in line:
                    self.console.print(f"[red]{line.strip()}[/red]")
                elif "[WARNING]" in line:
                    self.console.print(f"[yellow]{line.strip()}[/yellow]")
                else:
                    self.console.print(f"[dim]{line.strip()}[/dim]")

            self.console.print(f"\n[dim]Showing last {len(last_lines)} lines from {self.log_file}[/dim]")
            self.console.print("[dim]Use 'logs <number>' to show different number of lines[/dim]")

        except Exception as e:
            self.console.print(f"[red]Error reading log file: {str(e)}[/red]") 

    def start_agent(self):
        """Start an interactive agent session"""
        if not self.config["api_key"]:
            self.console.print("[red]Please set your API key first using 'config' command[/red]")
            return

        self.console.print("[bold cyan]Starting Agent Session[/bold cyan]")
        self.console.print("[dim]Type 'help' to see available commands[/dim]\n")

        # 创建命令补全器
        agent_commands = [
            'writeup', 'github', 'view', 'knowledge',
            'knowledge add', 'knowledge search', 'knowledge list', 'knowledge analyze', 'knowledge query',
            'help', 'exit', 'quit', 'back'
        ]
        
        # 添加知识库分类作为补全
        categories = self.config.get('knowledge', {}).get('categories', [])
        for category in categories:
            agent_commands.append(f'knowledge add {category}')
            agent_commands.append(f'knowledge list {category}')
            agent_commands.append(f'knowledge analyze {category}')

        completer = WordCompleter(agent_commands, ignore_case=True)
        
        # 设置历史记录文件
        history_file = Path("data/agent/agent_history")
        history_file.parent.mkdir(parents=True, exist_ok=True)
        
        # 定义提示符样式
        style = Style.from_dict({
            'prompt': 'bold green',
        })
        
        # 创建prompt session
        session = PromptSession(
            history=FileHistory(str(history_file)),
            completer=completer,
            complete_while_typing=True,
            style=style
        )

        from agent_manager import AgentManager
        agent = AgentManager()

        while True:
            try:
                # 使用prompt_toolkit获取输入
                command = session.prompt(
                    "\nagent> ",
                    style=style
                ).strip()
                
                # 检查退出命令
                if command.lower() in ['exit', 'quit', 'q', 'back', 'b']:
                    self.console.print("[yellow]Exiting agent mode...[/yellow]")
                    break
                
                # 检查帮助命令
                if command.lower() in ['help', 'h', '?']:
                    self.show_agent_help()
                    continue
                
                if not command:  # 跳过空输入
                    continue
                
                # 处理命令
                agent.handle_command(command)
                
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Command interrupted[/yellow]")
                continue
            except EOFError:
                self.console.print("\n[yellow]Exiting agent mode...[/yellow]")
                break
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")
                continue

    def show_agent_help(self):
        """显示agent帮助信息"""
        self.console.print("\n[bold cyan]Agent Commands:[/bold cyan]")
        table = Table(show_header=False, box=None)
        table.add_column("Command", style="green")
        table.add_column("Description", style="white")
        
        table.add_row("writeup <title>", "Generate reverse engineering write-up template")
        table.add_row("github", "Monitor and report new RE projects from GitHub")
        table.add_row("view [date]", "View GitHub project recommendations (date format: YYYYMMDD)")
        table.add_row("knowledge add <category> <title> [file/url]", "Add knowledge from file, URL, or text input")
        table.add_row("knowledge search <query>", "Search knowledge base")
        table.add_row("knowledge query <search_text>", "Search knowledge base using semantic search")
        table.add_row("knowledge list [category]", "List knowledge entries")
        table.add_row("knowledge analyze [category]", "Analyze knowledge base")
        table.add_row("knowledge delete <category> <title>", "Delete knowledge entry")
        table.add_row("classify <folder>", "Classify files in a folder into categories")
        table.add_row("help", "Show this help message")
        table.add_row("exit/quit/back", "Exit agent mode")
        
        self.console.print(table)
        self.console.print("\n[dim]Knowledge categories: techniques, tools, vulnerabilities, papers, experiences, tutorials[/dim]")
        self.console.print("[dim]Use Tab for command completion and arrow keys for command history[/dim]") 

    def _ensure_data(self):
        """Ensure necessary data directories exist"""
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self.log_dir.mkdir(exist_ok=True)
        self.config_dir.mkdir(exist_ok=True)
        self.history_file = self.history_dir / "chat_history.json"
        self.history_file.touch(exist_ok=True)
        self.log_file = self.log_dir / "ai_api.log"
        self.log_file.touch(exist_ok=True)
        self.config_file = self.config_dir / "ai_config.json"
        self.config_file.touch(exist_ok=True)

    def _chat(self, prompt: str = None):
        """Handle chat command - Interactive chat mode"""
        self.console.print("[bold cyan]Entering chat mode (type 'q' or 'quit' to exit)[/bold cyan]")
        
        while True:
            try:
                # If initial prompt is provided, use it for first iteration
                if prompt:
                    user_input = prompt
                    prompt = None  # Clear it for next iterations
                else:
                    user_input = self.console.input("\n[bold green]You:[/bold green] ").strip()
                
                # Check for exit commands
                if user_input.lower() in ['q', 'quit', 'exit']:
                    self.console.print("[yellow]Exiting chat mode...[/yellow]")
                    break
                
                if not user_input:  # Skip empty input
                    continue
                
                # Process the chat
                response = self.chat(user_input, self.context)
                if response:
                    # Add the conversation to context for continuity
                    self.context.extend([
                        {"role": "user", "content": user_input},
                        {"role": "assistant", "content": response}
                    ])
                    
            except KeyboardInterrupt:
                self.console.print("\n[yellow]Chat interrupted[/yellow]")
                break
            except Exception as e:
                self.console.print(f"[red]Error: {str(e)}[/red]")
                continue
        
        return True

    def _show_history(self):
        """Handle history command"""
        return self.show_history()

    def _clear_history(self):
        """Handle clear command"""
        # Implementation needed
        pass

    def _configure(self):
        """Handle config command"""
        return self.configure()

    def _start_agent(self):
        """Handle agent command"""
        return self.start_agent()

    def _show_logs(self, num_lines: int = 100):
        """Handle logs command"""
        return self.show_logs(num_lines) 