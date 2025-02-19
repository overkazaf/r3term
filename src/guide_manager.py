from base_manager import BaseManager
from rich.console import Console
from rich.markdown import Markdown
from pathlib import Path
import os
import re

console = Console()

class GuideManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.guides_dir = Path("data/guides")
        self.guides_dir.mkdir(parents=True, exist_ok=True)
    
    def read_guide(self, module_name: str) -> str:
        """Read guide content from markdown file"""
        guide_path = os.path.join(self.guides_dir, f"{module_name}_guide.md")
        try:
            with open(guide_path, 'r', encoding='utf-8') as f:
                return f.read()
        except FileNotFoundError:
            return f"Guide for {module_name} not found."
        except Exception as e:
            return f"Error reading guide: {str(e)}"
    
    def extract_tool_section(self, content: str, tool_name: str) -> str:
        """Extract specific tool section from guide content"""
        # 将工具名转换为小写以进行不区分大小写的匹配
        tool_name = tool_name.lower()
        
        # 定义可能的标题格式
        patterns = [
            # 匹配 ### n. Tool_Name 或 ### Tool_Name 格式
            rf"###\s*(?:\d+\.)?\s*{tool_name}.*?(?=###|\Z)",
            # 匹配 ## Tool_Name 格式
            rf"##\s*{tool_name}.*?(?=##|\Z)",
            # 匹配 # Tool_Name 格式
            rf"#\s*{tool_name}.*?(?=#|\Z)"
        ]
        
        # 使用正则表达式查找匹配的部分，忽略大小写
        for pattern in patterns:
            matches = re.finditer(pattern, content, re.IGNORECASE | re.DOTALL | re.MULTILINE)
            for match in matches:
                section = match.group(0).strip()
                if section:  # 如果找到匹配的部分
                    return f"# {tool_name.upper()} Guide\n\n{section}"
        
        return f"No guide found for tool: {tool_name}"
    
    def display_guide(self, module_name: str, tool_name: str = None):
        """Display guide content with rich formatting"""
        content = self.read_guide(module_name)
        
        if tool_name:
            # 如果指定了工具名，只显示该工具的部分
            content = self.extract_tool_section(content, tool_name)
        
        md = Markdown(content)
        console.print(md)

    def handle_command(self, command: str, *args):
        """Handle guide commands"""
        try:
            # 首先检查是否是shell命令
            if self.handle_shell_command(command):
                return
                
            if command == "list":
                self.list_guides()
            elif command == "show":
                if len(args) > 0:
                    self.show_guide(args[0])
                else:
                    console.print("[red]Please provide a guide name[/red]")
            elif command == "search":
                if len(args) > 0:
                    self.search_guides(args[0])
                else:
                    console.print("[red]Please provide a search term[/red]")
            else:
                console.print("[red]Unknown command[/red]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]") 