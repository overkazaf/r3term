from base_manager import BaseManager
from rich.console import Console
from rich.table import Table
from rich.syntax import Syntax
import json
import os
import tempfile
import subprocess
from datetime import datetime
from pathlib import Path

console = Console()

class SnippetsManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.snippets_dir = Path("data/snippets")
        self.snippets_dir.mkdir(parents=True, exist_ok=True)
        self.snippets_file = os.path.join(self.snippets_dir, "snippets.json")
        self._ensure_snippets_file()
    
    def _ensure_snippets_file(self):
        """确保代码片段文件和目录存在"""
        if not os.path.exists(self.snippets_file):
            with open(self.snippets_file, 'w', encoding='utf-8') as f:
                json.dump([], f, ensure_ascii=False, indent=2)
    
    def _load_snippets(self):
        """加载所有代码片段"""
        with open(self.snippets_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    
    def _save_snippets(self, snippets):
        """保存所有代码片段"""
        with open(self.snippets_file, 'w', encoding='utf-8') as f:
            json.dump(snippets, f, ensure_ascii=False, indent=2)
    
    def handle_command(self, command: str, *args):
        """Handle snippets commands"""
        try:
            # 首先检查是否是shell命令
            if self.handle_shell_command(command):
                return
                
            if command == "list":
                self.list_snippets()
            elif command == "add":
                self.add_snippet()
            elif command == "show":
                if len(args) > 0:
                    self.show_snippet(args[0])
                else:
                    console.print("[red]Please provide a snippet ID[/red]")
            elif command == "edit":
                if len(args) > 0:
                    self.edit_snippet(args[0])
                else:
                    console.print("[red]Please provide a snippet ID[/red]")
            elif command == "delete":
                if len(args) > 0:
                    self.delete_snippet(args[0])
                else:
                    console.print("[red]Please provide a snippet ID[/red]")
            elif command == "search":
                if len(args) > 0:
                    self.search_snippets(args[0])
                else:
                    console.print("[red]Please provide a search term[/red]")
            else:
                console.print("[red]Unknown command[/red]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
    
    def list_snippets(self):
        """列出所有代码片段"""
        snippets = self._load_snippets()
        
        table = Table(title="Code Snippets")
        table.add_column("ID", style="cyan")
        table.add_column("Title", style="green")
        table.add_column("Language", style="magenta")
        table.add_column("Tags", style="yellow")
        table.add_column("Created", style="blue")
        
        for snippet in snippets:
            table.add_row(
                str(snippet['id']),
                snippet['title'],
                snippet['language'],
                ", ".join(snippet['tags']),
                snippet['created_at']
            )
        
        console.print(table)
    
    def add_snippet(self):
        """添加新的代码片段"""
        title = console.input("[cyan]Title:[/cyan] ").strip()
        language = console.input("[cyan]Language:[/cyan] ").strip()
        tags = console.input("[cyan]Tags (comma-separated):[/cyan] ").strip()
        tags = [tag.strip() for tag in tags.split(",") if tag.strip()]
        
        # 创建临时文件
        with tempfile.NamedTemporaryFile(suffix=f'.{language}', mode='w+', delete=False) as temp_file:
            # 写入一些基本注释
            temp_file.write(f"""// Title: {title}
// Language: {language}
// Tags: {', '.join(tags)}
// Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

""")
            temp_file.flush()
            temp_path = temp_file.name
        
        try:
            # 使用vim打开临时文件
            console.print("[cyan]Opening vim editor. Save and quit (:wq) when done...[/cyan]")
            subprocess.run(['vim', temp_path])
            
            # 读取编辑后的内容
            with open(temp_path, 'r') as f:
                content = f.read()
            
            # 删除临时文件
            os.unlink(temp_path)
            
            # 加载现有片段并生成新ID
            snippets = self._load_snippets()
            new_id = max([s['id'] for s in snippets], default=0) + 1
            
            # 创建新片段
            new_snippet = {
                'id': new_id,
                'title': title,
                'language': language,
                'tags': tags,
                'content': content,
                'created_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }
            
            snippets.append(new_snippet)
            self._save_snippets(snippets)
            console.print(f"[green]Snippet {new_id} added successfully![/green]")
            
        except Exception as e:
            console.print(f"[red]Error during snippet creation: {str(e)}[/red]")
            if os.path.exists(temp_path):
                os.unlink(temp_path)
    
    def show_snippet(self, snippet_id: str):
        """显示特定代码片段"""
        try:
            snippet_id = int(snippet_id)
            snippets = self._load_snippets()
            snippet = next((s for s in snippets if s['id'] == snippet_id), None)
            
            if not snippet:
                console.print(f"[red]Snippet {snippet_id} not found[/red]")
                return
            
            console.print(f"[cyan]Title:[/cyan] {snippet['title']}")
            console.print(f"[cyan]Language:[/cyan] {snippet['language']}")
            console.print(f"[cyan]Tags:[/cyan] {', '.join(snippet['tags'])}")
            console.print(f"[cyan]Created:[/cyan] {snippet['created_at']}")
            console.print("\n[cyan]Content:[/cyan]")
            
            syntax = Syntax(snippet['content'], snippet['language'], theme="monokai")
            console.print(syntax)
            
        except ValueError:
            console.print("[red]Invalid snippet ID[/red]")
    
    def edit_snippet(self, snippet_id: str):
        """编辑代码片段"""
        try:
            snippet_id = int(snippet_id)
            snippets = self._load_snippets()
            snippet = next((s for s in snippets if s['id'] == snippet_id), None)
            
            if not snippet:
                console.print(f"[red]Snippet {snippet_id} not found[/red]")
                return
            
            # 创建临时文件
            with tempfile.NamedTemporaryFile(suffix=f'.{snippet["language"]}', mode='w+', delete=False) as temp_file:
                temp_file.write(snippet['content'])
                temp_file.flush()
                temp_path = temp_file.name
            
            try:
                # 使用vim打开临时文件
                console.print("[cyan]Opening vim editor. Save and quit (:wq) when done...[/cyan]")
                subprocess.run(['vim', temp_path])
                
                # 读取编辑后的内容
                with open(temp_path, 'r') as f:
                    content = f.read()
                
                # 删除临时文件
                os.unlink(temp_path)
                
                # 更新片段
                snippet['content'] = content
                self._save_snippets(snippets)
                console.print(f"[green]Snippet {snippet_id} updated successfully![/green]")
                
            except Exception as e:
                console.print(f"[red]Error during snippet editing: {str(e)}[/red]")
                if os.path.exists(temp_path):
                    os.unlink(temp_path)
                    
        except ValueError:
            console.print("[red]Invalid snippet ID[/red]")
    
    def delete_snippet(self, snippet_id: str):
        """删除代码片段"""
        try:
            snippet_id = int(snippet_id)
            snippets = self._load_snippets()
            snippet = next((s for s in snippets if s['id'] == snippet_id), None)
            
            if not snippet:
                console.print(f"[red]Snippet {snippet_id} not found[/red]")
                return
            
            confirm = console.input(f"[yellow]Are you sure you want to delete snippet {snippet_id}? (y/N):[/yellow] ").strip().lower()
            if confirm == 'y':
                snippets = [s for s in snippets if s['id'] != snippet_id]
                self._save_snippets(snippets)
                console.print(f"[green]Snippet {snippet_id} deleted successfully![/green]")
            else:
                console.print("[yellow]Deletion cancelled[/yellow]")
                
        except ValueError:
            console.print("[red]Invalid snippet ID[/red]")
    
    def search_snippets(self, keyword: str):
        """搜索代码片段"""
        snippets = self._load_snippets()
        keyword = keyword.lower()
        
        table = Table(title=f"Search Results for '{keyword}'")
        table.add_column("ID", style="cyan")
        table.add_column("Title", style="green")
        table.add_column("Language", style="magenta")
        table.add_column("Tags", style="yellow")
        table.add_column("Match Type", style="red")
        
        for snippet in snippets:
            match_type = []
            if keyword in snippet['title'].lower():
                match_type.append("title")
            if keyword in snippet['content'].lower():
                match_type.append("content")
            if any(keyword in tag.lower() for tag in snippet['tags']):
                match_type.append("tags")
                
            if match_type:
                table.add_row(
                    str(snippet['id']),
                    snippet['title'],
                    snippet['language'],
                    ", ".join(snippet['tags']),
                    ", ".join(match_type)
                )
        
        console.print(table) 