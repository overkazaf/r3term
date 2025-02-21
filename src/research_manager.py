from base_manager import BaseManager
from rich.console import Console
from rich.table import Table
from kanxue_manager import KanxueManager

console = Console()

class ResearchManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.current_mode = None
        self.kanxue = KanxueManager()
        
    def handle_command(self, command: str, *args):
        """处理研究相关命令"""
        try:
            # 如果当前在看雪模式
            if self.current_mode == "kanxue":
                if command.lower() in ['q', 'quit', 'exit', 'b', 'back']:
                    self.current_mode = None
                    console.print("[yellow]Exiting Kanxue mode...[/yellow]")
                    return
                self.kanxue.handle_command(command, *args)
                return
                
            # 处理主菜单命令
            if command == "kanxue":
                self.current_mode = "kanxue"
                console.print("[cyan]Entering Kanxue mode...[/cyan]")
                self.kanxue._show_help()
            elif command.lower() in ['h', 'help', '?']:
                self._show_help()
            elif command.lower() in ['q', 'quit', 'exit', 'b', 'back']:
                console.print("[yellow]Returning to main menu...[/yellow]")
                return True
            else:
                console.print("[red]Unknown command[/red]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
            
    def _show_help(self):
        """显示帮助信息"""
        console.print("\n[bold cyan]Research Commands:[/bold cyan]")
        table = Table(show_header=False, box=None)
        table.add_column("Command", style="green")
        table.add_column("Description", style="white")
        
        # 主命令
        table.add_row("kanxue", "Enter Kanxue forum browsing mode")
        table.add_row("help", "Show this help message")
        table.add_row("quit/back", "Return to main menu")
        
        console.print(table)
        
        # 显示看雪相关的子命令
        console.print("\n[bold cyan]Kanxue Forum Commands:[/bold cyan]")
        kanxue_table = Table(show_header=False, box=None)
        kanxue_table.add_column("Command", style="green")
        kanxue_table.add_column("Description", style="white")
        
        kanxue_table.add_row("kanxue list", "Show all article categories")
        kanxue_table.add_row("kanxue list <0-9>", "List articles in specific category:")
        
        # 添加分类说明
        for index, category in self.kanxue.categories.items():
            kanxue_table.add_row(f"  {index}", f"Browse {category} articles")
            
        kanxue_table.add_row("kanxue open <index>", "Open selected article in browser")
        
        console.print(kanxue_table)
        
        # 添加使用示例
        console.print("\n[bold cyan]Examples:[/bold cyan]")
        examples = Table(show_header=False, box=None)
        examples.add_column("Example", style="green")
        examples.add_column("Description", style="white")
        
        examples.add_row("kanxue", "Enter Kanxue browsing mode")
        examples.add_row("kanxue list", "Show all categories")
        examples.add_row("kanxue list 1", "List all Reverse Engineering articles")
        examples.add_row("kanxue open 0", "Open the first article in current list")
        
        console.print(examples) 