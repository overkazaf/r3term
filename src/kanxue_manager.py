from base_manager import BaseManager
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
import httpx
from bs4 import BeautifulSoup
import webbrowser
import asyncio
from datetime import datetime
import json

console = Console()

class KanxueManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.base_url = "https://www.kanxue.com"
        self.categories = {
            0: "资讯",
            1: "逆向",
            2: "移动",
            3: "漏洞",
            4: "开发",
            5: "IoT",
            6: "WEB",
            7: "CTF",
            8: "区块链",
            9: "业务安全"
        }
        self.current_articles = []  # 存储当前显示的文章列表
        self.current_article_index = 0
    def handle_command(self, command: str, *args):
        """处理看雪相关命令"""
        try:
            if self.handle_shell_command(command):
                return

            print(f"kanxue command: {command}")
            if "list" in command:
                args = command.split(" ")[1:]
                if len(args) > 0:
                    try:
                        index = int(args[0])
                        if 0 <= index <= 9:
                            self._fetch_articles(index)
                        else:
                            console.print("[red]Invalid category index. Please use 0-9.[/red]")
                    except ValueError:
                        console.print("[red]Invalid category index. Please use 0-9.[/red]")
                else:
                    self._show_categories()
            elif "open" in command:
                args = command.split(" ")[1:]
                if len(args) > 0:
                    try:
                        article_index = int(args[0])
                        self._open_article(article_index)
                    except ValueError:
                        console.print("[red]Invalid article index.[/red]")
                else:
                    console.print("[red]Please provide an article index.[/red]")
            else:
                console.print("[red]Unknown command[/red]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

    def handle_shell_command(self, command: str) -> bool:
        """处理shell命令"""
        if command.lower() in ['q', 'quit', 'exit', 'b', 'back']:
            console.print("[yellow]Returning to main menu...[/yellow]")
            return True
        elif command.lower() in ['h', 'help', '?']:
            self._show_help()
            return True
        return False

    def _show_help(self):
        """显示帮助信息"""
        console.print("\n[bold cyan]Kanxue Forum Commands:[/bold cyan]")
        table = Table(show_header=False, box=None)
        table.add_column("Command", style="green")
        table.add_column("Description", style="white")
        
        table.add_row("list", "Show all categories")
        table.add_row("list <index>", "List articles in category (0-9)")
        table.add_row("open <index>", "Open article in browser")
        table.add_row("help", "Show this help message")
        table.add_row("quit/back", "Return to main menu")
        
        console.print(table)
        
        # 显示分类信息
        console.print("\n[bold cyan]Categories:[/bold cyan]")
        categories_table = Table(show_header=True, header_style="bold magenta")
        categories_table.add_column("Index", style="dim")
        categories_table.add_column("Category", style="green")
        
        for index, category in self.categories.items():
            categories_table.add_row(str(index), category)
            
        console.print(categories_table)

    def _show_categories(self):
        """显示所有分类"""
        console.print("\n[bold cyan]Kanxue Forum Categories:[/bold cyan]")
        table = Table(show_header=True, header_style="bold magenta")
        table.add_column("Index", style="dim")
        table.add_column("Category", style="green")
        table.add_column("URL", style="blue")
        
        for index, category in self.categories.items():
            url = f"{self.base_url}/index-thread_list-{index}-1.htm"
            table.add_row(str(index), category, url)
            
        console.print(table)
        console.print("\n[dim]Use 'list <index>' to view articles in a category[/dim]")

    async def _fetch_page(self, url: str) -> str:
        """异步获取页面内容"""
        async with httpx.AsyncClient() as client:
            response = await client.get(url)
            return response.text

    def _fetch_articles(self, index: int):
        """获取指定分类的文章列表"""
        url = f"{self.base_url}/index-thread_list-{index}-1.htm"
        
        try:
            console.print(f"[cyan]Fetching articles from {self.categories[index]}...[/cyan]")
            
            # 使用 httpx 发送请求
            headers = {
                'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36',
                'Accept': 'application/json',
                'Referer': self.base_url
            }
            
            response = httpx.get(url, headers=headers)
            
            # 检查响应状态
            if response.status_code != 200:
                console.print(f"[red]Error: API returned status code {response.status_code}[/red]")
                return
                
            try:
                # 尝试解析JSON响应
                data = response.json()
                
                # 清空当前文章列表
                self.current_articles = []
                
                # 创建表格
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Index", style="dim", width=6)
                table.add_column("Title", style="green", width=30)
                table.add_column("Author", style="blue", width=15)
                table.add_column("Brief", style="cyan", width=80)
                table.add_column("Create Date", style="yellow", width=12)
                table.add_column("Update Date", style="magenta", width=12)
                table.add_column("Views", style="magenta", width=8)
                
                # 处理文章数据
                if 'message' in data and 'list' in data['message']:
                    threads = data['message']['list']
                    if not threads:
                        console.print("[yellow]No articles found.[/yellow]")
                        return
                        
                    for idx, thread in enumerate(threads):
                        # 提取文章信息
                        title = thread.get('subject', 'Untitled')
                        author = thread.get('username', 'Unknown')
                        brief = thread.get('brief', 'Unknown')
                        create_date = thread.get('create_date_fmt', 'Unknown')
                        update_date = thread.get('update_date_fmt', 'Unknown')
                        url = thread.get('source_url', 'Unknown')
                        views = str(thread.get('views', 0))
                        
                        # 保存文章URL
                        article_url = url
                        self.current_articles.append(article_url)
                        
                        # 添加到表格
                        table.add_row(
                            str(idx),
                            title[:47] + "..." if len(title) > 47 else title,
                            author[:15],
                            brief,
                            create_date,
                            update_date,
                            views
                        )
                    
                    console.print(f"\n[bold]Articles in {self.categories[index]}:[/bold]")
                    console.print(table)
                    console.print("\n[dim]Use 'open <index>' to open an article in your browser[/dim]")
                    
                else:
                    console.print("[yellow]No articles data found in response.[/yellow]")
                    
            except json.JSONDecodeError:
                # 如果JSON解析失败，尝试使用HTML解析（作为备选方案）
                console.print("[yellow]Failed to parse JSON response, falling back to HTML parsing...[/yellow]")
                
                soup = BeautifulSoup(response.text, 'html.parser')
                articles = soup.find_all('div', class_='thread-list-item')
                
                if not articles:
                    console.print("[yellow]No articles found.[/yellow]")
                    return
                
                # 创建表格
                table = Table(show_header=True, header_style="bold magenta")
                table.add_column("Index", style="dim", width=6)
                table.add_column("Title", style="green", width=50)
                table.add_column("Author", style="blue", width=15)
                table.add_column("Brief", style="cyan", width=50)
                table.add_column("Create Date", style="yellow", width=12)
                table.add_column("Update Date", style="magenta", width=12)
                table.add_column("Views", style="magenta", width=8)
                
                for idx, article in enumerate(articles):
                    # 提取文章信息
                    title_elem = article.find('a', class_='thread-title')
                    author_elem = article.find('a', class_='thread-author')
                    date_elem = article.find('span', class_='thread-time')
                    views_elem = article.find('span', class_='thread-views')
                    brief_elem = article.find('div', class_='thread-brief')
                    if title_elem and author_elem:
                        title = title_elem.text.strip()
                        author = author_elem.text.strip()
                        date = date_elem.text.strip() if date_elem else "Unknown"
                        views = views_elem.text.strip() if views_elem else "0"
                        
                        # 保存文章URL
                        article_url = self.base_url + title_elem['href'] if title_elem.has_attr('href') else None
                        self.current_articles.append(article_url)
                        
                        # 添加到表格
                        table.add_row(
                            str(idx),
                            title[:47] + "..." if len(title) > 47 else title,
                            author[:15],
                            date,
                            views
                        )
                
                console.print(f"\n[bold]Articles in {self.categories[index]}:[/bold]")
                console.print(table)
                console.print("\n[dim]Use 'open <index>' to open an article in your browser[/dim]")
            
        except Exception as e:
            console.print(f"[red]Error fetching articles: {str(e)}[/red]")

    def _open_article(self, index: int):
        """在浏览器中打开指定文章"""
        if not self.current_articles:
            console.print("[red]No articles loaded. Please list a category first.[/red]")
            return
            
        if 0 <= index < len(self.current_articles):
            url = self.current_articles[index]
            if url:
                console.print(f"[cyan]Opening article in browser: {url}[/cyan]")
                webbrowser.open(url)
            else:
                console.print("[red]Invalid article URL.[/red]")
        else:
            console.print("[red]Invalid article index.[/red]") 