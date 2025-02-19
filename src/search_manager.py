from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.markdown import Markdown
import httpx
from bs4 import BeautifulSoup
from urllib.parse import quote_plus
import json
from pathlib import Path
import webbrowser
import asyncio
from datetime import datetime
from base_manager import BaseManager
import os

console = Console()

class SearchManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.engines = {
            "duckduckgo": {
                "name": "DuckDuckGo",
                "search_url": "https://duckduckgo.com/html/?q={}",
                "result_selector": "div.result",
                "title_selector": "h2.result__title a",
                "snippet_selector": "div.result__snippet",
            },
            "stackoverflow": {
                "name": "Stack Overflow",
                "search_url": "https://stackoverflow.com/search?q={}",
                "result_selector": "div.question-summary",
                "title_selector": "h3.result-link a",
                "snippet_selector": "div.excerpt",
            },
            "github": {
                "name": "GitHub",
                "search_url": "https://github.com/search?q={}&type=repositories",
                "result_selector": "div.Box-row",
                "title_selector": "a.v-align-middle",
                "description_selector": "p.mb-1",
                "meta_selector": "div.f6.color-fg-muted.mt-2",
                "stars_selector": "a.Link--muted",
                "language_selector": "span[itemprop='programmingLanguage']",
                "headers": {
                    "Accept": "application/vnd.github.v3+json",
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
                }
            }
        }
        self.headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
        }
        self.history_dir = Path("data/search_history")
        self.history_dir.mkdir(parents=True, exist_ok=True)
        self.engines_file = "data/search/engines.json"
        self._ensure_data()

    def _handle_specific_command(self, cmd: str, *args):
        """处理搜索相关的具体命令"""
        if cmd == "list":
            return self._list_engines()
        elif cmd == "add":
            return self._add_engine(args[0] if args else None)
        elif cmd == "remove":
            return self._remove_engine(args[0] if args else None)
        elif cmd == "search":
            return self._search(args[0] if args else None)
        else:
            self.console.print("[red]Unknown command[/red]")
            return False

    async def search(self, query: str, engine: str = "all", limit: int = 5):
        """Execute search query"""
        results = []
        engines_to_search = [engine] if engine != "all" else self.engines.keys()

        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                for eng in engines_to_search:
                    if eng not in self.engines:
                        console.print(f"[red]Unknown search engine: {eng}[/red]")
                        continue

                    engine_config = self.engines[eng]
                    url = engine_config["search_url"].format(quote_plus(query))
                    
                    # 使用特定引擎的headers（如果有）
                    headers = engine_config.get("headers", self.headers)
                    
                    console.print(f"[cyan]Searching {engine_config['name']}...[/cyan]")
                    response = await client.get(url, headers=headers)
                    
                    if response.status_code == 200:
                        soup = BeautifulSoup(response.text, 'html.parser')
                        items = soup.select(engine_config["result_selector"])[:limit]
                        
                        for item in items:
                            if eng == "github":
                                title_elem = item.select_one(engine_config["title_selector"])
                                desc_elem = item.select_one(engine_config["snippet_selector"])
                                extra_elem = item.select_one(engine_config["meta_selector"])
                                
                                if title_elem:
                                    repo_name = title_elem.get_text(strip=True)
                                    repo_url = f"https://github.com{title_elem.get('href', '')}"
                                    description = desc_elem.get_text(strip=True) if desc_elem else ""
                                    extra_info = extra_elem.get_text(strip=True) if extra_elem else ""
                                    
                                    results.append({
                                        "engine": engine_config["name"],
                                        "title": repo_name,
                                        "url": repo_url,
                                        "snippet": f"{description}\n{extra_info}" if description else extra_info
                                    })
                            else:
                                title_elem = item.select_one(engine_config["title_selector"])
                                snippet_elem = item.select_one(engine_config["snippet_selector"])
                                
                                if title_elem:
                                    title = title_elem.get_text(strip=True)
                                    url = title_elem.get('href', '')
                                    if not url.startswith('http'):
                                        if eng == "stackoverflow":
                                            url = f"https://stackoverflow.com{url}"
                                
                                    snippet = snippet_elem.get_text(strip=True) if snippet_elem else ""
                                    results.append({
                                        "engine": engine_config["name"],
                                        "title": title,
                                        "url": url,
                                        "snippet": snippet
                                    })

        except Exception as e:
            console.print(f"[red]Error during search: {str(e)}[/red]")

        # Save search results to history
        self.save_to_history(query, results)
        return results

    def display_results(self, results: list):
        """Display search results in a formatted table"""
        if not results:
            console.print("[yellow]No results found[/yellow]")
            return

        # Group results by search engine
        grouped_results = {}
        for result in results:
            engine = result["engine"]
            if engine not in grouped_results:
                grouped_results[engine] = []
            grouped_results[engine].append(result)

        # Display results for each engine
        for engine, engine_results in grouped_results.items():
            console.print(Panel(
                f"[bold cyan]{engine} Results[/bold cyan]",
                border_style="cyan"
            ))
            
            for i, result in enumerate(engine_results, 1):
                console.print(f"[bold cyan]{i}.[/bold cyan] {result['title']}")
                console.print(f"[blue]{result['url']}[/blue]")
                if result['snippet']:
                    console.print(f"{result['snippet']}\n")
                console.print("---")

    def save_to_history(self, query: str, results: list):
        """Save search results to history"""
        history_file = self.history_dir / f"search_history.json"
        
        # Load existing history
        if history_file.exists():
            with open(history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
        else:
            history = []

        # Add new search
        history.append({
            "timestamp": datetime.now().isoformat(),
            "query": query,
            "results": results
        })

        # Save updated history
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(history, f, indent=2, ensure_ascii=False)

    def show_history(self):
        """Show search history"""
        history_file = self.history_dir / f"search_history.json"
        
        if not history_file.exists():
            console.print("[yellow]No search history found[/yellow]")
            return

        with open(history_file, 'r', encoding='utf-8') as f:
            history = json.load(f)

        table = Table(title="Search History")
        table.add_column("Time", style="cyan")
        table.add_column("Query", style="green")
        table.add_column("Results", style="yellow")

        for entry in reversed(history):
            timestamp = datetime.fromisoformat(entry["timestamp"]).strftime("%Y-%m-%d %H:%M")
            result_count = sum(1 for r in entry["results"] if r["url"])
            table.add_row(timestamp, entry["query"], f"{result_count} results")

        console.print(table)

    def open_url(self, url: str):
        """Open URL in default browser"""
        try:
            webbrowser.open(url)
            console.print("[green]Opening URL in browser...[/green]")
        except Exception as e:
            console.print(f"[red]Error opening URL: {str(e)}[/red]")

    async def get_trending_repos(self, language: str = None, since: str = "daily"):
        """Get trending GitHub repositories
        
        Args:
            language: Programming language filter (optional)
            since: Time range (daily, weekly, monthly)
        """
        try:
            url = "https://github.com/trending"
            if language:
                url += f"/{language}"
            url += f"?since={since}"

            async with httpx.AsyncClient(follow_redirects=True) as client:
                response = await client.get(url, headers=self.headers)
                
                if response.status_code == 200:
                    soup = BeautifulSoup(response.text, 'html.parser')
                    repo_list = soup.select("article.Box-row")
                    
                    trending_repos = []
                    for repo in repo_list:
                        # Get repository name and link
                        name_elem = repo.select_one("h2.h3 a")
                        if name_elem:
                            repo_name = name_elem.get_text(strip=True).replace(" ", "")
                            repo_url = f"https://github.com{name_elem.get('href', '')}"
                            
                            # Get description
                            desc_elem = repo.select_one("p.col-9")
                            description = desc_elem.get_text(strip=True) if desc_elem else ""
                            
                            # Get language
                            lang_elem = repo.select_one("span[itemprop='programmingLanguage']")
                            language = lang_elem.get_text(strip=True) if lang_elem else "Unknown"
                            
                            # Get stars and forks
                            stats = repo.select("a.Link--muted")
                            stars = stats[0].get_text(strip=True) if len(stats) > 0 else "0"
                            forks = stats[1].get_text(strip=True) if len(stats) > 1 else "0"
                            
                            # Get today's stars
                            today_stars_elem = repo.select_one("span.d-inline-block.float-sm-right")
                            today_stars = today_stars_elem.get_text(strip=True) if today_stars_elem else "0"
                            
                            trending_repos.append({
                                "name": repo_name,
                                "url": repo_url,
                                "description": description,
                                "language": language,
                                "stars": stars,
                                "forks": forks,
                                "today_stars": today_stars
                            })
                    
                    return trending_repos
                else:
                    console.print(f"[red]Error fetching trending repositories: {response.status_code}[/red]")
                    return []
                    
        except Exception as e:
            console.print(f"[red]Error fetching trending repositories: {str(e)}[/red]")
            return []

    def display_trending(self, repos: list):
        """Display trending repositories in a formatted table"""
        if not repos:
            console.print("[yellow]No trending repositories found[/yellow]")
            return

        table = Table(title="GitHub Trending Repositories")
        table.add_column("Repository", style="cyan")
        table.add_column("Description", style="green")
        table.add_column("Language", style="yellow")
        table.add_column("Stars", style="magenta")
        table.add_column("Today", style="red")

        for repo in repos:
            table.add_row(
                repo["name"],
                repo["description"][:100] + "..." if len(repo["description"]) > 100 else repo["description"],
                repo["language"],
                repo["stars"],
                repo["today_stars"]
            )

        console.print(table)

    def handle_command(self, command: str, *args):
        """Handle search commands
        
        Args:
            command: The command to execute (all, ddg, so, github, trending, history)
            args: Additional arguments (query for search commands)
        """
        try:
            # 首先检查是否是shell命令
            if self.handle_shell_command(command):
                return
                
            if command == "trending":
                language = None
                since = "daily"
                
                if args:
                    language = args[0]
                if len(args) > 1:
                    since = args[1]
                    
                repos = asyncio.run(self.get_trending_repos(language, since))
                self.display_trending(repos)
                
                # Allow opening results
                while True:
                    choice = console.input("\n[cyan]Enter repository number to open in browser (or 'q' to quit):[/cyan] ").strip()
                    if choice.lower() == 'q':
                        break
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(repos):
                            self.open_url(repos[idx]["url"])
                        else:
                            console.print("[red]Invalid repository number[/red]")
                    except ValueError:
                        console.print("[red]Invalid input[/red]")
                    
            elif command in ["all", "ddg", "so", "github"]:
                if not args:
                    console.print("[red]Please provide a search query[/red]")
                    return
                
                query = args[0]
                engine_map = {
                    "all": "all",
                    "ddg": "duckduckgo",
                    "so": "stackoverflow",
                    "github": "github"
                }
                engine = engine_map[command]
                results = asyncio.run(self.search(query, engine))
                self.display_results(results)
                
                # Allow opening results
                while True:
                    choice = console.input("\n[cyan]Enter result number to open in browser (or 'q' to quit):[/cyan] ").strip()
                    if choice.lower() == 'q':
                        break
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(results):
                            self.open_url(results[idx]["url"])
                        else:
                            console.print("[red]Invalid result number[/red]")
                    except ValueError:
                        console.print("[red]Invalid input[/red]")
                
            elif command == "history":
                self.show_history()
            else:
                console.print("[red]Unknown command. Available commands: all, ddg, so, github, trending, history[/red]")
                
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

    def _ensure_data(self):
        """Ensure necessary data directories exist"""
        os.makedirs(self.engines_file, exist_ok=True)

    def _list_engines(self):
        """List available search engines"""
        console.print("[cyan]Available search engines:[/cyan]")
        for engine, config in self.engines.items():
            console.print(f"- {config['name']}")

    def _add_engine(self, config: dict):
        """Add a new search engine"""
        if not config or not config.get("name") or not config.get("search_url"):
            console.print("[red]Invalid engine configuration[/red]")
            return False

        self.engines[config['name'].lower()] = config
        self.save_engines()
        console.print("[green]Engine added successfully[/green]")
        return True

    def _remove_engine(self, name: str):
        """Remove a search engine"""
        if not name or name.lower() not in self.engines:
            console.print("[red]Unknown engine[/red]")
            return False

        del self.engines[name.lower()]
        self.save_engines()
        console.print("[green]Engine removed successfully[/green]")
        return True

    def _search(self, query: str):
        """Search for results using all available engines"""
        if not query:
            console.print("[red]Please provide a search query[/red]")
            return False

        results = []
        for engine, config in self.engines.items():
            console.print(f"[cyan]Searching {config['name']}...[/cyan]")
            results.extend(asyncio.run(self.search(query, engine)))

        self.display_results(results)
        return True

    def save_engines(self):
        """Save search engines to file"""
        with open(self.engines_file, 'w', encoding='utf-8') as f:
            json.dump(self.engines, f, indent=2, ensure_ascii=False)

    def display_engines(self):
        """Display available search engines"""
        self._list_engines()

    def handle_shell_command(self, command: str):
        """Handle shell commands"""
        if command == "search":
            return self._search(input("Enter search query: "))
        elif command == "list":
            self.display_engines()
            return True
        elif command == "add":
            return self._add_engine(json.loads(input("Enter engine configuration: ")))
        elif command == "remove":
            return self._remove_engine(input("Enter engine name: "))
        else:
            return False 