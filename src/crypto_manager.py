from rich.console import Console
from rich.table import Table
from rich.live import Live
import requests
import time
from datetime import datetime
import json
import os
from pathlib import Path
from prompt_toolkit import PromptSession
from prompt_toolkit.completion import WordCompleter
from base_manager import BaseManager
from rich import box

class CryptoManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.api_base = "https://api.coingecko.com/api/v3"
        self.watchlist = []
        self.watchlist_file = "data/crypto/watchlist.json"
        self.session = PromptSession()
        self._ensure_data_dir()
        self.coin_index_map = {}  # 用于存储币种序号映射
    
    def _ensure_data_dir(self):
        """确保数据目录存在，并预置主流加密货币"""
        os.makedirs(os.path.dirname(self.watchlist_file), exist_ok=True)
        if not os.path.exists(self.watchlist_file):
            # 预置主流加密货币
            default_coins = [
                "bitcoin",      # BTC
                "ethereum",     # ETH
                "tether",       # USDT
                "ripple",       # XRP
                "solana",       # SOL
                "pepe",         # PEPE
                "trump",        # TRUMP
                "dogecoin",     # DOGE
                "cardano",      # ADA
                "polkadot"      # DOT
            ]
            with open(self.watchlist_file, 'w') as f:
                json.dump(default_coins, f, indent=2)
    
    def _get_coin_completer(self):
        """获取币种补全器"""
        watchlist = self._get_watchlist()
        # 创建带序号的补全列表
        completion_list = []
        self.coin_index_map = {}
        
        for idx, coin in enumerate(watchlist, 1):
            self.coin_index_map[str(idx)] = coin
            completion_list.append(str(idx))
            completion_list.append(coin)
            
        return WordCompleter(completion_list, ignore_case=True)
    
    def _get_coin_input(self, prompt_text: str) -> str:
        """获取带补全功能的币种输入，支持序号或名称"""
        try:
            # 显示币种列表
            watchlist = self._get_watchlist()
            table = Table(title="Available Coins")
            table.add_column("ID", style="cyan")
            table.add_column("Coin", style="green")
            
            for idx, coin in enumerate(watchlist, 1):
                table.add_row(str(idx), coin)
            
            self.console.print(table)
            self.console.print("[cyan]Enter coin ID (number) or name:[/cyan]")
            
            input_value = self.session.prompt(
                f"{prompt_text} ",
                completer=self._get_coin_completer()
            ).strip()
            
            # 如果输入是序号，转换为币种ID
            if input_value in self.coin_index_map:
                return self.coin_index_map[input_value]
            return input_value
            
        except KeyboardInterrupt:
            return ""
        except EOFError:
            return ""
    
    def _get_coins_input(self, prompt_text: str) -> list:
        """获取带补全功能的多币种输入，支持序号或名称"""
        try:
            # 显示币种列表
            watchlist = self._get_watchlist()
            table = Table(title="Available Coins")
            table.add_column("ID", style="cyan")
            table.add_column("Coin", style="green")
            
            for idx, coin in enumerate(watchlist, 1):
                table.add_row(str(idx), coin)
            
            self.console.print(table)
            self.console.print("[cyan]Enter coin IDs (numbers) or names, separated by commas:[/cyan]")
            
            input_str = self.session.prompt(
                f"{prompt_text} ",
                completer=self._get_coin_completer()
            ).strip()
            
            if not input_str:
                return []
                
            # 处理输入，支持序号和名称的混合输入
            coins = []
            for item in input_str.split(","):
                item = item.strip()
                if item in self.coin_index_map:
                    coins.append(self.coin_index_map[item])
                else:
                    coins.append(item)
            return coins
            
        except KeyboardInterrupt:
            return []
        except EOFError:
            return []
    
    def _handle_specific_command(self, cmd: str, *args):
        """处理加密货币相关的具体命令"""
        if cmd == "price":
            return self._show_prices(args[0] if args else None)
        elif cmd == "markets":
            return self._show_markets()
        elif cmd == "watchlist":
            return self._show_watchlist()
        elif cmd == "add":
            return self._add_to_watchlist(args[0])
        elif cmd == "remove":
            return self._remove_from_watchlist(args[0])
        elif cmd == "monitor":
            return self._start_monitoring()
        elif cmd == "info":
            return self._show_coin_info(args[0])
        elif cmd.startswith("sh "):
            return self.execute_shell_command(cmd[3:].strip())
        else:
            self.console.print("[red]Unknown command[/red]")
            return False
    
    def _get_watchlist(self):
        """获取关注列表"""
        with open(self.watchlist_file, 'r') as f:
            return json.load(f)
    
    def _save_watchlist(self, watchlist):
        """保存关注列表"""
        with open(self.watchlist_file, 'w') as f:
            json.dump(watchlist, f, indent=2)
    
    def _show_prices(self, coins=None):
        """显示加密货币价格"""
        try:
            coins = coins or self.watchlist
            if not coins:
                self.console.print("[yellow]No coins specified and watchlist is empty[/yellow]")
                return False

            coin_ids = ','.join(coins) if isinstance(coins, list) else coins
            response = requests.get(f"{self.api_base}/simple/price", 
                                 params={"ids": coin_ids, "vs_currencies": "usd"})
            
            if response.status_code == 200:
                data = response.json()
                table = Table(title="Cryptocurrency Prices", box=box.DOUBLE)
                table.add_column("Coin", style="cyan")
                table.add_column("Price (USD)", style="green")
                
                for coin_id, price_data in data.items():
                    table.add_row(coin_id, f"${price_data['usd']:,.2f}")
                
                self.console.print(table)
                return True
            else:
                self.console.print(f"[red]Error: {response.status_code}[/red]")
                return False
                
        except Exception as e:
            self.console.print(f"[red]Error: {str(e)}[/red]")
            return False
    
    def _show_markets(self):
        """显示市场概况"""
        try:
            response = requests.get(
                f"{self.api_base}/global"
            )
            data = response.json()["data"]
            
            table = Table(title="Crypto Market Overview")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            metrics = [
                ("Active Cryptocurrencies", "active_cryptocurrencies"),
                ("Active Markets", "markets"),
                ("Total Market Cap (USD)", "total_market_cap.usd"),
                ("24h Volume (USD)", "total_volume.usd"),
                ("BTC Dominance", "market_cap_percentage.btc"),
                ("ETH Dominance", "market_cap_percentage.eth")
            ]
            
            for label, key in metrics:
                value = data
                for k in key.split('.'):
                    value = value[k]
                
                if "market_cap" in key or "volume" in key:
                    value = f"${value:,.0f}"
                elif "percentage" in key:
                    value = f"{value:.2f}%"
                
                table.add_row(label, str(value))
            
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error fetching market data: {str(e)}[/red]")
    
    def _show_watchlist(self):
        """显示关注列表"""
        watchlist = self._get_watchlist()
        if not watchlist:
            self.console.print("[yellow]Watchlist is empty.[/yellow]")
            return False
        
        table = Table(title="Watchlist")
        table.add_column("ID", style="cyan")
        table.add_column("Coin", style="green")
        
        for idx, coin in enumerate(watchlist, 1):
            table.add_row(str(idx), coin)
        
        self.console.print(table)
        return True
    
    def _add_to_watchlist(self, coin_id):
        """添加币种到关注列表"""
        watchlist = self._get_watchlist()
        if coin_id not in watchlist:
            # 验证币种是否存在
            try:
                response = requests.get(f"{self.api_base}/simple/price?ids={coin_id}&vs_currencies=usd")
                if response.json():
                    watchlist.append(coin_id)
                    self._save_watchlist(watchlist)
                    self.console.print(f"[green]Added {coin_id} to watchlist[/green]")
                else:
                    self.console.print(f"[red]Invalid coin ID: {coin_id}[/red]")
            except Exception as e:
                self.console.print(f"[red]Error validating coin: {str(e)}[/red]")
        else:
            self.console.print(f"[yellow]{coin_id} is already in watchlist[/yellow]")
        return True
    
    def _remove_from_watchlist(self, coin_id):
        """从关注列表移除币种"""
        watchlist = self._get_watchlist()
        if coin_id in watchlist:
            watchlist.remove(coin_id)
            self._save_watchlist(watchlist)
            self.console.print(f"[green]Removed {coin_id} from watchlist[/green]")
        else:
            self.console.print(f"[yellow]{coin_id} is not in watchlist[/yellow]")
        return True
    
    def _start_monitoring(self):
        """实时监控价格"""
        watchlist = self._get_watchlist()
        if not watchlist:
            self.console.print("[yellow]Watchlist is empty. Add coins first.[/yellow]")
            return False
        
        self.console.print("[cyan]Starting price monitor (press 'q' to quit)...[/cyan]")
        
        try:
            with Live(auto_refresh=False) as live:
                while True:
                    response = requests.get(
                        f"{self.api_base}/simple/price",
                        params={
                            "ids": ",".join(watchlist),
                            "vs_currencies": "usd",
                            "include_24hr_change": "true"
                        }
                    )
                    data = response.json()
                    
                    table = Table(title=f"Live Prices - {datetime.now().strftime('%H:%M:%S')}")
                    table.add_column("ID", style="cyan")
                    table.add_column("Coin", style="green")
                    table.add_column("Price (USD)", style="green")
                    table.add_column("24h Change", style="magenta")
                    
                    for idx, coin_id in enumerate(watchlist, 1):
                        if coin_id in data:
                            coin_data = data[coin_id]
                            change = coin_data.get("usd_24h_change", 0)
                            change_color = "green" if change >= 0 else "red"
                            table.add_row(
                                str(idx),
                                coin_id,
                                f"${coin_data['usd']:,.2f}",
                                f"[{change_color}]{change:+.2f}%[/{change_color}]"
                            )
                    
                    live.update(table)
                    live.refresh()
                    
                    time.sleep(10)  # 每10秒更新一次
                    
        except KeyboardInterrupt:
            self.console.print("\n[yellow]Monitoring stopped[/yellow]")
        return True
    
    def _show_coin_info(self, coin_id):
        """显示币种详细信息"""
        try:
            response = requests.get(f"{self.api_base}/coins/{coin_id}")
            data = response.json()
            
            # 获取当前币种在watchlist中的序号
            watchlist = self._get_watchlist()
            try:
                idx = watchlist.index(coin_id) + 1
                id_str = f"#{idx}"
            except ValueError:
                id_str = "N/A"
            
            table = Table(title=f"Coin Information - {data['name']} (ID: {id_str})")
            table.add_column("Metric", style="cyan")
            table.add_column("Value", style="green")
            
            metrics = [
                ("Symbol", data["symbol"].upper()),
                ("Current Price (USD)", f"${data['market_data']['current_price']['usd']:,.2f}"),
                ("Market Cap Rank", f"#{data['market_cap_rank']}"),
                ("Market Cap (USD)", f"${data['market_data']['market_cap']['usd']:,.0f}"),
                ("24h Volume", f"${data['market_data']['total_volume']['usd']:,.0f}"),
                ("24h High", f"${data['market_data']['high_24h']['usd']:,.2f}"),
                ("24h Low", f"${data['market_data']['low_24h']['usd']:,.2f}"),
                ("Price Change 24h", f"{data['market_data']['price_change_percentage_24h']:+.2f}%"),
                ("Price Change 7d", f"{data['market_data']['price_change_percentage_7d']:+.2f}%"),
                ("Price Change 30d", f"{data['market_data']['price_change_percentage_30d']:+.2f}%")
            ]
            
            for label, value in metrics:
                table.add_row(label, str(value))
            
            self.console.print(table)
            
        except Exception as e:
            self.console.print(f"[red]Error fetching coin info: {str(e)}[/red]") 