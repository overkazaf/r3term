from base_manager import BaseManager
from rich.console import Console
from rich.table import Table
import subprocess
import os
import tempfile
import signal
import json
import re
import geoip2.database
import plotext as plt
from pathlib import Path
import requests
import time
from bs4 import BeautifulSoup
import socket
from rich import print as rprint
from dotenv import load_dotenv
import scapy.all as scapy

console = Console()

class NetworkManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.console = Console()
        self.capture_process = None
        self.proxy_process = None
        self.capture_file = None
        self.location_cache = {}  # Cache for IP locations
        load_dotenv()
        self.ipinfo_token = os.getenv('IPINFO_TOKEN')
        self._ensure_geoip_db()
        self.captures_dir = Path("data/network_captures")
        self.captures_dir.mkdir(parents=True, exist_ok=True)
    
    def _ensure_geoip_db(self):
        """确保GeoIP数据库存在"""
        db_dir = Path("data/geoip")
        db_dir.mkdir(parents=True, exist_ok=True)
        db_path = db_dir / "GeoLite2-City.mmdb"
        
        if not db_path.exists():
            self.console.print("[yellow]GeoIP database not found. Downloading...[/yellow]")
            # 这里应该从MaxMind下载数据库，需要license key
            # 为了演示，我们可以提示用户手动下载
            self.console.print("[red]Please download GeoLite2-City.mmdb from MaxMind and place it in data/geoip/[/red]")
    
    def handle_command(self, command: str, *args):
        """Handle network analysis commands"""
        try:
            # 首先检查是否是shell命令
            if self.handle_shell_command(command):
                return
                
            if command == "scan":
                if len(args) > 0:
                    self._nmap_scan(args[0])
                else:
                    console.print("[red]Please provide a target[/red]")
            elif command == "capture":
                self._start_capture(*args)
            elif command == "stop":
                self._stop_capture()
            elif command == "analyze":
                if len(args) > 0:
                    self._analyze_capture(args[0])
                else:
                    console.print("[red]Please provide a capture file[/red]")
            elif command == "proxy":
                self._start_proxy(*args)
            elif command == "proxy_stop":
                self._stop_proxy()
            elif command == "convert":
                self._convert_capture(*args)
            elif command == "filter":
                self._filter_capture(*args)
            elif command == "trace":
                self._trace_route(*args)
            else:
                console.print("[red]Unknown command[/red]")
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")
    
    def _get_ip_location(self, ip: str):
        """获取IP地址的地理位置信息，使用多个数据源"""
        if ip in self.location_cache:
            return self.location_cache[ip]
            
        if self._is_private_ip(ip):
            location = {"city": "Private Network", "country": "Local"}
            self.location_cache[ip] = location
            return location

        # Try multiple sources for location data
        location = None
        
        # Try GeoIP first
        location = self._get_location_from_geoip(ip)
        
        # If no result or unknown city, try IPInfo
        if not location or location.get("city") == "Unknown City":
            location = self._get_location_from_ipinfo(ip)
            
        # If still no result, try IP138
        if not location or location.get("city") == "Unknown City":
            location = self._get_location_from_ip138(ip)
            
        # If all sources failed, return unknown
        if not location:
            location = {"city": "Unknown City", "country": "Unknown"}
            
        self.location_cache[ip] = location
        return location
    
    def _is_private_ip(self, ip: str) -> bool:
        """检查是否是内网IP"""
        try:
            ip_parts = [int(part) for part in ip.split('.')]
            return (
                ip_parts[0] == 10 or
                (ip_parts[0] == 172 and 16 <= ip_parts[1] <= 31) or
                (ip_parts[0] == 192 and ip_parts[1] == 168) or
                ip_parts[0] == 127
            )
        except:
            return False
    
    def _get_location_from_geoip(self, ip: str):
        """从GeoIP数据库获取位置信息"""
        try:
            with geoip2.database.Reader('data/geoip/GeoLite2-City.mmdb') as reader:
                response = reader.city(ip)
                return {
                    "city": response.city.name or "Unknown City",
                    "country": response.country.name or "Unknown"
                }
        except:
            return None
    
    def _get_location_from_ipinfo(self, ip: str):
        """从IPInfo获取位置信息"""
        if not self.ipinfo_token:
            return None
            
        try:
            response = requests.get(
                f'https://ipinfo.io/{ip}?token={self.ipinfo_token}',
                timeout=5
            ).json()
            
            return {
                "city": response.get('city', 'Unknown City'),
                "country": response.get('country', 'Unknown')
            }
        except:
            return None
    
    def _get_location_from_ip138(self, ip: str):
        """从IP138获取位置信息（作为备选）"""
        try:
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            response = requests.get(f'https://www.ip138.com/iplookup.asp?ip={ip}', headers=headers, timeout=5)
            response.encoding = 'gb2312'
            
            soup = BeautifulSoup(response.text, 'html.parser')
            location_text = soup.find('ul', class_='ul1').get_text()
            
            # Extract city and country from the response
            # This is a simplified version - you might need to adjust the parsing logic
            location_parts = location_text.split('：')[1].split()
            if len(location_parts) >= 2:
                return {
                    "city": location_parts[0],
                    "country": "China" if "中国" in location_text else location_parts[-1]
                }
        except:
            return None
    
    def _parse_traceroute(self, output: str):
        """解析traceroute输出"""
        hops = []
        for line in output.splitlines():
            if not line.strip():
                continue
                
            match = re.search(r'(\d+)\s+(?:\*\s+)*(?:(\d+\.\d+\.\d+\.\d+)\s+(\d+\.\d+)\s*ms)?', line)
            if match:
                hop_num = int(match.group(1))
                ip = match.group(2)
                response_time = float(match.group(3)) if match.group(3) else None
                
                if ip:
                    location = self._get_ip_location(ip)
                    if location and location["city"] != "Unknown City":
                        hops.append({
                            'hop': hop_num,
                            'ip': ip,
                            'location': location,
                            'response_time': response_time
                        })
        return hops
    
    def _visualize_trace(self, hops: list):
        """可视化追踪结果"""
        # 创建路由跳转表格
        table = Table(title="Route Trace")
        table.add_column("Hop", style="cyan")
        table.add_column("IP", style="green")
        table.add_column("Location", style="yellow")
        table.add_column("Response Time", style="magenta")
        
        for hop in hops:
            location = hop['location']
            location_str = f"{location['city']}, {location['country']}"
            if location['city'] == 'Private Network':
                location_str = "Local Network"
            
            table.add_row(
                str(hop['hop']),
                hop['ip'],
                location_str,
                f"{hop['response_time']:.2f} ms" if hop['response_time'] else "N/A"
            )
        
        # 显示表格
        self.console.print(table)
    
    def _trace_route(self, target: str, max_hops: str = "16"):
        """追踪路由并可视化"""
        self.console.print(f"[cyan]Tracing route to {target}...[/cyan]")
        
        try:
            # 使用traceroute命令
            cmd = f"traceroute -n -m {max_hops} {target}"
            result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
            
            if result.returncode == 0:
                # 解析输出
                hops = self._parse_traceroute(result.stdout)
                
                if hops:
                    self.console.print("[green]Trace complete. Visualizing results...[/green]")
                    self._visualize_trace(hops)
                else:
                    self.console.print("[red]No valid hops found in the trace[/red]")
            else:
                self.console.print(f"[red]Error running traceroute: {result.stderr}[/red]")
                
        except Exception as e:
            self.console.print(f"[red]Error during trace: {str(e)}[/red]")
    
    def _nmap_scan(self, target: str, options: str = "-sV -sC"):
        """执行nmap扫描"""
        self.console.print(f"[cyan]Starting Nmap scan of {target}...[/cyan]")
        cmd = f"nmap {options} {target}"
        self._run_command(cmd)
    
    def _start_capture(self, interface: str, filter_str: str = None):
        """开始抓包"""
        if self.capture_process:
            self.console.print("[yellow]Capture already running. Stop it first.[/yellow]")
            return
        
        self.capture_file = os.path.join(
            "data/captures",
            f"capture_{int(time.time())}.pcap"
        )
        os.makedirs("data/captures", exist_ok=True)
        
        cmd = f"tcpdump -i {interface} -w {self.capture_file}"
        if filter_str:
            cmd += f" {filter_str}"
        
        try:
            self.capture_process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.console.print(f"[green]Started capture on {interface}, saving to {self.capture_file}[/green]")
        except Exception as e:
            self.console.print(f"[red]Error starting capture: {str(e)}[/red]")
    
    def _stop_capture(self):
        """停止抓包"""
        if not self.capture_process:
            self.console.print("[yellow]No capture running[/yellow]")
            return
        
        try:
            self.capture_process.send_signal(signal.SIGTERM)
            self.capture_process.wait()
            self.console.print(f"[green]Capture stopped and saved to {self.capture_file}[/green]")
            self.capture_process = None
        except Exception as e:
            self.console.print(f"[red]Error stopping capture: {str(e)}[/red]")
    
    def _analyze_capture(self, file_path: str, display_filter: str = None):
        """使用tshark分析抓包文件"""
        if not os.path.exists(file_path):
            self.console.print(f"[red]File {file_path} not found[/red]")
            return
        
        cmd = f"tshark -r {file_path}"
        if display_filter:
            cmd += f" -Y '{display_filter}'"
        
        self._run_command(cmd)
    
    def _start_proxy(self, port: str = "8080", options: str = ""):
        """启动mitmproxy"""
        if self.proxy_process:
            self.console.print("[yellow]Proxy already running. Stop it first.[/yellow]")
            return
        
        cmd = f"mitmweb -p {port} {options}"
        try:
            self.proxy_process = subprocess.Popen(
                cmd.split(),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            self.console.print(f"[green]Started mitmweb on port {port}[/green]")
            self.console.print(f"[green]You can open the proxy in browser by visiting http://localhost:8081[/green]")
        except Exception as e:
            self.console.print(f"[red]Error starting proxy: {str(e)}[/red]")
    
    def _stop_proxy(self):
        """停止mitmproxy"""
        if not self.proxy_process:
            self.console.print("[yellow]No proxy running[/yellow]")
            return
        
        try:
            self.proxy_process.send_signal(signal.SIGTERM)
            self.proxy_process.wait()
            self.console.print("[green]Proxy stopped[/green]")
            self.proxy_process = None
        except Exception as e:
            self.console.print(f"[red]Error stopping proxy: {str(e)}[/red]")
    
    def _convert_capture(self, input_file: str, output_file: str, format: str = "json"):
        """转换抓包文件格式"""
        if not os.path.exists(input_file):
            self.console.print(f"[red]Input file {input_file} not found[/red]")
            return
        
        cmd = f"tshark -r {input_file} -T {format} -w {output_file}"
        self._run_command(cmd)
        self.console.print(f"[green]Converted {input_file} to {output_file}[/green]")
    
    def _filter_capture(self, input_file: str, filter_str: str, output_file: str):
        """过滤抓包文件"""
        if not os.path.exists(input_file):
            self.console.print(f"[red]Input file {input_file} not found[/red]")
            return
        
        cmd = f"tshark -r {input_file} -Y '{filter_str}' -w {output_file}"
        self._run_command(cmd)
        self.console.print(f"[green]Filtered {input_file} to {output_file}[/green]")
    
    def _run_command(self, cmd: str):
        """执行命令并显示输出"""
        try:
            result = subprocess.run(cmd, shell=True, text=True, capture_output=True)
            if result.stdout:
                self.console.print(result.stdout)
            if result.stderr:
                self.console.print(f"[red]{result.stderr}[/red]")
        except Exception as e:
            self.console.print(f"[red]Error executing command: {str(e)}[/red]") 