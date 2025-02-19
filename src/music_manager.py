import os
import sqlite3
import sys
import json
import tty
import select
import termios
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, List, Tuple, Dict
import re
import threading
import time
import asyncio
import httpx
from base_manager import BaseManager

import vlc
from mutagen.mp3 import MP3
from mutagen.id3 import ID3
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.text import Text
from rich.console import Console
from rich.layout import Layout

console = Console()

class LyricParser:
    def __init__(self):
        self.lyrics: Dict[float, str] = {}  # 时间戳: 歌词内容
        self.times: List[float] = []        # 排序后的时间戳列表
        
    def parse_lrc(self, lrc_content: str) -> bool:
        """解析LRC格式歌词"""
        try:
            # 清空现有数据
            self.lyrics.clear()
            self.times.clear()
            
            # LRC时间标签正则表达式
            time_pattern = re.compile(r'\[(\d{2}):(\d{2})\.(\d{2,3})\]')
            
            for line in lrc_content.split('\n'):
                # 跳过空行
                if not line.strip():
                    continue
                    
                # 查找所有时间标签
                matches = time_pattern.findall(line)
                if not matches:
                    continue
                    
                # 提取歌词内容
                lyric = time_pattern.sub('', line).strip()
                if not lyric:
                    continue
                    
                # 转换时间标签为秒数
                for match in matches:
                    minutes = int(match[0])
                    seconds = int(match[1])
                    milliseconds = int(match[2].ljust(3, '0'))
                    timestamp = minutes * 60 + seconds + milliseconds / 1000
                    self.lyrics[timestamp] = lyric
            
            # 对时间戳排序
            self.times = sorted(self.lyrics.keys())
            return bool(self.lyrics)
            
        except Exception as e:
            console.print(f"[red]Error parsing lyrics: {str(e)}[/red]")
            return False
    
    def get_current_lyric(self, current_time: float) -> Tuple[str, str, str]:
        """获取当前时间的歌词及前后歌词"""
        if not self.times:
            return "", "", ""
            
        # 找到当前时间对应的歌词
        current_index = -1
        for i, timestamp in enumerate(self.times):
            if timestamp > current_time:
                current_index = i - 1
                break
        
        if current_index == -1:
            current_index = 0
            
        # 获取前一句、当前句和下一句歌词
        prev_lyric = self.lyrics.get(self.times[current_index - 1], "") if current_index > 0 else ""
        current_lyric = self.lyrics.get(self.times[current_index], "")
        next_lyric = self.lyrics.get(self.times[current_index + 1], "") if current_index < len(self.times) - 1 else ""
        
        return prev_lyric, current_lyric, next_lyric

class KeyPoller:
    def __enter__(self):
        # 保存终端设置
        self.fd = sys.stdin.fileno()
        self.old_settings = termios.tcgetattr(self.fd)
        tty.setraw(sys.stdin.fileno())
        return self

    def __exit__(self, type, value, traceback):
        # 恢复终端设置
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old_settings)

    def poll(self, timeout=0.1):
        # 检查是否有按键输入
        dr, dw, de = select.select([sys.stdin], [], [], timeout)
        if not dr:
            return None
        return sys.stdin.read(1)

class MusicManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.console = Console()
        self.music_dir = Path("data/music")
        self.music_dir.mkdir(parents=True, exist_ok=True)
        self.current_player = None
        self.is_playing = False
        self.current_song = None
        self.playlist = []
        self.playlist_index = 0
        self.playlist_mode = False
        self.play_mode = "order"  # 播放模式：order(顺序播放), shuffle(随机播放)
        
        # Initialize database
        self.db_path = Path("data/music.db")
        self.init_database()
        
        # Load last playlist and settings
        self.load_settings()
        
        # Initialize VLC instance
        self.vlc_instance = vlc.Instance()
        self.player = self.vlc_instance.media_player_new()
        
        # API endpoints (using NetEase Music API as example)
        self.api_base = "http://67.219.99.40"  # NetEase Cloud Music API
        
        self._start_playlist_monitor()  # Start playlist monitor thread
        
        self.lyric_parser = LyricParser()
        self.lyric_update_thread = None
        self.stop_lyric_update = threading.Event()
        
    def init_database(self):
        """Initialize database tables"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create playlists table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS playlists (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create playlist_songs table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS playlist_songs (
                    playlist_id INTEGER,
                    song_path TEXT,
                    position INTEGER,
                    FOREIGN KEY (playlist_id) REFERENCES playlists(id)
                )
            """)
            
            # Create settings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)
            
            conn.commit()

    def save_settings(self):
        """Save current settings to database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT OR REPLACE INTO settings (key, value) VALUES (?, ?)",
                         ("play_mode", self.play_mode))
            
            # Save current playlist
            cursor.execute("DELETE FROM playlists WHERE name = 'default'")
            cursor.execute("INSERT INTO playlists (name) VALUES ('default')")
            playlist_id = cursor.lastrowid
            
            # Save playlist songs
            cursor.execute("DELETE FROM playlist_songs WHERE playlist_id = ?", (playlist_id,))
            for i, song in enumerate(self.playlist):
                cursor.execute(
                    "INSERT INTO playlist_songs (playlist_id, song_path, position) VALUES (?, ?, ?)",
                    (playlist_id, str(song), i)
                )
            
            conn.commit()

    def load_settings(self):
        """Load settings from database"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Load play mode
            cursor.execute("SELECT value FROM settings WHERE key = 'play_mode'")
            result = cursor.fetchone()
            if result:
                self.play_mode = result[0]
            
            # Load last playlist
            cursor.execute("""
                SELECT ps.song_path 
                FROM playlists p 
                JOIN playlist_songs ps ON p.id = ps.playlist_id 
                WHERE p.name = 'default' 
                ORDER BY ps.position
            """)
            
            songs = cursor.fetchall()
            self.playlist = [Path(song[0]) for song in songs if Path(song[0]).exists()]

    def handle_command(self, command: str, *args):
        """Handle music commands"""
        try:
            # 首先检查是否是shell命令
            if self.handle_shell_command(command):
                return
                
            if command == "search":
                if not args:
                    console.print("[red]Please provide a search query[/red]")
                    return
                self.search_music(args[0])
            elif command == "download":
                if not args:
                    console.print("[red]Please provide a song ID[/red]")
                    return
                self.download_music(args[0])
            elif command == "play":
                if not args:
                    console.print("[red]Please provide a song name or number[/red]")
                    return
                self.play_music(args[0])
            elif command == "pause":
                self.pause_music()
            elif command == "resume":
                self.resume_music()
            elif command == "stop":
                self.stop_music()
            elif command == "list":
                self.list_local_music()
            elif command == "current":
                self.show_current_song_info()
            elif command == "playlist":
                if not args:
                    # 如果没有子命令，显示交互式菜单
                    console.print("\n[cyan]Enter playlist command (show/add/remove/clear/play/mode):[/cyan]")
                    subcommand = console.input("playlist# ").strip().lower()
                    
                    if subcommand == "show":
                        self.show_playlist()
                    elif subcommand == "add":
                        # 显示可用的歌曲列表
                        self.list_local_music()
                        song_name = console.input("\n[cyan]Enter song name or number: [/cyan]").strip()
                        if song_name:
                            self.add_to_playlist(song_name)
                    elif subcommand == "remove":
                        self.show_playlist()
                        song_num = console.input("\n[cyan]Enter song number to remove: [/cyan]").strip()
                        if song_num.isdigit():
                            self.remove_from_playlist(song_num)
                    elif subcommand == "clear":
                        confirm = console.input("[yellow]Are you sure you want to clear the playlist? (y/N): [/yellow]").strip().lower()
                        if confirm == 'y':
                            self.clear_playlist()
                    elif subcommand == "play":
                        self.play_playlist()
                    elif subcommand == "mode":
                        mode = console.input("[cyan]Enter play mode (order/shuffle): [/cyan]").strip().lower()
                        if mode in ["order", "shuffle"]:
                            self.set_play_mode(mode)
                        else:
                            console.print("[red]Invalid play mode. Use 'order' or 'shuffle'[/red]")
                    else:
                        console.print("[red]Invalid playlist command. Available commands: show, add, remove, clear, play, mode[/red]")
                    return
                
                # 处理带参数的命令
                subcommand = args[0].lower()
                if subcommand == "show":
                    self.show_playlist()
                elif subcommand == "add" and len(args) > 1:
                    self.add_to_playlist(args[1])
                elif subcommand == "remove" and len(args) > 1:
                    self.remove_from_playlist(args[1])
                elif subcommand == "clear":
                    self.clear_playlist()
                elif subcommand == "play":
                    self.play_playlist()
                elif subcommand == "mode" and len(args) > 1:
                    mode = args[1].lower()
                    if mode in ["order", "shuffle"]:
                        self.set_play_mode(mode)
                    else:
                        console.print("[red]Invalid play mode. Use 'order' or 'shuffle'[/red]")
                else:
                    console.print("[red]Invalid playlist command. Available commands: show, add, remove, clear, play, mode[/red]")
                
            elif command == "next":
                self.play_next()
            elif command == "prev":
                self.play_previous()
            else:
                self.show_help()
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

    async def search_music_async(self, query: str):
        """Search music using API"""
        try:
            async with httpx.AsyncClient() as client:
                # Search endpoint
                response = await client.get(f"{self.api_base}/song/search?kw={query}")
                data = response.json()
                
                if 'data' in data:
                    songs = data['data']
                    
                    table = Table(title=f"Search Results for '{query}'")
                    table.add_column("No.", style="cyan")
                    table.add_column("ID", style="green")
                    table.add_column("Title", style="yellow")
                    table.add_column("Artist", style="magenta")
                    table.add_column("Album", style="blue")
                    table.add_column("Duration", style="red")
                    
                    for i, song in enumerate(songs[:25], 1):
                        attr = song['attributes']
                        duration = time.strftime('%M:%S', time.gmtime(attr['durationInMillis'] / 1000))
                        artists = attr['artistName']
                        
                        table.add_row(
                            str(i),
                            song['id'],
                            attr['name'],
                            artists,
                            attr['albumName'],
                            duration
                        )
                    
                    console.print(table)
                    return songs[:10]
                else:
                    console.print("[yellow]No results found[/yellow]")
                    return []
                    
        except Exception as e:
            console.print(f"[red]Error searching music: {str(e)}[/red]")
            return []

    def search_music(self, query: str):
        """Search music and handle user interaction"""
        songs = asyncio.run(self.search_music_async(query))
        
        if songs:
            while True:
                console.print("\n[cyan]Enter options:[/cyan]")
                console.print("- Single number (e.g., '3') to download one song")
                console.print("- Range (e.g., '1,5' or '1-5') to download multiple songs")
                console.print("- 'q' to quit")
                choice = console.input("\nYour choice: ").strip()
                
                if choice.lower() == 'q':
                    break
                    
                try:
                    # Handle range download
                    if ',' in choice or '-' in choice:
                        # Support both comma and hyphen as separators
                        separator = ',' if ',' in choice else '-'
                        start, end = map(int, choice.split(separator))
                        if 1 <= start <= end <= len(songs):
                            console.print(f"[yellow]Downloading songs {start} to {end}...[/yellow]")
                            # Create and start download threads
                            threads = []
                            for idx in range(start-1, end):
                                thread = threading.Thread(
                                    target=self.download_music,
                                    args=(songs[idx]['id'],),
                                    name=f"Download-{idx+1}"
                                )
                                threads.append(thread)
                                thread.start()
                            
                            # Wait for all downloads to complete
                            for thread in threads:
                                thread.join()
                            
                            console.print("[green]All downloads completed![/green]")
                        else:
                            console.print("[red]Invalid range. Please check your numbers.[/red]")
                    else:
                        # Handle single song download
                        idx = int(choice) - 1
                        if 0 <= idx < len(songs):
                            self.download_music(songs[idx]['id'])
                        else:
                            console.print("[red]Invalid number[/red]")
                except ValueError:
                    console.print("[red]Invalid input. Please enter a number, range, or 'q'[/red]")

    async def download_music_async(self, song_id: str):
        """Download music using API"""
        try:
            async with httpx.AsyncClient() as client:
                # Get song details first
                response = await client.get(f"{self.api_base}/song/info?id={song_id}", timeout=15)
                details = response.json()
                
                if 'data' in details and details:
                    song = details['data']
                    filename = f"{song['name']} - {song['artistName']}.mp3"
                    filename = "".join(c for c in filename if c.isalnum() or c in (' ', '-', '.'))
                    
                    # Download AAC stream with loading animation
                    with console.status(f"[yellow]Downloading: {filename}...[/yellow]", spinner="dots"):
                        response = await client.get(f"{self.api_base}/song/id/sudo?id={song_id}")
                        if response.status_code == 200:
                            filepath = self.music_dir / filename
                            with open(filepath, 'wb') as f:
                                f.write(response.content)
                            console.print(f"[green]Downloaded: {filename}[/green]")
                            return True
                
                console.print("[red]Failed to download song[/red]")
                return False
                
        except Exception as e:
            console.print(f"[red]Error downloading music: {str(e)}[/red]")
            return False

    def download_music(self, song_id: str):
        """Download music and handle user interaction with retries"""
        max_retries = 3
        for attempt in range(max_retries):
            try:
                if asyncio.run(self.download_music_async(song_id)):
                    return
                console.print(f"[yellow]Download attempt {attempt + 1} failed, retrying...[/yellow]")
            except Exception as e:
                if attempt < max_retries - 1:
                    console.print(f"[yellow]Error on attempt {attempt + 1}: {str(e)}. Retrying...[/yellow]")
                else:
                    console.print(f"[red]Failed to download after {max_retries} attempts. Error: {str(e)}[/red]")

    def play_music(self, song_name: str):
        """Play a music file"""
        try:
            # 处理输入的歌曲名
            if song_name.isdigit():
                # 如果输入的是数字，从列表中获取对应的歌曲
                songs = list(self.music_dir.glob("*.mp3"))
                idx = int(song_name) - 1
                if 0 <= idx < len(songs):
                    song_path = songs[idx]
                else:
                    console.print("[red]Invalid song number[/red]")
                    return
            else:
                # 如果输入的是歌曲名，构造完整路径
                song_path = self.music_dir / song_name
                if not song_path.suffix:
                    song_path = song_path.with_suffix('.mp3')
            
            # 检查文件是否存在
            if not song_path.exists():
                console.print(f"[red]Song not found: {song_path.name}[/red]")
                return
            
            # 停止当前播放
            if self.player:
                self.player.stop()
            
            # 创建新的媒体播放器
            media = self.vlc_instance.media_new(str(song_path))
            self.player = self.vlc_instance.media_player_new()
            self.player.set_media(media)
            
            # 开始播放
            self.player.play()
            self.is_playing = True
            self.current_song = song_path  # 保存完整的Path对象
            
            console.print(f"[green]Now playing: {song_path.stem}[/green]")
            
        except Exception as e:
            console.print(f"[red]Error playing music: {str(e)}[/red]")

    def pause_music(self):
        """Pause current playback"""
        if self.is_playing:
            self.player.pause()
            self.is_playing = False
            console.print("[yellow]Music paused[/yellow]")
        else:
            console.print("[yellow]No music is playing[/yellow]")

    def resume_music(self):
        """Resume paused playback"""
        if not self.is_playing and self.current_song:
            self.player.play()
            self.is_playing = True
            console.print("[green]Music resumed[/green]")
        else:
            console.print("[yellow]No paused music to resume[/yellow]")

    def stop_music(self):
        """Stop current playback"""
        self.player.stop()
        self.is_playing = False
        self.current_song = None
        console.print("[yellow]Music stopped[/yellow]")

    def list_local_music(self):
        """List all downloaded music"""
        music_files = list(self.music_dir.glob("*.mp3"))
        
        if not music_files:
            console.print("[yellow]No music files found[/yellow]")
            return
            
        table = Table(title="Local Music Library")
        table.add_column("No.", style="cyan")
        table.add_column("Title", style="green")
        
        for i, file in enumerate(music_files, 1):
            table.add_row(str(i), file.stem)
            
        console.print(table)

    def show_current_song_info(self):
        """Show detailed information about the currently playing song"""
        if not self.current_song or not self.player:
            console.print("[yellow]No song is currently playing[/yellow]")
            return

        try:
            # 使用 ffprobe 获取媒体信息和时长
            cmd = [
                'ffprobe',
                '-v', 'quiet',
                '-print_format', 'json',
                '-show_format',
                '-show_streams',
                str(self.current_song)
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True)
            media_info = {}
            total_duration = 0
            
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if 'format' in data:
                    if 'duration' in data['format']:
                        total_duration = int(float(data['format']['duration']) * 1000)  # 转换为毫秒
                    if 'tags' in data['format']:
                        media_info = data['format']['tags']
            
            # 创建信息表格
            info_table = Table(box=box.ROUNDED, show_header=False)
            info_table.add_column("Property", style="cyan", width=15)
            info_table.add_column("Value", style="yellow", width=65)
            
            # 添加基本信息
            info_table.add_row("Title", self.current_song.stem)
            info_table.add_row("Status", "[green]▶ Playing[/green]" if self.is_playing else "[yellow]❚❚ Paused[/yellow]")
            
            # 获取当前播放时间
            current_time = self.player.get_time()
            if current_time < 0:
                current_time = 0
            
            # 格式化时间
            current_min = int(current_time / 1000 / 60)
            current_sec = int((current_time / 1000) % 60)
            total_min = int(total_duration / 1000 / 60)
            total_sec = int((total_duration / 1000) % 60)
            
            time_str = f"{current_min:02d}:{current_sec:02d} / {total_min:02d}:{total_sec:02d}"
            info_table.add_row("Time", time_str)
            
            # 计算并显示进度条
            progress = current_time / total_duration if total_duration > 0 else 0
            bar_width = 50
            filled = int(progress * bar_width)
            progress_bar = "[magenta]" + "━" * filled + "⬤" + "─" * (bar_width - filled) + "[/magenta]"
            info_table.add_row("Progress", progress_bar)
            
            # 添加音量信息
            info_table.add_row("Volume", f"{self.player.audio_get_volume()}%")
            
            # 添加媒体标签信息
            tag_mapping = {
                'artist': 'Artist',
                'album': 'Album',
                'genre': 'Genre',
                'date': 'Year',
                'composer': 'Composer',
                'lyricist': 'Lyricist',
                'copyright': 'Copyright',
                'publisher': 'Label',
                'isrc': 'ISRC'
            }
            
            for tag, display in tag_mapping.items():
                if tag.lower() in {k.lower() for k in media_info.keys()}:
                    key = next(k for k in media_info.keys() if k.lower() == tag.lower())
                    info_table.add_row(display, media_info[key])
            
            # 添加控制提示
            info_table.add_row("")
            info_table.add_row("Controls", "[dim]Space: Play/Pause  ←/→: Volume  q: Back[/dim]")
            
            # 创建面板
            panel = Panel(
                info_table,
                title="[bold magenta]Current Song Information[/bold magenta]",
                border_style="cyan"
            )
            
            # 显示面板
            console.clear()
            console.print(panel)
            
            # 设置定时更新
            last_update = time.time()
            
            try:
                old_settings = termios.tcgetattr(sys.stdin.fileno())
                tty.setraw(sys.stdin.fileno())
                
                while True:
                    # 每秒更新一次显示
                    current_time = time.time()
                    if current_time - last_update >= 0.5:
                        self.update_display()
                        last_update = current_time
                    
                    # 检查按键输入
                    if sys.stdin in select.select([sys.stdin], [], [], 0.1)[0]:
                        char = sys.stdin.read(1)
                        if char == 'q':  # 退出
                            break
                        elif char == ' ':  # 播放/暂停
                            self.is_playing = not self.is_playing
                            if self.is_playing:
                                self.player.play()
                            else:
                                self.player.pause()
                            self.update_display()
                        elif char == '\x1b':  # 方向键
                            next1, next2 = sys.stdin.read(2)
                            if next1 == '[':
                                if next2 == 'D':  # 左方向键
                                    current_volume = self.player.audio_get_volume()
                                    new_volume = max(current_volume - 5, 0)
                                    self.player.audio_set_volume(new_volume)
                                    self.update_display()
                                elif next2 == 'C':  # 右方向键
                                    current_volume = self.player.audio_get_volume()
                                    new_volume = min(current_volume + 5, 100)
                                    self.player.audio_set_volume(new_volume)
                                    self.update_display()
                
            except Exception as e:
                console.print(f"[red]Error: {str(e)}[/red]")
            finally:
                termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
                console.clear()
            
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]")

    def update_display(self):
        """Update the display with current playback information"""
        if not self.current_song or not self.player:
            return
        
        # 创建信息表格
        info_table = Table(box=box.ROUNDED, show_header=False)
        info_table.add_column("Property", style="cyan", width=15)
        info_table.add_column("Value", style="yellow", width=65)
        
        # 添加基本信息
        info_table.add_row("Title", self.current_song.stem)
        info_table.add_row("Status", "[green]▶ Playing[/green]" if self.is_playing else "[yellow]❚❚ Paused[/yellow]")
        
        # 获取当前播放时间和总时长
        current_time = self.player.get_time()
        total_duration = self.player.get_length()
        
        if current_time < 0:
            current_time = 0
        
        # 格式化时间
        current_min = int(current_time / 1000 / 60)
        current_sec = int((current_time / 1000) % 60)
        total_min = int(total_duration / 1000 / 60)
        total_sec = int((total_duration / 1000) % 60)
        
        time_str = f"{current_min:02d}:{current_sec:02d} / {total_min:02d}:{total_sec:02d}"
        info_table.add_row("Time", time_str)
        
        # 计算并显示进度条
        progress = current_time / total_duration if total_duration > 0 else 0
        bar_width = 50
        filled = int(progress * bar_width)
        progress_bar = "[magenta]" + "━" * filled + "⬤" + "─" * (bar_width - filled) + "[/magenta]"
        info_table.add_row("Progress", progress_bar)
        
        # 添加音量信息
        info_table.add_row("Volume", f"{self.player.audio_get_volume()}%")
        
        # 获取媒体信息
        cmd = [
            'ffprobe',
            '-v', 'quiet',
            '-print_format', 'json',
            '-show_format',
            '-show_streams',
            str(self.current_song)
        ]
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            if result.returncode == 0:
                data = json.loads(result.stdout)
                if 'format' in data and 'tags' in data['format']:
                    media_info = data['format']['tags']
                    
                    # 添加媒体标签信息
                    tag_mapping = {
                        'artist': 'Artist',
                        'album': 'Album',
                        'genre': 'Genre',
                        'date': 'Year',
                        'composer': 'Composer',
                        'lyricist': 'Lyricist',
                        'copyright': 'Copyright',
                        'publisher': 'Label',
                        'isrc': 'ISRC'
                    }
                    
                    for tag, display in tag_mapping.items():
                        if tag.lower() in {k.lower() for k in media_info.keys()}:
                            key = next(k for k in media_info.keys() if k.lower() == tag.lower())
                            info_table.add_row(display, media_info[key])
        except Exception as e:
            pass  # 忽略媒体信息获取错误
        
        # 添加控制提示
        info_table.add_row("")
        info_table.add_row("Controls", "[dim]Space: Play/Pause  ←/→: Volume  q: Back[/dim]")
        
        # 创建面板
        panel = Panel(
            info_table,
            title="[bold magenta]Current Song Information[/bold magenta]",
            border_style="cyan"
        )
        
        # 显示面板
        console.clear()
        console.print(panel)

    def show_playlist(self):
        """Display current playlist"""
        if not self.playlist:
            console.print("[yellow]Playlist is empty[/yellow]")
            return
            
        table = Table(title="Current Playlist")
        table.add_column("No.", style="cyan", justify="right")
        table.add_column("Title", style="green")
        table.add_column("Status", style="yellow")
        
        for i, song in enumerate(self.playlist, 1):
            status = ""
            if i-1 == self.playlist_index and self.playlist_mode:
                if self.is_playing:
                    status = "▶ Playing"
                else:
                    status = "❚❚ Paused"
            table.add_row(str(i), song.stem, status)
        
        # 显示当前播放模式
        mode_str = "🔁 Order" if self.play_mode == "order" else "🔀 Shuffle"
        console.print(f"\n[bold cyan]Play Mode: {mode_str}[/bold cyan]")
        console.print(table)

    def add_to_playlist(self, identifier):
        """Add a song to playlist by name or number"""
        music_files = list(self.music_dir.glob("*.mp3"))
        
        if identifier.isdigit():
            idx = int(identifier) - 1
            if 0 <= idx < len(music_files):
                self.playlist.append(music_files[idx])
                console.print(f"[green]Added to playlist: {music_files[idx].stem}[/green]")
                self.save_settings()  # Save changes
            else:
                console.print("[red]Invalid song number[/red]")
        else:
            matches = [f for f in music_files if identifier.lower() in f.stem.lower()]
            if matches:
                self.playlist.append(matches[0])
                console.print(f"[green]Added to playlist: {matches[0].stem}[/green]")
                self.save_settings()  # Save changes
            else:
                console.print("[red]No matching songs found[/red]")

    def remove_from_playlist(self, identifier):
        """Remove a song from playlist by number"""
        if not identifier.isdigit():
            console.print("[red]Please provide a valid playlist number[/red]")
            return
            
        idx = int(identifier) - 1
        if 0 <= idx < len(self.playlist):
            removed = self.playlist.pop(idx)
            console.print(f"[yellow]Removed from playlist: {removed.stem}[/yellow]")
            self.save_settings()  # Save changes
        else:
            console.print("[red]Invalid playlist number[/red]")

    def clear_playlist(self):
        """Clear the entire playlist"""
        self.playlist = []
        self.playlist_index = 0
        self.playlist_mode = False
        self.save_settings()  # Save changes
        console.print("[yellow]Playlist cleared[/yellow]")

    def play_playlist(self):
        """Start playing the playlist"""
        if not self.playlist:
            console.print("[yellow]Playlist is empty[/yellow]")
            return
            
        self.playlist_mode = True
        
        if self.play_mode == "shuffle":
            # 随机打乱播放列表，但保持原列表不变
            import random
            self.playlist_index = random.randint(0, len(self.playlist) - 1)
        else:
            self.playlist_index = 0
            
        self._play_current_playlist_song()

    def _play_current_playlist_song(self):
        """Play current song in playlist"""
        if not self.playlist or not self.playlist_mode:
            return
        
        if 0 <= self.playlist_index < len(self.playlist):
            file_to_play = self.playlist[self.playlist_index]
            media = self.vlc_instance.media_new(str(file_to_play))
            self.player.set_media(media)
            self.player.play()
            self.is_playing = True
            self.current_song = file_to_play.stem
            self.show_current_song_info()
            
            # Show song info in new terminal
            self.show_song_info_window(file_to_play)

    def _start_playlist_monitor(self):
        """Start a thread to monitor playlist progression"""
        def monitor_playlist():
            while True:
                if self.playlist_mode and self.is_playing:
                    # Check if current song has ended
                    state = self.player.get_state()
                    if state == vlc.State.Ended:
                        if self.play_mode == "shuffle":
                            # 随机选择下一首，避免重复
                            import random
                            remaining_indices = list(range(len(self.playlist)))
                            remaining_indices.remove(self.playlist_index)
                            if remaining_indices:
                                self.playlist_index = random.choice(remaining_indices)
                            else:
                                self.playlist_index = random.randint(0, len(self.playlist) - 1)
                        else:
                            # 顺序播放
                            self.playlist_index += 1
                            if self.playlist_index >= len(self.playlist):
                                self.playlist_index = 0
                        
                        self._play_current_playlist_song()
                time.sleep(0.1)

        threading.Thread(target=monitor_playlist, daemon=True).start()

    def set_play_mode(self, mode: str):
        """Set playlist play mode"""
        if mode not in ["order", "shuffle"]:
            console.print("[red]Invalid play mode. Use 'order' or 'shuffle'[/red]")
            return
            
        self.play_mode = mode
        self.save_settings()  # Save changes
        mode_str = "🔁 Order" if mode == "order" else "🔀 Shuffle"
        console.print(f"[green]Play mode set to: {mode_str}[/green]")

    def show_help(self):
        """Show available commands"""
        help_text = """
        [bold cyan]Available Commands:[/bold cyan]
        
        search <query>     - Search for music
        download <id>      - Download a song by ID
        play <name/num>    - Play a song by name or number
        pause             - Pause current playback
        resume            - Resume paused playback
        stop              - Stop current playback
        next              - Play next song in playlist
        prev              - Play previous song in playlist
        list              - List all downloaded music
        current           - Show currently playing song
        playlist          - Show current playlist
        playlist add <name/num>    - Add song to playlist
        playlist remove <num>      - Remove song from playlist
        playlist clear            - Clear playlist
        playlist play            - Play playlist
        playlist mode <order/shuffle> - Set playlist play mode
        sh [command]      - Execute shell command
        sh               - Enter interactive shell
        """
        console.print(help_text)

    def show_song_info_window(self, file_path: Path):
        """Show song information in a new terminal window"""
        try:
            # Get song metadata using ID3 tags
            try:
                audio = ID3(str(file_path))
                info = {
                    "Title": str(audio.get("TIT2", self.current_song)),
                    "Artist": str(audio.get("TPE1", "Unknown Artist")),
                    "Album": str(audio.get("TALB", "Unknown Album")),
                    "Year": str(audio.get("TDRC", "")),
                    "Genre": str(audio.get("TCON", "")),
                }
                
                # Try to get lyrics
                if "USLT" in audio:
                    info["Lyrics"] = str(audio["USLT"].text)
                elif "SYLT" in audio:
                    info["Lyrics"] = str(audio["SYLT"].text)
                
            except Exception as e:
                # Fallback to basic file info
                info = {
                    "Title": self.current_song,
                    "File": str(file_path.name),
                }
            
            # Add current status
            info["Status"] = "▶ Playing"
            
            # Create temporary script file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
                f.write("""
import time
from rich.live import Live
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.layout import Layout
from rich import box
import sys

console = Console()

def format_lyrics(lyrics):
    if not lyrics:
        return ""
    # Split lyrics into lines and take first few lines
    lines = lyrics.split('\\n')[:10]
    return '\\n'.join(lines)

def create_info_panel(info_dict):
    layout = Layout()
    
    # Create info table
    info_table = Table(show_header=False, box=box.ROUNDED)
    info_table.add_column("Key", style="cyan", width=12)
    info_table.add_column("Value", style="yellow")
    
    # Add basic info
    for key in ["Title", "Artist", "Album", "Year", "Genre", "Status"]:
        if key in info_dict and info_dict[key]:
            info_table.add_row(key, str(info_dict[key]))
    
    # Create main panel
    main_panel = Panel(
        info_table,
        title="[bold magenta]Now Playing[/bold magenta]",
        border_style="cyan",
        padding=(1, 2)
    )
    
    # Add lyrics panel if available
    if "Lyrics" in info_dict and info_dict["Lyrics"]:
        lyrics_panel = Panel(
            format_lyrics(info_dict["Lyrics"]),
            title="[bold magenta]Lyrics[/bold magenta]",
            border_style="cyan",
            padding=(1, 2)
        )
        
        # Create layout with both panels
        layout.split_column(
            Layout(main_panel, size=10),
            Layout(lyrics_panel)
        )
    else:
        layout.update(main_panel)
    
    return layout

def main():
    try:
        info = eval(sys.argv[1])
        with Live(refresh_per_second=1) as live:
            while True:
                live.update(create_info_panel(info))
                time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
""")
            
            # Escape special characters in info dict
            info_str = json.dumps(info).replace('"', '\\"')
            
            # Start info window in new terminal
            if sys.platform == "darwin":  # macOS
                script = f'''
                tell application "Terminal"
                    do script "python3 \\"{f.name}\\" \\"{info_str}\\""
                end tell
                '''
                subprocess.run(['osascript', '-e', script])
            elif sys.platform == "linux":
                subprocess.Popen([
                    "x-terminal-emulator", "-e",
                    f"python3 '{f.name}' '{info_str}'"
                ])
            else:
                console.print("[yellow]Song info window not supported on this platform[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Error showing song info: {str(e)}[/red]")

    def play_next(self):
        """Play next song in playlist"""
        if not self.playlist_mode:
            console.print("[yellow]Not in playlist mode[/yellow]")
            return
        
        if not self.playlist:
            console.print("[yellow]Playlist is empty[/yellow]")
            return
        
        if self.play_mode == "shuffle":
            # 随机选择下一首，避免重复
            import random
            remaining_indices = list(range(len(self.playlist)))
            remaining_indices.remove(self.playlist_index)
            if remaining_indices:
                self.playlist_index = random.choice(remaining_indices)
            else:
                self.playlist_index = random.randint(0, len(self.playlist) - 1)
        else:
            # 顺序播放
            self.playlist_index = (self.playlist_index + 1) % len(self.playlist)
        
        self._play_current_playlist_song()
        console.print(f"[green]Playing next: {self.playlist[self.playlist_index].stem}[/green]")

    def play_previous(self):
        """Play previous song in playlist"""
        if not self.playlist_mode:
            console.print("[yellow]Not in playlist mode[/yellow]")
            return
        
        if not self.playlist:
            console.print("[yellow]Playlist is empty[/yellow]")
            return
        
        if self.play_mode == "shuffle":
            # 在随机模式下，可以选择:
            # 1. 真随机选择一首
            # 2. 回到上一首播放的歌曲（需要记录播放历史）
            # 这里选择简单的随机选择实现
            import random
            remaining_indices = list(range(len(self.playlist)))
            remaining_indices.remove(self.playlist_index)
            if remaining_indices:
                self.playlist_index = random.choice(remaining_indices)
            else:
                self.playlist_index = random.randint(0, len(self.playlist) - 1)
        else:
            # 顺序播放模式下回到上一首
            self.playlist_index = (self.playlist_index - 1) % len(self.playlist)
        
        self._play_current_playlist_song()
        console.print(f"[green]Playing previous: {self.playlist[self.playlist_index].stem}[/green]")

    def stop(self):
        """Stop playback"""
        if self.player:
            self.player.stop()
            self.is_playing = False
            
        # 停止歌词更新线程
        if self.lyric_update_thread and self.lyric_update_thread.is_alive():
            self.stop_lyric_update.set()
            self.lyric_update_thread.join()

    def extract_lyrics_from_mp3(self, file_path: Path) -> Optional[str]:
        """从MP3文件中提取歌词"""
        try:
            audio = File(file_path)
            if audio is None:
                return None
            
            lyrics = None
            
            # 1. 尝试读取 USLT (Unsynchronized lyrics) 标签
            if hasattr(audio, 'tags'):
                for tag in audio.tags.values():
                    if isinstance(tag, USLT):
                        lyrics = tag.text
                        break
                    
            # 2. 尝试读取 SYLT (Synchronized lyrics) 标签
            if not lyrics and 'SYLT' in audio:
                sylt = audio['SYLT'].text
                # 转换为LRC格式
                lyrics = ''
                for time, text in sylt:
                    minutes = time // 60000
                    seconds = (time % 60000) // 1000
                    milliseconds = time % 1000
                    lyrics += f'[{minutes:02d}:{seconds:02d}.{milliseconds:03d}]{text}\n'
                    
            # 3. 尝试读取 TXXX 标签中的歌词
            if not lyrics and 'TXXX' in audio:
                for txxx in audio.tags.getall('TXXX'):
                    if txxx.description.lower() in ['lyrics', 'lrc', 'synchronized lyrics']:
                        lyrics = txxx.text[0]
                        break
                    
            # 4. 尝试读取 COMM (Comments) 标签
            if not lyrics and 'COMM' in audio:
                for comm in audio.tags.getall('COMM'):
                    if 'lyrics' in comm.desc.lower():
                        lyrics = comm.text[0]
                        break
                    
            # 5. 尝试读取 Lyrics3v2 标签
            if not lyrics:
                try:
                    with open(file_path, 'rb') as f:
                        f.seek(-128-9, 2)  # 从文件末尾向前搜索
                        if f.read(9) == b'LYRICS200':
                            f.seek(-9-6, 1)  # 读取大小字段
                            size = int(f.read(6))
                            f.seek(-size-6, 1)
                            lyrics_data = f.read(size)
                            # 解析 Lyrics3v2 格式
                            if b'LYR' in lyrics_data:
                                start = lyrics_data.find(b'LYR') + 8
                                end = lyrics_data.find(b'ETL')
                                if start > 8 and end > start:
                                    lyrics = lyrics_data[start:end].decode('utf-8', errors='ignore')
                except:
                    pass
                
            return lyrics
            
        except Exception as e:
            console.print(f"[yellow]Warning: Error extracting lyrics: {str(e)}[/yellow]")
            return None

    def show_playback_progress(self):
        """Show current song playback progress with a nice progress bar"""
        if not self.current_song or not self.player:
            console.print("[yellow]No song is currently playing[/yellow]")
            return

        try:
            # 使用 mutagen 获取音频文件信息
            audio = MP3(self.current_song)
            total_duration = int(audio.info.length * 1000)  # 转换为毫秒
            
            # 清屏
            console.clear()
            
            # 创建进度显示布局
            with Live(refresh_per_second=10, transient=True) as live:
                try:
                    old_settings = termios.tcgetattr(sys.stdin.fileno())
                    tty.setraw(sys.stdin.fileno())
                    
                    while True:
                        # 获取当前播放时间(毫秒)
                        current_time = self.player.get_time()
                        if current_time < 0:
                            current_time = 0
                        
                        # 计算进度
                        progress = current_time / total_duration if total_duration > 0 else 0
                        
                        # 创建进度条
                        bar_width = 40
                        filled = int(progress * bar_width)
                        
                        # 格式化时间 (转换为分:秒格式)
                        current_min = int(current_time / 1000 / 60)
                        current_sec = int((current_time / 1000) % 60)
                        total_min = int(total_duration / 1000 / 60)
                        total_sec = int((total_duration / 1000) % 60)
                        
                        current_str = f"{current_min:02d}:{current_sec:02d}"
                        total_str = f"{total_min:02d}:{total_sec:02d}"
                        
                        # 构建进度显示
                        progress_bar = (
                            "[magenta]" +
                            "━" * filled +
                            "⬤" +
                            "─" * (bar_width - filled) +
                            "[/magenta]"
                        )
                        
                        # 构建状态显示
                        status = "[green]▶ Playing[/green]" if self.is_playing else "[yellow]❚❚ Paused[/yellow]"
                        volume = f"[cyan]Volume: {self.player.audio_get_volume()}%[/cyan]"
                        
                        # 获取当前歌曲名称
                        song_name = self.current_song.stem if self.current_song else "Unknown"
                        
                        # 构建显示内容
                        content = (
                            f"\n{status} - {song_name}\n\n"
                            f"{progress_bar}\n\n"
                            f"[cyan]{current_str}[/cyan] / [cyan]{total_str}[/cyan]\n\n"
                            f"{volume}\n\n"
                            "[dim]Space: Play/Pause  ←/→: Volume  q: Back[/dim]"
                        )
                        
                        # 创建显示面板
                        panel = Panel(
                            content,
                            title="[bold magenta]Playback Progress[/bold magenta]",
                            border_style="cyan",
                            width=60
                        )
                        
                        # 更新显示
                        live.update(panel)
                        
                        # 检查按键
                        if sys.stdin in select.select([sys.stdin], [], [], 0.1)[0]:
                            char = sys.stdin.read(1)
                            if char == 'q':  # 退出
                                break
                            elif char == ' ':  # 播放/暂停
                                self.toggle_play()
                            elif char == '\x1b':  # 方向键
                                next1, next2 = sys.stdin.read(2)
                                if next1 == '[':
                                    if next2 == 'D':  # 左方向键
                                        self.decrease_volume()
                                    elif next2 == 'C':  # 右方向键
                                        self.increase_volume()
                    
                except Exception as e:
                    console.print(f"[red]Error updating progress: {str(e)}[/red]")
                finally:
                    # 恢复终端设置
                    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, old_settings)
                    console.clear()  # 清屏
                
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]") 

    def toggle_play(self):
        """Toggle play/pause state"""
        if not self.player:
            return
        
        if self.is_playing:
            self.player.pause()
            self.is_playing = False
        else:
            self.player.play()
            self.is_playing = True
        
        # 重新显示当前信息
        self.show_current_song_info()
        
    def increase_volume(self):
        """Increase volume by 5%"""
        if not self.player:
            return
        
        current_volume = self.player.audio_get_volume()
        new_volume = min(current_volume + 5, 100)
        self.player.audio_set_volume(new_volume)
        
        # 重新显示当前信息
        self.show_current_song_info()
        
    def decrease_volume(self):
        """Decrease volume by 5%"""
        if not self.player:
            return
        
        current_volume = self.player.audio_get_volume()
        new_volume = max(current_volume - 5, 0)
        self.player.audio_set_volume(new_volume)
        
        # 重新显示当前信息
        self.show_current_song_info() 