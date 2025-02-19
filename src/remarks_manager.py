from rich.console import Console
from rich.table import Table
from datetime import datetime
import sqlite3
from pathlib import Path
from base_manager import BaseManager

console = Console()

class RemarksManager(BaseManager):
    def __init__(self):
        super().__init__()
        self.db_dir = Path("data/db")
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.db_dir / "remarks.db"
        self.init_db()

    def init_db(self):
        """Initialize database and create tables if they don't exist"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create remarks table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS remarks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                url TEXT NOT NULL,
                description TEXT,
                category TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Create tags table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL
            )
        ''')
        
        # Create remarks_tags table for many-to-many relationship
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS remarks_tags (
                remark_id INTEGER,
                tag_id INTEGER,
                FOREIGN KEY (remark_id) REFERENCES remarks (id) ON DELETE CASCADE,
                FOREIGN KEY (tag_id) REFERENCES tags (id) ON DELETE CASCADE,
                PRIMARY KEY (remark_id, tag_id)
            )
        ''')
        
        conn.commit()
        conn.close()

    def add_remark(self, title: str, url: str, description: str = "", category: str = "", tags: list = None):
        """Add new remark"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Insert remark
            cursor.execute('''
                INSERT INTO remarks (title, url, description, category)
                VALUES (?, ?, ?, ?)
            ''', (title, url, description, category))
            
            remark_id = cursor.lastrowid
            
            # Handle tags
            if tags:
                for tag in tags:
                    # Insert tag if not exists
                    cursor.execute('INSERT OR IGNORE INTO tags (name) VALUES (?)', (tag,))
                    cursor.execute('SELECT id FROM tags WHERE name = ?', (tag,))
                    tag_id = cursor.fetchone()[0]
                    
                    # Link tag to remark
                    cursor.execute('''
                        INSERT INTO remarks_tags (remark_id, tag_id)
                        VALUES (?, ?)
                    ''', (remark_id, tag_id))
            
            conn.commit()
            console.print("[green]Remark added successfully![/green]")
            
        except Exception as e:
            conn.rollback()
            console.print(f"[red]Error adding remark: {str(e)}[/red]")
        finally:
            conn.close()

    def list_remarks(self, category: str = None, tag: str = None):
        """List remarks with optional filtering"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            query = '''
                SELECT DISTINCT r.id, r.title, r.url, r.description, r.category,
                       GROUP_CONCAT(t.name) as tags, r.created_at
                FROM remarks r
                LEFT JOIN remarks_tags rt ON r.id = rt.remark_id
                LEFT JOIN tags t ON rt.tag_id = t.id
            '''
            params = []
            
            if category or tag:
                query += " WHERE "
                conditions = []
                if category:
                    conditions.append("r.category = ?")
                    params.append(category)
                if tag:
                    conditions.append("t.name = ?")
                    params.append(tag)
                query += " AND ".join(conditions)
            
            query += " GROUP BY r.id ORDER BY r.created_at DESC"
            
            cursor.execute(query, params)
            remarks = cursor.fetchall()
            
            if not remarks:
                console.print("[yellow]No remarks found[/yellow]")
                return
            
            table = Table(title="Remarks Collection")
            table.add_column("ID", style="cyan")
            table.add_column("Title", style="green")
            table.add_column("URL", style="blue")
            table.add_column("Category", style="yellow")
            table.add_column("Tags", style="magenta")
            table.add_column("Created", style="white")
            
            for remark in remarks:
                table.add_row(
                    str(remark[0]),
                    remark[1],
                    remark[2],
                    remark[4] or "N/A",
                    remark[5] or "N/A",
                    datetime.fromisoformat(remark[6]).strftime("%Y-%m-%d %H:%M")
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error listing remarks: {str(e)}[/red]")
        finally:
            conn.close()

    def show_remark(self, remark_id: int):
        """Show detailed information about a specific remark"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT r.*, GROUP_CONCAT(t.name) as tags
                FROM remarks r
                LEFT JOIN remarks_tags rt ON r.id = rt.remark_id
                LEFT JOIN tags t ON rt.tag_id = t.id
                WHERE r.id = ?
                GROUP BY r.id
            ''', (remark_id,))
            
            remark = cursor.fetchone()
            if remark:
                console.print(f"\n[bold cyan]Remark #{remark[0]}[/bold cyan]")
                console.print(f"[bold]Title:[/bold] {remark[1]}")
                console.print(f"[bold]URL:[/bold] [blue]{remark[2]}[/blue]")
                console.print(f"[bold]Description:[/bold] {remark[3]}")
                console.print(f"[bold]Category:[/bold] {remark[4] or 'N/A'}")
                console.print(f"[bold]Tags:[/bold] {remark[8] or 'N/A'}")
                console.print(f"[bold]Created:[/bold] {datetime.fromisoformat(remark[5]).strftime('%Y-%m-%d %H:%M')}")
                console.print(f"[bold]Updated:[/bold] {datetime.fromisoformat(remark[6]).strftime('%Y-%m-%d %H:%M')}")
            else:
                console.print("[yellow]Remark not found[/yellow]")
                
        except Exception as e:
            console.print(f"[red]Error showing remark: {str(e)}[/red]")
        finally:
            conn.close()

    def update_remark(self, remark_id: int, title: str = None, url: str = None, 
                     description: str = None, category: str = None, tags: list = None):
        """Update existing remark"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            # Update remark
            update_fields = []
            params = []
            
            if title is not None:
                update_fields.append("title = ?")
                params.append(title)
            if url is not None:
                update_fields.append("url = ?")
                params.append(url)
            if description is not None:
                update_fields.append("description = ?")
                params.append(description)
            if category is not None:
                update_fields.append("category = ?")
                params.append(category)
                
            if update_fields:
                update_fields.append("updated_at = CURRENT_TIMESTAMP")
                query = f"UPDATE remarks SET {', '.join(update_fields)} WHERE id = ?"
                params.append(remark_id)
                cursor.execute(query, params)
            
            # Update tags if provided
            if tags is not None:
                # Remove existing tags
                cursor.execute('DELETE FROM remarks_tags WHERE remark_id = ?', (remark_id,))
                
                # Add new tags
                for tag in tags:
                    cursor.execute('INSERT OR IGNORE INTO tags (name) VALUES (?)', (tag,))
                    cursor.execute('SELECT id FROM tags WHERE name = ?', (tag,))
                    tag_id = cursor.fetchone()[0]
                    cursor.execute('''
                        INSERT INTO remarks_tags (remark_id, tag_id)
                        VALUES (?, ?)
                    ''', (remark_id, tag_id))
            
            conn.commit()
            console.print("[green]Remark updated successfully![/green]")
            
        except Exception as e:
            conn.rollback()
            console.print(f"[red]Error updating remark: {str(e)}[/red]")
        finally:
            conn.close()

    def delete_remark(self, remark_id: int):
        """Delete a remark"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('DELETE FROM remarks WHERE id = ?', (remark_id,))
            if cursor.rowcount > 0:
                conn.commit()
                console.print("[green]Remark deleted successfully![/green]")
            else:
                console.print("[yellow]Remark not found[/yellow]")
                
        except Exception as e:
            conn.rollback()
            console.print(f"[red]Error deleting remark: {str(e)}[/red]")
        finally:
            conn.close()

    def search_remarks(self, keyword: str):
        """Search remarks by keyword"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        try:
            cursor.execute('''
                SELECT DISTINCT r.id, r.title, r.url, r.description, r.category,
                       GROUP_CONCAT(t.name) as tags, r.created_at
                FROM remarks r
                LEFT JOIN remarks_tags rt ON r.id = rt.remark_id
                LEFT JOIN tags t ON rt.tag_id = t.id
                WHERE r.title LIKE ? OR r.description LIKE ? OR r.url LIKE ?
                GROUP BY r.id
                ORDER BY r.created_at DESC
            ''', (f'%{keyword}%', f'%{keyword}%', f'%{keyword}%'))
            
            remarks = cursor.fetchall()
            
            if not remarks:
                console.print("[yellow]No matching remarks found[/yellow]")
                return
            
            table = Table(title=f"Search Results for '{keyword}'")
            table.add_column("ID", style="cyan")
            table.add_column("Title", style="green")
            table.add_column("URL", style="blue")
            table.add_column("Category", style="yellow")
            table.add_column("Tags", style="magenta")
            
            for remark in remarks:
                table.add_row(
                    str(remark[0]),
                    remark[1],
                    remark[2],
                    remark[4] or "N/A",
                    remark[5] or "N/A"
                )
            
            console.print(table)
            
        except Exception as e:
            console.print(f"[red]Error searching remarks: {str(e)}[/red]")
        finally:
            conn.close()

    def handle_command(self, command: str, *args):
        """Handle remarks commands"""
        try:
            # 首先检查是否是shell命令
            if self.handle_shell_command(command):
                return
                
            # ... existing command handling code ...
            
        except Exception as e:
            console.print(f"[red]Error: {str(e)}[/red]") 