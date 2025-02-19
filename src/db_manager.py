import sqlite3
from pathlib import Path
from datetime import datetime

class DBManager:
    def __init__(self):
        self.db_dir = Path("data/db")
        self.db_dir.mkdir(parents=True, exist_ok=True)
        self.db_path = self.db_dir / "r3term.db"
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Create frida scripts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS frida_scripts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    description TEXT,
                    filename TEXT NOT NULL,
                    type TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create tags table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS script_tags (
                    script_id INTEGER,
                    tag TEXT,
                    FOREIGN KEY (script_id) REFERENCES frida_scripts(id),
                    PRIMARY KEY (script_id, tag)
                )
            ''')
            
            conn.commit()

    def add_script(self, name, description, filename, script_type, tags):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Insert script
            cursor.execute('''
                INSERT INTO frida_scripts (name, description, filename, type)
                VALUES (?, ?, ?, ?)
            ''', (name, description, filename, script_type))
            
            script_id = cursor.lastrowid
            
            # Insert tags
            for tag in tags:
                cursor.execute('''
                    INSERT INTO script_tags (script_id, tag)
                    VALUES (?, ?)
                ''', (script_id, tag.strip()))
            
            conn.commit()
            return script_id

    def get_script_tags(self, script_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT tag FROM script_tags WHERE script_id = ?', (script_id,))
            return [row[0] for row in cursor.fetchall()]

    def get_all_scripts(self, filter_tag=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if filter_tag:
                cursor.execute('''
                    SELECT DISTINCT s.* 
                    FROM frida_scripts s
                    JOIN script_tags t ON s.id = t.script_id
                    WHERE t.tag = ?
                ''', (filter_tag,))
            else:
                cursor.execute('SELECT * FROM frida_scripts')
            
            scripts = []
            for row in cursor.fetchall():
                script = {
                    'id': row[0],
                    'name': row[1],
                    'description': row[2],
                    'filename': row[3],
                    'type': row[4],
                    'created_at': row[5],
                    'tags': self.get_script_tags(row[0])
                }
                scripts.append(script)
            
            return scripts

    def get_script_by_id(self, script_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM frida_scripts WHERE id = ?', (script_id,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'id': row[0],
                    'name': row[1],
                    'description': row[2],
                    'filename': row[3],
                    'type': row[4],
                    'created_at': row[5],
                    'tags': self.get_script_tags(row[0])
                }
            return None

    def delete_script(self, script_id):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            # Delete tags first due to foreign key constraint
            cursor.execute('DELETE FROM script_tags WHERE script_id = ?', (script_id,))
            cursor.execute('DELETE FROM frida_scripts WHERE id = ?', (script_id,))
            
            conn.commit()
            return cursor.rowcount > 0

    def script_exists(self, filename):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT id FROM frida_scripts WHERE filename = ?', (filename,))
            return cursor.fetchone() is not None

    def get_script_by_name(self, name):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('SELECT * FROM frida_scripts WHERE name = ?', (name,))
            row = cursor.fetchone()
            
            if row:
                return {
                    'id': row[0],
                    'name': row[1],
                    'description': row[2],
                    'filename': row[3],
                    'type': row[4],
                    'created_at': row[5],
                    'tags': self.get_script_tags(row[0])
                }
            return None

    def search_scripts(self, keyword=None, tag=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            
            if keyword and tag:
                cursor.execute('''
                    SELECT DISTINCT s.* 
                    FROM frida_scripts s
                    JOIN script_tags t ON s.id = t.script_id
                    WHERE (s.name LIKE ? OR s.description LIKE ?) 
                    AND t.tag = ?
                ''', (f'%{keyword}%', f'%{keyword}%', tag))
            elif keyword:
                cursor.execute('''
                    SELECT DISTINCT s.* 
                    FROM frida_scripts s
                    WHERE s.name LIKE ? OR s.description LIKE ?
                ''', (f'%{keyword}%', f'%{keyword}%'))
            elif tag:
                cursor.execute('''
                    SELECT DISTINCT s.* 
                    FROM frida_scripts s
                    JOIN script_tags t ON s.id = t.script_id
                    WHERE t.tag = ?
                ''', (tag,))
            else:
                return []
            
            scripts = []
            for row in cursor.fetchall():
                script = {
                    'id': row[0],
                    'name': row[1],
                    'description': row[2],
                    'filename': row[3],
                    'type': row[4],
                    'created_at': row[5],
                    'tags': self.get_script_tags(row[0])
                }
                scripts.append(script)
            
            return scripts

    def update_script_metadata(self, script_id, name=None, description=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            updates = []
            params = []
            
            if name is not None:
                updates.append("name = ?")
                params.append(name)
            if description is not None:
                updates.append("description = ?")
                params.append(description)
            
            if updates:
                params.append(script_id)
                cursor.execute(f'''
                    UPDATE frida_scripts 
                    SET {", ".join(updates)}
                    WHERE id = ?
                ''', params)
                conn.commit()
                return True
            return False

    def add_script_tag(self, script_id, tag):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute('''
                    INSERT INTO script_tags (script_id, tag)
                    VALUES (?, ?)
                ''', (script_id, tag.strip()))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                return False

    def remove_script_tag(self, script_id, tag):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                DELETE FROM script_tags 
                WHERE script_id = ? AND tag = ?
            ''', (script_id, tag.strip()))
            conn.commit()
            return cursor.rowcount > 0 