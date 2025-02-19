from rich.console import Console
from rich.table import Table
import curses
import time
import random
import os
import sys
from threading import Thread
import math

class GameManager:
    def __init__(self):
        self.console = Console()
        self.games = {
            "2048": self._play_2048,
            "tetris": self._play_tetris,
            "snake": self._play_snake,
            "space": self._play_space_shooter
        }
    
    def handle_command(self, command: str, *args):
        if command in self.games:
            self.games[command]()
        elif command == "list":
            self._list_games()
    
    def _list_games(self):
        """显示可用的游戏列表"""
        table = Table(title="Available Games")
        table.add_column("Game", style="cyan")
        table.add_column("Description", style="green")
        
        table.add_row("2048", "Classic 2048 puzzle game")
        table.add_row("tetris", "Classic Tetris game")
        table.add_row("snake", "Classic Snake game")
        table.add_row("space", "Space Shooter game")
        
        self.console.print(table)
    
    def _play_2048(self):
        """2048游戏实现"""
        def init_board():
            return [[0] * 4 for _ in range(4)]
        
        def add_new_tile(board):
            empty = [(i, j) for i in range(4) for j in range(4) if board[i][j] == 0]
            if empty:
                i, j = random.choice(empty)
                board[i][j] = 2 if random.random() < 0.9 else 4
        
        def merge(row):
            # 移除零
            row = [x for x in row if x != 0]
            # 合并相同的数字
            for i in range(len(row)-1):
                if row[i] == row[i+1]:
                    row[i] *= 2
                    row[i+1] = 0
            # 再次移除零并补齐
            row = [x for x in row if x != 0]
            return row + [0] * (4 - len(row))
        
        def move(board, direction):
            rotated = False
            if direction in ['left', 'right']:
                pass
            elif direction == 'up':
                board = list(map(list, zip(*board)))  # 转置
                rotated = True
            elif direction == 'down':
                board = list(map(list, zip(*board)))  # 转置
                rotated = True
            
            # 处理每一行
            for i in range(4):
                row = board[i]
                if direction in ['right', 'down']:
                    row.reverse()
                row = merge(row)
                if direction in ['right', 'down']:
                    row.reverse()
                board[i] = row
            
            if rotated:
                board = list(map(list, zip(*board)))  # 转置回来
            return board
        
        def is_game_over(board):
            # 检查是否有空格
            if any(0 in row for row in board):
                return False
            # 检查是否可以合并
            for i in range(4):
                for j in range(3):
                    if board[i][j] == board[i][j+1]:
                        return False
            for i in range(3):
                for j in range(4):
                    if board[i][j] == board[i+1][j]:
                        return False
            return True
        
        try:
            # 初始化curses
            stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            stdscr.keypad(True)
            
            # 初始化游戏
            board = init_board()
            add_new_tile(board)
            add_new_tile(board)
            score = 0
            
            while True:
                # 清屏并显示游戏板
                stdscr.clear()
                stdscr.addstr(0, 0, "2048 Game - Use arrow keys to move, 'q' to quit")
                stdscr.addstr(1, 0, f"Score: {score}")
                
                for i in range(4):
                    for j in range(4):
                        stdscr.addstr(i+3, j*6, str(board[i][j]) if board[i][j] != 0 else '.')
                
                # 获取用户输入
                key = stdscr.getch()
                old_board = [row[:] for row in board]
                
                if key == ord('q'):
                    break
                elif key == curses.KEY_UP:
                    board = move(board, 'up')
                elif key == curses.KEY_DOWN:
                    board = move(board, 'down')
                elif key == curses.KEY_LEFT:
                    board = move(board, 'left')
                elif key == curses.KEY_RIGHT:
                    board = move(board, 'right')
                
                # 如果板子有变化，添加新的数字
                if board != old_board:
                    add_new_tile(board)
                    score += 1
                
                # 检查游戏是否结束
                if is_game_over(board):
                    stdscr.addstr(8, 0, "Game Over! Press any key to exit.")
                    stdscr.getch()
                    break
        
        finally:
            # 恢复终端设置
            curses.nocbreak()
            stdscr.keypad(False)
            curses.echo()
            curses.endwin()
    
    def _play_tetris(self):
        """俄罗斯方块游戏实现"""
        # 定义方块形状
        SHAPES = [
            [[1, 1, 1, 1]],  # I
            [[1, 1], [1, 1]],  # O
            [[1, 1, 1], [0, 1, 0]],  # T
            [[1, 1, 1], [1, 0, 0]],  # L
            [[1, 1, 1], [0, 0, 1]],  # J
            [[1, 1, 0], [0, 1, 1]],  # S
            [[0, 1, 1], [1, 1, 0]]   # Z
        ]
        
        def create_board():
            return [[0 for _ in range(10)] for _ in range(20)]
        
        def rotate_shape(shape):
            return list(zip(*shape[::-1]))
        
        def valid_move(board, shape, offset):
            off_x, off_y = offset
            for y, row in enumerate(shape):
                for x, cell in enumerate(row):
                    if cell:
                        if (off_y + y >= len(board) or
                            off_x + x < 0 or
                            off_x + x >= len(board[0]) or
                            board[off_y + y][off_x + x]):
                            return False
            return True
        
        def merge_board(board, shape, offset):
            off_x, off_y = offset
            for y, row in enumerate(shape):
                for x, cell in enumerate(row):
                    if cell:
                        board[off_y + y][off_x + x] = cell
        
        def clear_lines(board):
            lines = 0
            for i, row in enumerate(board):
                if all(cell for cell in row):
                    del board[i]
                    board.insert(0, [0 for _ in range(10)])
                    lines += 1
            return lines
        
        try:
            # 初始化curses
            stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            stdscr.keypad(True)
            curses.start_color()
            curses.init_pair(1, curses.COLOR_CYAN, curses.COLOR_BLACK)
            
            # 游戏变量
            board = create_board()
            current_piece = random.choice(SHAPES)
            piece_pos = [3, 0]  # x, y
            score = 0
            game_speed = 0.5  # 秒
            last_fall = time.time()
            
            while True:
                # 显示游戏状态
                stdscr.clear()
                stdscr.addstr(0, 0, f"Score: {score}")
                
                # 显示游戏板
                for y, row in enumerate(board):
                    for x, cell in enumerate(row):
                        stdscr.addch(y + 2, x * 2, '□' if cell else '.')
                
                # 显示当前方块
                for y, row in enumerate(current_piece):
                    for x, cell in enumerate(row):
                        if cell:
                            stdscr.addch(piece_pos[1] + y + 2, (piece_pos[0] + x) * 2, '■')
                
                stdscr.refresh()
                
                # 处理输入
                stdscr.timeout(100)
                try:
                    key = stdscr.getch()
                except:
                    key = -1
                
                if key == ord('q'):
                    break
                elif key == curses.KEY_LEFT:
                    if valid_move(board, current_piece, [piece_pos[0] - 1, piece_pos[1]]):
                        piece_pos[0] -= 1
                elif key == curses.KEY_RIGHT:
                    if valid_move(board, current_piece, [piece_pos[0] + 1, piece_pos[1]]):
                        piece_pos[0] += 1
                elif key == curses.KEY_UP:
                    rotated = rotate_shape(current_piece)
                    if valid_move(board, rotated, piece_pos):
                        current_piece = rotated
                elif key == curses.KEY_DOWN:
                    if valid_move(board, current_piece, [piece_pos[0], piece_pos[1] + 1]):
                        piece_pos[1] += 1
                
                # 自动下落
                if time.time() - last_fall > game_speed:
                    if valid_move(board, current_piece, [piece_pos[0], piece_pos[1] + 1]):
                        piece_pos[1] += 1
                    else:
                        # 固定当前方块
                        merge_board(board, current_piece, piece_pos)
                        lines = clear_lines(board)
                        score += lines * 100
                        
                        # 新的方块
                        current_piece = random.choice(SHAPES)
                        piece_pos = [3, 0]
                        
                        # 检查游戏是否结束
                        if not valid_move(board, current_piece, piece_pos):
                            stdscr.addstr(10, 0, "Game Over! Press any key to exit.")
                            stdscr.getch()
                            break
                    
                    last_fall = time.time()
        
        finally:
            # 恢复终端设置
            curses.nocbreak()
            stdscr.keypad(False)
            curses.echo()
            curses.endwin()
    
    def _play_snake(self):
        """贪吃蛇游戏实现"""
        def create_food(snake):
            while True:
                food = [random.randint(1, 18), random.randint(1, 58)]
                if food not in snake:
                    return food
        
        try:
            # 初始化curses
            stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            stdscr.keypad(True)
            curses.start_color()
            curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
            
            # 初始化游戏
            snake = [[4, 10], [4, 9], [4, 8]]  # 蛇的身体
            food = create_food(snake)  # 食物位置
            direction = curses.KEY_RIGHT  # 初始方向
            score = 0
            
            while True:
                # 显示边界
                stdscr.clear()
                stdscr.border(0)
                stdscr.addstr(0, 2, f" Score: {score} ")
                
                # 显示食物
                stdscr.addch(food[0], food[1], '*', curses.color_pair(2))
                
                # 显示蛇
                for i, pos in enumerate(snake):
                    if i == 0:
                        stdscr.addch(pos[0], pos[1], '@', curses.color_pair(1))
                    else:
                        stdscr.addch(pos[0], pos[1], 'o', curses.color_pair(1))
                
                # 获取用户输入
                stdscr.timeout(100)
                key = stdscr.getch()
                
                if key == ord('q'):
                    break
                elif key in [curses.KEY_RIGHT, curses.KEY_LEFT, curses.KEY_UP, curses.KEY_DOWN]:
                    # 防止反向移动
                    if (key == curses.KEY_RIGHT and direction != curses.KEY_LEFT) or \
                       (key == curses.KEY_LEFT and direction != curses.KEY_RIGHT) or \
                       (key == curses.KEY_UP and direction != curses.KEY_DOWN) or \
                       (key == curses.KEY_DOWN and direction != curses.KEY_UP):
                        direction = key
                
                # 移动蛇
                new_head = snake[0][:]
                if direction == curses.KEY_RIGHT:
                    new_head[1] += 1
                elif direction == curses.KEY_LEFT:
                    new_head[1] -= 1
                elif direction == curses.KEY_UP:
                    new_head[0] -= 1
                elif direction == curses.KEY_DOWN:
                    new_head[0] += 1
                
                snake.insert(0, new_head)
                
                # 检查是否吃到食物
                if snake[0] == food:
                    score += 1
                    food = create_food(snake)
                else:
                    snake.pop()
                
                # 检查是否撞墙或撞到自己
                if (snake[0][0] in [0, 19] or
                    snake[0][1] in [0, 59] or
                    snake[0] in snake[1:]):
                    stdscr.addstr(10, 25, "Game Over!")
                    stdscr.addstr(11, 23, f"Final Score: {score}")
                    stdscr.addstr(12, 20, "Press any key to exit")
                    stdscr.getch()
                    break
        
        finally:
            # 恢复终端设置
            curses.nocbreak()
            stdscr.keypad(False)
            curses.echo()
            curses.endwin()
    
    def _play_space_shooter(self):
        """飞机大战游戏实现"""
        class Player:
            def __init__(self, x, y):
                self.x = x
                self.y = y
                self.shape = '^'
                self.bullets = []
        
        class Enemy:
            def __init__(self, x, y):
                self.x = x
                self.y = y
                self.shape = 'V'
        
        class Bullet:
            def __init__(self, x, y):
                self.x = x
                self.y = y
                self.shape = '|'
        
        try:
            # 初始化curses
            stdscr = curses.initscr()
            curses.noecho()
            curses.cbreak()
            stdscr.keypad(True)
            curses.start_color()
            curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
            curses.init_pair(2, curses.COLOR_RED, curses.COLOR_BLACK)
            curses.init_pair(3, curses.COLOR_YELLOW, curses.COLOR_BLACK)
            
            # 游戏变量
            height, width = 20, 40
            player = Player(width // 2, height - 2)
            enemies = []
            score = 0
            game_speed = 0.1
            last_enemy_spawn = time.time()
            enemy_spawn_rate = 2.0  # 秒
            
            while True:
                # 清屏
                stdscr.clear()
                
                # 显示边界和分数
                for i in range(height):
                    stdscr.addch(i, 0, '|')
                    stdscr.addch(i, width - 1, '|')
                stdscr.addstr(0, 2, f"Score: {score}")
                
                # 显示玩家
                stdscr.addch(player.y, player.x, player.shape, curses.color_pair(1))
                
                # 显示子弹
                for bullet in player.bullets:
                    stdscr.addch(bullet.y, bullet.x, bullet.shape, curses.color_pair(3))
                
                # 显示敌人
                for enemy in enemies:
                    stdscr.addch(enemy.y, enemy.x, enemy.shape, curses.color_pair(2))
                
                # 获取用户输入
                stdscr.timeout(100)
                key = stdscr.getch()
                
                if key == ord('q'):
                    break
                elif key == curses.KEY_LEFT and player.x > 1:
                    player.x -= 1
                elif key == curses.KEY_RIGHT and player.x < width - 2:
                    player.x += 1
                elif key == ord(' '):  # 空格键发射子弹
                    player.bullets.append(Bullet(player.x, player.y - 1))
                
                # 移动子弹
                for bullet in player.bullets[:]:
                    bullet.y -= 1
                    if bullet.y < 0:
                        player.bullets.remove(bullet)
                
                # 生成敌人
                if time.time() - last_enemy_spawn > enemy_spawn_rate:
                    enemies.append(Enemy(random.randint(1, width - 2), 1))
                    last_enemy_spawn = time.time()
                
                # 移动敌人
                for enemy in enemies[:]:
                    enemy.y += 1
                    if enemy.y >= height - 1:
                        enemies.remove(enemy)
                        score -= 50  # 惩罚
                
                # 检查碰撞
                for bullet in player.bullets[:]:
                    for enemy in enemies[:]:
                        if bullet.x == enemy.x and bullet.y == enemy.y:
                            player.bullets.remove(bullet)
                            enemies.remove(enemy)
                            score += 100
                            break
                
                # 检查游戏是否结束
                for enemy in enemies:
                    if enemy.y == player.y and abs(enemy.x - player.x) <= 1:
                        stdscr.addstr(height // 2, width // 2 - 5, "Game Over!")
                        stdscr.addstr(height // 2 + 1, width // 2 - 8, f"Final Score: {score}")
                        stdscr.addstr(height // 2 + 2, width // 2 - 10, "Press any key to exit")
                        stdscr.getch()
                        return
                
                # 更新显示
                stdscr.refresh()
                time.sleep(game_speed)
        
        finally:
            # 恢复终端设置
            curses.nocbreak()
            stdscr.keypad(False)
            curses.echo()
            curses.endwin() 