# Network Analysis Guide

## Tools Overview

### 1. Nmap (Network Scanner)
- Command: `scan <target> [options]`
- Default options: `-sV -sC` (版本检测和默认脚本)
- Common Options:
  - `-sS`: SYN扫描
  - `-sV`: 版本检测
  - `-sC`: 默认脚本扫描
  - `-p-`: 扫描所有端口
  - `-A`: 激进扫描
- Example: `scan 192.168.1.0/24 -sV -p 80,443,8080`

### 2. Tcpdump (Packet Capture)
- Commands:
  - `capture <interface> [filter]`: 开始抓包
  - `stop`: 停止抓包
- Filter Examples:
  - `port 80`: 只抓取HTTP流量
  - `host 192.168.1.1`: 特定主机的流量
  - `tcp`: 只抓取TCP流量
- Example: `capture eth0 "port 80 or port 443"`

### 3. Tshark (Traffic Analysis)
- Commands:
  - `analyze <file> [filter]`: 分析抓包文件
  - `convert <input> <output> [format]`: 转换文件格式
  - `filter <input> <filter> <output>`: 过滤数据包
- Display Filters:
  - `http`: HTTP流量
  - `tcp.port == 80`: 特定端口
  - `ip.addr == 192.168.1.1`: 特定IP
- Example: `analyze capture.pcap "http.request"`

### 4. Mitmproxy (HTTP/HTTPS Proxy)
- Commands:
  - `proxy [port] [options]`: 启动代理
  - `proxy_stop`: 停止代理
- Features:
  - HTTP/HTTPS拦截
  - 实时流量分析
  - 请求/响应修改
- Example: `proxy 8080 --mode transparent`

## Common Tasks

### Port Scanning
1. 快速扫描:
```
scan 192.168.1.1
```

2. 完整扫描:
```
scan 192.168.1.1 -p- -A
```

### Traffic Capture
1. 开始抓包:
```
capture eth0
```

2. 带过滤器抓包:
```
capture eth0 "port 80 or port 443"
```

3. 停止抓包:
```
stop
```

### Traffic Analysis
1. 分析HTTP流量:
```
analyze capture.pcap "http"
```

2. 提取特定主机流量:
```
filter input.pcap "ip.addr == 192.168.1.1" output.pcap
```

### HTTPS Proxy
1. 启动代理:
```
proxy 8080
```

2. 停止代理:
```
proxy_stop
```

## Best Practices
1. 扫描前获取许可
2. 合理使用过滤器减少数据量
3. 注意保护敏感数据
4. 定期清理抓包文件
5. 使用精确的过滤条件

## Troubleshooting
- 确保有足够的权限
- 检查网络接口是否正确
- 验证过滤器语法
- 确保目标可达
- 检查存储空间是否充足

## Tips
- 使用 `-h` 查看工具帮助
- 保存常用过滤器
- 使用 `convert` 转换格式方便分析
- 合理使用过滤减少数据量
- 注意网络安全法规 