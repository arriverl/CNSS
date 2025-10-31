# Wireshark安装和配置指南

## 概述

本系统支持使用Wireshark进行真实网络流量监控。Wireshark是一个强大的网络协议分析器，可以捕获和分析网络数据包。

## 安装Wireshark

### Windows系统

#### 方法1：官方安装包
1. 访问 [Wireshark官网](https://www.wireshark.org/download.html)
2. 下载Windows安装包（64位推荐）
3. 运行安装程序，按默认设置安装
4. 安装过程中选择安装WinPcap或Npcap（用于数据包捕获）

#### 方法2：Chocolatey包管理器
```powershell
# 以管理员身份运行PowerShell
choco install wireshark
```

#### 方法3：Scoop包管理器
```powershell
scoop install wireshark
```

### Linux系统

#### Ubuntu/Debian
```bash
# 更新包列表
sudo apt update

# 安装Wireshark
sudo apt install wireshark

# 将当前用户添加到wireshark组
sudo usermod -a -G wireshark $USER

# 重新登录或重启系统
```

#### CentOS/RHEL/Fedora
```bash
# CentOS/RHEL
sudo yum install wireshark

# Fedora
sudo dnf install wireshark

# 将用户添加到wireshark组
sudo usermod -a -G wireshark $USER
```

#### Arch Linux
```bash
sudo pacman -S wireshark-cli
```

### macOS系统

#### 方法1：Homebrew
```bash
brew install wireshark
```

#### 方法2：官方安装包
1. 访问 [Wireshark官网](https://www.wireshark.org/download.html)
2. 下载macOS安装包
3. 运行安装程序

## 配置Wireshark

### 1. 权限配置

#### Linux系统
```bash
# 设置tshark权限
sudo chmod +x /usr/bin/tshark

# 或者使用sudo运行（不推荐）
sudo tshark --version
```

#### Windows系统
- 确保以管理员权限运行应用程序
- 或者配置Npcap以普通用户权限运行

### 2. 网络接口配置

#### 查看可用接口
```bash
# 使用tshark查看接口
tshark -D

# 使用ip命令查看接口（Linux）
ip link show

# 使用netsh查看接口（Windows）
netsh interface show interface
```

#### 常见接口类型
- **以太网接口**: eth0, en0, enp0s3
- **WiFi接口**: wlan0, wlp2s0
- **回环接口**: lo, lo0
- **虚拟接口**: docker0, veth*

### 3. 防火墙配置

#### Windows防火墙
1. 打开Windows Defender防火墙
2. 允许Wireshark通过防火墙
3. 或者临时关闭防火墙进行测试

#### Linux防火墙
```bash
# Ubuntu/Debian (ufw)
sudo ufw allow wireshark

# CentOS/RHEL (firewalld)
sudo firewall-cmd --permanent --add-service=wireshark
sudo firewall-cmd --reload

# 或者临时关闭防火墙
sudo systemctl stop firewalld
```

## 系统集成配置

### 1. 环境变量设置

#### Windows
```cmd
# 添加到系统PATH
set PATH=%PATH%;C:\Program Files\Wireshark

# 或者添加到用户环境变量
setx PATH "%PATH%;C:\Program Files\Wireshark"
```

#### Linux/macOS
```bash
# 添加到~/.bashrc或~/.zshrc
echo 'export PATH="/usr/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

### 2. Python依赖安装

```bash
# 安装必要的Python包
pip install psutil subprocess32

# 如果使用虚拟环境
python -m venv venv
source venv/bin/activate  # Linux/macOS
# 或
venv\Scripts\activate  # Windows
pip install -r requirements.txt
```

### 3. 系统权限配置

#### Linux系统
```bash
# 设置capabilities（推荐）
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tshark

# 或者使用sudo（不推荐）
sudo chmod +s /usr/bin/tshark
```

#### Windows系统
- 确保以管理员权限运行Python脚本
- 或者配置Npcap以普通用户权限运行

## 测试Wireshark集成

### 1. 基本功能测试

```bash
# 测试tshark是否可用
tshark --version

# 测试接口列表
tshark -D

# 测试数据包捕获（5秒）
tshark -i eth0 -a duration:5
```

### 2. Python集成测试

```python
# 测试脚本
import subprocess
import sys

def test_wireshark():
    try:
        # 测试tshark命令
        result = subprocess.run(['tshark', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ Wireshark可用")
            return True
        else:
            print("❌ Wireshark不可用")
            return False
    except Exception as e:
        print(f"❌ 测试失败: {e}")
        return False

if __name__ == "__main__":
    test_wireshark()
```

### 3. 系统集成测试

```bash
# 启动系统
python backend/main.py

# 测试API端点
curl http://localhost:8000/api/health
curl http://localhost:8000/api/wireshark/interfaces
```

## 常见问题解决

### 1. 权限问题

#### 问题：tshark: There are no interfaces on which a capture can be done
**解决方案**：
```bash
# Linux
sudo usermod -a -G wireshark $USER
# 重新登录

# 或者使用sudo
sudo tshark -D
```

#### 问题：Permission denied
**解决方案**：
```bash
# 设置capabilities
sudo setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/bin/tshark

# 或者以root权限运行
sudo python main.py
```

### 2. 接口问题

#### 问题：找不到网络接口
**解决方案**：
```bash
# 检查网络接口
ip link show  # Linux
netsh interface show interface  # Windows

# 检查接口状态
ip link set eth0 up  # Linux
```

#### 问题：接口权限不足
**解决方案**：
```bash
# 以管理员权限运行
sudo python main.py

# 或者配置接口权限
sudo chmod 666 /dev/net/tun
```

### 3. 性能问题

#### 问题：CPU使用率过高
**解决方案**：
- 减少捕获时间间隔
- 使用过滤器减少数据包数量
- 优化tshark参数

#### 问题：内存使用过多
**解决方案**：
- 限制历史数据保存数量
- 定期清理缓存数据
- 使用更高效的数据结构

### 4. 网络问题

#### 问题：无法捕获数据包
**解决方案**：
```bash
# 检查网络接口状态
ip link show

# 检查网络连接
ping google.com

# 检查防火墙设置
sudo ufw status
```

#### 问题：数据包丢失
**解决方案**：
- 增加缓冲区大小
- 使用更快的存储设备
- 优化网络配置

## 高级配置

### 1. 自定义过滤器

```bash
# 只捕获HTTP流量
tshark -i eth0 -f "tcp port 80"

# 只捕获特定IP的流量
tshark -i eth0 -f "host 192.168.1.1"

# 排除广播和组播
tshark -i eth0 -f "not broadcast and not multicast"
```

### 2. 性能优化

```bash
# 使用更快的捕获方法
tshark -i eth0 -B 1000 -c 1000

# 限制捕获时间
tshark -i eth0 -a duration:60

# 使用多线程
tshark -i eth0 -T fields -e frame.len
```

### 3. 数据导出

```bash
# 导出为CSV格式
tshark -i eth0 -T fields -e frame.time -e ip.src -e ip.dst -e frame.len

# 导出为JSON格式
tshark -i eth0 -T json

# 导出为PCAP文件
tshark -i eth0 -w capture.pcap
```

## 安全注意事项

### 1. 权限管理
- 不要以root权限运行应用程序
- 使用最小权限原则
- 定期审查用户权限

### 2. 数据安全
- 敏感数据加密存储
- 定期清理历史数据
- 限制数据访问权限

### 3. 网络安全
- 监控异常流量
- 设置访问控制
- 定期更新软件

## 监控和维护

### 1. 日志监控
```bash
# 查看系统日志
tail -f /var/log/syslog

# 查看应用程序日志
tail -f logs/app.log
```

### 2. 性能监控
```bash
# 监控CPU使用率
top -p $(pgrep tshark)

# 监控内存使用
ps aux | grep tshark

# 监控网络流量
iftop -i eth0
```

### 3. 故障排除
```bash
# 检查进程状态
ps aux | grep python
ps aux | grep tshark

# 检查端口占用
netstat -tlnp | grep 8000

# 检查系统资源
free -h
df -h
```

## 总结

Wireshark集成提供了强大的网络流量监控能力，但需要正确配置权限和网络接口。建议在生产环境中：

1. 使用专用监控服务器
2. 配置适当的权限和安全策略
3. 定期监控系统性能
4. 备份重要配置和数据

通过以上配置，系统将能够使用Wireshark进行真实的网络流量监控和分析。



