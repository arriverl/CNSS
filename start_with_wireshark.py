#!/usr/bin/env python3
"""
支持Wireshark的流量监控系统启动脚本
使用真实网络流量数据，无需模拟数据
"""

import os
import sys
import platform
import subprocess
import time
import json
from pathlib import Path

def check_environment():
    """检查运行环境"""
    print("=" * 60)
    print("实时流量监控系统 - Wireshark模式启动器")
    print("=" * 60)
    
    # 检查操作系统
    print(f"✅ 操作系统: {platform.system()} {platform.release()}")
    
    # 检查Python版本
    python_version = sys.version_info
    if python_version.major < 3 or (python_version.major == 3 and python_version.minor < 8):
        print("❌ 需要Python 3.8或更高版本")
        return False
    
    print(f"✅ Python版本: {python_version.major}.{python_version.minor}.{python_version.micro}")
    
    # 检查必要的包
    required_packages = ['fastapi', 'uvicorn', 'psutil', 'pydantic']
    missing_packages = []
    
    for package in required_packages:
        try:
            __import__(package)
            print(f"✅ {package} 已安装")
        except ImportError:
            missing_packages.append(package)
            print(f"❌ {package} 未安装")
    
    if missing_packages:
        print(f"\n需要安装以下包: {', '.join(missing_packages)}")
        print("运行: pip install -r backend/requirements.txt")
        return False
    
    return True

def check_wireshark():
    """检查Wireshark是否可用"""
    print("\n🔍 检查Wireshark...")
    
    try:
        # 检查tshark命令，在Windows下使用UTF-8编码
        if platform.system().lower() == 'windows':
            result = subprocess.run(['tshark', '--version'], 
                                capture_output=True, text=True, 
                                encoding='utf-8', errors='ignore', timeout=5)
        else:
            result = subprocess.run(['tshark', '--version'], 
                                capture_output=True, text=True, timeout=5)
        
        if result.returncode == 0:
            print("✅ Wireshark (tshark) 可用")
            return True
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    
    print("❌ Wireshark不可用")
    print("\n请安装Wireshark:")
    if platform.system().lower() == 'windows':
        print("1. 访问 https://www.wireshark.org/download.html")
        print("2. 下载并安装Wireshark")
        print("3. 确保tshark在系统PATH中")
    elif platform.system().lower() == 'linux':
        print("1. Ubuntu/Debian: sudo apt install wireshark")
        print("2. CentOS/RHEL: sudo yum install wireshark")
        print("3. 将用户添加到wireshark组: sudo usermod -a -G wireshark $USER")
    elif platform.system().lower() == 'darwin':
        print("1. 使用Homebrew: brew install wireshark")
        print("2. 或下载官方安装包")
    
    return False

def get_network_interfaces():
    """获取网络接口列表"""
    print("\n🌐 获取网络接口...")
    
    interfaces = []
    
    try:
        # 使用tshark获取接口，在Windows下使用UTF-8编码
        if platform.system().lower() == 'windows':
            result = subprocess.run(['tshark', '-D'], 
                                capture_output=True, text=True, 
                                encoding='utf-8', errors='ignore', timeout=10)
        else:
            result = subprocess.run(['tshark', '-D'], 
                                capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout:
            for line in result.stdout.strip().split('\n'):
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 2:
                        interface_id = parts[0]
                        interface_name = parts[1]
                        interfaces.append({
                            'id': interface_id,
                            'name': interface_name,
                            'description': ' '.join(parts[2:]) if len(parts) > 2 else ''
                        })
    except Exception as e:
        print(f"⚠️ 使用tshark获取接口失败: {e}")
    
    # 如果tshark失败，使用psutil
    if not interfaces:
        try:
            import psutil
            net_io = psutil.net_io_counters(pernic=True)
            for interface_name in net_io.keys():
                interfaces.append({
                    'id': interface_name,
                    'name': interface_name,
                    'description': f'Network interface {interface_name}'
                })
        except Exception as e:
            print(f"⚠️ 使用psutil获取接口失败: {e}")
    
    if interfaces:
        print(f"✅ 找到 {len(interfaces)} 个网络接口:")
        for i, interface in enumerate(interfaces):
            print(f"  {i+1}. {interface['name']} - {interface['description']}")
    else:
        print("❌ 未找到网络接口")
    
    return interfaces

def create_wireshark_config(interfaces):
    """创建Wireshark配置"""
    config = {
        "wireshark_mode": True,
        "simulation_enabled": False,
        "interfaces": interfaces,
        "capture_duration": 5,
        "auto_start_capture": True,
        "default_interface": interfaces[0]['name'] if interfaces else None
    }
    
    config_path = Path("wireshark_config.json")
    with open(config_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)
    
    print(f"✅ Wireshark配置已创建: {config_path}")
    return config_path

def check_postgresql():
    """检查并启动PostgreSQL"""
    print("\n🐘 检查PostgreSQL...")
    
    # 检查Docker是否可用
    try:
        result = subprocess.run(['docker', '--version'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print("✅ Docker可用")
            
            # 检查PostgreSQL容器是否运行
            result = subprocess.run(['docker', 'ps', '--filter', 'name=security-monitor-db', '--format', '{{.Names}}'],
                                  capture_output=True, text=True, timeout=5)
            
            if 'security-monitor-db' in result.stdout:
                print("✅ PostgreSQL容器已在运行")
                return True
            else:
                # 尝试启动PostgreSQL容器
                print("⏳ 启动PostgreSQL容器...")
                result = subprocess.run([
                    'docker', 'run', '-d',
                    '--name', 'security-monitor-db',
                    '-e', 'POSTGRES_USER=postgres',
                    '-e', 'POSTGRES_PASSWORD=postgres',
                    '-e', 'POSTGRES_DB=security_monitor',
                    '-p', '5432:5432',
                    '--restart', 'unless-stopped',
                    'postgres:15-alpine'
                ], capture_output=True, text=True, timeout=30)
                
                if result.returncode == 0:
                    print("✅ PostgreSQL容器启动成功")
                    print("⏳ 等待PostgreSQL就绪（10秒）...")
                    time.sleep(10)
                    return True
                else:
                    # 如果容器已存在，尝试启动
                    if 'already in use' in result.stderr or 'already exists' in result.stderr:
                        print("📦 PostgreSQL容器已存在，尝试启动...")
                        subprocess.run(['docker', 'start', 'security-monitor-db'], 
                                     capture_output=True, timeout=10)
                        time.sleep(5)
                        return True
                    else:
                        print(f"⚠️ 无法启动PostgreSQL容器: {result.stderr}")
                        print("将使用SQLite作为后备数据库")
                        return False
        else:
            print("⚠️ Docker不可用")
            return False
    except (FileNotFoundError, subprocess.TimeoutExpired):
        print("⚠️ Docker不可用，将使用SQLite作为后备数据库")
        return False
    except Exception as e:
        print(f"⚠️ 检查PostgreSQL时出错: {e}")
        print("将使用SQLite作为后备数据库")
        return False

def start_backend():
    """启动后端服务"""
    print("\n🚀 启动后端服务...")
    
    # 切换到backend目录
    backend_dir = Path("backend")
    if not backend_dir.exists():
        print("❌ 找不到backend目录")
        return False
    
    # 创建日志目录
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    print(f"📝 日志目录: {log_dir.absolute()}")
    
    try:
        print("启动FastAPI服务器...")
        print("服务地址: http://localhost:8000")
        print("API文档: http://localhost:8000/docs")
        print("Wireshark接口: http://localhost:8000/api/wireshark/interfaces")
        print("日志文件: logs/security_monitor.log")
        print("按 Ctrl+C 停止服务")
        print("-" * 60)
        
        # 使用uvicorn启动服务
        subprocess.run([
            sys.executable, "-m", "uvicorn", 
            "main:app", 
            "--host", "0.0.0.0", 
            "--port", "8000", 
            "--reload"
        ], cwd=backend_dir)
        
    except KeyboardInterrupt:
        print("\n👋 服务已停止")
        return True
    except Exception as e:
        print(f"❌ 启动服务失败: {e}")
        return False

def show_usage_info():
    """显示使用信息"""
    print("\n" + "=" * 60)
    print("使用说明")
    print("=" * 60)
    print("1. 后端服务已启动在 http://localhost:8000")
    print("2. 访问 http://localhost:8000/docs 查看API文档")
    print("3. 默认登录账号:")
    print("   - 管理员: admin / admin123")
    print("   - 监控员: monitor / monitor123")
    print("4. 系统使用Wireshark获取真实网络流量数据")
    print("5. 按 Ctrl+C 停止服务")
    print("\nWireshark特有功能:")
    print("- 接口列表: /api/wireshark/interfaces")
    print("- 开始捕获: POST /api/wireshark/start_capture")
    print("- 停止捕获: POST /api/wireshark/stop_capture")
    print("- 数据包分析: /api/wireshark/packet_analysis")
    print("- 网络连接: /api/wireshark/connections")
    print("- 接口状态: /api/wireshark/interface_status")
    print("- 流量统计: /api/traffic/statistics")
    print("\n注意事项:")
    print("- 需要管理员权限运行Wireshark")
    print("- 确保网络接口可用")
    print("- 防火墙可能阻止数据包捕获")

def check_permissions():
    """检查权限"""
    print("\n🔐 检查权限...")
    
    if platform.system().lower() == 'windows':
        try:
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
            if is_admin:
                print("✅ 以管理员权限运行")
            else:
                print("⚠️ 未以管理员权限运行，可能无法捕获数据包")
                print("建议以管理员身份运行此脚本")
        except Exception:
            print("⚠️ 无法检查管理员权限")
    else:
        # Linux/macOS
        if os.geteuid() == 0:
            print("✅ 以root权限运行")
        else:
            print("⚠️ 未以root权限运行，可能无法捕获数据包")
            print("建议使用sudo运行此脚本")

def test_wireshark_capture():
    """测试Wireshark捕获"""
    print("\n🧪 测试Wireshark捕获...")
    
    try:
        # 测试短时间捕获，在Windows下使用UTF-8编码
        if platform.system().lower() == 'windows':
            result = subprocess.run([
                'tshark', '-i', 'any', '-a', 'duration:3', '-T', 'fields', '-e', 'frame.len'
            ], capture_output=True, text=True, 
            encoding='utf-8', errors='ignore', timeout=10)
        else:
            result = subprocess.run([
                'tshark', '-i', 'any', '-a', 'duration:3', '-T', 'fields', '-e', 'frame.len'
            ], capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0 and result.stdout and result.stdout.strip():
            print("✅ Wireshark捕获测试成功")
            return True
        else:
            print("⚠️ Wireshark捕获测试失败")
            if result.stderr:
                print(f"错误信息: {result.stderr}")
            return False
    except Exception as e:
        print(f"❌ Wireshark捕获测试失败: {e}")
        return False

def main():
    """主函数"""
    print("正在检查环境...")
    
    if not check_environment():
        print("\n❌ 环境检查失败，请解决上述问题后重试")
        return
    
    print("\n✅ 环境检查通过")
    
    # 检查权限
    check_permissions()
    
    # 检查Wireshark
    if not check_wireshark():
        print("\n❌ Wireshark检查失败，请安装Wireshark后重试")
        return
    
    # 获取网络接口
    interfaces = get_network_interfaces()
    if not interfaces:
        print("\n❌ 未找到网络接口，请检查网络配置")
        return
    
    # 创建配置
    create_wireshark_config(interfaces)
    
    # 测试Wireshark捕获
    if not test_wireshark_capture():
        print("\n⚠️ Wireshark捕获测试失败，但继续启动服务")
    
    # 检查并启动PostgreSQL
    check_postgresql()
    
    # 显示使用信息
    show_usage_info()
    
    # 启动后端服务
    try:
        start_backend()
    except KeyboardInterrupt:
        print("\n👋 程序已退出")
    except Exception as e:
        print(f"\n❌ 程序运行出错: {e}")

if __name__ == "__main__":
    main()
