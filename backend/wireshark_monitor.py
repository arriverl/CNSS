"""
基于Wireshark的流量监控模块
使用tshark命令行工具获取真实网络流量数据
"""

import subprocess
import json
import time
import logging
import threading
from typing import Dict, List, Optional, Tuple
from collections import defaultdict, deque
import re
import os
import platform

logger = logging.getLogger(__name__)

class WiresharkMonitor:
    """基于Wireshark的流量监控器"""
    
    def __init__(self, interface: str = None, capture_duration: int = 5):
        self.interface = interface
        self.capture_duration = capture_duration
        self.is_running = False
        self.traffic_data = deque(maxlen=1000)  # 保存最近1000个数据点
        self.interface_stats = defaultdict(lambda: {
            'bytes_sent': 0,
            'bytes_recv': 0,
            'packets_sent': 0,
            'packets_recv': 0,
            'last_update': time.time()
        })
        self.capture_thread = None
        
    def check_tshark_available(self) -> bool:
        """检查tshark是否可用"""
        try:
            # 在Windows下使用UTF-8编码
            if platform.system().lower() == 'windows':
                result = subprocess.run(['tshark', '--version'], 
                                      capture_output=True, text=True, 
                                      encoding='utf-8', errors='ignore', timeout=5)
            else:
                result = subprocess.run(['tshark', '--version'], 
                                      capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                logger.info("tshark可用")
                return True
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        logger.warning("tshark不可用，请安装Wireshark")
        return False
    
    def get_available_interfaces(self) -> List[Dict]:
        """获取可用的网络接口"""
        interfaces = []
        
        try:
            # 使用tshark获取接口列表
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
                        # 解析接口信息
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
            logger.error(f"获取接口列表失败: {e}")
        
        # 如果tshark不可用，使用psutil获取接口
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
                logger.error(f"使用psutil获取接口失败: {e}")
        
        return interfaces
    
    def start_capture(self, interface: str = None) -> bool:
        """开始流量捕获"""
        if self.is_running:
            logger.warning("捕获已在运行中")
            return False
        
        if not self.check_tshark_available():
            logger.error("tshark不可用，无法开始捕获")
            return False
        
        target_interface = interface or self.interface
        if not target_interface:
            # 自动选择活跃接口
            target_interface = self._find_active_interface()
            if not target_interface:
                logger.error("未找到活跃的网络接口")
                return False
        
        self.interface = target_interface
        self.is_running = True
        
        # 启动捕获线程
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()
        
        logger.info(f"开始捕获接口 {target_interface} 的流量")
        return True
    
    def _find_active_interface(self) -> str:
        """自动查找活跃的网络接口"""
        # 按优先级排序的接口列表
        preferred_interfaces = [
            "WLAN",           # WiFi
            "以太网",         # 以太网
            "本地连接* 1",    # 本地连接
            "本地连接* 9",
            "本地连接* 10"
        ]
        
        for interface in preferred_interfaces:
            if self._test_interface_activity(interface):
                logger.info(f"选择活跃接口: {interface}")
                return interface
        
        # 如果没有找到活跃接口，返回第一个可用接口
        interfaces = self.get_available_interfaces()
        if interfaces:
            return interfaces[0]['name']
        
        return None
    
    def _test_interface_activity(self, interface: str) -> bool:
        """测试接口是否有网络活动"""
        try:
            cmd = [
                'tshark', '-i', interface,
                '-a', 'duration:3',
                '-T', 'fields', '-e', 'frame.len'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, 
                                  encoding='utf-8', errors='ignore', timeout=8)
            
            if result.returncode == 0 and result.stdout.strip():
                return True
        except Exception:
            pass
        
        return False
    
    def stop_capture(self):
        """停止流量捕获"""
        self.is_running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=5)
        logger.info("流量捕获已停止")
    
    def _capture_loop(self):
        """捕获循环"""
        while self.is_running:
            try:
                # 使用tshark捕获流量统计
                self._capture_interface_stats()
                time.sleep(self.capture_duration)
            except Exception as e:
                logger.error(f"捕获过程中出错: {e}")
                time.sleep(1)
    
    def _capture_interface_stats(self):
        """捕获接口统计信息"""
        try:
            # 使用tshark获取接口统计
            cmd = [
                'tshark', '-i', self.interface,
                '-T', 'fields', '-e', 'frame.len',
                '-e', 'frame.protocols',
                '-a', f'duration:{self.capture_duration}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.capture_duration + 5)
            
            if result.returncode == 0:
                self._parse_tshark_output(result.stdout)
            else:
                logger.warning(f"tshark命令失败: {result.stderr}")
                
        except subprocess.TimeoutExpired:
            logger.warning("tshark命令超时")
        except Exception as e:
            logger.error(f"捕获接口统计失败: {e}")
    
    def _parse_tshark_output(self, output: str):
        """解析tshark输出"""
        current_time = time.time()
        total_bytes = 0
        packet_count = 0
        
        for line in output.strip().split('\n'):
            if line.strip():
                parts = line.split('\t')
                if len(parts) >= 1:
                    try:
                        frame_len = int(parts[0])
                        total_bytes += frame_len
                        packet_count += 1
                    except ValueError:
                        continue
        
        # 更新统计数据
        if total_bytes > 0:
            self.interface_stats[self.interface]['bytes_sent'] += total_bytes
            self.interface_stats[self.interface]['bytes_recv'] += total_bytes
            self.interface_stats[self.interface]['packets_sent'] += packet_count
            self.interface_stats[self.interface]['packets_recv'] += packet_count
            self.interface_stats[self.interface]['last_update'] = current_time
    
    def get_traffic_data(self) -> List[Dict]:
        """获取流量数据"""
        current_time = time.time()
        traffic_data = []
        
        for interface, stats in self.interface_stats.items():
            # 计算带宽
            time_diff = current_time - stats['last_update']
            bandwidth_sent = 0
            bandwidth_recv = 0
            
            if time_diff > 0:
                bandwidth_sent = stats['bytes_sent'] / time_diff
                bandwidth_recv = stats['bytes_recv'] / time_diff
            
            traffic_data.append({
                'timestamp': current_time,
                'interface': interface,
                'bytes_sent': stats['bytes_sent'],
                'bytes_recv': stats['bytes_recv'],
                'packets_sent': stats['packets_sent'],
                'packets_recv': stats['packets_recv'],
                'bandwidth_sent': bandwidth_sent,
                'bandwidth_recv': bandwidth_recv
            })
        
        return traffic_data
    
    def get_packet_analysis(self, duration: int = 10) -> Dict:
        """获取数据包分析"""
        try:
            cmd = [
                'tshark', '-i', self.interface,
                '-T', 'fields', '-e', 'ip.src', '-e', 'ip.dst', '-e', 'ip.proto',
                '-e', 'tcp.srcport', '-e', 'tcp.dstport',
                '-e', 'udp.srcport', '-e', 'udp.dstport',
                '-a', f'duration:{duration}'
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=duration + 5)
            
            if result.returncode == 0:
                return self._parse_packet_analysis(result.stdout)
            else:
                logger.warning(f"数据包分析失败: {result.stderr}")
                return {}
                
        except Exception as e:
            logger.error(f"数据包分析出错: {e}")
            return {}
    
    def _parse_packet_analysis(self, output: str) -> Dict:
        """解析数据包分析结果"""
        analysis = {
            'total_packets': 0,
            'protocols': defaultdict(int),
            'top_sources': defaultdict(int),
            'top_destinations': defaultdict(int),
            'ports': defaultdict(int)
        }
        
        for line in output.strip().split('\n'):
            if line.strip():
                parts = line.split('\t')
                if len(parts) >= 3:
                    src_ip = parts[0]
                    dst_ip = parts[1]
                    protocol = parts[2]
                    
                    analysis['total_packets'] += 1
                    analysis['protocols'][protocol] += 1
                    analysis['top_sources'][src_ip] += 1
                    analysis['top_destinations'][dst_ip] += 1
                    
                    # 解析端口信息
                    if len(parts) >= 5:
                        src_port = parts[3]
                        dst_port = parts[4]
                        if src_port and src_port != '':
                            analysis['ports'][src_port] += 1
                        if dst_port and dst_port != '':
                            analysis['ports'][dst_port] += 1
        
        return dict(analysis)
    
    def get_network_connections(self) -> List[Dict]:
        """获取网络连接信息"""
        connections = []
        
        try:
            # 使用netstat获取连接信息
            if platform.system().lower() == 'windows':
                cmd = ['netstat', '-an']
            else:
                cmd = ['netstat', '-tuln']
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                connections = self._parse_netstat_output(result.stdout)
                
        except Exception as e:
            logger.error(f"获取网络连接失败: {e}")
        
        return connections
    
    def _parse_netstat_output(self, output: str) -> List[Dict]:
        """解析netstat输出，提取连接信息"""
        connections = []
        
        for line in output.strip().split('\n'):
            if line.strip() and not line.startswith('Active') and not line.startswith('Proto'):
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        protocol = parts[0].upper()
                        
                        # 解析本地地址和端口
                        local_addr = parts[1] if len(parts) > 1 else '0.0.0.0:0'
                        remote_addr = parts[2] if len(parts) > 2 else '0.0.0.0:0'
                        state = parts[3] if len(parts) > 3 else 'UNKNOWN'
                        
                        # 提取IP和端口
                        def parse_address(addr_str):
                            """解析地址字符串，返回(ip, port)"""
                            try:
                                if ':' in addr_str:
                                    ip, port = addr_str.rsplit(':', 1)
                                    return ip, int(port) if port.isdigit() else 0
                                else:
                                    return addr_str, 0
                            except:
                                return '0.0.0.0', 0
                        
                        src_ip, src_port = parse_address(local_addr)
                        dst_ip, dst_port = parse_address(remote_addr)
                        
                        # 提取TCP标志（从状态推断）
                        tcp_flags = {}
                        if protocol == 'TCP':
                            if 'SYN' in state or 'ESTABLISHED' in state:
                                tcp_flags['SYN'] = 1
                            if 'RST' in state:
                                tcp_flags['RST'] = 1
                            if 'FIN' in state or 'CLOSE' in state:
                                tcp_flags['FIN'] = 1
                        
                        connection = {
                            'protocol': protocol,
                            'src_ip': src_ip,
                            'dst_ip': dst_ip,
                            'port': dst_port if dst_port else src_port,
                            'src_port': src_port,
                            'dst_port': dst_port,
                            'state': state,
                            'tcp_flags': tcp_flags,
                            'interface': self.interface or 'unknown',
                            'bytes_sent': 0,  # netstat不提供流量统计
                            'bytes_recv': 0,
                            'packets_sent': 0,
                            'packets_recv': 0
                        }
                        connections.append(connection)
                    except (IndexError, ValueError) as e:
                        continue
        
        return connections
    
    def get_interface_status(self) -> Dict:
        """获取接口状态"""
        try:
            # 使用ip命令获取接口状态（Linux）
            if platform.system().lower() == 'linux':
                result = subprocess.run(['ip', 'link', 'show'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return self._parse_ip_link_output(result.stdout)
            
            # 使用netsh命令获取接口状态（Windows）
            elif platform.system().lower() == 'windows':
                result = subprocess.run(['netsh', 'interface', 'show', 'interface'], 
                                      capture_output=True, text=True, timeout=5)
                if result.returncode == 0:
                    return self._parse_netsh_output(result.stdout)
            
        except Exception as e:
            logger.error(f"获取接口状态失败: {e}")
        
        return {}
    
    def _parse_ip_link_output(self, output: str) -> Dict:
        """解析ip link输出"""
        interfaces = {}
        
        for line in output.strip().split('\n'):
            if ':' in line and 'state' in line:
                # 解析接口状态
                match = re.search(r'(\d+):\s+(\w+).*state\s+(\w+)', line)
                if match:
                    interface_id, interface_name, state = match.groups()
                    interfaces[interface_name] = {
                        'id': interface_id,
                        'name': interface_name,
                        'state': state,
                        'status': 'UP' if state == 'UP' else 'DOWN'
                    }
        
        return interfaces
    
    def _parse_netsh_output(self, output: str) -> Dict:
        """解析netsh输出"""
        interfaces = {}
        
        for line in output.strip().split('\n'):
            if line.strip() and not line.startswith('Admin') and not line.startswith('State'):
                parts = line.split()
                if len(parts) >= 4:
                    try:
                        interface_name = parts[3]
                        state = parts[0]
                        interfaces[interface_name] = {
                            'name': interface_name,
                            'state': state,
                            'status': 'UP' if state == 'Enabled' else 'DOWN'
                        }
                    except IndexError:
                        continue
        
        return interfaces

class RealTimeTrafficAnalyzer:
    """实时流量分析器"""
    
    def __init__(self):
        self.traffic_history = deque(maxlen=1000)
        self.anomaly_threshold = 0.8  # 异常检测阈值
        
    def analyze_traffic(self, traffic_data: List[Dict]) -> List[Dict]:
        """分析流量数据，检测异常"""
        anomalies = []
        
        for data in traffic_data:
            # 添加到历史数据
            self.traffic_history.append(data)
            
            # 检测异常
            anomaly = self._detect_anomaly(data)
            if anomaly:
                anomalies.append(anomaly)
        
        return anomalies
    
    def _detect_anomaly(self, data: Dict) -> Optional[Dict]:
        """检测流量异常"""
        if len(self.traffic_history) < 10:
            return None
        
        # 计算历史平均值
        recent_data = list(self.traffic_history)[-10:]
        avg_bandwidth_sent = sum(d.get('bandwidth_sent', 0) for d in recent_data) / len(recent_data)
        avg_bandwidth_recv = sum(d.get('bandwidth_recv', 0) for d in recent_data) / len(recent_data)
        
        current_sent = data.get('bandwidth_sent', 0)
        current_recv = data.get('bandwidth_recv', 0)
        
        # 检测异常高带宽
        if current_sent > avg_bandwidth_sent * 5 or current_recv > avg_bandwidth_recv * 5:
            return {
                'type': 'high_bandwidth',
                'severity': 'high',
                'interface': data.get('interface', 'unknown'),
                'description': f"检测到异常高带宽使用",
                'timestamp': data.get('timestamp', time.time()),
                'current_sent': current_sent,
                'current_recv': current_recv,
                'avg_sent': avg_bandwidth_sent,
                'avg_recv': avg_bandwidth_recv
            }
        
        return None
    
    def get_traffic_statistics(self) -> Dict:
        """获取流量统计信息"""
        if not self.traffic_history:
            return {}
        
        recent_data = list(self.traffic_history)[-100:]  # 最近100个数据点
        
        total_bytes_sent = sum(d.get('bytes_sent', 0) for d in recent_data)
        total_bytes_recv = sum(d.get('bytes_recv', 0) for d in recent_data)
        total_packets_sent = sum(d.get('packets_sent', 0) for d in recent_data)
        total_packets_recv = sum(d.get('packets_recv', 0) for d in recent_data)
        
        avg_bandwidth_sent = sum(d.get('bandwidth_sent', 0) for d in recent_data) / len(recent_data)
        avg_bandwidth_recv = sum(d.get('bandwidth_recv', 0) for d in recent_data) / len(recent_data)
        
        return {
            'total_bytes_sent': total_bytes_sent,
            'total_bytes_recv': total_bytes_recv,
            'total_packets_sent': total_packets_sent,
            'total_packets_recv': total_packets_recv,
            'avg_bandwidth_sent': avg_bandwidth_sent,
            'avg_bandwidth_recv': avg_bandwidth_recv,
            'data_points': len(recent_data)
        }
