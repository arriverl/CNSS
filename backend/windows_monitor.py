"""
Windows环境下的系统监控模块
支持无网络接口环境下的模拟数据生成和系统监控
"""

import time
import random
import psutil
import logging
from typing import Dict, List, Optional
from datetime import datetime, timedelta
import json
import os

logger = logging.getLogger(__name__)

class WindowsSystemMonitor:
    """Windows系统监控器"""
    
    def __init__(self, enable_simulation: bool = True):
        self.enable_simulation = enable_simulation
        self.simulation_data = self._init_simulation_data()
        self.last_update = time.time()
        
    def _init_simulation_data(self) -> Dict:
        """初始化模拟数据"""
        return {
            'interfaces': [
                {'name': 'eth0', 'type': 'ethernet', 'status': 'up'},
                {'name': 'wlan0', 'name': 'wifi', 'type': 'wireless', 'status': 'up'},
                {'name': 'lo', 'type': 'loopback', 'status': 'up'}
            ],
            'traffic_patterns': {
                'normal': {'min_bytes': 1000, 'max_bytes': 100000},
                'high': {'min_bytes': 100000, 'max_bytes': 1000000},
                'burst': {'min_bytes': 1000000, 'max_bytes': 10000000}
            },
            'current_pattern': 'normal',
            'pattern_start_time': time.time()
        }
    
    def get_system_info(self) -> Dict:
        """获取系统信息"""
        try:
            # 获取真实的系统信息
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('C:')
            
            # 获取网络接口（如果存在）
            network_interfaces = []
            try:
                net_io = psutil.net_io_counters(pernic=True)
                network_interfaces = list(net_io.keys())
            except Exception as e:
                logger.warning(f"无法获取网络接口: {e}")
                # 使用模拟接口
                network_interfaces = ['eth0', 'wlan0', 'lo']
            
            return {
                'cpu_percent': cpu_percent,
                'memory_percent': memory.percent,
                'disk_usage': (disk.used / disk.total) * 100,
                'network_interfaces': network_interfaces,
                'timestamp': time.time(),
                'platform': 'windows',
                'simulation_mode': self.enable_simulation
            }
        except Exception as e:
            logger.error(f"获取系统信息失败: {e}")
            return self._get_simulation_system_info()
    
    def _get_simulation_system_info(self) -> Dict:
        """获取模拟系统信息"""
        return {
            'cpu_percent': random.uniform(10, 80),
            'memory_percent': random.uniform(20, 90),
            'disk_usage': random.uniform(30, 95),
            'network_interfaces': ['eth0', 'wlan0', 'lo'],
            'timestamp': time.time(),
            'platform': 'windows',
            'simulation_mode': True
        }
    
    def get_traffic_data(self) -> List[Dict]:
        """获取流量数据"""
        if self.enable_simulation:
            return self._generate_simulation_traffic()
        else:
            return self._get_real_traffic_data()
    
    def _generate_simulation_traffic(self) -> List[Dict]:
        """生成模拟流量数据"""
        current_time = time.time()
        traffic_data = []
        
        # 模拟不同的流量模式
        self._update_traffic_pattern()
        
        for interface in self.simulation_data['interfaces']:
            # 根据接口类型生成不同的流量模式
            if interface['name'] == 'lo':
                # 回环接口流量较小
                bytes_sent = random.randint(100, 10000)
                bytes_recv = random.randint(100, 10000)
            elif interface['name'] == 'wlan0':
                # WiFi接口流量中等
                bytes_sent = random.randint(10000, 100000)
                bytes_recv = random.randint(10000, 100000)
            else:
                # 以太网接口流量较大
                pattern = self.simulation_data['current_pattern']
                min_bytes = self.simulation_data['traffic_patterns'][pattern]['min_bytes']
                max_bytes = self.simulation_data['traffic_patterns'][pattern]['max_bytes']
                
                bytes_sent = random.randint(min_bytes, max_bytes)
                bytes_recv = random.randint(min_bytes, max_bytes)
            
            # 计算带宽（基于时间差）
            time_diff = current_time - self.last_update
            if time_diff > 0:
                bandwidth_sent = bytes_sent / time_diff
                bandwidth_recv = bytes_recv / time_diff
            else:
                bandwidth_sent = 0
                bandwidth_recv = 0
            
            traffic_data.append({
                'timestamp': current_time,
                'interface': interface['name'],
                'bytes_sent': bytes_sent,
                'bytes_recv': bytes_recv,
                'packets_sent': random.randint(100, 10000),
                'packets_recv': random.randint(100, 10000),
                'bandwidth_sent': bandwidth_sent,
                'bandwidth_recv': bandwidth_recv,
                'interface_type': interface['type'],
                'status': interface['status']
            })
        
        self.last_update = current_time
        return traffic_data
    
    def _update_traffic_pattern(self):
        """更新流量模式"""
        current_time = time.time()
        pattern_duration = current_time - self.simulation_data['pattern_start_time']
        
        # 每30秒切换一次流量模式
        if pattern_duration > 30:
            patterns = list(self.simulation_data['traffic_patterns'].keys())
            current_pattern = self.simulation_data['current_pattern']
            current_index = patterns.index(current_pattern)
            next_index = (current_index + 1) % len(patterns)
            
            self.simulation_data['current_pattern'] = patterns[next_index]
            self.simulation_data['pattern_start_time'] = current_time
            
            logger.info(f"切换到流量模式: {patterns[next_index]}")
    
    def _get_real_traffic_data(self) -> List[Dict]:
        """获取真实流量数据"""
        try:
            net_io = psutil.net_io_counters(pernic=True)
            current_time = time.time()
            traffic_data = []
            
            for interface, stats in net_io.items():
                # 计算带宽（需要与历史数据对比）
                bandwidth_sent = 0.0
                bandwidth_recv = 0.0
                
                traffic_data.append({
                    'timestamp': current_time,
                    'interface': interface,
                    'bytes_sent': stats.bytes_sent,
                    'bytes_recv': stats.bytes_recv,
                    'packets_sent': stats.packets_sent,
                    'packets_recv': stats.packets_recv,
                    'bandwidth_sent': bandwidth_sent,
                    'bandwidth_recv': bandwidth_recv,
                    'interface_type': 'real',
                    'status': 'up'
                })
            
            return traffic_data
            
        except Exception as e:
            logger.error(f"获取真实流量数据失败: {e}")
            return self._generate_simulation_traffic()
    
    def get_process_info(self) -> List[Dict]:
        """获取进程信息"""
        try:
            processes = []
            for proc in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
                try:
                    proc_info = proc.info
                    if proc_info['cpu_percent'] > 0.1 or proc_info['memory_percent'] > 0.1:
                        processes.append({
                            'pid': proc_info['pid'],
                            'name': proc_info['name'],
                            'cpu_percent': proc_info['cpu_percent'],
                            'memory_percent': proc_info['memory_percent']
                        })
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
            
            # 按CPU使用率排序
            processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
            return processes[:20]  # 返回前20个进程
            
        except Exception as e:
            logger.error(f"获取进程信息失败: {e}")
            return []
    
    def get_network_connections(self) -> List[Dict]:
        """获取网络连接信息"""
        try:
            connections = []
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'ESTABLISHED':
                    connections.append({
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A",
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A",
                        'status': conn.status,
                        'pid': conn.pid
                    })
            return connections[:50]  # 返回前50个连接
            
        except Exception as e:
            logger.error(f"获取网络连接失败: {e}")
            return []
    
    def get_disk_io(self) -> Dict:
        """获取磁盘IO信息"""
        try:
            disk_io = psutil.disk_io_counters()
            return {
                'read_count': disk_io.read_count,
                'write_count': disk_io.write_count,
                'read_bytes': disk_io.read_bytes,
                'write_bytes': disk_io.write_bytes,
                'read_time': disk_io.read_time,
                'write_time': disk_io.write_time
            }
        except Exception as e:
            logger.error(f"获取磁盘IO失败: {e}")
            return {}
    
    def get_system_uptime(self) -> Dict:
        """获取系统运行时间"""
        try:
            boot_time = psutil.boot_time()
            uptime = time.time() - boot_time
            return {
                'boot_time': boot_time,
                'uptime_seconds': uptime,
                'uptime_formatted': str(timedelta(seconds=int(uptime)))
            }
        except Exception as e:
            logger.error(f"获取系统运行时间失败: {e}")
            return {}
    
    def save_simulation_config(self, config_path: str = "simulation_config.json"):
        """保存模拟配置"""
        try:
            config = {
                'enable_simulation': self.enable_simulation,
                'interfaces': self.simulation_data['interfaces'],
                'traffic_patterns': self.simulation_data['traffic_patterns'],
                'current_pattern': self.simulation_data['current_pattern']
            }
            
            with open(config_path, 'w', encoding='utf-8') as f:
                json.dump(config, f, indent=2, ensure_ascii=False)
                
            logger.info(f"模拟配置已保存到: {config_path}")
            
        except Exception as e:
            logger.error(f"保存模拟配置失败: {e}")
    
    def load_simulation_config(self, config_path: str = "simulation_config.json"):
        """加载模拟配置"""
        try:
            if os.path.exists(config_path):
                with open(config_path, 'r', encoding='utf-8') as f:
                    config = json.load(f)
                
                self.enable_simulation = config.get('enable_simulation', True)
                self.simulation_data.update(config)
                
                logger.info(f"模拟配置已从 {config_path} 加载")
            else:
                logger.info("未找到模拟配置文件，使用默认配置")
                
        except Exception as e:
            logger.error(f"加载模拟配置失败: {e}")

class WindowsSecurityMonitor:
    """Windows安全监控器"""
    
    def __init__(self):
        self.alerts = []
        self.alert_history = []
    
    def analyze_system_security(self, system_info: Dict, traffic_data: List[Dict]) -> List[Dict]:
        """分析系统安全状态"""
        alerts = []
        
        # 检查CPU使用率异常
        if system_info.get('cpu_percent', 0) > 90:
            alerts.append({
                'type': 'high_cpu_usage',
                'severity': 'high',
                'description': f"CPU使用率过高: {system_info['cpu_percent']:.1f}%",
                'timestamp': time.time()
            })
        
        # 检查内存使用率异常
        if system_info.get('memory_percent', 0) > 95:
            alerts.append({
                'type': 'high_memory_usage',
                'severity': 'critical',
                'description': f"内存使用率过高: {system_info['memory_percent']:.1f}%",
                'timestamp': time.time()
            })
        
        # 检查磁盘使用率异常
        if system_info.get('disk_usage', 0) > 90:
            alerts.append({
                'type': 'high_disk_usage',
                'severity': 'high',
                'description': f"磁盘使用率过高: {system_info['disk_usage']:.1f}%",
                'timestamp': time.time()
            })
        
        # 检查流量异常（模拟数据）
        for traffic in traffic_data:
            if traffic.get('bandwidth_sent', 0) > 1000000000:  # 1GB/s
                alerts.append({
                    'type': 'high_bandwidth',
                    'severity': 'medium',
                    'description': f"接口 {traffic['interface']} 带宽异常高",
                    'timestamp': time.time()
                })
        
        # 更新告警历史
        self.alerts.extend(alerts)
        self.alert_history.extend(alerts)
        
        # 清理过期告警（保留最近1小时）
        current_time = time.time()
        self.alerts = [alert for alert in self.alerts if current_time - alert['timestamp'] < 3600]
        
        return alerts
    
    def get_security_summary(self) -> Dict:
        """获取安全摘要"""
        current_time = time.time()
        recent_alerts = [alert for alert in self.alert_history if current_time - alert['timestamp'] < 3600]
        
        return {
            'total_alerts': len(recent_alerts),
            'critical_alerts': len([a for a in recent_alerts if a['severity'] == 'critical']),
            'high_alerts': len([a for a in recent_alerts if a['severity'] == 'high']),
            'medium_alerts': len([a for a in recent_alerts if a['severity'] == 'medium']),
            'low_alerts': len([a for a in recent_alerts if a['severity'] == 'low'])
        }



