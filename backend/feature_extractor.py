"""
特征提取模块
从实时流量数据中提取特征用于异常检测
"""

import logging
import numpy as np
from typing import List, Dict, Optional
from collections import defaultdict, deque
from datetime import datetime, timedelta
import statistics

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """特征提取器"""
    
    def __init__(self, window_size: int = 1000):
        self.window_size = window_size
        self.ip_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'dst_ips': set(),
            'dst_ports': set(),
            'protocols': set(),
            'syn_count': 0,
            'rst_count': 0,
            'fin_count': 0,
            'timestamps': deque(maxlen=50)
        })
    
    def extract_features_from_traffic(self, traffic_data: List[Dict]) -> np.ndarray:
        """从流量数据中提取特征
        
        Args:
            traffic_data: 流量数据列表，每个元素包含：
                - src_ip, dst_ip
                - bytes_sent, bytes_recv
                - packets_sent, packets_recv
                - protocol
                - port
                - timestamp
        
        Returns:
            特征矩阵，每行代表一个连接/数据点的特征向量
        """
        features = []
        
        for data in traffic_data:
            # 更新统计信息
            src_ip = data.get('src_ip', 'unknown')
            dst_ip = data.get('dst_ip', 'unknown')
            protocol = data.get('protocol', 'unknown')
            port = data.get('port', 0)
            
            if src_ip and src_ip != 'unknown':
                self.ip_stats[src_ip]['packet_count'] += data.get('packets_sent', 0) + data.get('packets_recv', 0)
                self.ip_stats[src_ip]['byte_count'] += data.get('bytes_sent', 0) + data.get('bytes_recv', 0)
                self.ip_stats[src_ip]['dst_ips'].add(dst_ip)
                if port:
                    self.ip_stats[src_ip]['dst_ports'].add(port)
                if protocol:
                    self.ip_stats[src_ip]['protocols'].add(protocol)
                
                # TCP标志统计（如果可用）
                tcp_flags = data.get('tcp_flags', {})
                self.ip_stats[src_ip]['syn_count'] += tcp_flags.get('SYN', 0)
                self.ip_stats[src_ip]['rst_count'] += tcp_flags.get('RST', 0)
                self.ip_stats[src_ip]['fin_count'] += tcp_flags.get('FIN', 0)
                
                timestamp = data.get('timestamp', datetime.utcnow())
                if isinstance(timestamp, (int, float)):
                    timestamp = datetime.fromtimestamp(timestamp)
                self.ip_stats[src_ip]['timestamps'].append(timestamp)
            
            # 提取单个连接的特征
            feature_vector = self._extract_connection_features(data)
            if feature_vector:
                features.append(feature_vector)
        
        if not features:
            return np.array([])
        
        return np.array(features)
    
    def _extract_connection_features(self, data: Dict) -> Optional[List[float]]:
        """提取单个连接的特征向量"""
        try:
            # 基础流量特征
            bytes_sent = data.get('bytes_sent', 0)
            bytes_recv = data.get('bytes_recv', 0)
            packets_sent = data.get('packets_sent', 0)
            packets_recv = data.get('packets_recv', 0)
            total_bytes = bytes_sent + bytes_recv
            total_packets = packets_sent + packets_recv
            
            # 计算带宽特征
            timestamp = data.get('timestamp', datetime.utcnow())
            if isinstance(timestamp, (int, float)):
                timestamp = datetime.fromtimestamp(timestamp)
            
            # 时间特征
            hour = timestamp.hour
            weekday = timestamp.weekday()
            minute = timestamp.minute
            
            # 协议特征（编码）
            protocol = data.get('protocol', 'unknown').upper()
            protocol_encoding = {
                'TCP': 1.0,
                'UDP': 2.0,
                'ICMP': 3.0,
                'HTTP': 4.0,
                'HTTPS': 5.0,
                'DNS': 6.0,
                'UNKNOWN': 0.0
            }
            protocol_code = protocol_encoding.get(protocol, 0.0)
            
            # 端口特征
            port = data.get('port', 0)
            is_well_known_port = 1.0 if 0 < port < 1024 else 0.0
            
            # IP统计特征（基于历史窗口）
            src_ip = data.get('src_ip', '')
            ip_features = self._extract_ip_statistical_features(src_ip)
            
            # TCP标志特征
            tcp_flags = data.get('tcp_flags', {})
            syn_ratio = 0.0
            if total_packets > 0:
                syn_count = tcp_flags.get('SYN', 0)
                syn_ratio = syn_count / total_packets
            
            # 构建特征向量
            feature_vector = [
                # 基础流量特征（归一化）
                np.log1p(total_bytes),  # 使用log防止数值过大
                np.log1p(total_packets),
                bytes_sent / max(total_bytes, 1),  # 发送比例
                bytes_recv / max(total_bytes, 1),  # 接收比例
                
                # 时间特征
                hour / 24.0,  # 归一化到0-1
                weekday / 7.0,
                minute / 60.0,
                
                # 协议和端口特征
                protocol_code,
                is_well_known_port,
                port / 65535.0,  # 端口归一化
                
                # TCP特征
                syn_ratio,
                
                # IP统计特征
                ip_features['unique_dst_count'],
                ip_features['unique_port_count'],
                ip_features['packet_rate'],
                ip_features['byte_rate'],
            ]
            
            return feature_vector
            
        except Exception as e:
            logger.error(f"提取连接特征失败: {e}")
            return None
    
    def _extract_ip_statistical_features(self, src_ip: str) -> Dict[str, float]:
        """提取IP的统计特征"""
        if not src_ip or src_ip == 'unknown' or src_ip not in self.ip_stats:
            return {
                'unique_dst_count': 0.0,
                'unique_port_count': 0.0,
                'packet_rate': 0.0,
                'byte_rate': 0.0,
            }
        
        stats = self.ip_stats[src_ip]
        
        # 计算时间窗口内的速率
        timestamps = list(stats['timestamps'])
        if len(timestamps) >= 2:
            time_span = (timestamps[-1] - timestamps[0]).total_seconds()
            if time_span > 0:
                packet_rate = stats['packet_count'] / time_span
                byte_rate = stats['byte_count'] / time_span
            else:
                packet_rate = 0.0
                byte_rate = 0.0
        else:
            packet_rate = 0.0
            byte_rate = 0.0
        
        return {
            'unique_dst_count': min(len(stats['dst_ips']), 100) / 100.0,  # 归一化到0-1
            'unique_port_count': min(len(stats['dst_ports']), 100) / 100.0,
            'packet_rate': np.log1p(packet_rate),  # 使用log防止数值过大
            'byte_rate': np.log1p(byte_rate),
        }
    
    def extract_aggregated_features(self, traffic_data: List[Dict], window_minutes: int = 5) -> Dict:
        """提取聚合特征（用于规则匹配）
        
        Returns:
            包含聚合统计特征的字典
        """
        if not traffic_data:
            return {}
        
        # 按源IP聚合
        src_ip_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'dst_ips': set(),
            'dst_ports': set(),
            'syn_count': 0,
            'connection_count': 0
        })
        
        for data in traffic_data:
            src_ip = data.get('src_ip', '')
            if src_ip:
                stats = src_ip_stats[src_ip]
                stats['packet_count'] += data.get('packets_sent', 0) + data.get('packets_recv', 0)
                stats['byte_count'] += data.get('bytes_sent', 0) + data.get('bytes_recv', 0)
                stats['dst_ips'].add(data.get('dst_ip', ''))
                if data.get('port'):
                    stats['dst_ports'].add(data.get('port'))
                stats['connection_count'] += 1
                
                tcp_flags = data.get('tcp_flags', {})
                stats['syn_count'] += tcp_flags.get('SYN', 0)
        
        # 计算聚合统计
        aggregated = {
            'total_connections': len(traffic_data),
            'unique_src_ips': len(src_ip_stats),
            'high_activity_ips': [],
            'scan_patterns': []
        }
        
        for src_ip, stats in src_ip_stats.items():
            # 检测高活跃IP
            if stats['connection_count'] > 50:  # 5分钟内超过50个连接
                aggregated['high_activity_ips'].append({
                    'ip': src_ip,
                    'connections': stats['connection_count'],
                    'packets': stats['packet_count'],
                    'bytes': stats['byte_count']
                })
            
            # 检测扫描模式
            syn_ratio = stats['syn_count'] / max(stats['packet_count'], 1)
            unique_dst = len(stats['dst_ips'])
            unique_ports = len(stats['dst_ports'])
            
            if syn_ratio > 0.8 and unique_dst > 10:
                aggregated['scan_patterns'].append({
                    'ip': src_ip,
                    'type': 'port_scan',
                    'syn_ratio': syn_ratio,
                    'unique_dst': unique_dst,
                    'unique_ports': unique_ports
                })
        
        return aggregated

