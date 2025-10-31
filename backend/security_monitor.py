"""
网络安全监控模块
集成流量分析、异常检测、威胁识别等功能
"""

import time
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
from collections import deque, defaultdict
import statistics

logger = logging.getLogger(__name__)

@dataclass
class SecurityAlert:
    """安全告警数据结构"""
    alert_id: str
    alert_type: str
    severity: str  # low, medium, high, critical
    interface: str
    description: str
    timestamp: float
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    bytes_transferred: Optional[int] = None
    confidence: float = 0.0  # 0.0-1.0

class TrafficAnalyzer:
    """流量分析器"""
    
    def __init__(self, window_size: int = 100):
        self.window_size = window_size
        self.traffic_history = deque(maxlen=window_size)
        self.interface_stats = defaultdict(lambda: {
            'bytes_sent': deque(maxlen=window_size),
            'bytes_recv': deque(maxlen=window_size),
            'packets_sent': deque(maxlen=window_size),
            'packets_recv': deque(maxlen=window_size)
        })
        
    def add_traffic_data(self, traffic_data: Dict):
        """添加流量数据"""
        self.traffic_history.append(traffic_data)
        
        interface = traffic_data.get('interface', 'unknown')
        self.interface_stats[interface]['bytes_sent'].append(traffic_data.get('bytes_sent', 0))
        self.interface_stats[interface]['bytes_recv'].append(traffic_data.get('bytes_recv', 0))
        self.interface_stats[interface]['packets_sent'].append(traffic_data.get('packets_sent', 0))
        self.interface_stats[interface]['packets_recv'].append(traffic_data.get('packets_recv', 0))
    
    def detect_anomalies(self) -> List[SecurityAlert]:
        """检测流量异常"""
        alerts = []
        
        for interface, stats in self.interface_stats.items():
            if len(stats['bytes_sent']) < 10:  # 需要足够的数据点
                continue
                
            # 检测带宽异常
            bandwidth_alerts = self._detect_bandwidth_anomalies(interface, stats)
            alerts.extend(bandwidth_alerts)
            
            # 检测流量模式异常
            pattern_alerts = self._detect_traffic_pattern_anomalies(interface, stats)
            alerts.extend(pattern_alerts)
            
            # 检测连接异常
            connection_alerts = self._detect_connection_anomalies(interface, stats)
            alerts.extend(connection_alerts)
        
        return alerts
    
    def _detect_bandwidth_anomalies(self, interface: str, stats: Dict) -> List[SecurityAlert]:
        """检测带宽异常"""
        alerts = []
        
        # 计算当前带宽
        if len(stats['bytes_sent']) >= 2:
            current_sent = stats['bytes_sent'][-1]
            previous_sent = stats['bytes_sent'][-2]
            bandwidth_sent = current_sent - previous_sent
            
            # 计算历史平均值和标准差
            if len(stats['bytes_sent']) >= 10:
                historical_data = list(stats['bytes_sent'])[-10:-1]
                mean_sent = statistics.mean(historical_data)
                std_sent = statistics.stdev(historical_data) if len(historical_data) > 1 else 0
                
                # 检测异常高带宽
                if bandwidth_sent > mean_sent + 3 * std_sent and bandwidth_sent > 1000000000:  # 1GB/s
                    alert = SecurityAlert(
                        alert_id=f"high_bandwidth_{int(time.time())}",
                        alert_type="high_bandwidth",
                        severity="high",
                        interface=interface,
                        description=f"接口 {interface} 检测到异常高发送带宽: {bandwidth_sent / 1000000:.2f} MB/s",
                        timestamp=time.time(),
                        bytes_transferred=bandwidth_sent,
                        confidence=0.8
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_traffic_pattern_anomalies(self, interface: str, stats: Dict) -> List[SecurityAlert]:
        """检测流量模式异常"""
        alerts = []
        
        # 检测流量突然停止
        if len(stats['bytes_sent']) >= 5:
            recent_sent = list(stats['bytes_sent'])[-5:]
            if all(x == recent_sent[0] for x in recent_sent) and recent_sent[0] > 0:
                alert = SecurityAlert(
                    alert_id=f"traffic_stop_{int(time.time())}",
                    alert_type="traffic_stop",
                    severity="medium",
                    interface=interface,
                    description=f"接口 {interface} 流量突然停止",
                    timestamp=time.time(),
                    confidence=0.9
                )
                alerts.append(alert)
        
        # 检测流量激增
        if len(stats['bytes_sent']) >= 10:
            recent_data = list(stats['bytes_sent'])[-10:]
            if len(recent_data) >= 5:
                first_half = recent_data[:5]
                second_half = recent_data[5:]
                
                if statistics.mean(second_half) > statistics.mean(first_half) * 5:
                    alert = SecurityAlert(
                        alert_id=f"traffic_surge_{int(time.time())}",
                        alert_type="traffic_surge",
                        severity="medium",
                        interface=interface,
                        description=f"接口 {interface} 检测到流量激增",
                        timestamp=time.time(),
                        confidence=0.7
                    )
                    alerts.append(alert)
        
        return alerts
    
    def _detect_connection_anomalies(self, interface: str, stats: Dict) -> List[SecurityAlert]:
        """检测连接异常"""
        alerts = []
        
        # 检测包数异常
        if len(stats['packets_sent']) >= 10:
            recent_packets = list(stats['packets_sent'])[-10:]
            packet_rate = [recent_packets[i] - recent_packets[i-1] for i in range(1, len(recent_packets))]
            
            if packet_rate:
                avg_rate = statistics.mean(packet_rate)
                if avg_rate > 10000:  # 每秒超过10000个包
                    alert = SecurityAlert(
                        alert_id=f"high_packet_rate_{int(time.time())}",
                        alert_type="high_packet_rate",
                        severity="medium",
                        interface=interface,
                        description=f"接口 {interface} 检测到异常高包速率: {avg_rate:.0f} 包/秒",
                        timestamp=time.time(),
                        confidence=0.6
                    )
                    alerts.append(alert)
        
        return alerts

class ThreatDetector:
    """威胁检测器"""
    
    def __init__(self):
        self.suspicious_patterns = {
            'ddos': self._detect_ddos_pattern,
            'port_scan': self._detect_port_scan,
            'data_exfiltration': self._detect_data_exfiltration
        }
    
    def analyze_traffic(self, traffic_data: List[Dict]) -> List[SecurityAlert]:
        """分析流量数据，检测威胁"""
        alerts = []
        
        for pattern_name, detector_func in self.suspicious_patterns.items():
            pattern_alerts = detector_func(traffic_data)
            alerts.extend(pattern_alerts)
        
        return alerts
    
    def _detect_ddos_pattern(self, traffic_data: List[Dict]) -> List[SecurityAlert]:
        """检测DDoS攻击模式"""
        alerts = []
        
        # 简化的DDoS检测：检测短时间内大量连接
        if len(traffic_data) >= 20:
            recent_data = traffic_data[-20:]
            total_packets = sum(data.get('packets_sent', 0) + data.get('packets_recv', 0) for data in recent_data)
            
            if total_packets > 100000:  # 20个数据点内超过10万个包
                alert = SecurityAlert(
                    alert_id=f"ddos_detected_{int(time.time())}",
                    alert_type="ddos_attack",
                    severity="critical",
                    interface="multiple",
                    description="检测到可能的DDoS攻击模式",
                    timestamp=time.time(),
                    confidence=0.7
                )
                alerts.append(alert)
        
        return alerts
    
    def _detect_port_scan(self, traffic_data: List[Dict]) -> List[SecurityAlert]:
        """检测端口扫描"""
        alerts = []
        
        # 简化的端口扫描检测
        if len(traffic_data) >= 10:
            recent_data = traffic_data[-10:]
            packet_rates = []
            
            for i in range(1, len(recent_data)):
                prev_packets = recent_data[i-1].get('packets_sent', 0) + recent_data[i-1].get('packets_recv', 0)
                curr_packets = recent_data[i].get('packets_sent', 0) + recent_data[i].get('packets_recv', 0)
                packet_rate = curr_packets - prev_packets
                packet_rates.append(packet_rate)
            
            if packet_rates and statistics.mean(packet_rates) > 5000:
                alert = SecurityAlert(
                    alert_id=f"port_scan_{int(time.time())}",
                    alert_type="port_scan",
                    severity="high",
                    interface="multiple",
                    description="检测到可能的端口扫描活动",
                    timestamp=time.time(),
                    confidence=0.6
                )
                alerts.append(alert)
        
        return alerts
    
    def _detect_data_exfiltration(self, traffic_data: List[Dict]) -> List[SecurityAlert]:
        """检测数据泄露"""
        alerts = []
        
        # 检测异常大的数据传输
        if len(traffic_data) >= 5:
            recent_data = traffic_data[-5:]
            total_bytes = sum(data.get('bytes_sent', 0) for data in recent_data)
            
            if total_bytes > 1000000000:  # 1GB
                alert = SecurityAlert(
                    alert_id=f"data_exfiltration_{int(time.time())}",
                    alert_type="data_exfiltration",
                    severity="high",
                    interface="multiple",
                    description="检测到可能的数据泄露活动",
                    timestamp=time.time(),
                    confidence=0.5
                )
                alerts.append(alert)
        
        return alerts

class SecurityMonitor:
    """安全监控主类"""
    
    def __init__(self):
        self.traffic_analyzer = TrafficAnalyzer()
        self.threat_detector = ThreatDetector()
        self.active_alerts = []
        self.alert_history = []
    
    def process_traffic_data(self, traffic_data: Dict) -> List[SecurityAlert]:
        """处理流量数据，返回安全告警"""
        # 添加流量数据到分析器
        self.traffic_analyzer.add_traffic_data(traffic_data)
        
        # 检测异常
        anomaly_alerts = self.traffic_analyzer.detect_anomalies()
        
        # 检测威胁
        traffic_history = list(self.traffic_analyzer.traffic_history)
        threat_alerts = self.threat_detector.analyze_traffic(traffic_history)
        
        # 合并告警
        all_alerts = anomaly_alerts + threat_alerts
        
        # 更新活跃告警
        self.active_alerts.extend(all_alerts)
        self.alert_history.extend(all_alerts)
        
        # 清理过期告警（保留最近1小时）
        current_time = time.time()
        self.active_alerts = [
            alert for alert in self.active_alerts 
            if current_time - alert.timestamp < 3600
        ]
        
        return all_alerts
    
    def get_active_alerts(self) -> List[SecurityAlert]:
        """获取活跃告警"""
        return self.active_alerts
    
    def get_alert_statistics(self) -> Dict:
        """获取告警统计信息"""
        current_time = time.time()
        recent_alerts = [
            alert for alert in self.alert_history 
            if current_time - alert.timestamp < 3600
        ]
        
        stats = {
            'total_alerts': len(recent_alerts),
            'critical_alerts': len([a for a in recent_alerts if a.severity == 'critical']),
            'high_alerts': len([a for a in recent_alerts if a.severity == 'high']),
            'medium_alerts': len([a for a in recent_alerts if a.severity == 'medium']),
            'low_alerts': len([a for a in recent_alerts if a.severity == 'low']),
            'alert_types': {}
        }
        
        # 统计告警类型
        for alert in recent_alerts:
            alert_type = alert.alert_type
            stats['alert_types'][alert_type] = stats['alert_types'].get(alert_type, 0) + 1
        
        return stats



