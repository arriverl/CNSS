"""
事件分析模块
负责日志分类、异常检测（规则+可选AI模型）
"""

import logging
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from database import SecurityEvent, get_db, SessionLocal
from sklearn.ensemble import IsolationForest
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import json

logger = logging.getLogger(__name__)


class EventAnalyzer:
    """事件分析器"""
    
    def __init__(self, use_ai: bool = True):
        self.use_ai = use_ai
        self.isolation_forest = None
        self.kmeans = None
        self.scaler = StandardScaler()
        self.is_trained = False
        
        # 规则检测器
        self.rule_detectors = {
            'ddos': self._detect_ddos_rule,
            'port_scan': self._detect_port_scan_rule,
            'brute_force': self._detect_brute_force_rule,
            'data_exfiltration': self._detect_data_exfiltration_rule,
            'suspicious_connection': self._detect_suspicious_connection_rule
        }
    
    def classify_event(self, event: SecurityEvent) -> str:
        """分类安全事件"""
        # 根据事件类型和特征进行分类
        event_type = event.event_type.lower()
        
        if 'ddos' in event_type or 'flood' in event_type:
            return 'ddos_attack'
        elif 'scan' in event_type or 'probe' in event_type:
            return 'reconnaissance'
        elif 'exfiltrat' in event_type or 'leak' in event_type:
            return 'data_theft'
        elif 'malware' in event_type or 'virus' in event_type:
            return 'malware'
        elif 'unauthorized' in event_type or 'access' in event_type:
            return 'unauthorized_access'
        else:
            return 'other'
    
    def detect_anomalies_by_rules(self, events: List[SecurityEvent]) -> List[Dict]:
        """使用规则检测异常"""
        anomalies = []
        
        # 按时间窗口分组分析
        time_window = timedelta(minutes=5)
        current_time = datetime.utcnow()
        window_start = current_time - time_window
        
        window_events = [e for e in events if e.timestamp >= window_start]
        
        # 应用各个规则检测器
        for detector_name, detector_func in self.rule_detectors.items():
            detected = detector_func(window_events)
            anomalies.extend(detected)
        
        return anomalies
    
    def detect_anomalies_by_ai(self, events: List[SecurityEvent]) -> List[Dict]:
        """使用AI模型检测异常"""
        if not events or len(events) < 10:
            logger.warning("事件数量不足，无法进行AI分析")
            return []
        
        try:
            # 提取特征
            features = self._extract_features(events)
            
            if len(features) < 10:
                return []
            
            # 标准化特征
            features_scaled = self.scaler.fit_transform(features)
            
            # 使用IsolationForest检测异常
            if not self.is_trained:
                self.isolation_forest = IsolationForest(
                    contamination=0.1,  # 假设10%是异常
                    random_state=42
                )
                self.isolation_forest.fit(features_scaled)
                self.is_trained = True
            
            # 预测异常
            predictions = self.isolation_forest.predict(features_scaled)
            anomaly_scores = self.isolation_forest.score_samples(features_scaled)
            
            # 找出异常事件
            anomalies = []
            for i, (event, pred, score) in enumerate(zip(events, predictions, anomaly_scores)):
                if pred == -1:  # -1表示异常
                    anomalies.append({
                        'event_id': event.id,
                        'type': 'ai_anomaly',
                        'confidence': abs(score),
                        'description': f'AI模型检测到异常事件: {event.event_type}'
                    })
            
            return anomalies
            
        except Exception as e:
            logger.error(f"AI异常检测失败: {e}")
            return []
    
    def _extract_features(self, events: List[SecurityEvent]) -> np.ndarray:
        """提取事件特征用于AI分析"""
        features = []
        
        for event in events:
            feature = [
                # 时间特征
                event.timestamp.hour if event.timestamp else 12,
                event.timestamp.weekday() if event.timestamp else 0,
                
                # 风险等级特征（编码）
                {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}.get(event.risk_level, 0),
                
                # 数值特征
                event.bytes_transferred or 0,
                event.port or 0,
                event.confidence or 0.0,
                
                # IP特征（简化：统计出现次数）
                1.0,  # 占位符，实际可以统计IP频率
            ]
            features.append(feature)
        
        return np.array(features)
    
    def _detect_ddos_rule(self, events: List[SecurityEvent]) -> List[Dict]:
        """规则：检测DDoS攻击"""
        anomalies = []
        
        # 统计短时间内大量连接
        if len(events) > 50:
            # 按源IP分组
            src_ip_counts = {}
            for event in events:
                if event.src_ip:
                    src_ip_counts[event.src_ip] = src_ip_counts.get(event.src_ip, 0) + 1
            
            # 检测异常高频IP
            for src_ip, count in src_ip_counts.items():
                if count > 20:  # 5分钟内超过20次
                    anomalies.append({
                        'type': 'ddos_detected',
                        'source_ip': src_ip,
                        'count': count,
                        'description': f'检测到可能的DDoS攻击，源IP: {src_ip}，5分钟内{count}次事件'
                    })
        
        return anomalies
    
    def _detect_port_scan_rule(self, events: List[SecurityEvent]) -> List[Dict]:
        """规则：检测端口扫描"""
        anomalies = []
        
        # 统计同一源IP访问的不同端口数
        src_port_map = {}
        for event in events:
            if event.src_ip and event.port:
                if event.src_ip not in src_port_map:
                    src_port_map[event.src_ip] = set()
                src_port_map[event.src_ip].add(event.port)
        
        # 检测端口扫描模式
        for src_ip, ports in src_port_map.items():
            if len(ports) > 10:  # 短时间内访问超过10个不同端口
                anomalies.append({
                    'type': 'port_scan_detected',
                    'source_ip': src_ip,
                    'port_count': len(ports),
                    'description': f'检测到可能的端口扫描，源IP: {src_ip}，访问了{len(ports)}个不同端口'
                })
        
        return anomalies
    
    def _detect_brute_force_rule(self, events: List[SecurityEvent]) -> List[Dict]:
        """规则：检测暴力破解"""
        anomalies = []
        
        # 统计同一源IP的失败登录尝试
        failed_attempts = {}
        for event in events:
            if 'failed' in event.description.lower() or 'unauthorized' in event.event_type.lower():
                if event.src_ip:
                    failed_attempts[event.src_ip] = failed_attempts.get(event.src_ip, 0) + 1
        
        # 检测暴力破解
        for src_ip, count in failed_attempts.items():
            if count > 5:  # 5分钟内超过5次失败
                anomalies.append({
                    'type': 'brute_force_detected',
                    'source_ip': src_ip,
                    'attempt_count': count,
                    'description': f'检测到可能的暴力破解攻击，源IP: {src_ip}，{count}次失败尝试'
                })
        
        return anomalies
    
    def _detect_data_exfiltration_rule(self, events: List[SecurityEvent]) -> List[Dict]:
        """规则：检测数据泄露"""
        anomalies = []
        
        # 检测异常大的数据传输
        for event in events:
            if event.bytes_transferred and event.bytes_transferred > 1000000000:  # 1GB
                anomalies.append({
                    'type': 'data_exfiltration_detected',
                    'event_id': event.id,
                    'bytes': event.bytes_transferred,
                    'description': f'检测到可能的数据泄露，传输了{event.bytes_transferred / 1000000:.2f}MB数据'
                })
        
        return anomalies
    
    def _detect_suspicious_connection_rule(self, events: List[SecurityEvent]) -> List[Dict]:
        """规则：检测可疑连接"""
        anomalies = []
        
        # 检测来自内网的异常外连
        suspicious_ports = [22, 23, 3389, 5900, 1433, 3306]  # SSH, Telnet, RDP, VNC, SQL
        
        for event in events:
            if event.port in suspicious_ports and event.dst_ip:
                # 简单判断：如果目标IP是外网（这里简化处理）
                if event.dst_ip and not event.dst_ip.startswith('192.168.') and not event.dst_ip.startswith('10.'):
                    anomalies.append({
                        'type': 'suspicious_connection',
                        'event_id': event.id,
                        'port': event.port,
                        'destination_ip': event.dst_ip,
                        'description': f'检测到可疑连接，端口{event.port}连接到{event.dst_ip}'
                    })
        
        return anomalies
    
    def analyze_events(self, time_range_hours: int = 24) -> Dict:
        """综合分析事件"""
        db = SessionLocal()
        try:
            # 获取指定时间范围内的事件
            start_time = datetime.utcnow() - timedelta(hours=time_range_hours)
            events = db.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= start_time
            ).all()
            
            # 规则检测
            rule_anomalies = self.detect_anomalies_by_rules(events)
            
            # AI检测（如果启用）
            ai_anomalies = []
            if self.use_ai:
                ai_anomalies = self.detect_anomalies_by_ai(events)
            
            # 统计分析
            stats = {
                'total_events': len(events),
                'by_type': {},
                'by_risk_level': {},
                'rule_anomalies': len(rule_anomalies),
                'ai_anomalies': len(ai_anomalies)
            }
            
            for event in events:
                # 按类型统计
                event_type = event.event_type
                stats['by_type'][event_type] = stats['by_type'].get(event_type, 0) + 1
                
                # 按风险等级统计
                risk_level = event.risk_level
                stats['by_risk_level'][risk_level] = stats['by_risk_level'].get(risk_level, 0) + 1
            
            return {
                'statistics': stats,
                'rule_anomalies': rule_anomalies,
                'ai_anomalies': ai_anomalies,
                'events': [self._event_to_dict(e) for e in events[-100:]]  # 最近100条
            }
            
        except Exception as e:
            logger.error(f"分析事件失败: {e}")
            return {}
        finally:
            db.close()
    
    def _event_to_dict(self, event: SecurityEvent) -> Dict:
        """将事件转换为字典"""
        return {
            'id': event.id,
            'event_type': event.event_type,
            'src_ip': event.src_ip,
            'dst_ip': event.dst_ip,
            'timestamp': event.timestamp.isoformat() if event.timestamp else None,
            'risk_level': event.risk_level,
            'description': event.description,
            'confidence': event.confidence
        }

