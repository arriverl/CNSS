"""
实时异常检测模块
结合规则匹配和AI模型进行实时流量异常检测
"""

import logging
import numpy as np
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple
from collections import deque, defaultdict
from sklearn.ensemble import IsolationForest
from sklearn.cluster import DBSCAN, KMeans
from sklearn.preprocessing import StandardScaler
from feature_extractor import FeatureExtractor
from database import SecurityEvent, SessionLocal

logger = logging.getLogger(__name__)


class RealTimeAnomalyDetector:
    """实时异常检测器"""
    
    def __init__(self, use_isolation_forest: bool = True, use_clustering: bool = True):
        self.use_isolation_forest = use_isolation_forest
        self.use_clustering = use_clustering
        
        # Isolation Forest模型
        self.isolation_forest = None
        self.contamination = 0.02  # 假设2%是异常
        
        # DBSCAN聚类模型
        self.dbscan = None
        
        # K-Means聚类模型（用于对比）
        self.kmeans = None
        self.n_clusters = 5
        
        # 特征标准化
        self.scaler = StandardScaler()
        
        # 特征提取器
        self.feature_extractor = FeatureExtractor(window_size=1000)
        
        # 模型训练状态
        self.is_trained = False
        self.min_samples_for_training = 100
        
        # 历史数据窗口
        self.traffic_window = deque(maxlen=1000)
        
        # 风险权重配置
        self.risk_weights = {
            'w_syn': 2.0,      # SYN比例权重
            'w_dst': 1.5,      # 目标数量权重
            'w_anomaly': 3.0   # 异常分数权重
        }
    
    def add_traffic_data(self, traffic_data: List[Dict]):
        """添加流量数据到窗口"""
        for data in traffic_data:
            self.traffic_window.append(data)
            # 更新特征提取器的统计信息
            self.feature_extractor.traffic_window.append(data)
    
    def train_models(self, traffic_data: Optional[List[Dict]] = None):
        """训练异常检测模型"""
        if traffic_data is None:
            traffic_data = list(self.traffic_window)
        
        if len(traffic_data) < self.min_samples_for_training:
            logger.warning(f"训练数据不足: {len(traffic_data)} < {self.min_samples_for_training}")
            return False
        
        try:
            # 提取特征
            features = self.feature_extractor.extract_features_from_traffic(traffic_data)
            
            if len(features) == 0:
                logger.warning("无法提取特征")
                return False
            
            # 标准化特征
            features_scaled = self.scaler.fit_transform(features)
            
            # 训练Isolation Forest
            if self.use_isolation_forest:
                self.isolation_forest = IsolationForest(
                    contamination=self.contamination,
                    random_state=42,
                    n_estimators=100,
                    max_samples='auto'
                )
                self.isolation_forest.fit(features_scaled)
                logger.info("Isolation Forest模型训练完成")
            
            # 训练DBSCAN聚类
            if self.use_clustering:
                try:
                    self.dbscan = DBSCAN(eps=0.5, min_samples=5)
                    self.dbscan.fit(features_scaled)
                    logger.info("DBSCAN聚类模型训练完成")
                except Exception as e:
                    logger.warning(f"DBSCAN训练失败，使用K-Means替代: {e}")
                    self.kmeans = KMeans(n_clusters=self.n_clusters, random_state=42, n_init=10)
                    self.kmeans.fit(features_scaled)
                    logger.info("K-Means聚类模型训练完成")
            
            self.is_trained = True
            return True
            
        except Exception as e:
            logger.error(f"模型训练失败: {e}")
            return False
    
    def detect_anomalies(self, traffic_data: List[Dict]) -> List[Dict]:
        """检测异常流量
        
        Returns:
            异常检测结果列表，每个元素包含：
            - anomaly_type: 异常类型（'isolation_forest', 'clustering', 'rule_based'）
            - is_anomaly: 是否为异常
            - anomaly_score: 异常分数
            - confidence: 置信度
            - features: 特征向量
            - traffic_data: 原始流量数据
        """
        if not traffic_data:
            return []
        
        anomalies = []
        
        # 提取特征
        features = self.feature_extractor.extract_features_from_traffic(traffic_data)
        
        if len(features) == 0:
            return []
        
        # 标准化特征
        try:
            features_scaled = self.scaler.transform(features)
        except Exception:
            # 如果scaler未训练，先训练
            features_scaled = self.scaler.fit_transform(features)
        
        # 1. Isolation Forest检测
        if self.use_isolation_forest and self.isolation_forest:
            if_anomalies = self._detect_with_isolation_forest(features_scaled, traffic_data)
            anomalies.extend(if_anomalies)
        
        # 2. 聚类检测
        if self.use_clustering:
            if self.dbscan:
                cluster_anomalies = self._detect_with_dbscan(features_scaled, traffic_data)
            elif self.kmeans:
                cluster_anomalies = self._detect_with_kmeans(features_scaled, traffic_data)
            else:
                cluster_anomalies = []
            anomalies.extend(cluster_anomalies)
        
        # 3. 规则匹配检测
        rule_anomalies = self._detect_with_rules(traffic_data)
        anomalies.extend(rule_anomalies)
        
        return anomalies
    
    def _detect_with_isolation_forest(self, features_scaled: np.ndarray, 
                                      traffic_data: List[Dict]) -> List[Dict]:
        """使用Isolation Forest检测异常"""
        anomalies = []
        
        try:
            predictions = self.isolation_forest.predict(features_scaled)
            anomaly_scores = self.isolation_forest.score_samples(features_scaled)
            
            for i, (data, pred, score) in enumerate(zip(traffic_data, predictions, anomaly_scores)):
                if pred == -1:  # -1表示异常
                    anomalies.append({
                        'anomaly_type': 'isolation_forest',
                        'is_anomaly': True,
                        'anomaly_score': float(abs(score)),
                        'confidence': min(abs(score) * 10, 1.0),  # 归一化到0-1
                        'traffic_data': data,
                        'method': 'IsolationForest'
                    })
        
        except Exception as e:
            logger.error(f"Isolation Forest检测失败: {e}")
        
        return anomalies
    
    def _detect_with_dbscan(self, features_scaled: np.ndarray, 
                           traffic_data: List[Dict]) -> List[Dict]:
        """使用DBSCAN检测异常（噪声点作为异常）"""
        anomalies = []
        
        try:
            labels = self.dbscan.labels_
            
            for i, (data, label) in enumerate(zip(traffic_data, labels)):
                if label == -1:  # -1表示噪声点（异常）
                    # 计算到最近簇的距离作为异常分数
                    core_samples = self.dbscan.core_sample_indices_
                    if len(core_samples) > 0:
                        distances = np.linalg.norm(
                            features_scaled[i] - features_scaled[core_samples],
                            axis=1
                        )
                        min_distance = float(np.min(distances))
                        anomaly_score = min_distance
                    else:
                        anomaly_score = 1.0
                    
                    anomalies.append({
                        'anomaly_type': 'clustering',
                        'is_anomaly': True,
                        'anomaly_score': anomaly_score,
                        'confidence': min(anomaly_score, 1.0),
                        'traffic_data': data,
                        'method': 'DBSCAN',
                        'cluster_label': int(label)
                    })
        
        except Exception as e:
            logger.error(f"DBSCAN检测失败: {e}")
        
        return anomalies
    
    def _detect_with_kmeans(self, features_scaled: np.ndarray, 
                           traffic_data: List[Dict]) -> List[Dict]:
        """使用K-Means检测异常（距离中心较远的点作为异常）"""
        anomalies = []
        
        try:
            labels = self.kmeans.predict(features_scaled)
            centers = self.kmeans.cluster_centers_
            
            for i, (data, label) in enumerate(zip(traffic_data, labels)):
                # 计算到所属簇中心的距离
                center = centers[label]
                distance = float(np.linalg.norm(features_scaled[i] - center))
                
                # 计算距离阈值（使用所有点到中心的距离的中位数+2倍标准差）
                cluster_distances = []
                for j, l in enumerate(labels):
                    if l == label:
                        cluster_distances.append(
                            float(np.linalg.norm(features_scaled[j] - center))
                        )
                
                if cluster_distances:
                    threshold = np.median(cluster_distances) + 2 * np.std(cluster_distances)
                    
                    if distance > threshold:
                        anomalies.append({
                            'anomaly_type': 'clustering',
                            'is_anomaly': True,
                            'anomaly_score': distance / threshold,
                            'confidence': min(distance / (threshold * 2), 1.0),
                            'traffic_data': data,
                            'method': 'KMeans',
                            'cluster_label': int(label),
                            'distance_to_center': float(distance)
                        })
        
        except Exception as e:
            logger.error(f"K-Means检测失败: {e}")
        
        return anomalies
    
    def _detect_with_rules(self, traffic_data: List[Dict]) -> List[Dict]:
        """使用规则匹配检测异常"""
        anomalies = []
        
        # 提取聚合特征（使用整个窗口数据）
        window_data = list(self.traffic_window)
        aggregated = self.feature_extractor.extract_aggregated_features(window_data)
        
        # 检测端口扫描
        for scan in aggregated.get('scan_patterns', []):
            for data in traffic_data:
                if data.get('src_ip') == scan['ip']:
                    anomalies.append({
                        'anomaly_type': 'rule_based',
                        'is_anomaly': True,
                        'anomaly_score': scan['syn_ratio'] * (scan['unique_ports'] / 100),
                        'confidence': min(scan['syn_ratio'], 1.0),
                        'traffic_data': data,
                        'method': 'PortScanRule',
                        'rule_details': scan
                    })
        
        # 检测DDoS（高活跃IP）
        for high_activity in aggregated.get('high_activity_ips', []):
            if high_activity['connections'] > 100:  # 5分钟内超过100个连接
                for data in traffic_data:
                    if data.get('src_ip') == high_activity['ip']:
                        anomalies.append({
                            'anomaly_type': 'rule_based',
                            'is_anomaly': True,
                            'anomaly_score': min(high_activity['connections'] / 200, 1.0),
                            'confidence': 0.8,
                            'traffic_data': data,
                            'method': 'DDoSRule',
                            'rule_details': high_activity
                        })
        
        return anomalies
    
    def classify_and_assess_risk(self, anomalies: List[Dict]) -> List[Dict]:
        """分类异常并计算风险等级
        
        Args:
            anomalies: 异常检测结果列表
        
        Returns:
            包含分类和风险等级的事件列表
        """
        events = []
        
        for anomaly in anomalies:
            traffic_data = anomaly['traffic_data']
            
            # 提取特征用于分类
            syn_ratio = 0.0
            unique_dst = 0
            anomaly_score = anomaly.get('anomaly_score', 0.0)
            
            # 从规则详情中提取特征
            rule_details = anomaly.get('rule_details', {})
            if rule_details:
                syn_ratio = rule_details.get('syn_ratio', 0.0)
                unique_dst = rule_details.get('unique_dst', 0)
            
            # 分类事件类型
            event_type = self._classify_event_type(anomaly, syn_ratio, unique_dst)
            
            # 计算风险分数
            risk_score = self._calculate_risk_score(syn_ratio, unique_dst, anomaly_score)
            
            # 确定风险等级
            risk_level = self._determine_risk_level(risk_score)
            
            events.append({
                'event_type': event_type,
                'src_ip': traffic_data.get('src_ip'),
                'dst_ip': traffic_data.get('dst_ip'),
                'port': traffic_data.get('port'),
                'protocol': traffic_data.get('protocol'),
                'bytes_transferred': traffic_data.get('bytes_sent', 0) + traffic_data.get('bytes_recv', 0),
                'risk_level': risk_level,
                'risk_score': risk_score,
                'confidence': anomaly.get('confidence', 0.0),
                'description': self._generate_description(anomaly, event_type),
                'detection_method': anomaly.get('method', 'Unknown'),
                'anomaly_score': anomaly_score,
                'timestamp': traffic_data.get('timestamp', datetime.utcnow())
            })
        
        return events
    
    def _classify_event_type(self, anomaly: Dict, syn_ratio: float, unique_dst: int) -> str:
        """分类事件类型"""
        method = anomaly.get('method', '')
        
        # 规则匹配优先
        if 'PortScanRule' in method or (syn_ratio > 0.8 and unique_dst > 10):
            return 'PortScan'
        elif 'DDoSRule' in method:
            return 'DDoSAttack'
        elif 'IsolationForest' in method:
            return 'SuspiciousTraffic'
        elif 'DBSCAN' in method or 'KMeans' in method:
            return 'AnomalousPattern'
        else:
            return 'UnknownAnomaly'
    
    def _calculate_risk_score(self, syn_ratio: float, unique_dst: int, anomaly_score: float) -> float:
        """计算风险分数
        
        Risk = w1 × f_syn + w2 × f_dst + w3 × anomaly_score
        """
        # 归一化特征
        f_syn = syn_ratio  # 0-1
        f_dst = min(unique_dst / 100.0, 1.0)  # 归一化到0-1
        f_anomaly = min(anomaly_score, 1.0)  # 归一化到0-1
        
        # 计算加权风险分数
        risk = (
            self.risk_weights['w_syn'] * f_syn +
            self.risk_weights['w_dst'] * f_dst +
            self.risk_weights['w_anomaly'] * f_anomaly
        )
        
        # 归一化到0-100
        max_risk = sum(self.risk_weights.values())
        risk_score = (risk / max_risk) * 100
        
        return min(risk_score, 100.0)
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """确定风险等级"""
        if risk_score >= 70:
            return 'high'
        elif risk_score >= 40:
            return 'medium'
        else:
            return 'low'
    
    def _generate_description(self, anomaly: Dict, event_type: str) -> str:
        """生成事件描述"""
        method = anomaly.get('method', 'Unknown')
        traffic_data = anomaly.get('traffic_data', {})
        src_ip = traffic_data.get('src_ip', 'Unknown')
        
        descriptions = {
            'PortScan': f'检测到端口扫描活动，源IP: {src_ip}',
            'DDoSAttack': f'检测到可能的DDoS攻击，源IP: {src_ip}',
            'SuspiciousTraffic': f'AI模型检测到可疑流量，源IP: {src_ip}',
            'AnomalousPattern': f'聚类模型检测到异常模式，源IP: {src_ip}',
            'UnknownAnomaly': f'检测到未知异常，源IP: {src_ip}'
        }
        
        base_desc = descriptions.get(event_type, f'检测到异常活动，源IP: {src_ip}')
        
        if method:
            base_desc += f' (检测方法: {method})'
        
        return base_desc
    
    def save_events_to_db(self, events: List[Dict]):
        """将检测到的事件保存到数据库"""
        db = SessionLocal()
        try:
            for event_data in events:
                # 检查是否已存在相同事件（避免重复）
                existing = db.query(SecurityEvent).filter(
                    SecurityEvent.src_ip == event_data['src_ip'],
                    SecurityEvent.event_type == event_data['event_type'],
                    SecurityEvent.timestamp >= datetime.utcnow() - timedelta(minutes=1)
                ).first()
                
                if not existing:
                    event = SecurityEvent(
                        event_type=event_data['event_type'],
                        src_ip=event_data['src_ip'],
                        dst_ip=event_data['dst_ip'],
                        timestamp=event_data['timestamp'],
                        risk_level=event_data['risk_level'],
                        description=event_data['description'],
                        port=event_data.get('port'),
                        protocol=event_data.get('protocol'),
                        bytes_transferred=event_data.get('bytes_transferred'),
                        confidence=event_data.get('confidence', 0.0)
                    )
                    db.add(event)
            
            db.commit()
            logger.info(f"保存了 {len(events)} 个异常事件到数据库")
            
        except Exception as e:
            db.rollback()
            logger.error(f"保存事件到数据库失败: {e}")
        finally:
            db.close()

