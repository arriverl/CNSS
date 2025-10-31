"""
数据采集模块
负责定时采集网络日志和安全事件数据，并持久化到数据库
集成实时异常检测
"""

import asyncio
import logging
import time
from datetime import datetime
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from database import SecurityEvent, TrafficHistory, get_db, SessionLocal
from security_monitor import SecurityMonitor, SecurityAlert
from wireshark_monitor import WiresharkMonitor, RealTimeTrafficAnalyzer
from realtime_anomaly_detector import RealTimeAnomalyDetector
import platform

logger = logging.getLogger(__name__)


class DataCollector:
    """数据采集器"""
    
    def __init__(self, enable_realtime_detection: bool = True):
        self.security_monitor = SecurityMonitor()
        self.wireshark_monitor = WiresharkMonitor()
        self.traffic_analyzer = RealTimeTrafficAnalyzer()
        self.is_collecting = False
        self.collection_interval = 5  # 默认5秒采集一次
        
        # 实时异常检测器
        self.enable_realtime_detection = enable_realtime_detection
        if enable_realtime_detection:
            self.anomaly_detector = RealTimeAnomalyDetector(
                use_isolation_forest=True,
                use_clustering=True
            )
            logger.info("实时异常检测器已初始化")
        
    def start_collection(self, interval: int = 5):
        """开始定时采集数据"""
        if self.is_collecting:
            logger.warning("数据采集已在运行中")
            return
        
        self.is_collecting = True
        self.collection_interval = interval
        logger.info(f"数据采集已启动，采集间隔: {interval}秒")
        
        # 在后台任务中运行（使用线程）
        import threading
        collection_thread = threading.Thread(target=self._run_collection_loop, daemon=True)
        collection_thread.start()
    
    def stop_collection(self):
        """停止数据采集"""
        self.is_collecting = False
        logger.info("数据采集已停止")
    
    async def _collection_loop(self):
        """采集循环"""
        while self.is_collecting:
            try:
                await self.collect_current_data()
                await asyncio.sleep(self.collection_interval)
            except Exception as e:
                logger.error(f"数据采集错误: {e}")
                await asyncio.sleep(self.collection_interval)
    
    def _run_collection_loop(self):
        """同步方式运行采集循环（用于后台任务）"""
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop.run_until_complete(self._collection_loop())
    
    def _enrich_traffic_data(self, traffic_data: List[Dict]) -> List[Dict]:
        """丰富流量数据，添加连接级别信息"""
        enriched_data = []
        
        try:
            # 尝试获取网络连接信息
            if self.wireshark_monitor.check_tshark_available():
                # 获取数据包分析（包含连接信息）
                packet_analysis = self.wireshark_monitor.get_packet_analysis(duration=5)
                
                # 从数据包分析中提取连接信息
                connections = []
                if packet_analysis:
                    # 获取连接信息
                    try:
                        network_connections = self.wireshark_monitor.get_network_connections()
                        connections = network_connections
                    except:
                        pass
                
                # 为每个接口的流量数据添加连接信息
                for data in traffic_data:
                    # 如果已有连接信息，直接使用
                    if 'src_ip' in data and 'dst_ip' in data:
                        enriched_data.append(data)
                    else:
                        # 为接口级别的数据创建一个"聚合"连接记录
                        # 在实际应用中，这应该从数据包分析中提取
                        enriched_data.append({
                            **data,
                            'src_ip': '0.0.0.0',  # 接口级别数据，无具体IP
                            'dst_ip': '0.0.0.0',
                            'protocol': 'UNKNOWN',
                            'port': 0,
                            'tcp_flags': {}
                        })
                
                # 如果有连接信息，添加连接级别的数据
                if connections:
                    for conn in connections:
                        enriched_data.append({
                            'timestamp': time.time(),
                            'interface': conn.get('interface', 'unknown'),
                            'src_ip': conn.get('src_ip', '0.0.0.0'),
                            'dst_ip': conn.get('dst_ip', '0.0.0.0'),
                            'port': conn.get('port', 0),
                            'protocol': conn.get('protocol', 'UNKNOWN'),
                            'bytes_sent': conn.get('bytes_sent', 0),
                            'bytes_recv': conn.get('bytes_recv', 0),
                            'packets_sent': conn.get('packets_sent', 0),
                            'packets_recv': conn.get('packets_recv', 0),
                            'tcp_flags': conn.get('tcp_flags', {})
                        })
            else:
                # 无Wireshark时，使用原始数据
                for data in traffic_data:
                    enriched_data.append({
                        **data,
                        'src_ip': data.get('src_ip', '0.0.0.0'),
                        'dst_ip': data.get('dst_ip', '0.0.0.0'),
                        'protocol': data.get('protocol', 'UNKNOWN'),
                        'port': data.get('port', 0),
                        'tcp_flags': data.get('tcp_flags', {})
                    })
        
        except Exception as e:
            logger.warning(f"丰富流量数据失败，使用原始数据: {e}")
            enriched_data = traffic_data
        
        return enriched_data
    
    async def collect_current_data(self):
        """采集当前数据并执行实时异常检测"""
        try:
            import psutil
            import platform
            import time
            
            # 获取流量数据（多源支持）
            traffic_data = []
            
            if self.wireshark_monitor.check_tshark_available():
                # 优先使用Wireshark获取真实流量数据
                traffic_data = self.wireshark_monitor.get_traffic_data()
            elif platform.system().lower() == 'windows':
                # Windows环境使用系统监控器
                try:
                    from windows_monitor import WindowsSystemMonitor
                    windows_monitor = WindowsSystemMonitor(enable_simulation=False)
                    traffic_data = windows_monitor.get_traffic_data()
                except Exception as e:
                    logger.warning(f"Windows监控器获取数据失败: {e}, 尝试使用psutil")
                    # 降级使用psutil
                    current_time = time.time()
                    net_io = psutil.net_io_counters(pernic=True)
                    for interface, stats in net_io.items():
                        traffic_data.append({
                            "timestamp": current_time,
                            "interface": interface,
                            "bytes_sent": stats.bytes_sent,
                            "bytes_recv": stats.bytes_recv,
                            "packets_sent": stats.packets_sent,
                            "packets_recv": stats.packets_recv,
                            "bandwidth_sent": 0.0,
                            "bandwidth_recv": 0.0
                        })
            else:
                # Linux/Unix环境使用psutil
                try:
                    current_time = time.time()
                    net_io = psutil.net_io_counters(pernic=True)
                    for interface, stats in net_io.items():
                        traffic_data.append({
                            "timestamp": current_time,
                            "interface": interface,
                            "bytes_sent": stats.bytes_sent,
                            "bytes_recv": stats.bytes_recv,
                            "packets_sent": stats.packets_sent,
                            "packets_recv": stats.packets_recv,
                            "bandwidth_sent": 0.0,
                            "bandwidth_recv": 0.0
                        })
                except Exception as e:
                    logger.error(f"psutil获取数据失败: {e}")
            
            if not traffic_data:
                logger.debug("未获取到流量数据，跳过本次采集")
                return
            
            logger.debug(f"采集到 {len(traffic_data)} 条流量数据")
            
            # 丰富流量数据，添加连接级别信息
            enriched_data = self._enrich_traffic_data(traffic_data)
            
            # 1. 传统安全监控（规则检测）
            alerts = []
            for data in traffic_data:
                traffic_alerts = self.security_monitor.process_traffic_data(data)
                alerts.extend(traffic_alerts)
            
            # 2. 实时异常检测（AI模型）- 使用丰富的连接数据
            ai_events = []
            if self.enable_realtime_detection and self.anomaly_detector:
                try:
                    # 添加数据到检测器窗口
                    self.anomaly_detector.add_traffic_data(enriched_data)
                    
                    # 如果模型未训练且有足够数据，先训练
                    if not self.anomaly_detector.is_trained:
                        window_data = list(self.anomaly_detector.traffic_window)
                        if len(window_data) >= self.anomaly_detector.min_samples_for_training:
                            self.anomaly_detector.train_models(window_data)
                    
                    # 执行异常检测
                    anomalies = self.anomaly_detector.detect_anomalies(enriched_data)
                    
                    if anomalies:
                        # 分类异常并计算风险
                        ai_events = self.anomaly_detector.classify_and_assess_risk(anomalies)
                        
                        # 保存到数据库
                        self.anomaly_detector.save_events_to_db(ai_events)
                        
                        logger.debug(f"实时异常检测发现 {len(ai_events)} 个异常事件")
                
                except Exception as e:
                    logger.error(f"实时异常检测失败: {e}")
            
            # 3. 保存传统告警到数据库
            if alerts:
                await self.save_events_to_db(alerts)
            
            # 4. 保存流量历史到数据库（持久化）
            if enriched_data:
                self.save_traffic_history(enriched_data)
                
        except Exception as e:
            logger.error(f"采集数据时出错: {e}")
    
    def save_traffic_history(self, traffic_data: List[Dict]):
        """保存流量历史到数据库"""
        db = SessionLocal()
        try:
            for data in traffic_data:
                # 转换时间戳为datetime
                timestamp = data.get('timestamp')
                if isinstance(timestamp, (int, float)):
                    timestamp = datetime.fromtimestamp(timestamp)
                elif timestamp is None:
                    timestamp = datetime.utcnow()
                
                # 创建流量历史记录
                history = TrafficHistory(
                    timestamp=timestamp,
                    interface=data.get('interface'),
                    bytes_sent=data.get('bytes_sent', 0),
                    bytes_recv=data.get('bytes_recv', 0),
                    packets_sent=data.get('packets_sent', 0),
                    packets_recv=data.get('packets_recv', 0),
                    bandwidth_sent=data.get('bandwidth_sent', 0.0),
                    bandwidth_recv=data.get('bandwidth_recv', 0.0),
                    src_ip=data.get('src_ip'),
                    dst_ip=data.get('dst_ip'),
                    protocol=data.get('protocol'),
                    port=data.get('port')
                )
                db.add(history)
            
            db.commit()
            
        except Exception as e:
            db.rollback()
            logger.error(f"保存流量历史失败: {e}")
        finally:
            db.close()
    
    async def save_events_to_db(self, alerts: List[SecurityAlert]):
        """将安全告警保存到数据库"""
        db = SessionLocal()
        try:
            for alert in alerts:
                # 检查是否已存在相同的告警（避免重复）
                existing = db.query(SecurityEvent).filter(
                    SecurityEvent.event_type == alert.alert_type,
                    SecurityEvent.timestamp >= datetime.fromtimestamp(alert.timestamp - 60)  # 1分钟内
                ).first()
                
                if not existing:
                    event = SecurityEvent(
                        event_type=alert.alert_type,
                        src_ip=alert.source_ip,
                        dst_ip=alert.destination_ip,
                        timestamp=datetime.fromtimestamp(alert.timestamp),
                        risk_level=alert.severity,
                        description=alert.description,
                        interface=alert.interface,
                        protocol=alert.protocol,
                        port=alert.port,
                        bytes_transferred=alert.bytes_transferred,
                        confidence=alert.confidence
                    )
                    db.add(event)
            
            db.commit()
            logger.debug(f"保存了 {len(alerts)} 个安全事件到数据库")
            
        except Exception as e:
            db.rollback()
            logger.error(f"保存事件到数据库失败: {e}")
        finally:
            db.close()
    
    def collect_traffic_batch(self, duration: int = 60) -> List[Dict]:
        """批量采集流量数据（用于报告生成）"""
        collected_data = []
        start_time = time.time()
        
        while time.time() - start_time < duration:
            try:
                traffic_data = self.wireshark_monitor.get_traffic_data() if self.wireshark_monitor.check_tshark_available() else []
                collected_data.extend(traffic_data)
                time.sleep(self.collection_interval)
            except Exception as e:
                logger.error(f"批量采集错误: {e}")
                time.sleep(self.collection_interval)
        
        return collected_data

