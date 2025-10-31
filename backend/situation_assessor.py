"""
态势评估模块
计算风险指数、趋势分析
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from sqlalchemy.orm import Session
from database import RiskSummary, SecurityEvent, get_db, SessionLocal
from collections import defaultdict

logger = logging.getLogger(__name__)


class SituationAssessor:
    """态势评估器"""
    
    def __init__(self):
        # 风险权重配置
        self.risk_weights = {
            'critical': 10.0,
            'high': 5.0,
            'medium': 2.0,
            'low': 1.0
        }
        
        # 风险指数阈值
        self.risk_thresholds = {
            'low': 0.0,
            'medium': 30.0,
            'high': 60.0,
            'critical': 90.0
        }
    
    def calculate_risk_score(self, events: List[SecurityEvent]) -> float:
        """计算风险指数"""
        if not events:
            return 0.0
        
        total_score = 0.0
        for event in events:
            weight = self.risk_weights.get(event.risk_level, 1.0)
            # 考虑置信度
            score = weight * (event.confidence or 1.0)
            total_score += score
        
        # 归一化到0-100
        # 假设正常情况下每天最多100个事件
        normalized_score = min(total_score / 10.0, 100.0)
        
        return round(normalized_score, 2)
    
    def assess_current_situation(self, time_range_hours: int = 1) -> Dict:
        """评估当前安全态势"""
        db = SessionLocal()
        try:
            # 获取指定时间范围内的事件
            start_time = datetime.utcnow() - timedelta(hours=time_range_hours)
            events = db.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= start_time
            ).all()
            
            # 统计各风险等级数量
            risk_counts = defaultdict(int)
            for event in events:
                risk_counts[event.risk_level] += 1
            
            # 计算风险指数
            risk_score = self.calculate_risk_score(events)
            
            # 评估风险等级
            risk_level = self._get_risk_level(risk_score)
            
            # 趋势分析（与上一时段对比）
            previous_start = start_time - timedelta(hours=time_range_hours)
            previous_events = db.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= previous_start,
                SecurityEvent.timestamp < start_time
            ).all()
            
            previous_score = self.calculate_risk_score(previous_events)
            trend = self._calculate_trend(risk_score, previous_score)
            
            return {
                'risk_score': risk_score,
                'risk_level': risk_level,
                'event_counts': {
                    'critical': risk_counts['critical'],
                    'high': risk_counts['high'],
                    'medium': risk_counts['medium'],
                    'low': risk_counts['low'],
                    'total': len(events)
                },
                'trend': trend,
                'trend_percentage': round(((risk_score - previous_score) / previous_score * 100) if previous_score > 0 else 0, 2),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logger.error(f"评估安全态势失败: {e}")
            return {}
        finally:
            db.close()
    
    def _get_risk_level(self, score: float) -> str:
        """根据风险指数确定风险等级"""
        if score >= self.risk_thresholds['critical']:
            return 'critical'
        elif score >= self.risk_thresholds['high']:
            return 'high'
        elif score >= self.risk_thresholds['medium']:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_trend(self, current_score: float, previous_score: float) -> str:
        """计算趋势"""
        if previous_score == 0:
            return 'stable' if current_score == 0 else 'increasing'
        
        change_percentage = ((current_score - previous_score) / previous_score) * 100
        
        if change_percentage > 20:
            return 'increasing'
        elif change_percentage < -20:
            return 'decreasing'
        else:
            return 'stable'
    
    def generate_daily_summary(self, target_date: Optional[datetime] = None) -> Dict:
        """生成每日风险汇总"""
        if target_date is None:
            target_date = datetime.utcnow()
        
        # 获取当天的开始和结束时间
        day_start = target_date.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end = day_start + timedelta(days=1)
        
        db = SessionLocal()
        try:
            # 获取当天的事件
            events = db.query(SecurityEvent).filter(
                SecurityEvent.timestamp >= day_start,
                SecurityEvent.timestamp < day_end
            ).all()
            
            # 统计各风险等级
            risk_counts = defaultdict(int)
            event_types = defaultdict(int)
            
            for event in events:
                risk_counts[event.risk_level] += 1
                event_types[event.event_type] += 1
            
            # 计算总风险指数
            total_score = self.calculate_risk_score(events)
            
            # 检查是否已存在汇总记录
            existing_summary = db.query(RiskSummary).filter(
                RiskSummary.date == day_start
            ).first()
            
            if existing_summary:
                # 更新现有记录
                existing_summary.high = risk_counts['high']
                existing_summary.medium = risk_counts['medium']
                existing_summary.low = risk_counts['low']
                existing_summary.critical = risk_counts['critical']
                existing_summary.total_score = total_score
                db.commit()
                summary = existing_summary
            else:
                # 创建新记录
                summary = RiskSummary(
                    date=day_start,
                    high=risk_counts['high'],
                    medium=risk_counts['medium'],
                    low=risk_counts['low'],
                    critical=risk_counts['critical'],
                    total_score=total_score
                )
                db.add(summary)
                db.commit()
            
            return {
                'date': day_start.isoformat(),
                'high': risk_counts['high'],
                'medium': risk_counts['medium'],
                'low': risk_counts['low'],
                'critical': risk_counts['critical'],
                'total_score': total_score,
                'event_types': dict(event_types),
                'total_events': len(events)
            }
            
        except Exception as e:
            db.rollback()
            logger.error(f"生成每日汇总失败: {e}")
            return {}
        finally:
            db.close()
    
    def get_trend_analysis(self, days: int = 7) -> Dict:
        """获取趋势分析"""
        db = SessionLocal()
        try:
            # 获取最近N天的汇总数据
            end_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            start_date = end_date - timedelta(days=days)
            
            summaries = db.query(RiskSummary).filter(
                RiskSummary.date >= start_date,
                RiskSummary.date < end_date
            ).order_by(RiskSummary.date.asc()).all()
            
            # 构建趋势数据
            trend_data = {
                'dates': [],
                'scores': [],
                'high_counts': [],
                'medium_counts': [],
                'low_counts': [],
                'critical_counts': []
            }
            
            for summary in summaries:
                trend_data['dates'].append(summary.date.isoformat())
                trend_data['scores'].append(summary.total_score)
                trend_data['high_counts'].append(summary.high)
                trend_data['medium_counts'].append(summary.medium)
                trend_data['low_counts'].append(summary.low)
                trend_data['critical_counts'].append(summary.critical)
            
            # 计算平均趋势
            avg_score = sum(trend_data['scores']) / len(trend_data['scores']) if trend_data['scores'] else 0
            overall_trend = 'stable'
            if len(trend_data['scores']) >= 2:
                if trend_data['scores'][-1] > trend_data['scores'][0]:
                    overall_trend = 'increasing'
                elif trend_data['scores'][-1] < trend_data['scores'][0]:
                    overall_trend = 'decreasing'
            
            return {
                'trend_data': trend_data,
                'average_score': round(avg_score, 2),
                'overall_trend': overall_trend,
                'period_days': days
            }
            
        except Exception as e:
            logger.error(f"获取趋势分析失败: {e}")
            return {}
        finally:
            db.close()

