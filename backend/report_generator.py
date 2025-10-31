"""
报告生成模块
导出日报/周报PDF，提供安全建议
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from sqlalchemy.orm import Session
from database import SecurityEvent, RiskSummary, get_db, SessionLocal
from situation_assessor import SituationAssessor
from event_analyzer import EventAnalyzer
import io

logger = logging.getLogger(__name__)


class ReportGenerator:
    """报告生成器"""
    
    def __init__(self):
        self.assessor = SituationAssessor()
        self.analyzer = EventAnalyzer()
    
    def generate_daily_report(self, target_date: Optional[datetime] = None, output_path: Optional[str] = None) -> bytes:
        """生成日报PDF"""
        if target_date is None:
            target_date = datetime.utcnow()
        
        # 创建PDF缓冲区
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        # 标题样式
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f4788'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        # 副标题样式
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        # 正文样式
        normal_style = styles['Normal']
        
        # 标题
        story.append(Paragraph("校园网络安全态势日报", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # 报告日期
        date_str = target_date.strftime('%Y年%m月%d日')
        story.append(Paragraph(f"<b>报告日期：</b>{date_str}", normal_style))
        story.append(Paragraph(f"<b>生成时间：</b>{datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}", normal_style))
        story.append(Spacer(1, 0.3*inch))
        
        # 获取数据
        daily_summary = self.assessor.generate_daily_summary(target_date)
        current_situation = self.assessor.assess_current_situation(24)
        event_analysis = self.analyzer.analyze_events(24)
        
        # 1. 安全态势概览
        story.append(Paragraph("1. 安全态势概览", heading_style))
        
        # 风险指数
        risk_score = daily_summary.get('total_score', 0)
        risk_level = current_situation.get('risk_level', 'low')
        risk_color = self._get_risk_color(risk_level)
        
        story.append(Paragraph(f"<b>风险指数：</b><font color='{risk_color}'>{risk_score}</font>", normal_style))
        story.append(Paragraph(f"<b>风险等级：</b>{risk_level}", normal_style))
        story.append(Spacer(1, 0.1*inch))
        
        # 事件统计表格
        event_counts = daily_summary.get('event_counts', {})
        event_data = [
            ['风险等级', '数量'],
            ['严重 (Critical)', str(event_counts.get('critical', 0))],
            ['高 (High)', str(event_counts.get('high', 0))],
            ['中 (Medium)', str(event_counts.get('medium', 0))],
            ['低 (Low)', str(event_counts.get('low', 0))],
            ['总计', str(event_counts.get('total', 0))]
        ]
        
        event_table = Table(event_data, colWidths=[4*inch, 2*inch])
        event_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('FONTSIZE', (0, 1), (-1, -1), 10),
        ]))
        story.append(event_table)
        story.append(Spacer(1, 0.2*inch))
        
        # 2. 事件类型分析
        story.append(Paragraph("2. 事件类型分析", heading_style))
        
        event_types = daily_summary.get('event_types', {})
        if event_types:
            type_data = [['事件类型', '发生次数']]
            for event_type, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:10]:
                type_data.append([event_type, str(count)])
            
            type_table = Table(type_data, colWidths=[4*inch, 2*inch])
            type_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(type_table)
        else:
            story.append(Paragraph("当日无安全事件", normal_style))
        
        story.append(Spacer(1, 0.2*inch))
        
        # 3. 异常检测结果
        story.append(Paragraph("3. 异常检测结果", heading_style))
        
        rule_anomalies = event_analysis.get('rule_anomalies', [])
        ai_anomalies = event_analysis.get('ai_anomalies', [])
        
        story.append(Paragraph(f"规则检测发现异常：<b>{len(rule_anomalies)}</b> 个", normal_style))
        story.append(Paragraph(f"AI模型检测发现异常：<b>{len(ai_anomalies)}</b> 个", normal_style))
        
        if rule_anomalies:
            story.append(Spacer(1, 0.1*inch))
            story.append(Paragraph("<b>规则检测异常详情：</b>", normal_style))
            for i, anomaly in enumerate(rule_anomalies[:5], 1):  # 只显示前5个
                story.append(Paragraph(f"{i}. {anomaly.get('description', 'N/A')}", normal_style))
        
        story.append(Spacer(1, 0.2*inch))
        
        # 4. 安全建议
        story.append(Paragraph("4. 安全建议", heading_style))
        suggestions = self._generate_suggestions(daily_summary, current_situation, event_analysis)
        for suggestion in suggestions:
            story.append(Paragraph(f"• {suggestion}", normal_style))
        
        story.append(Spacer(1, 0.3*inch))
        
        # 页脚
        footer = Paragraph(
            f"本报告由校园网络安全态势可视化平台自动生成 | {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
            ParagraphStyle('Footer', parent=normal_style, fontSize=8, textColor=colors.grey, alignment=TA_CENTER)
        )
        story.append(footer)
        
        # 生成PDF
        doc.build(story)
        buffer.seek(0)
        pdf_bytes = buffer.read()
        buffer.close()
        
        # 如果指定了输出路径，保存到文件
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)
            logger.info(f"日报已保存到: {output_path}")
        
        return pdf_bytes
    
    def generate_weekly_report(self, target_date: Optional[datetime] = None, output_path: Optional[str] = None) -> bytes:
        """生成周报PDF"""
        if target_date is None:
            target_date = datetime.utcnow()
        
        # 获取一周的开始和结束日期
        week_start = target_date - timedelta(days=target_date.weekday())
        week_end = week_start + timedelta(days=6)
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4)
        story = []
        styles = getSampleStyleSheet()
        
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1f4788'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12,
            spaceBefore=12
        )
        
        normal_style = styles['Normal']
        
        # 标题
        story.append(Paragraph("校园网络安全态势周报", title_style))
        story.append(Spacer(1, 0.2*inch))
        
        # 报告周期
        story.append(Paragraph(f"<b>报告周期：</b>{week_start.strftime('%Y-%m-%d')} 至 {week_end.strftime('%Y-%m-%d')}", normal_style))
        story.append(Spacer(1, 0.3*inch))
        
        # 获取趋势分析
        trend_analysis = self.assessor.get_trend_analysis(7)
        
        # 周统计
        story.append(Paragraph("1. 本周安全态势", heading_style))
        
        trend_data = trend_analysis.get('trend_data', {})
        if trend_data.get('scores'):
            avg_score = trend_analysis.get('average_score', 0)
            story.append(Paragraph(f"<b>平均风险指数：</b>{avg_score}", normal_style))
            story.append(Paragraph(f"<b>总体趋势：</b>{trend_analysis.get('overall_trend', 'stable')}", normal_style))
        
        story.append(Spacer(1, 0.2*inch))
        
        # 每日风险指数表格
        if trend_data.get('dates'):
            weekly_data = [['日期', '风险指数', '严重', '高', '中', '低']]
            for i in range(len(trend_data['dates'])):
                date_str = datetime.fromisoformat(trend_data['dates'][i]).strftime('%m-%d')
                weekly_data.append([
                    date_str,
                    f"{trend_data['scores'][i]:.1f}",
                    str(trend_data['critical_counts'][i]),
                    str(trend_data['high_counts'][i]),
                    str(trend_data['medium_counts'][i]),
                    str(trend_data['low_counts'][i])
                ])
            
            weekly_table = Table(weekly_data, colWidths=[1*inch, 1*inch, 0.8*inch, 0.8*inch, 0.8*inch, 0.8*inch])
            weekly_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 10),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ]))
            story.append(weekly_table)
        
        story.append(Spacer(1, 0.3*inch))
        
        # 本周建议
        story.append(Paragraph("2. 本周安全建议", heading_style))
        week_suggestions = [
            "持续监控高风险事件，及时响应安全告警",
            "加强网络访问控制，限制不必要的端口开放",
            "定期检查系统日志，识别可疑活动模式",
            "更新安全策略，应对新的威胁类型"
        ]
        for suggestion in week_suggestions:
            story.append(Paragraph(f"• {suggestion}", normal_style))
        
        # 生成PDF
        doc.build(story)
        buffer.seek(0)
        pdf_bytes = buffer.read()
        buffer.close()
        
        if output_path:
            with open(output_path, 'wb') as f:
                f.write(pdf_bytes)
            logger.info(f"周报已保存到: {output_path}")
        
        return pdf_bytes
    
    def _get_risk_color(self, risk_level: str) -> str:
        """获取风险等级对应的颜色"""
        color_map = {
            'critical': '#e74c3c',
            'high': '#e67e22',
            'medium': '#f39c12',
            'low': '#27ae60'
        }
        return color_map.get(risk_level, '#95a5a6')
    
    def _generate_suggestions(self, daily_summary: Dict, situation: Dict, analysis: Dict) -> List[str]:
        """生成安全建议"""
        suggestions = []
        
        risk_score = daily_summary.get('total_score', 0)
        event_counts = daily_summary.get('event_counts', {})
        
        # 根据风险指数给出建议
        if risk_score >= 70:
            suggestions.append("风险指数较高，建议立即进行全面的安全检查和响应")
        
        if event_counts.get('critical', 0) > 0:
            suggestions.append("存在严重级别安全事件，需要立即调查和处理")
        
        if event_counts.get('high', 0) > 5:
            suggestions.append("高危险事件数量较多，建议加强安全防护措施")
        
        # 根据异常检测结果
        rule_anomalies = analysis.get('rule_anomalies', [])
        if len(rule_anomalies) > 0:
            suggestions.append("检测到异常网络活动，建议加强监控和访问控制")
        
        # 根据事件类型
        event_types = daily_summary.get('event_types', {})
        if 'ddos_attack' in str(event_types.keys()).lower():
            suggestions.append("检测到DDoS攻击，建议启用流量清洗和限流措施")
        
        if 'port_scan' in str(event_types.keys()).lower():
            suggestions.append("检测到端口扫描活动，建议关闭不必要的端口并加强防火墙规则")
        
        if not suggestions:
            suggestions.append("当前安全态势良好，建议继续保持现有安全策略并定期检查")
        
        return suggestions

