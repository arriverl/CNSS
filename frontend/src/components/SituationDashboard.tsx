import React, { useState, useEffect } from 'react';
import { Card, Row, Col, Statistic, Alert, Button, Select, Space } from 'antd';
import { 
  WarningOutlined, 
  ArrowUpOutlined, 
  ArrowDownOutlined,
  ReloadOutlined,
  FilePdfOutlined
} from '@ant-design/icons';
import { LineChart, Line, BarChart, Bar, PieChart, Pie, Cell, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { getSituation, getTrend, generateReport } from '../services/api';
import moment from 'moment';

const { Option } = Select;

interface SituationData {
  risk_score: number;
  risk_level: string;
  event_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    total: number;
  };
  trend: string;
  trend_percentage: number;
  timestamp: string;
}

interface TrendData {
  dates: string[];
  scores: number[];
  high_counts: number[];
  medium_counts: number[];
  low_counts: number[];
  critical_counts: number[];
}

const SituationDashboard: React.FC = () => {
  const [situation, setSituation] = useState<SituationData | null>(null);
  const [trendData, setTrendData] = useState<TrendData | null>(null);
  const [loading, setLoading] = useState(false);
  const [timeRange, setTimeRange] = useState(1); // hours
  const [trendDays, setTrendDays] = useState(7);

  const fetchSituation = async () => {
    try {
      setLoading(true);
      const response = await getSituation(timeRange);
      setSituation(response.data);
    } catch (error) {
      console.error('获取安全态势失败:', error);
    } finally {
      setLoading(false);
    }
  };

  const fetchTrend = async () => {
    try {
      const response = await getTrend(trendDays);
      setTrendData(response.data.trend_data);
    } catch (error) {
      console.error('获取趋势数据失败:', error);
    }
  };

  useEffect(() => {
    fetchSituation();
    fetchTrend();
    const interval = setInterval(() => {
      fetchSituation();
    }, 30000); // 每30秒刷新一次

    return () => clearInterval(interval);
  }, [timeRange, trendDays]);

  const handleGenerateDailyReport = async () => {
    try {
      const response = await generateReport('daily');
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `daily_report_${moment().format('YYYYMMDD')}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error('生成日报失败:', error);
    }
  };

  const handleGenerateWeeklyReport = async () => {
    try {
      const response = await generateReport('weekly');
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', `weekly_report_${moment().format('YYYYMMDD')}.pdf`);
      document.body.appendChild(link);
      link.click();
      link.remove();
    } catch (error) {
      console.error('生成周报失败:', error);
    }
  };

  const getRiskColor = (level: string) => {
    const colors: { [key: string]: string } = {
      critical: '#cf1322',
      high: '#ff4d4f',
      medium: '#faad14',
      low: '#52c41a'
    };
    return colors[level] || '#8c8c8c';
  };

  const getRiskLevelText = (level: string) => {
    const texts: { [key: string]: string } = {
      critical: '严重',
      high: '高',
      medium: '中',
      low: '低'
    };
    return texts[level] || level;
  };

  // 风险指数趋势图数据
  const trendChartData = trendData ? trendData.dates.map((date, index) => ({
    date: moment(date).format('MM-DD'),
    score: trendData.scores[index]
  })) : [];

  // 事件统计饼图数据
  const pieChartData = situation ? [
    { name: '严重', value: situation.event_counts.critical, color: '#cf1322' },
    { name: '高', value: situation.event_counts.high, color: '#ff4d4f' },
    { name: '中', value: situation.event_counts.medium, color: '#faad14' },
    { name: '低', value: situation.event_counts.low, color: '#52c41a' },
  ].filter(item => item.value > 0) : [];

  // 事件数量柱状图数据
  const barChartData = trendData ? trendData.dates.map((date, index) => ({
    date: moment(date).format('MM-DD'),
    '严重': trendData.critical_counts[index],
    '高': trendData.high_counts[index],
    '中': trendData.medium_counts[index],
    '低': trendData.low_counts[index],
  })) : [];

  return (
    <div style={{ padding: '24px', background: '#f0f2f5' }}>
      {/* 控制栏 */}
      <Card style={{ marginBottom: 16 }}>
        <Space>
          <span>时间范围：</span>
          <Select value={timeRange} onChange={setTimeRange} style={{ width: 120 }}>
            <Option value={1}>1小时</Option>
            <Option value={6}>6小时</Option>
            <Option value={24}>24小时</Option>
          </Select>
          
          <span style={{ marginLeft: 16 }}>趋势天数：</span>
          <Select value={trendDays} onChange={setTrendDays} style={{ width: 120 }}>
            <Option value={7}>7天</Option>
            <Option value={14}>14天</Option>
            <Option value={30}>30天</Option>
          </Select>

          <Button 
            icon={<ReloadOutlined />} 
            onClick={() => {
              fetchSituation();
              fetchTrend();
            }}
            loading={loading}
          >
            刷新
          </Button>

          <Button 
            icon={<FilePdfOutlined />} 
            onClick={handleGenerateDailyReport}
            type="primary"
          >
            生成日报
          </Button>

          <Button 
            icon={<FilePdfOutlined />} 
            onClick={handleGenerateWeeklyReport}
          >
            生成周报
          </Button>
        </Space>
      </Card>

      {/* 风险指标卡片 */}
      <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="风险指数"
              value={situation?.risk_score || 0}
              precision={1}
              valueStyle={{ 
                color: situation ? getRiskColor(situation.risk_level) : '#8c8c8c',
                fontSize: 32
              }}
              suffix="/ 100"
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="风险等级"
              value={situation ? getRiskLevelText(situation.risk_level) : '-'}
              valueStyle={{ 
                color: situation ? getRiskColor(situation.risk_level) : '#8c8c8c',
                fontSize: 32
              }}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="趋势"
              value={situation?.trend_percentage || 0}
              precision={1}
              prefix={situation?.trend === 'increasing' ? <ArrowUpOutlined /> : <ArrowDownOutlined />}
              valueStyle={{ 
                color: situation?.trend === 'increasing' ? '#cf1322' : '#52c41a',
                fontSize: 24
              }}
              suffix="%"
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card>
            <Statistic
              title="总事件数"
              value={situation?.event_counts.total || 0}
              valueStyle={{ color: '#1890ff', fontSize: 32 }}
            />
          </Card>
        </Col>
      </Row>

      {/* 风险等级分布 */}
      {situation && (
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col xs={24} sm={6}>
            <Card>
              <Statistic
                title="严重事件"
                value={situation.event_counts.critical}
                valueStyle={{ color: '#cf1322' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={6}>
            <Card>
              <Statistic
                title="高风险事件"
                value={situation.event_counts.high}
                valueStyle={{ color: '#ff4d4f' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={6}>
            <Card>
              <Statistic
                title="中风险事件"
                value={situation.event_counts.medium}
                valueStyle={{ color: '#faad14' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={6}>
            <Card>
              <Statistic
                title="低风险事件"
                value={situation.event_counts.low}
                valueStyle={{ color: '#52c41a' }}
              />
            </Card>
          </Col>
        </Row>
      )}

      {/* 风险告警 */}
      {situation && situation.risk_level === 'critical' && (
        <Alert
          message="严重风险警告"
          description={`当前风险指数为 ${situation.risk_score}，风险等级为严重，请立即采取应对措施！`}
          type="error"
          icon={<WarningOutlined />}
          showIcon
          style={{ marginBottom: 16 }}
        />
      )}

      {/* 图表区域 */}
      <Row gutter={[16, 16]}>
        <Col xs={24} lg={12}>
          <Card title="风险指数趋势">
            {trendChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <LineChart data={trendChartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Line type="monotone" dataKey="score" stroke="#1890ff" strokeWidth={2} name="风险指数" />
                </LineChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ textAlign: 'center', padding: '50px' }}>暂无数据</div>
            )}
          </Card>
        </Col>
        <Col xs={24} lg={12}>
          <Card title="事件类型分布">
            {pieChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <PieChart>
                  <Pie
                    data={pieChartData}
                    cx="50%"
                    cy="50%"
                    labelLine={false}
                    label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                    outerRadius={80}
                    fill="#8884d8"
                    dataKey="value"
                  >
                    {pieChartData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ textAlign: 'center', padding: '50px' }}>暂无数据</div>
            )}
          </Card>
        </Col>
        <Col xs={24}>
          <Card title="每日事件统计">
            {barChartData.length > 0 ? (
              <ResponsiveContainer width="100%" height={300}>
                <BarChart data={barChartData}>
                  <CartesianGrid strokeDasharray="3 3" />
                  <XAxis dataKey="date" />
                  <YAxis />
                  <Tooltip />
                  <Legend />
                  <Bar dataKey="严重" stackId="a" fill="#cf1322" />
                  <Bar dataKey="高" stackId="a" fill="#ff4d4f" />
                  <Bar dataKey="中" stackId="a" fill="#faad14" />
                  <Bar dataKey="低" stackId="a" fill="#52c41a" />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ textAlign: 'center', padding: '50px' }}>暂无数据</div>
            )}
          </Card>
        </Col>
      </Row>
    </div>
  );
};

export default SituationDashboard;

