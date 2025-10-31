import React, { useState, useEffect, useCallback } from 'react';
import { Card, Select, Button, DatePicker, Space, Statistic, Row, Col } from 'antd';
import { ReloadOutlined } from '@ant-design/icons';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';
import { getTrafficHistory } from '../services/api';
import dayjs, { Dayjs } from 'dayjs';

const { RangePicker } = DatePicker;
const { Option } = Select;

interface TrafficData {
  timestamp: number;
  interface: string;
  bytes_sent: number;
  bytes_recv: number;
  packets_sent: number;
  packets_recv: number;
  bandwidth_sent: number;
  bandwidth_recv: number;
}

interface TrafficTrendChartProps {
  defaultHours?: number;
}

const TrafficTrendChart: React.FC<TrafficTrendChartProps> = ({ defaultHours = 24 }) => {
  const [data, setData] = useState<TrafficData[]>([]);
  const [loading, setLoading] = useState(false);
  const [hours, setHours] = useState(defaultHours);
  const [selectedInterface, setSelectedInterface] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<[Dayjs, Dayjs] | null>(null);

  const fetchData = useCallback(async () => {
    try {
      setLoading(true);
      let hoursToFetch = hours;
      
      // 如果选择了时间范围，计算小时数
      if (timeRange) {
        hoursToFetch = timeRange[1].diff(timeRange[0], 'hours');
      }
      
      const response = await getTrafficHistory(selectedInterface === 'all' ? undefined : selectedInterface, hoursToFetch);
      
      if (response.data && response.data.data) {
        // 按时间排序
        const sortedData = response.data.data.sort((a: TrafficData, b: TrafficData) => 
          a.timestamp - b.timestamp
        );
        setData(sortedData);
      }
    } catch (error) {
      console.error('获取历史流量数据失败:', error);
    } finally {
      setLoading(false);
    }
  }, [hours, selectedInterface, timeRange]);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  // 处理时间范围选择
  const handleTimeRangeChange = (dates: [Dayjs, Dayjs] | null) => {
    setTimeRange(dates);
    if (dates) {
      const hours = dates[1].diff(dates[0], 'hours');
      setHours(hours);
    }
  };

  // 处理预设时间范围
  const handlePresetTime = (presetHours: number) => {
    setHours(presetHours);
    setTimeRange(null);
  };

  // 获取唯一接口列表
  const interfaces = Array.from(new Set(data.map(d => d.interface))).filter(Boolean);

  // 按接口分组数据
  const groupedData = React.useMemo(() => {
    if (selectedInterface === 'all') {
      // 所有接口合并
      // 如果数据点较少（<100），直接使用原始数据，不聚合
      // 如果数据点较多，按时间间隔聚合以减少图表负载
      if (data.length < 100) {
        // 直接使用所有数据点，按接口合并
        const timeMap = new Map<number, TrafficData>();
        
        data.forEach(item => {
          // 使用原始时间戳，不聚合
          const timeKey = item.timestamp;
          
          if (!timeMap.has(timeKey)) {
            timeMap.set(timeKey, {
              timestamp: timeKey,
              interface: 'all',
              bytes_sent: 0,
              bytes_recv: 0,
              packets_sent: 0,
              packets_recv: 0,
              bandwidth_sent: 0,
              bandwidth_recv: 0
            });
          }
          
          const aggregated = timeMap.get(timeKey)!;
          aggregated.bytes_sent += item.bytes_sent;
          aggregated.bytes_recv += item.bytes_recv;
          aggregated.packets_sent += item.packets_sent;
          aggregated.packets_recv += item.packets_recv;
          aggregated.bandwidth_sent += item.bandwidth_sent;
          aggregated.bandwidth_recv += item.bandwidth_recv;
        });
        
        return Array.from(timeMap.values()).sort((a, b) => a.timestamp - b.timestamp);
      } else {
        // 数据点多时，按分钟聚合
        const timeMap = new Map<number, TrafficData>();
        const interval = 60; // 1分钟聚合间隔
        
        data.forEach(item => {
          const timeKey = Math.floor(item.timestamp / interval) * interval;
          
          if (!timeMap.has(timeKey)) {
            timeMap.set(timeKey, {
              timestamp: timeKey,
              interface: 'all',
              bytes_sent: 0,
              bytes_recv: 0,
              packets_sent: 0,
              packets_recv: 0,
              bandwidth_sent: 0,
              bandwidth_recv: 0
            });
          }
          
          const aggregated = timeMap.get(timeKey)!;
          aggregated.bytes_sent += item.bytes_sent;
          aggregated.bytes_recv += item.bytes_recv;
          aggregated.packets_sent += item.packets_sent;
          aggregated.packets_recv += item.packets_recv;
          aggregated.bandwidth_sent += item.bandwidth_sent;
          aggregated.bandwidth_recv += item.bandwidth_recv;
        });
        
        return Array.from(timeMap.values()).sort((a, b) => a.timestamp - b.timestamp);
      }
    } else {
      return data.filter(d => d.interface === selectedInterface);
    }
  }, [data, selectedInterface]);

  // 准备图表数据
  const chartData = groupedData.map(item => ({
    time: dayjs(item.timestamp * 1000).format('HH:mm'),
    date: dayjs(item.timestamp * 1000).format('MM-DD HH:mm'),
    timestamp: item.timestamp,
    '发送带宽(Mbps)': parseFloat((item.bandwidth_sent / 1000000).toFixed(2)),
    '接收带宽(Mbps)': parseFloat((item.bandwidth_recv / 1000000).toFixed(2)),
    '总流量(MB)': parseFloat(((item.bytes_sent + item.bytes_recv) / 1024 / 1024).toFixed(2)),
  }));

  // 计算统计数据
  const stats = React.useMemo(() => {
    if (groupedData.length === 0) return null;
    
    const totalBytesSent = groupedData.reduce((sum, d) => sum + d.bytes_sent, 0);
    const totalBytesRecv = groupedData.reduce((sum, d) => sum + d.bytes_recv, 0);
    const avgBandwidthSent = groupedData.reduce((sum, d) => sum + d.bandwidth_sent, 0) / groupedData.length;
    const avgBandwidthRecv = groupedData.reduce((sum, d) => sum + d.bandwidth_recv, 0) / groupedData.length;
    
    return {
      totalBytesSent,
      totalBytesRecv,
      avgBandwidthSent,
      avgBandwidthRecv
    };
  }, [groupedData]);

  const formatBytes = (bytes: number): string => {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  const formatBandwidth = (bps: number): string => {
    if (bps === 0) return '0 bps';
    const k = 1000;
    const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    const i = Math.floor(Math.log(bps) / Math.log(k));
    return parseFloat((bps / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  return (
    <Card
      title="流量趋势分析"
      extra={
        <Space>
          <Select
            value={selectedInterface}
            onChange={setSelectedInterface}
            style={{ width: 150 }}
          >
            <Option value="all">全部接口</Option>
            {interfaces.map(iface => (
              <Option key={iface} value={iface}>{iface}</Option>
            ))}
          </Select>
          <Button
            icon={<ReloadOutlined />}
            onClick={fetchData}
            loading={loading}
          >
            刷新
          </Button>
        </Space>
      }
    >
      {/* 时间范围选择 */}
      <Space style={{ marginBottom: 16 }}>
        <span>时间范围：</span>
        <Button size="small" onClick={() => handlePresetTime(1)}>1小时</Button>
        <Button size="small" onClick={() => handlePresetTime(6)}>6小时</Button>
        <Button size="small" onClick={() => handlePresetTime(24)}>24小时</Button>
        <Button size="small" onClick={() => handlePresetTime(168)}>7天</Button>
        <RangePicker
          showTime
          format="YYYY-MM-DD HH:mm"
          onChange={(dates) => handleTimeRangeChange(dates as [Dayjs, Dayjs] | null)}
          value={timeRange}
          style={{ marginLeft: 8 }}
        />
      </Space>

      {/* 统计信息 */}
      {stats && (
        <Row gutter={16} style={{ marginBottom: 16 }}>
          <Col span={6}>
            <Statistic
              title="总发送流量"
              value={formatBytes(stats.totalBytesSent)}
              valueStyle={{ color: '#1890ff' }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="总接收流量"
              value={formatBytes(stats.totalBytesRecv)}
              valueStyle={{ color: '#52c41a' }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="平均发送带宽"
              value={formatBandwidth(stats.avgBandwidthSent)}
              valueStyle={{ color: '#1890ff' }}
            />
          </Col>
          <Col span={6}>
            <Statistic
              title="平均接收带宽"
              value={formatBandwidth(stats.avgBandwidthRecv)}
              valueStyle={{ color: '#52c41a' }}
            />
          </Col>
        </Row>
      )}

      {/* 趋势图表 */}
      {chartData.length > 0 ? (
        <ResponsiveContainer width="100%" height={400}>
          <LineChart data={chartData}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis 
              dataKey="time" 
              tick={{ fontSize: 12 }}
              interval="preserveStartEnd"
              label={{ value: '时间', position: 'insideBottom', offset: -5 }}
            />
            <YAxis 
              yAxisId="bandwidth"
              orientation="left"
              tick={{ fontSize: 12 }}
              label={{ value: '带宽 (Mbps)', angle: -90, position: 'insideLeft' }}
            />
            <YAxis 
              yAxisId="volume"
              orientation="right"
              tick={{ fontSize: 12 }}
              label={{ value: '总流量 (MB)', angle: 90, position: 'insideRight' }}
            />
            <Tooltip 
              formatter={(value: number, name: string) => {
                if (name.includes('带宽')) {
                  return [`${value.toFixed(2)} Mbps`, name];
                } else {
                  return [`${value.toFixed(2)} MB`, name];
                }
              }}
              labelFormatter={(label) => `时间: ${label}`}
            />
            <Legend />
            <Line
              yAxisId="bandwidth"
              type="monotone"
              dataKey="发送带宽(Mbps)"
              stroke="#1890ff"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 6 }}
            />
            <Line
              yAxisId="bandwidth"
              type="monotone"
              dataKey="接收带宽(Mbps)"
              stroke="#52c41a"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 6 }}
            />
            <Line
              yAxisId="volume"
              type="monotone"
              dataKey="总流量(MB)"
              stroke="#fa8c16"
              strokeWidth={2}
              dot={false}
              activeDot={{ r: 6 }}
              strokeDasharray="5 5"
            />
          </LineChart>
        </ResponsiveContainer>
      ) : (
        <div style={{ textAlign: 'center', padding: '50px', color: '#999' }}>
          {loading ? '加载中...' : '暂无数据，请等待数据采集'}
        </div>
      )}

      {/* 数据点统计 */}
      <div style={{ marginTop: 16, color: '#999', fontSize: 12 }}>
        共 {chartData.length} 个数据点，时间范围: {hours} 小时
      </div>
    </Card>
  );
};

export default TrafficTrendChart;

