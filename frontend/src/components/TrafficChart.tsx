import React from 'react';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer } from 'recharts';

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

interface TrafficChartProps {
  data: TrafficData[];
}

const TrafficChart: React.FC<TrafficChartProps> = ({ data }) => {
  // 处理数据，转换为图表格式，按时间排序
  const chartData = data
    .sort((a, b) => a.timestamp - b.timestamp) // 按时间排序
    .map(item => ({
      time: new Date(item.timestamp * 1000).toLocaleTimeString(),
      timestamp: item.timestamp,
      '发送带宽(Mbps)': parseFloat((item.bandwidth_sent / 1000000).toFixed(2)),
      '接收带宽(Mbps)': parseFloat((item.bandwidth_recv / 1000000).toFixed(2)),
      '发送包数': item.packets_sent,
      '接收包数': item.packets_recv,
    }));

  const CustomTooltip = ({ active, payload, label }: any) => {
    if (active && payload && payload.length) {
      return (
        <div style={{
          background: 'rgba(0, 0, 0, 0.8)',
          border: '1px solid #ccc',
          borderRadius: '4px',
          padding: '10px',
          color: 'white'
        }}>
          <p style={{ margin: 0, fontWeight: 'bold' }}>{`时间: ${label}`}</p>
          {payload.map((entry: any, index: number) => (
            <p key={index} style={{ margin: '5px 0 0 0', color: entry.color }}>
              {`${entry.name}: ${entry.value}`}
            </p>
          ))}
        </div>
      );
    }
    return null;
  };

  if (data.length === 0) {
    return (
      <div style={{ 
        height: 400, 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'center',
        color: '#999'
      }}>
        暂无数据
      </div>
    );
  }

  return (
    <div style={{ height: 400 }}>
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={chartData}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis 
            dataKey="time" 
            tick={{ fontSize: 12 }}
            interval="preserveStartEnd"
            type="category"
            scale="point"
          />
          <YAxis 
            yAxisId="bandwidth"
            orientation="left"
            tick={{ fontSize: 12 }}
            label={{ value: '带宽 (Mbps)', angle: -90, position: 'insideLeft' }}
          />
          <YAxis 
            yAxisId="packets"
            orientation="right"
            tick={{ fontSize: 12 }}
            label={{ value: '包数', angle: 90, position: 'insideRight' }}
          />
          <Tooltip content={<CustomTooltip />} />
          <Legend />
          <Line
            yAxisId="bandwidth"
            type="monotone"
            dataKey="发送带宽(Mbps)"
            stroke="#1890ff"
            strokeWidth={2}
            dot={{ r: 4 }}
            activeDot={{ r: 6 }}
          />
          <Line
            yAxisId="bandwidth"
            type="monotone"
            dataKey="接收带宽(Mbps)"
            stroke="#52c41a"
            strokeWidth={2}
            dot={{ r: 4 }}
            activeDot={{ r: 6 }}
          />
          <Line
            yAxisId="packets"
            type="monotone"
            dataKey="发送包数"
            stroke="#fa8c16"
            strokeWidth={2}
            dot={{ r: 4 }}
            activeDot={{ r: 6 }}
          />
          <Line
            yAxisId="packets"
            type="monotone"
            dataKey="接收包数"
            stroke="#eb2f96"
            strokeWidth={2}
            dot={{ r: 4 }}
            activeDot={{ r: 6 }}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
};

export default TrafficChart;
