import React, { useState, useEffect } from 'react';
import { Layout, Card, Row, Col, Statistic, Button, Select, message, Alert, Spin } from 'antd';
import { LogoutOutlined, ReloadOutlined, WarningOutlined } from '@ant-design/icons';
import { useAuth } from '../contexts/AuthContext';
import { useNavigate } from 'react-router-dom';
import TrafficChart from './TrafficChart';
import TrafficTrendChart from './TrafficTrendChart';
import SystemInfo from './SystemInfo';
import SecurityAlerts from './SecurityAlerts';
import { getCurrentTraffic, getTrafficHistory, getSystemInfo, getSecurityAlerts } from '../services/api';

const { Header, Content } = Layout;
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

interface SystemInfoData {
  cpu_percent: number;
  memory_percent: number;
  disk_usage: number;
  network_interfaces: string[];
  timestamp: number;
  platform?: string;
  simulation_mode?: boolean;
}

const Dashboard: React.FC = () => {
  const { logout } = useAuth();
  const navigate = useNavigate();
  const [trafficHistory, setTrafficHistory] = useState<TrafficData[]>([]);
  const [systemInfo, setSystemInfo] = useState<SystemInfoData | null>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [selectedInterface, setSelectedInterface] = useState<string>('all');
  const [loading, setLoading] = useState(false);
  const [autoRefresh, setAutoRefresh] = useState(true);

  // 首次加载时获取历史数据
  const fetchHistoryData = async () => {
    try {
      const response = await getTrafficHistory(undefined, 24); // 获取过去24小时的数据
      if (response.data && response.data.data) {
        // 按时间排序
        const sortedData = response.data.data.sort((a: TrafficData, b: TrafficData) => 
          a.timestamp - b.timestamp
        );
        setTrafficHistory(sortedData);
      }
    } catch (error) {
      console.error('获取历史数据失败:', error);
    }
  };

  const fetchData = async () => {
    try {
      setLoading(true);
      const [trafficResponse, systemResponse, alertsResponse] = await Promise.all([
        getCurrentTraffic(),
        getSystemInfo(),
        getSecurityAlerts()
      ]);

      const newTrafficData = trafficResponse.data.data;
      
      // 添加新数据到历史记录（去重并保持按时间排序）
      if (newTrafficData && newTrafficData.length > 0) {
        setTrafficHistory(prevHistory => {
          const existingTimestamps = new Set(prevHistory.map(d => d.timestamp));
          const newData = newTrafficData.filter((d: TrafficData) => 
            !existingTimestamps.has(d.timestamp)
          );
          const updatedHistory = [...prevHistory, ...newData];
          // 按时间排序并保留最近24小时的数据（约17280个数据点，5秒一个）
          return updatedHistory
            .sort((a, b) => a.timestamp - b.timestamp)
            .slice(-17280);
        });
      }
      
      setSystemInfo(systemResponse.data);
      setAlerts(alertsResponse.data.alerts);
    } catch (error) {
      message.error('获取数据失败');
      console.error('获取数据失败:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    // 首次加载时获取历史数据
    fetchHistoryData();
    // 然后开始实时刷新
    fetchData();
    
    if (autoRefresh) {
      const interval = setInterval(fetchData, 5000); // 每5秒刷新一次
      return () => clearInterval(interval);
    }
  }, [autoRefresh]);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

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

  const filteredTrafficData = selectedInterface === 'all' 
    ? trafficHistory 
    : trafficHistory.filter(data => data.interface === selectedInterface);

  const totalBytesSent = filteredTrafficData.reduce((sum, data) => sum + data.bytes_sent, 0);
  const totalBytesRecv = filteredTrafficData.reduce((sum, data) => sum + data.bytes_recv, 0);
  const totalBandwidthSent = filteredTrafficData.reduce((sum, data) => sum + data.bandwidth_sent, 0);
  const totalBandwidthRecv = filteredTrafficData.reduce((sum, data) => sum + data.bandwidth_recv, 0);

  return (
    <Layout style={{ minHeight: '100vh' }}>
      <Header style={{ 
        background: '#001529', 
        padding: '0 24px',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center'
      }}>
        <h1 style={{ color: 'white', margin: 0 }}>实时流量监控系统</h1>
        <div>
          <Button 
            type="primary" 
            icon={<ReloadOutlined />} 
            onClick={fetchData}
            loading={loading}
            style={{ marginRight: 16 }}
          >
            刷新
          </Button>
          <Button 
            type="default" 
            icon={<LogoutOutlined />} 
            onClick={handleLogout}
          >
            退出
          </Button>
        </div>
      </Header>

      <Content style={{ padding: '24px', background: '#f0f2f5' }}>
        {/* 安全告警 */}
        {alerts.length > 0 && (
          <Alert
            message={`发现 ${alerts.length} 个安全告警`}
            description="请查看安全监控面板了解详情"
            type="warning"
            icon={<WarningOutlined />}
            style={{ marginBottom: 16 }}
            showIcon
          />
        )}

        {/* 系统概览 */}
        <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="CPU使用率"
                value={systemInfo?.cpu_percent || 0}
                suffix="%"
                valueStyle={{ color: systemInfo && systemInfo.cpu_percent > 80 ? '#cf1322' : '#3f8600' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="内存使用率"
                value={systemInfo?.memory_percent || 0}
                suffix="%"
                valueStyle={{ color: systemInfo && systemInfo.memory_percent > 80 ? '#cf1322' : '#3f8600' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="磁盘使用率"
                value={systemInfo?.disk_usage || 0}
                suffix="%"
                valueStyle={{ color: systemInfo && systemInfo.disk_usage > 80 ? '#cf1322' : '#3f8600' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="网络接口"
                value={systemInfo?.network_interfaces?.length || 0}
                suffix="个"
              />
            </Card>
          </Col>
        </Row>

        {/* 流量统计 */}
        <Row gutter={[16, 16]} style={{ marginBottom: 24 }}>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="总发送流量"
                value={formatBytes(totalBytesSent)}
                valueStyle={{ color: '#1890ff' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="总接收流量"
                value={formatBytes(totalBytesRecv)}
                valueStyle={{ color: '#52c41a' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="发送带宽"
                value={formatBandwidth(totalBandwidthSent)}
                valueStyle={{ color: '#1890ff' }}
              />
            </Card>
          </Col>
          <Col xs={24} sm={12} md={6}>
            <Card>
              <Statistic
                title="接收带宽"
                value={formatBandwidth(totalBandwidthRecv)}
                valueStyle={{ color: '#52c41a' }}
              />
            </Card>
          </Col>
        </Row>

        {/* 接口选择 */}
        <Card style={{ marginBottom: 24 }}>
          <Row gutter={16} align="middle">
            <Col>
              <span>选择网络接口：</span>
            </Col>
            <Col>
              <Select
                value={selectedInterface}
                onChange={setSelectedInterface}
                style={{ width: 200 }}
              >
                <Option value="all">全部接口</Option>
                {systemInfo?.network_interfaces?.map(iface => (
                  <Option key={iface} value={iface}>{iface}</Option>
                ))}
              </Select>
            </Col>
            <Col>
              <Button
                type={autoRefresh ? 'primary' : 'default'}
                onClick={() => setAutoRefresh(!autoRefresh)}
                style={{ marginRight: 8 }}
              >
                {autoRefresh ? '停止自动刷新' : '开始自动刷新'}
              </Button>
              <Button
                type="default"
                onClick={() => setTrafficHistory([])}
                danger
              >
                清除历史数据
              </Button>
            </Col>
          </Row>
        </Card>

        {/* 历史趋势图表 */}
        <Row gutter={[16, 16]} style={{ marginBottom: 16 }}>
          <Col span={24}>
            <TrafficTrendChart defaultHours={24} />
          </Col>
        </Row>

        {/* 图表区域 */}
        <Row gutter={[16, 16]}>
          <Col xs={24} lg={16}>
            <Card 
              title={`实时流量图表 (${filteredTrafficData.length} 个数据点)`} 
              extra={<Spin spinning={loading} />}
            >
              <TrafficChart data={filteredTrafficData} />
            </Card>
          </Col>
          <Col xs={24} lg={8}>
            <Card title="系统信息">
              <SystemInfo data={systemInfo} />
            </Card>
          </Col>
        </Row>

        {/* 安全告警 */}
        <Row style={{ marginTop: 16 }}>
          <Col span={24}>
            <SecurityAlerts alerts={alerts} />
          </Col>
        </Row>
      </Content>
    </Layout>
  );
};

export default Dashboard;
