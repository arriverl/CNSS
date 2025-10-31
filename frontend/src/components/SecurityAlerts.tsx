import React from 'react';
import { Card, List, Tag, Typography, Empty, Space } from 'antd';
import { 
  WarningOutlined, 
  ExclamationCircleOutlined,
  ClockCircleOutlined,
  WifiOutlined
} from '@ant-design/icons';

const { Text } = Typography;

interface Alert {
  type: string;
  interface: string;
  value: number;
  timestamp: number;
  message: string;
}

interface SecurityAlertsProps {
  alerts: Alert[];
}

const SecurityAlerts: React.FC<SecurityAlertsProps> = ({ alerts }) => {
  const getAlertColor = (type: string) => {
    switch (type) {
      case 'high_bandwidth':
        return 'red';
      case 'suspicious_activity':
        return 'orange';
      case 'connection_anomaly':
        return 'purple';
      default:
        return 'blue';
    }
  };

  const getAlertIcon = (type: string) => {
    switch (type) {
      case 'high_bandwidth':
        return <ExclamationCircleOutlined />;
      case 'suspicious_activity':
        return <WarningOutlined />;
      case 'connection_anomaly':
        return <WifiOutlined />;
      default:
        return <WarningOutlined />;
    }
  };

  const formatBandwidth = (bps: number): string => {
    if (bps === 0) return '0 bps';
    const k = 1000;
    const sizes = ['bps', 'Kbps', 'Mbps', 'Gbps'];
    const i = Math.floor(Math.log(bps) / Math.log(k));
    return parseFloat((bps / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  };

  if (alerts.length === 0) {
    return (
      <Card title="安全告警" extra={<Tag color="green">正常</Tag>}>
        <Empty 
          description="暂无安全告警"
          image={Empty.PRESENTED_IMAGE_SIMPLE}
        />
      </Card>
    );
  }

  return (
    <Card 
      title={
        <Space>
          <WarningOutlined style={{ color: '#faad14' }} />
          <span>安全告警</span>
          <Tag color="red">{alerts.length} 个告警</Tag>
        </Space>
      }
    >
      <List
        dataSource={alerts}
        renderItem={(alert) => (
          <List.Item>
            <List.Item.Meta
              avatar={getAlertIcon(alert.type)}
              title={
                <Space>
                  <Text strong>{alert.message}</Text>
                  <Tag color={getAlertColor(alert.type)}>
                    {alert.type.replace('_', ' ').toUpperCase()}
                  </Tag>
                </Space>
              }
              description={
                <Space direction="vertical" size="small">
                  <Space>
                    <WifiOutlined />
                    <Text code>{alert.interface}</Text>
                    <Text type="secondary">带宽: {formatBandwidth(alert.value)}</Text>
                  </Space>
                  <Space>
                    <ClockCircleOutlined />
                    <Text type="secondary">
                      {new Date(alert.timestamp * 1000).toLocaleString()}
                    </Text>
                  </Space>
                </Space>
              }
            />
          </List.Item>
        )}
      />
    </Card>
  );
};

export default SecurityAlerts;



