import React from 'react';
import { Progress, List, Typography, Space, Tag } from 'antd';
import { 
  DesktopOutlined, 
  DatabaseOutlined, 
  HddOutlined,
  WifiOutlined 
} from '@ant-design/icons';

const { Text } = Typography;

interface SystemInfoData {
  cpu_percent: number;
  memory_percent: number;
  disk_usage: number;
  network_interfaces: string[];
  timestamp: number;
}

interface SystemInfoProps {
  data: SystemInfoData | null;
}

const SystemInfo: React.FC<SystemInfoProps> = ({ data }) => {
  if (!data) {
    return (
      <div style={{ textAlign: 'center', color: '#999' }}>
        暂无系统信息
      </div>
    );
  }

  const getProgressColor = (percent: number) => {
    if (percent < 50) return '#52c41a';
    if (percent < 80) return '#faad14';
    return '#f5222d';
  };

  const getStatusText = (percent: number) => {
    if (percent < 50) return '正常';
    if (percent < 80) return '警告';
    return '危险';
  };

  return (
    <div>
      {/* CPU使用率 */}
      <div style={{ marginBottom: 16 }}>
        <Space align="center" style={{ marginBottom: 8 }}>
          <DesktopOutlined />
          <Text strong>CPU使用率</Text>
          <Tag color={getProgressColor(data.cpu_percent)}>
            {getStatusText(data.cpu_percent)}
          </Tag>
        </Space>
        <Progress
          percent={data.cpu_percent}
          strokeColor={getProgressColor(data.cpu_percent)}
          showInfo={true}
          format={(percent) => `${percent}%`}
        />
      </div>

      {/* 内存使用率 */}
      <div style={{ marginBottom: 16 }}>
        <Space align="center" style={{ marginBottom: 8 }}>
          <DatabaseOutlined />
          <Text strong>内存使用率</Text>
          <Tag color={getProgressColor(data.memory_percent)}>
            {getStatusText(data.memory_percent)}
          </Tag>
        </Space>
        <Progress
          percent={data.memory_percent}
          strokeColor={getProgressColor(data.memory_percent)}
          showInfo={true}
          format={(percent) => `${percent}%`}
        />
      </div>

      {/* 磁盘使用率 */}
      <div style={{ marginBottom: 16 }}>
        <Space align="center" style={{ marginBottom: 8 }}>
          <HddOutlined />
          <Text strong>磁盘使用率</Text>
          <Tag color={getProgressColor(data.disk_usage)}>
            {getStatusText(data.disk_usage)}
          </Tag>
        </Space>
        <Progress
          percent={data.disk_usage}
          strokeColor={getProgressColor(data.disk_usage)}
          showInfo={true}
          format={(percent) => `${percent}%`}
        />
      </div>

      {/* 网络接口 */}
      <div>
        <Space align="center" style={{ marginBottom: 8 }}>
          <WifiOutlined />
          <Text strong>网络接口</Text>
          <Tag color="blue">{data.network_interfaces.length} 个</Tag>
        </Space>
        <List
          size="small"
          dataSource={data.network_interfaces}
          renderItem={(item) => (
            <List.Item>
              <Text code>{item}</Text>
            </List.Item>
          )}
        />
      </div>

      {/* 更新时间 */}
      <div style={{ 
        marginTop: 16, 
        padding: '8px 0', 
        borderTop: '1px solid #f0f0f0',
        textAlign: 'center'
      }}>
        <Text type="secondary" style={{ fontSize: '12px' }}>
          更新时间: {new Date(data.timestamp * 1000).toLocaleString()}
        </Text>
      </div>
    </div>
  );
};

export default SystemInfo;



