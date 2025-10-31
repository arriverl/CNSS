import axios from 'axios';

// 类型定义（如果需要可以在其他地方使用）
// interface TrafficData {
//   timestamp: number;
//   interface: string;
//   bytes_sent: number;
//   bytes_recv: number;
//   packets_sent: number;
//   packets_recv: number;
//   bandwidth_sent: number;
//   bandwidth_recv: number;
// }

// interface SystemInfo {
//   cpu_percent: number;
//   memory_percent: number;
//   disk_usage: number;
//   network_interfaces: string[];
//   timestamp: number;
//   platform?: string;
//   simulation_mode?: boolean;
// }

// interface SecurityAlert {
//   alert_id: string;
//   type: string;
//   severity: string;
//   interface: string;
//   description: string;
//   timestamp: number;
//   source_ip?: string;
//   destination_ip?: string;
//   port?: number;
//   protocol?: string;
//   bytes_transferred?: number;
//   confidence?: number;
// }

// 创建axios实例
const api = axios.create({
  baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8000',
  timeout: 10000,
});

// 请求拦截器
api.interceptors.request.use(
  (config) => {
    const token = localStorage.getItem('token');
    if (token) {
      config.headers.Authorization = `Bearer ${token}`;
    }
    return config;
  },
  (error) => {
    return Promise.reject(error);
  }
);

// 响应拦截器
api.interceptors.response.use(
  (response) => {
    return response;
  },
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

// API接口
export const apiService = {
  // 获取当前流量数据
  getCurrentTraffic: () => api.get('/api/traffic/current'),
  
  // 获取历史流量数据
  getTrafficHistory: (interfaceName?: string, hours?: number) => {
    const params = new URLSearchParams();
    if (interfaceName) params.append('interface', interfaceName);
    if (hours) params.append('hours', hours.toString());
    return api.get(`/api/traffic/history?${params.toString()}`);
  },
  
  // 获取系统信息
  getSystemInfo: () => api.get('/api/system/info'),
  
  // 获取安全告警
  getSecurityAlerts: () => api.get('/api/security/alerts'),
  
  // 获取当前安全态势
  getSituation: (hours: number = 1) => api.get(`/api/situation/current?hours=${hours}`),
  
  // 获取态势趋势
  getTrend: (days: number = 7) => api.get(`/api/situation/trend?days=${days}`),
  
  // 事件分析
  analyzeEvents: (hours: number = 24) => api.get(`/api/events/analysis?hours=${hours}`),
  
  // 获取事件列表
  listEvents: (params?: {
    start_time?: string;
    end_time?: string;
    risk_level?: string;
    event_type?: string;
    limit?: number;
  }) => {
    const queryParams = new URLSearchParams();
    if (params?.start_time) queryParams.append('start_time', params.start_time);
    if (params?.end_time) queryParams.append('end_time', params.end_time);
    if (params?.risk_level) queryParams.append('risk_level', params.risk_level);
    if (params?.event_type) queryParams.append('event_type', params.event_type);
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    return api.get(`/api/events/list?${queryParams.toString()}`);
  },
  
  // 生成报告
  generateReport: (type: 'daily' | 'weekly', date?: string) => {
    const url = type === 'daily' ? '/api/reports/daily' : '/api/reports/weekly';
    const params = date ? `?date=${date}` : '';
    return api.get(`${url}${params}`, { responseType: 'blob' });
  },
  
  // 获取风险汇总
  getRiskSummary: (days: number = 7) => api.get(`/api/risk/summary?days=${days}`),
  
  // 获取操作日志
  getAuditLogs: (params?: {
    start_time?: string;
    end_time?: string;
    user_id?: number;
    action?: string;
    limit?: number;
  }) => {
    const queryParams = new URLSearchParams();
    if (params?.start_time) queryParams.append('start_time', params.start_time);
    if (params?.end_time) queryParams.append('end_time', params.end_time);
    if (params?.user_id) queryParams.append('user_id', params.user_id.toString());
    if (params?.action) queryParams.append('action', params.action);
    if (params?.limit) queryParams.append('limit', params.limit.toString());
    return api.get(`/api/audit/logs?${queryParams.toString()}`);
  },
  
  // 健康检查
  healthCheck: () => api.get('/api/health'),
};

// 导出具体的API函数
export const getCurrentTraffic = apiService.getCurrentTraffic;
export const getTrafficHistory = apiService.getTrafficHistory;
export const getSystemInfo = apiService.getSystemInfo;
export const getSecurityAlerts = apiService.getSecurityAlerts;
export const getSituation = apiService.getSituation;
export const getTrend = apiService.getTrend;
export const analyzeEvents = apiService.analyzeEvents;
export const listEvents = apiService.listEvents;
export const generateReport = apiService.generateReport;
export const getRiskSummary = apiService.getRiskSummary;
export const getAuditLogs = apiService.getAuditLogs;
export const healthCheck = apiService.healthCheck;
