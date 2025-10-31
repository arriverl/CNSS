# 校园网络安全态势可视化平台 - 系统设计文档

## 一、系统概述

### 1.1 系统定位
校园网络安全态势可视化平台是一套面向校园局域网的安全事件监测与展示系统。系统通过采集模拟网络流量、日志或安全事件数据，对其进行分析、分类与风险等级评估，并以图形化仪表盘的方式呈现整体网络安全态势。

### 1.2 核心价值
- **实时监控**：24/7不间断监控校园网络安全状态
- **智能分析**：结合规则检测和AI模型，准确识别安全威胁
- **可视化展示**：直观的图表和仪表盘，快速了解安全态势
- **报告生成**：自动生成日报和周报，提供安全建议

## 二、系统架构

### 2.1 总体架构

```
┌─────────────────────────────────────────────────────────┐
│                    前端展示层                            │
│  React + TypeScript + Ant Design + Charts               │
│  - 仪表盘 - 趋势图 - 风险地图 - 告警视图                  │
└─────────────────────────────────────────────────────────┘
                          ↕ HTTP/REST API
┌─────────────────────────────────────────────────────────┐
│                   后端逻辑层                             │
│  FastAPI + Python                                        │
│  - API接口 - 业务逻辑 - 数据处理                         │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│                   数据采集层                             │
│  - Wireshark流量捕获                                     │
│  - 系统监控 (psutil)                                     │
│  - 定时采集器                                            │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│                   分析处理层                             │
│  - 事件分析器 (规则 + AI)                                │
│  - 态势评估器                                            │
│  - 报告生成器                                            │
└─────────────────────────────────────────────────────────┘
                          ↕
┌─────────────────────────────────────────────────────────┐
│                   数据存储层                             │
│  PostgreSQL                                             │
│  - users - events - risk_summary - logs                 │
└─────────────────────────────────────────────────────────┘
```

### 2.2 模块划分

#### 2.2.1 用户管理模块
- **功能**：用户登录、权限管理、操作日志
- **技术**：JWT认证、密码哈希、会话管理
- **数据库表**：users, logs

#### 2.2.2 数据采集模块
- **功能**：定时采集网络日志、安全告警
- **技术**：Wireshark、psutil、异步任务
- **特点**：可配置采集间隔、数据持久化

#### 2.2.3 事件分析模块
- **功能**：日志分类、异常检测
- **技术**：
  - 规则检测：DDoS、端口扫描、暴力破解等
  - AI模型：IsolationForest、KMeans
- **输出**：异常事件列表、检测统计

#### 2.2.4 态势评估模块
- **功能**：计算风险指数、趋势分析
- **算法**：
  - 风险指数 = Σ(事件权重 × 置信度)
  - 趋势分析：时间序列对比
- **输出**：风险等级、趋势方向、统计汇总

#### 2.2.5 可视化展示模块
- **功能**：实时仪表盘、告警趋势图、风险地图
- **组件**：
  - 风险指数卡片
  - 趋势折线图
  - 事件分布饼图
  - 每日统计柱状图

#### 2.2.6 报告生成模块
- **功能**：导出日报/周报PDF，提供安全建议
- **技术**：ReportLab
- **内容**：
  - 安全态势概览
  - 事件类型分析
  - 异常检测结果
  - 安全建议

## 三、数据库设计

### 3.1 表结构

#### users（用户表）
```sql
id: INTEGER PRIMARY KEY
username: VARCHAR(50) UNIQUE
password: VARCHAR(255)  -- 存储SHA256哈希值
role: VARCHAR(20)  -- admin, monitor, viewer
last_login: DATETIME
created_at: DATETIME
```

#### events（安全事件表）
```sql
id: INTEGER PRIMARY KEY
event_type: VARCHAR(50)  -- ddos, port_scan, etc.
src_ip: VARCHAR(45)  -- 支持IPv6
dst_ip: VARCHAR(45)
timestamp: DATETIME
risk_level: VARCHAR(20)  -- low, medium, high, critical
description: TEXT
interface: VARCHAR(100)
protocol: VARCHAR(20)
port: INTEGER
bytes_transferred: INTEGER
confidence: FLOAT  -- 0.0-1.0
metadata: TEXT  -- JSON格式
```

#### risk_summary（风险汇总表）
```sql
id: INTEGER PRIMARY KEY
date: DATETIME UNIQUE
high: INTEGER
medium: INTEGER
low: INTEGER
critical: INTEGER
total_score: FLOAT  -- 风险指数
created_at: DATETIME
```

#### logs（操作日志表）
```sql
id: INTEGER PRIMARY KEY
user_id: INTEGER FOREIGN KEY -> users.id
action: VARCHAR(100)  -- login, logout, view_dashboard, etc.
time: DATETIME
details: TEXT
ip_address: VARCHAR(45)
```

### 3.2 数据关系

```
users (1) ────< (N) logs
users (1) ────< (N) events (间接关联)
events → risk_summary (聚合)
```

## 四、API接口设计

### 4.1 认证接口
- `POST /api/auth/login` - 用户登录

### 4.2 态势接口
- `GET /api/situation/current?hours=1` - 获取当前安全态势
- `GET /api/situation/trend?days=7` - 获取态势趋势

### 4.3 事件接口
- `GET /api/events/analysis?hours=24` - 事件分析
- `GET /api/events/list` - 获取事件列表（支持过滤）

### 4.4 报告接口
- `GET /api/reports/daily?date=2024-01-01` - 生成日报PDF
- `GET /api/reports/weekly?date=2024-01-01` - 生成周报PDF

### 4.5 其他接口
- `GET /api/risk/summary?days=7` - 获取风险汇总
- `GET /api/audit/logs` - 获取操作日志
- `POST /api/collector/start?interval=5` - 启动数据采集
- `POST /api/collector/stop` - 停止数据采集

## 五、关键技术实现

### 5.1 风险指数计算

```python
风险指数 = Σ(事件权重 × 置信度) / 归一化因子

权重配置：
- critical: 10.0
- high: 5.0
- medium: 2.0
- low: 1.0

归一化：score = min(total_score / 10.0, 100.0)
```

### 5.2 异常检测算法

#### 规则检测
- DDoS检测：短时间内大量连接（>20次/5分钟）
- 端口扫描：同一IP访问多个端口（>10个端口）
- 暴力破解：多次失败登录尝试（>5次）
- 数据泄露：异常大传输（>1GB）

#### AI模型检测
- IsolationForest：孤立森林异常检测
- 特征提取：时间、风险等级、数值特征
- 置信度：基于异常分数

### 5.3 趋势分析

```python
趋势方向判断：
- increasing: 当前指数 > 前一时段指数 × 1.2
- decreasing: 当前指数 < 前一时段指数 × 0.8
- stable: 其他情况
```

## 六、部署架构

### 6.1 Docker Compose服务

```yaml
services:
  postgres:      # PostgreSQL数据库
  traffic-monitor:  # 主应用服务
  redis:        # 缓存服务（可选）
  nginx:        # 反向代理（可选）
```

### 6.2 环境变量

```bash
DATABASE_URL=postgresql://user:password@host:5432/dbname
SECRET_KEY=your_secret_key
```

## 七、安全设计

### 7.1 认证与授权
- JWT令牌：无状态认证
- 密码加密：SHA256哈希
- 角色权限：admin > monitor > viewer

### 7.2 数据安全
- SQL注入防护：ORM参数化查询
- XSS防护：前端输入验证
- CSRF防护：Token验证

### 7.3 日志审计
- 所有操作记录日志
- 登录失败记录
- 敏感操作追踪

## 八、扩展性设计

### 8.1 水平扩展
- 无状态API服务
- 数据库读写分离
- 负载均衡

### 8.2 功能扩展
- 插件化检测规则
- 自定义AI模型
- 多数据源支持

## 九、性能优化

### 9.1 数据库优化
- 索引优化（timestamp, risk_level等）
- 数据分区（按时间）
- 查询缓存

### 9.2 前端优化
- 组件懒加载
- 数据分页
- 图表虚拟滚动

## 十、未来规划

1. **实时告警**：WebSocket推送
2. **机器学习**：深度学习模型训练
3. **威胁情报**：集成外部威胁库
4. **自动化响应**：自动阻断异常流量
5. **多租户支持**：支持多个校园网络

