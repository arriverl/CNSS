# 校园网络安全态势可视化平台 (Campus Network Security Situation Visualization Platform)

## 项目概述

本项目是一套面向校园局域网的安全事件监测与展示系统。系统通过采集模拟网络流量、日志或安全事件数据，对其进行分析、分类与风险等级评估，并以图形化仪表盘的方式呈现整体网络安全态势。

系统提供用户管理、数据采集、事件分析、可视化展示、日志审计等模块，构建从数据获取到安全可视化的完整闭环。结合了编程、网络空间安全、软件工程等多学科技术，提供安全、高效的网络安全态势监控解决方案。

## 技术栈

### 后端技术
- **框架**: Python 3.9+ (FastAPI)
- **数据库**: PostgreSQL + SQLAlchemy ORM（自动降级到SQLite）
- **AI分析**: scikit-learn (IsolationForest, DBSCAN, KMeans)
- **特征工程**: 15维特征向量提取
- **实时检测**: 5秒周期实时异常检测
- **报告生成**: ReportLab (PDF生成)
- **数据分析**: pandas, numpy
- **安全**: JWT认证、密码哈希

### 前端技术
- **框架**: React 18 + TypeScript
- **UI组件**: Ant Design
- **可视化**: Recharts / ECharts
- **路由**: React Router

### 部署技术
- **容器化**: Docker + Docker Compose
- **缓存**: Redis（可选）
- **反向代理**: Nginx（可选）

## 系统架构

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   前端界面      │    │   API网关       │    │   微服务集群    │
│   (React)       │◄──►│   (Kong)        │◄──►│   (FastAPI)     │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌─────────────────┐
                       │   数据层        │
                       │ (PostgreSQL +   │
                       │  Redis)         │
                       └─────────────────┘
```

## 核心功能模块

### 🧩 核心模块

1. **用户管理模块**
   - 管理员登录、权限分配（admin、monitor、viewer）
   - 操作日志审计
   - 用户活动追踪

2. **数据采集模块**
   - 模拟或定时采集网络日志
   - 安全告警数据采集
   - 数据持久化存储

3. **事件分析模块**
   - 日志分类与识别
   - **实时异常检测（规则检测 + AI模型）**
     - Isolation Forest（孤立森林）异常检测
     - DBSCAN/K-Means 聚类异常检测
     - 15维特征向量提取
     - 实时风险评分计算
   - DDoS、端口扫描、暴力破解等威胁检测
   - 自动保存异常事件到数据库

4. **态势评估模块**
   - 风险指数计算
   - 趋势分析
   - 风险等级评估（low、medium、high、critical）
   - 每日/周风险汇总

5. **可视化展示模块**
   - 实时仪表盘
   - 告警趋势图
   - 风险地图
   - 态势动态更新

6. **报告生成模块**
   - 日报/周报PDF导出
   - 安全建议生成
   - 统计分析报表

## 快速开始

### 方式1：Wireshark模式（推荐）

使用真实网络流量数据，无需模拟数据：

```bash
# 1. 安装Wireshark（如果未安装）
# Windows: 下载并安装Wireshark
# Linux: sudo apt install wireshark
# macOS: brew install wireshark

# 2. 启动后端服务
python start_with_wireshark.py

# 3. 启动前端服务（新终端窗口）
# 方法A：完整前端（如果遇到TypeScript错误）
python start_frontend.py

# 方法B：简化测试页面（推荐，避免复杂问题）
python start_frontend_simple.py
```

### 方式1.1：仅后端API（无需前端）

如果只需要API服务，可以只启动后端：

```bash
# 启动后端服务
python start_with_wireshark.py

# 访问API文档
# http://localhost:8000/docs
```

### 方式2：Docker一键部署

```bash
# 1. 下载项目文件到服务器
# 2. 给部署脚本执行权限
chmod +x deploy.sh

# 3. 执行一键部署
./deploy.sh
```

部署完成后，访问 http://your-server-ip 即可使用系统。

### 方式3：手动部署

#### 环境要求
- Docker 20.10+
- Docker Compose 1.29+
- 4GB+ 内存
- 10GB+ 磁盘空间

#### 安装步骤

1. 构建和启动服务
```bash
# 构建Docker镜像
docker-compose build

# 启动所有服务
docker-compose up -d
```

2. 验证部署
```bash
# 检查服务状态
docker-compose ps

# 查看日志
docker-compose logs -f
```

3. 访问系统
- 前端界面: http://localhost
- API接口: http://localhost:8000
- 健康检查: http://localhost:8000/api/health

## 默认登录账号

- **管理员**: admin / admin123
- **监控员**: monitor / monitor123

> **安全提示**: 首次登录后请立即修改默认密码

## 项目结构

```
├── backend/                    # 后端服务
│   ├── main.py                # 主程序入口
│   ├── database.py            # 数据库模型和连接
│   ├── data_collector.py      # 数据采集模块（集成实时异常检测）
│   ├── feature_extractor.py   # 特征提取模块
│   ├── realtime_anomaly_detector.py  # 实时异常检测模块
│   ├── event_analyzer.py      # 事件分析模块
│   ├── situation_assessor.py  # 态势评估模块
│   ├── report_generator.py    # 报告生成模块
│   ├── security_monitor.py    # 安全监控模块
│   ├── windows_monitor.py     # Windows监控模块
│   ├── wireshark_monitor.py   # Wireshark监控模块
│   └── requirements.txt       # Python依赖
├── frontend/                   # 前端界面
│   ├── src/
│   │   ├── components/        # 组件
│   │   │   ├── Dashboard.tsx   # 主仪表盘
│   │   │   ├── SecurityAlerts.tsx
│   │   │   └── ...
│   │   ├── contexts/           # 上下文
│   │   ├── services/           # API服务
│   │   └── App.tsx
│   ├── public/
│   └── package.json
├── docs/                       # 项目文档
│   ├── deployment.md          # 部署指南
│   ├── user_guide.md          # 用户指南
│   └── architecture.md        # 架构文档
├── docker-compose.yml         # Docker编排
├── Dockerfile                 # Docker镜像
├── nginx.conf                 # Nginx配置
└── README.md                  # 项目说明
```

## 数据库表结构

### users - 用户表
- id: 主键
- username: 用户名（唯一）
- password: 密码哈希值
- role: 角色（admin/monitor/viewer）
- last_login: 最后登录时间

### events - 安全事件表
- id: 主键
- event_type: 事件类型
- src_ip: 源IP地址
- dst_ip: 目标IP地址
- timestamp: 时间戳
- risk_level: 风险等级（low/medium/high/critical）
- description: 事件描述
- confidence: 置信度

### risk_summary - 风险汇总表
- id: 主键
- date: 日期
- high: 高风险事件数
- medium: 中风险事件数
- low: 低风险事件数
- critical: 严重风险事件数
- total_score: 总风险指数

### logs - 操作日志表
- id: 主键
- user_id: 用户ID（外键）
- action: 操作类型
- time: 操作时间
- details: 详细信息
- ip_address: IP地址

## 功能特性

### 🔍 实时监控
- **真实流量监控**: 基于Wireshark的真实网络流量捕获
- **系统资源监控**: CPU、内存、磁盘使用情况
- **多接口支持**: 支持以太网、WiFi、虚拟接口等
- **自动数据刷新**: 实时数据更新和趋势分析

### 🛡️ 安全防护
- **AI异常检测**: 
  - Isolation Forest（孤立森林）算法
  - DBSCAN/K-Means 聚类检测
  - 15维特征向量实时分析
  - 自动模型训练和更新
- **规则匹配检测**: 
  - 端口扫描识别（SYN比例+目标数）
  - DDoS攻击检测（连接数阈值）
  - 数据泄露检测（流量异常）
- **智能风险评分**: 
  - 多因素加权风险计算
  - 自动风险等级分类（low/medium/high）
  - 置信度评估
- **实时告警**: 多级告警机制和通知系统
- **安全分析**: 深度数据包分析和协议识别

### 📊 数据可视化
- **实时图表**: 动态流量图表和趋势展示
- **历史分析**: 历史数据查询和统计分析
- **自定义面板**: 可配置的监控面板
- **多维度展示**: 按接口、协议、时间维度分析

### 🚀 部署方式
- **Wireshark模式**: 真实流量数据，功能最完整
- **Docker部署**: 容器化部署，生产环境就绪
- **跨平台支持**: Windows、Linux、macOS全平台支持
- **一键启动**: 自动化部署和配置脚本

## 技术栈

### 后端技术
- **FastAPI**: 高性能Python Web框架
- **Wireshark**: 网络流量捕获和分析
- **psutil**: 系统和进程监控
- **JWT**: 用户认证和授权
- **Docker**: 容器化部署

### 前端技术
- **React 18**: 现代化用户界面
- **TypeScript**: 类型安全开发
- **Ant Design**: 企业级UI组件
- **Recharts**: 数据可视化图表

### 监控技术
- **Wireshark集成**: 真实网络流量捕获
- **流量分析**: 实时流量模式分析
- **异常检测**: 基于统计学的异常检测
- **威胁识别**: DDoS、扫描、泄露检测
- **数据包分析**: 深度协议分析

### 安全技术
- **实时监控**: 24/7不间断监控
- **多级告警**: 分级告警和通知系统
- **安全分析**: 威胁情报和安全事件分析
- **权限控制**: 基于角色的访问控制

## 文档说明

- **[部署指南](docs/deployment.md)**: 详细的部署和配置说明
- **[用户指南](docs/user_guide.md)**: 完整的功能使用说明
- **[架构文档](docs/architecture.md)**: 系统架构和技术设计
- **[Wireshark配置](docs/wireshark_setup.md)**: Wireshark安装和配置指南
- **[实时异常检测](docs/realtime_anomaly_detection.md)**: AI异常检测技术文档
- **[异常检测总结](docs/anomaly_detection_summary.md)**: 异常检测实现总结

## 使用场景

### 🏢 企业网络监控
- 监控企业内网流量
- 检测异常网络行为
- 分析网络性能瓶颈
- 生成网络使用报告

### 🏠 家庭网络管理
- 监控家庭网络使用情况
- 检测设备连接状态
- 分析网络带宽使用
- 识别可疑网络活动

### 🔬 网络安全研究
- 网络流量分析研究
- 安全威胁检测实验
- 网络协议分析
- 安全工具开发测试

### 📚 教学演示
- 网络监控技术教学
- 网络安全课程演示
- 网络分析实验
- 系统监控实践

## 贡献指南

欢迎提交Issue和Pull Request来改进项目。

## 许可证

本项目采用 MIT 许可证。
