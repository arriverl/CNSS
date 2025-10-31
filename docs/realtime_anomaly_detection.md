# 实时流量异常检测技术文档

## 📋 概述

本文档详细说明校园网络安全态势可视化平台的实时流量异常检测实现，包括特征提取、AI模型、规则匹配和风险评估等核心模块。

## 🧩 系统架构

```
实时流量 → 特征提取 → AI异常检测 → 事件分类 → 风险计算 → 数据库存储
              ↓           ↓            ↓          ↓
          聚合特征    规则匹配    风险等级     事件记录
```

## 一、特征提取模块 (FeatureExtractor)

### 1.1 特征类型

从实时流量数据中提取以下特征：

#### 基础流量特征
- **总字节数** (total_bytes): `bytes_sent + bytes_recv`
- **总包数** (total_packets): `packets_sent + packets_recv`
- **发送比例** (send_ratio): `bytes_sent / total_bytes`
- **接收比例** (recv_ratio): `bytes_recv / total_bytes`

#### 时间特征
- **小时** (hour): 0-23，归一化到0-1
- **星期** (weekday): 0-6，归一化到0-1
- **分钟** (minute): 0-59，归一化到0-1

#### 协议和端口特征
- **协议编码**: TCP=1.0, UDP=2.0, ICMP=3.0, HTTP=4.0, HTTPS=5.0, DNS=6.0
- **知名端口标志**: 0-1023端口标记为1.0，否则0.0
- **端口归一化**: `port / 65535`

#### TCP标志特征
- **SYN比例**: `SYN包数 / 总包数`

#### IP统计特征（基于时间窗口）
- **唯一目标IP数**: 归一化到0-1
- **唯一端口数**: 归一化到0-1
- **包速率**: `总包数 / 时间跨度` (log归一化)
- **字节速率**: `总字节数 / 时间跨度` (log归一化)

### 1.2 特征向量示例

```python
feature_vector = [
    np.log1p(total_bytes),      # 特征1: 总字节数(log)
    np.log1p(total_packets),    # 特征2: 总包数(log)
    send_ratio,                 # 特征3: 发送比例
    recv_ratio,                 # 特征4: 接收比例
    hour/24.0,                  # 特征5: 小时
    weekday/7.0,                # 特征6: 星期
    minute/60.0,                # 特征7: 分钟
    protocol_code,              # 特征8: 协议
    is_well_known_port,         # 特征9: 知名端口
    port/65535.0,               # 特征10: 端口
    syn_ratio,                  # 特征11: SYN比例
    unique_dst_count,           # 特征12: 唯一目标数
    unique_port_count,          # 特征13: 唯一端口数
    packet_rate,                # 特征14: 包速率
    byte_rate                   # 特征15: 字节速率
]
```

### 1.3 聚合特征（用于规则匹配）

```python
aggregated_features = {
    'total_connections': 100,           # 总连接数
    'unique_src_ips': 10,               # 唯一源IP数
    'high_activity_ips': [             # 高活跃IP
        {
            'ip': '192.168.1.100',
            'connections': 150,
            'packets': 50000,
            'bytes': 100000000
        }
    ],
    'scan_patterns': [                  # 扫描模式
        {
            'ip': '192.168.1.200',
            'type': 'port_scan',
            'syn_ratio': 0.95,
            'unique_dst': 50,
            'unique_ports': 80
        }
    ]
}
```

## 二、AI异常检测模型

### 2.1 Isolation Forest（孤立森林）

#### 核心思想
正常流量在高维特征空间中分布密集，异常流量在稀疏区域。通过随机分裂树判断"孤立程度"。

#### 实现代码
```python
from sklearn.ensemble import IsolationForest

model = IsolationForest(
    contamination=0.02,      # 假设2%是异常
    random_state=42,
    n_estimators=100
)
model.fit(feature_data)

predictions = model.predict(feature_data)      # -1=异常, 1=正常
anomaly_scores = model.score_samples(feature_data)  # 异常分数
```

#### 输出解释
- `predictions[i] == -1`: 第i个样本被判定为异常
- `anomaly_scores[i]`: 异常分数（越负越异常）

### 2.2 DBSCAN 聚类

#### 核心思想
通过密度聚类识别正常流量群，偏离群体或噪声点即为异常。

#### 实现代码
```python
from sklearn.cluster import DBSCAN

dbscan = DBSCAN(eps=0.5, min_samples=5)
labels = dbscan.fit_predict(features_scaled)

# labels[i] == -1 表示噪声点（异常）
```

#### 输出解释
- `labels[i] == -1`: 噪声点，判定为异常
- `labels[i] >= 0`: 属于某个正常簇

### 2.3 K-Means 聚类

#### 核心思想
将流量分为k个簇，距离簇中心较远的点判定为异常。

#### 实现代码
```python
from sklearn.cluster import KMeans

kmeans = KMeans(n_clusters=5, random_state=42)
labels = kmeans.predict(features_scaled)
centers = kmeans.cluster_centers_

# 计算到簇中心的距离
distance = ||features[i] - centers[labels[i]]||

# 如果距离 > 阈值（中位数+2*标准差），判定为异常
```

## 三、规则匹配检测

### 3.1 端口扫描检测

```python
if syn_ratio > 0.8 and unique_dst > 10:
    event_type = "PortScan"
```

**判断条件：**
- SYN包比例 > 80%
- 5分钟内访问的不同目标 > 10个

### 3.2 DDoS攻击检测

```python
if connections_per_ip > 100 in 5_minutes:
    event_type = "DDoSAttack"
```

**判断条件：**
- 5分钟内同一源IP的连接数 > 100

### 3.3 数据泄露检测

```python
if bytes_transferred > 1GB:
    event_type = "DataExfiltration"
```

## 四、事件分析与分类

### 4.1 事件分类逻辑

```python
def classify_event_type(anomaly, syn_ratio, unique_dst):
    if 'PortScanRule' in method or (syn_ratio > 0.8 and unique_dst > 10):
        return 'PortScan'
    elif 'DDoSRule' in method:
        return 'DDoSAttack'
    elif 'IsolationForest' in method:
        return 'SuspiciousTraffic'
    elif 'DBSCAN' in method or 'KMeans' in method:
        return 'AnomalousPattern'
    else:
        return 'UnknownAnomaly'
```

### 4.2 风险分数计算

#### 计算公式

```
Risk = w1 × f_syn + w2 × f_dst + w3 × anomaly_score
```

其中：
- `w1 = 2.0` (SYN比例权重)
- `w2 = 1.5` (目标数量权重)
- `w3 = 3.0` (异常分数权重)
- `f_syn`: SYN比例 (0-1)
- `f_dst`: 归一化的唯一目标数 (0-1)
- `anomaly_score`: AI模型异常分数 (0-1)

#### 风险等级划分

```
高风险 (high):   Risk >= 70
中风险 (medium): 40 <= Risk < 70
低风险 (low):    Risk < 40
```

### 4.3 风险计算示例

```python
# 示例：检测到端口扫描
syn_ratio = 0.95        # 95%是SYN包
unique_dst = 50          # 访问50个不同目标
anomaly_score = 0.85    # IsolationForest异常分数

# 归一化
f_syn = 0.95
f_dst = min(50/100, 1.0) = 0.5
f_anomaly = 0.85

# 计算风险
Risk = 2.0×0.95 + 1.5×0.5 + 3.0×0.85
     = 1.9 + 0.75 + 2.55
     = 5.2

# 归一化到0-100
max_risk = 2.0 + 1.5 + 3.0 = 6.5
risk_score = (5.2 / 6.5) × 100 = 80

# 判定为高风险
risk_level = 'high'
```

## 五、实时检测流程

### 5.1 数据采集与处理流程

```
1. 数据采集 (Wireshark/psutil)
   ↓
2. 特征提取 (FeatureExtractor)
   ↓
3. 并行检测
   ├─→ 规则匹配
   ├─→ Isolation Forest
   └─→ DBSCAN/K-Means
   ↓
4. 异常合并与分类
   ↓
5. 风险计算
   ↓
6. 保存到数据库 (events表)
```

### 5.2 模型训练流程

```python
# 1. 收集训练数据（至少100个样本）
traffic_data = collect_traffic_data(window_size=100)

# 2. 提取特征
features = feature_extractor.extract_features_from_traffic(traffic_data)

# 3. 标准化
features_scaled = scaler.fit_transform(features)

# 4. 训练模型
isolation_forest.fit(features_scaled)
dbscan.fit(features_scaled)  # 或 kmeans.fit(features_scaled)

# 5. 标记为已训练
is_trained = True
```

### 5.3 实时检测流程

```python
# 每个采集周期（默认5秒）
while collecting:
    # 1. 获取新流量数据
    traffic_data = get_current_traffic()
    
    # 2. 添加到检测窗口
    anomaly_detector.add_traffic_data(traffic_data)
    
    # 3. 如果模型未训练且有足够数据，先训练
    if not is_trained and len(traffic_window) >= 100:
        train_models(traffic_window)
    
    # 4. 执行异常检测
    anomalies = detect_anomalies(traffic_data)
    
    # 5. 分类和风险计算
    events = classify_and_assess_risk(anomalies)
    
    # 6. 保存到数据库
    save_events_to_db(events)
    
    # 7. 等待下一个周期
    sleep(interval)
```

## 六、数据库存储

### 6.1 事件表结构

```sql
CREATE TABLE events (
    id SERIAL PRIMARY KEY,
    event_type VARCHAR(50),        -- PortScan, DDoSAttack, SuspiciousTraffic等
    src_ip VARCHAR(45),
    dst_ip VARCHAR(45),
    timestamp TIMESTAMP,
    risk_level VARCHAR(20),        -- low, medium, high, critical
    description TEXT,
    port INTEGER,
    protocol VARCHAR(20),
    bytes_transferred INTEGER,
    confidence FLOAT,              -- 置信度 0.0-1.0
    extra_metadata TEXT           -- JSON格式，存储检测方法等
);
```

### 6.2 事件插入示例

```python
event = SecurityEvent(
    event_type='PortScan',
    src_ip='192.168.1.200',
    dst_ip='192.168.1.1',
    timestamp=datetime.utcnow(),
    risk_level='high',
    description='检测到端口扫描活动，源IP: 192.168.1.200 (检测方法: IsolationForest)',
    port=80,
    protocol='TCP',
    bytes_transferred=50000,
    confidence=0.85,
    extra_metadata=json.dumps({
        'detection_method': 'IsolationForest',
        'anomaly_score': 0.85,
        'syn_ratio': 0.95,
        'unique_dst': 50
    })
)
```

## 七、性能优化

### 7.1 特征缓存

- IP统计特征使用滑动窗口缓存
- 避免重复计算相同IP的统计信息

### 7.2 模型更新

- 初始训练后，定期使用新数据重新训练
- 建议每小时或每1000个新样本重新训练一次

### 7.3 批量处理

- 累积多个数据点后批量检测
- 减少数据库写入次数

## 八、配置参数

### 8.1 Isolation Forest参数

```python
isolation_forest = IsolationForest(
    contamination=0.02,      # 异常比例估计（2%）
    random_state=42,         # 随机种子
    n_estimators=100,        # 树的数量
    max_samples='auto'       # 每棵树使用的样本数
)
```

### 8.2 DBSCAN参数

```python
dbscan = DBSCAN(
    eps=0.5,                 # 邻域半径
    min_samples=5            # 最小样本数
)
```

### 8.3 风险权重配置

```python
risk_weights = {
    'w_syn': 2.0,           # SYN比例权重
    'w_dst': 1.5,           # 目标数量权重
    'w_anomaly': 3.0        # 异常分数权重
}
```

## 九、监控指标

### 9.1 检测性能指标

- **检测延迟**: 从流量采集到事件生成的时间
- **准确率**: 异常检测的准确率（需要人工标注验证）
- **误报率**: 正常流量被误判为异常的比例
- **漏报率**: 异常流量未被检测到的比例

### 9.2 系统性能指标

- **特征提取时间**: 单次特征提取耗时
- **模型预测时间**: 单次预测耗时
- **数据库写入时间**: 事件保存耗时

## 十、扩展建议

### 10.1 模型改进

1. **增量学习**: 实现模型的增量更新，无需重新训练
2. **集成学习**: 结合多个模型的投票结果
3. **深度学习**: 使用LSTM等模型处理时间序列特征

### 10.2 特征工程

1. **更多网络层特征**: 提取L3/L4层更多特征
2. **行为特征**: 提取用户行为模式特征
3. **统计特征**: 提取更丰富的统计特征

### 10.3 实时告警

1. **WebSocket推送**: 实时推送异常事件到前端
2. **邮件/短信告警**: 高风险事件自动通知
3. **自动化响应**: 自动阻断异常IP

## 十一、使用示例

### 11.1 初始化检测器

```python
from realtime_anomaly_detector import RealTimeAnomalyDetector

detector = RealTimeAnomalyDetector(
    use_isolation_forest=True,
    use_clustering=True
)
```

### 11.2 训练模型

```python
# 收集训练数据
training_data = collect_traffic_data(duration=300)  # 5分钟

# 训练模型
success = detector.train_models(training_data)
if success:
    print("模型训练成功")
```

### 11.3 实时检测

```python
# 获取当前流量
traffic_data = get_current_traffic()

# 检测异常
anomalies = detector.detect_anomalies(traffic_data)

# 分类和风险评估
events = detector.classify_and_assess_risk(anomalies)

# 保存到数据库
detector.save_events_to_db(events)
```

## 十二、故障排除

### 12.1 模型训练失败

**原因**: 训练数据不足
**解决**: 增加数据采集时间或降低 `min_samples_for_training`

### 12.2 检测性能低

**原因**: 特征提取耗时过长
**解决**: 
- 减少特征维度
- 优化特征计算逻辑
- 使用特征缓存

### 12.3 误报率高

**原因**: 模型参数不合适
**解决**:
- 调整 `contamination` 参数
- 重新训练模型
- 优化风险权重配置

