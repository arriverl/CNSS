# 实时流量监控系统部署指南

## 系统要求

### 硬件要求
- **CPU**: 2核心以上
- **内存**: 4GB以上
- **磁盘**: 10GB以上可用空间
- **网络**: 支持监控的网络接口

### 软件要求
- **操作系统**: Linux (Ubuntu 20.04+, CentOS 7+, Debian 10+)
- **Docker**: 20.10+
- **Docker Compose**: 1.29+

## 快速部署

### 1. 环境准备

```bash
# 更新系统包
sudo apt update && sudo apt upgrade -y

# 安装Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh

# 安装Docker Compose
sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose

# 将当前用户添加到docker组
sudo usermod -aG docker $USER
```

### 2. 下载项目

```bash
# 克隆项目（如果从Git仓库）
git clone <repository-url>
cd traffic-monitor-system

# 或者直接下载项目文件到服务器
```

### 3. 一键部署

```bash
# 给部署脚本执行权限
chmod +x deploy.sh

# 执行一键部署
./deploy.sh
```

### 4. 验证部署

```bash
# 检查容器状态
docker-compose ps

# 检查服务健康状态
curl http://localhost:8000/api/health

# 查看日志
docker-compose logs -f
```

## 手动部署

### 1. 构建镜像

```bash
# 构建Docker镜像
docker-compose build
```

### 2. 启动服务

```bash
# 启动所有服务
docker-compose up -d

# 只启动核心服务（不包含Nginx和Redis）
docker-compose up -d traffic-monitor
```

### 3. 配置Nginx（可选）

```bash
# 启动Nginx反向代理
docker-compose up -d nginx
```

## 配置说明

### 环境变量

在 `docker-compose.yml` 中可以配置以下环境变量：

```yaml
environment:
  - PYTHONUNBUFFERED=1
  - TZ=Asia/Shanghai
  - LOG_LEVEL=INFO
  - SECRET_KEY=your_secret_key_here
```

### 端口配置

- **8000**: 后端API服务
- **80**: Nginx HTTP服务
- **443**: Nginx HTTPS服务（需要SSL证书）
- **6379**: Redis服务

### 数据持久化

系统会自动创建以下卷：

- `redis_data`: Redis数据持久化
- `./logs`: 应用日志目录

## 安全配置

### 1. 修改默认密码

编辑 `backend/main.py` 文件，修改默认用户密码：

```python
USERS = {
    "admin": hashlib.sha256("your_new_password".encode()).hexdigest(),
    "monitor": hashlib.sha256("your_monitor_password".encode()).hexdigest()
}
```

### 2. 配置HTTPS

1. 将SSL证书文件放入 `ssl/` 目录
2. 修改 `nginx.conf` 中的SSL配置
3. 取消注释HTTPS服务器配置

### 3. 防火墙配置

```bash
# 只允许必要端口
sudo ufw allow 22    # SSH
sudo ufw allow 80    # HTTP
sudo ufw allow 443   # HTTPS
sudo ufw enable
```

## 监控和维护

### 查看日志

```bash
# 查看所有服务日志
docker-compose logs -f

# 查看特定服务日志
docker-compose logs -f traffic-monitor
docker-compose logs -f nginx
```

### 重启服务

```bash
# 重启所有服务
docker-compose restart

# 重启特定服务
docker-compose restart traffic-monitor
```

### 更新服务

```bash
# 停止服务
docker-compose down

# 拉取最新镜像
docker-compose pull

# 重新构建和启动
docker-compose up -d --build
```

### 备份数据

```bash
# 备份Redis数据
docker-compose exec redis redis-cli BGSAVE
docker cp traffic-monitor-redis:/data/dump.rdb ./backup/

# 备份日志
tar -czf logs-backup-$(date +%Y%m%d).tar.gz logs/
```

## 故障排除

### 常见问题

1. **容器启动失败**
   ```bash
   # 检查Docker服务状态
   sudo systemctl status docker
   
   # 检查端口占用
   sudo netstat -tlnp | grep :8000
   ```

2. **无法访问Web界面**
   ```bash
   # 检查防火墙设置
   sudo ufw status
   
   # 检查容器网络
   docker network ls
   ```

3. **性能问题**
   ```bash
   # 检查系统资源
   docker stats
   
   # 调整Docker资源限制
   # 在docker-compose.yml中添加资源限制
   ```

### 日志分析

```bash
# 查看错误日志
docker-compose logs traffic-monitor | grep ERROR

# 查看访问日志
docker-compose logs nginx | grep "GET /"

# 实时监控日志
docker-compose logs -f --tail=100
```

## 性能优化

### 1. 系统优化

```bash
# 增加文件描述符限制
echo "* soft nofile 65536" >> /etc/security/limits.conf
echo "* hard nofile 65536" >> /etc/security/limits.conf

# 优化内核参数
echo "net.core.somaxconn = 65535" >> /etc/sysctl.conf
echo "net.ipv4.tcp_max_syn_backlog = 65535" >> /etc/sysctl.conf
sysctl -p
```

### 2. Docker优化

```yaml
# 在docker-compose.yml中添加资源限制
services:
  traffic-monitor:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
```

### 3. 应用优化

- 调整数据收集频率
- 优化数据库查询
- 启用缓存机制
- 使用CDN加速静态资源

## 扩展部署

### 集群部署

```bash
# 使用Docker Swarm
docker swarm init
docker stack deploy -c docker-compose.yml traffic-monitor

# 使用Kubernetes
kubectl apply -f k8s/
```

### 负载均衡

```yaml
# 多实例部署
services:
  traffic-monitor-1:
    # ... 配置
  traffic-monitor-2:
    # ... 配置
  nginx:
    # 配置负载均衡
```

## 联系支持

如果遇到问题，请：

1. 查看日志文件
2. 检查系统资源
3. 验证网络连接
4. 提交Issue到项目仓库



