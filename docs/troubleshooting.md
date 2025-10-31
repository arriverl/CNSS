# 故障排除指南

## 常见问题及解决方案

### 前端编译错误

#### 问题1：TypeScript语法错误
```
ERROR: 'interface' is a reserved word in strict mode
```

**解决方案**：
- 将参数名从 `interface` 改为 `interfaceName`
- 确保TypeScript配置正确

#### 问题2：模块找不到
```
Module not found: Error: Can't resolve './App'
```

**解决方案**：
```bash
# 清理并重新安装依赖
cd frontend
rm -rf node_modules package-lock.json
npm install
```

#### 问题3：类型错误
```
TS2345: Argument of type 'AxiosResponse' is not assignable
```

**解决方案**：
- 检查API响应类型定义
- 确保正确访问 `.data` 属性

### 后端启动问题

#### 问题1：语法错误
```
SyntaxError: name 'traffic_history' is used prior to global declaration
```

**解决方案**：
- 将 `global` 声明移到函数开头
- 检查变量作用域

#### 问题2：编码问题
```
UnicodeDecodeError: 'gbk' codec can't decode byte
```

**解决方案**：
- 在Windows下使用UTF-8编码
- 添加 `encoding='utf-8', errors='ignore'` 参数

#### 问题3：权限问题
```
tshark: The capture session could not be initiated
```

**解决方案**：
- 以管理员权限运行
- 检查网络接口权限
- 确保Wireshark正确安装

### 网络连接问题

#### 问题1：API请求失败
```
Network Error: Failed to fetch
```

**解决方案**：
- 检查后端服务是否启动
- 确认端口8000未被占用
- 检查防火墙设置

#### 问题2：CORS错误
```
Access to fetch at 'http://localhost:8000' from origin 'http://localhost:3000' has been blocked by CORS policy
```

**解决方案**：
- 检查后端CORS配置
- 确保允许前端域名访问

### 依赖安装问题

#### 问题1：npm安装失败
```
npm ERR! network timeout
```

**解决方案**：
```bash
# 使用国内镜像
npm config set registry https://registry.npmmirror.com
npm install
```

#### 问题2：Python包安装失败
```
ERROR: Could not find a version that satisfies the requirement
```

**解决方案**：
```bash
# 升级pip
pip install --upgrade pip

# 使用国内镜像
pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt
```

### 系统兼容性问题

#### Windows系统
- 确保以管理员权限运行
- 检查Windows Defender设置
- 使用PowerShell而不是CMD

#### Linux系统
- 检查用户权限
- 确保网络接口可访问
- 配置防火墙规则

#### macOS系统
- 检查系统完整性保护(SIP)
- 确保Xcode命令行工具已安装
- 检查Homebrew配置

## 调试技巧

### 1. 查看详细错误信息
```bash
# 前端调试
npm start -- --verbose

# 后端调试
python -u main.py
```

### 2. 检查服务状态
```bash
# 检查端口占用
netstat -tlnp | grep :8000
netstat -tlnp | grep :3000

# 检查进程
ps aux | grep python
ps aux | grep node
```

### 3. 查看日志
```bash
# 后端日志
tail -f logs/app.log

# 前端日志
# 在浏览器开发者工具中查看Console
```

### 4. 网络诊断
```bash
# 测试API连接
curl http://localhost:8000/api/health

# 测试前端连接
curl http://localhost:3000
```

## 性能优化

### 1. 减少内存使用
- 限制历史数据保存数量
- 定期清理缓存
- 优化数据结构

### 2. 提高响应速度
- 使用缓存机制
- 优化数据库查询
- 减少不必要的API调用

### 3. 网络优化
- 使用CDN加速
- 压缩静态资源
- 启用HTTP/2

## 安全注意事项

### 1. 权限控制
- 不要以root权限运行
- 使用最小权限原则
- 定期审查用户权限

### 2. 数据安全
- 敏感数据加密存储
- 定期备份重要数据
- 限制数据访问权限

### 3. 网络安全
- 配置防火墙规则
- 使用HTTPS传输
- 定期更新依赖包

## 联系支持

如果遇到无法解决的问题：

1. 查看系统日志
2. 检查错误信息
3. 搜索相关文档
4. 提交Issue到项目仓库

### 提供信息
- 操作系统版本
- Python/Node.js版本
- 错误信息截图
- 复现步骤
- 系统环境信息



