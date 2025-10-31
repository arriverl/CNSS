"""
校园网络安全态势可视化平台 - 后端主程序
结合编程、网络安全、软件工程等多学科技术
"""

from fastapi import FastAPI, HTTPException, Depends, status, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
import uvicorn
import asyncio
import psutil
import time
import json
import hashlib
import jwt
import platform
from datetime import datetime, timedelta
from typing import Dict, List, Optional
from pydantic import BaseModel
import logging
from sqlalchemy.orm import Session
from security_monitor import SecurityMonitor, SecurityAlert
from windows_monitor import WindowsSystemMonitor, WindowsSecurityMonitor
from wireshark_monitor import WiresharkMonitor, RealTimeTrafficAnalyzer
from database import init_db, get_db, User, SecurityEvent, RiskSummary, AuditLog, TrafficHistory, SessionLocal
from data_collector import DataCollector
from event_analyzer import EventAnalyzer
from situation_assessor import SituationAssessor
from report_generator import ReportGenerator

# 配置日志
import os
from pathlib import Path

# 创建日志目录
log_dir = Path("logs")
log_dir.mkdir(exist_ok=True)

# 配置日志文件
log_file = log_dir / "security_monitor.log"
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(log_file, encoding='utf-8'),
        logging.StreamHandler()  # 同时输出到控制台
    ]
)
logger = logging.getLogger(__name__)
logger.info(f"日志文件位置: {log_file.absolute()}")

# 创建FastAPI应用
app = FastAPI(
    title="校园网络安全态势可视化平台",
    description="基于FastAPI的校园网络安全态势监测与展示系统",
    version="2.0.0"
)

# CORS配置
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# 安全配置
SECRET_KEY = "traffic_monitor_secret_key_2024"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

# 数据模型
class LoginRequest(BaseModel):
    username: str
    password: str

class TrafficData(BaseModel):
    timestamp: float
    interface: str
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    bandwidth_sent: float
    bandwidth_recv: float

class SystemInfo(BaseModel):
    cpu_percent: float
    memory_percent: float
    disk_usage: float
    network_interfaces: List[str]

# 初始化新模块
data_collector = DataCollector()
event_analyzer = EventAnalyzer(use_ai=True)
situation_assessor = SituationAssessor()
report_generator = ReportGenerator()

# 后备用户认证（当数据库不可用时使用）
FALLBACK_USERS = {
    "admin": {
        "password": hashlib.sha256("admin123".encode()).hexdigest(),
        "role": "admin"
    },
    "monitor": {
        "password": hashlib.sha256("monitor123".encode()).hexdigest(),
        "role": "monitor"
    }
}

# 用户认证（从数据库加载，如果数据库不可用则使用后备）
def get_user_from_db(username: str, db: Optional[Session] = None) -> Optional[User]:
    """从数据库获取用户"""
    try:
        if db:
            return db.query(User).filter(User.username == username).first()
    except Exception as e:
        logger.warning(f"数据库查询失败，使用后备认证: {e}")
    return None

def authenticate_user(username: str, password: str, db: Optional[Session] = None):
    """验证用户（支持数据库和后备认证）"""
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    # 先尝试从数据库获取
    if db:
        try:
            user = get_user_from_db(username, db)
            if user and user.password == password_hash:
                return {"id": user.id, "username": user.username, "role": user.role, "source": "database"}
        except Exception as e:
            logger.warning(f"数据库认证失败，尝试后备认证: {e}")
    
    # 后备认证
    if username in FALLBACK_USERS:
        user_data = FALLBACK_USERS[username]
        if user_data["password"] == password_hash:
            return {"id": 0, "username": username, "role": user_data["role"], "source": "fallback"}
    
    return None

def create_access_token(data: dict):
    """创建访问令牌"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    """验证访问令牌"""
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="无效的认证凭据",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return username
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="无效的认证凭据",
            headers={"WWW-Authenticate": "Bearer"},
        )

# 全局变量存储流量数据
traffic_history = []
system_info_cache = {}

# 检测操作系统并初始化相应的监控器
is_windows = platform.system().lower() == 'windows'
logger.info(f"检测到操作系统: {platform.system()}")

# 初始化Wireshark监控器
wireshark_monitor = WiresharkMonitor()
traffic_analyzer = RealTimeTrafficAnalyzer()

# 检查Wireshark是否可用
if wireshark_monitor.check_tshark_available():
    logger.info("Wireshark可用，将使用真实流量数据")
    use_wireshark = True
    
    # 自动开始WLAN接口捕获
    if wireshark_monitor.start_capture("WLAN"):
        logger.info("已开始WLAN接口流量捕获")
    else:
        logger.warning("WLAN接口捕获启动失败，尝试其他接口")
        # 尝试其他接口
        for interface in ["以太网", "本地连接* 1", "本地连接* 9"]:
            if wireshark_monitor.start_capture(interface):
                logger.info(f"已开始{interface}接口流量捕获")
                break
else:
    logger.warning("Wireshark不可用，将使用psutil获取系统数据")
    use_wireshark = False

if is_windows:
    # Windows环境使用专门的监控器
    system_monitor = WindowsSystemMonitor(enable_simulation=False)  # 禁用模拟数据
    security_monitor = WindowsSecurityMonitor()
    logger.info("使用Windows监控器，禁用模拟数据模式")
else:
    # Linux/Unix环境使用标准监控器
    security_monitor = SecurityMonitor()
    system_monitor = None
    logger.info("使用标准监控器")

@app.post("/api/auth/login")
async def login(login_data: LoginRequest):
    """用户登录（支持数据库和后备认证）"""
    username = login_data.username
    password = login_data.password
    
    # 尝试获取数据库会话（如果可用）
    db = None
    try:
        db_gen = get_db()
        db = next(db_gen)
    except Exception as e:
        logger.warning(f"无法获取数据库会话，使用后备认证: {e}")
        db = None
    
    # 验证用户
    user = authenticate_user(username, password, db)
    if not user:
        # 尝试记录失败的登录尝试（如果数据库可用）
        if db:
            try:
                audit_log = AuditLog(
                    user_id=None,
                    action="login_failed",
                    details=f"Failed login attempt for username: {username}",
                    ip_address="0.0.0.0"
                )
                db.add(audit_log)
                db.commit()
            except Exception:
                pass  # 忽略数据库错误
        
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="用户名或密码错误"
        )
    
    # 如果是数据库用户，更新最后登录时间
    if db and user.get("source") == "database":
        try:
            db_user = get_user_from_db(username, db)
            if db_user:
                db_user.last_login = datetime.utcnow()
                db.commit()
        except Exception:
            pass  # 忽略数据库错误
    
    # 记录成功登录（如果数据库可用）
    if db:
        try:
            audit_log = AuditLog(
                user_id=user.get("id") or None,
                action="login_success",
                details=f"User {username} logged in successfully ({user.get('source', 'unknown')})",
                ip_address="0.0.0.0"
            )
            db.add(audit_log)
            db.commit()
        except Exception:
            pass  # 忽略数据库错误
    
    access_token = create_access_token(data={"sub": username, "role": user.get("role", "monitor")})
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "user": {
            "id": user.get("id", 0),
            "username": user.get("username"),
            "role": user.get("role", "monitor")
        }
    }

@app.get("/api/traffic/current")
async def get_current_traffic(current_user: str = Depends(verify_token)):
    """获取当前流量数据"""
    global traffic_history
    try:
        current_time = time.time()
        traffic_data = []
        
        if use_wireshark:
            # 使用Wireshark获取真实流量数据
            traffic_data = wireshark_monitor.get_traffic_data()
            
            # 分析流量异常
            anomalies = traffic_analyzer.analyze_traffic(traffic_data)
            if anomalies:
                logger.warning(f"检测到流量异常: {len(anomalies)} 个")
                
        elif is_windows and system_monitor:
            # Windows环境使用专门的监控器
            traffic_data = system_monitor.get_traffic_data()
        else:
            # Linux/Unix环境使用标准方法
            net_io = psutil.net_io_counters(pernic=True)
            
            for interface, stats in net_io.items():
                # 计算带宽（需要与历史数据对比）
                bandwidth_sent = 0.0
                bandwidth_recv = 0.0
                
                # 查找该接口的历史数据
                for hist in reversed(traffic_history):
                    if hist.get('interface') == interface:
                        time_diff = current_time - hist['timestamp']
                        if time_diff > 0:
                            bandwidth_sent = (stats.bytes_sent - hist['bytes_sent']) / time_diff
                            bandwidth_recv = (stats.bytes_recv - hist['bytes_recv']) / time_diff
                        break
                
                traffic_data.append({
                    "timestamp": current_time,
                    "interface": interface,
                    "bytes_sent": stats.bytes_sent,
                    "bytes_recv": stats.bytes_recv,
                    "packets_sent": stats.packets_sent,
                    "packets_recv": stats.packets_recv,
                    "bandwidth_sent": bandwidth_sent,
                    "bandwidth_recv": bandwidth_recv
                })
        
        # 更新历史数据
        for data in traffic_data:
            traffic_history.append(data)
            
            # 处理安全监控
            if is_windows and system_monitor:
                # Windows环境的安全监控
                system_info = system_monitor.get_system_info()
                security_alerts = security_monitor.analyze_system_security(system_info, [data])
            else:
                # Linux/Unix环境的安全监控
                security_alerts = security_monitor.process_traffic_data(data)
            
            if security_alerts:
                logger.warning(f"检测到安全告警: {len(security_alerts)} 个")
        
        # 保持历史数据在合理范围内（最近1小时）
        cutoff_time = current_time - 3600
        traffic_history = [h for h in traffic_history if h['timestamp'] > cutoff_time]
        
        return {"data": traffic_data, "timestamp": current_time}
        
    except Exception as e:
        logger.error(f"获取流量数据失败: {e}")
        raise HTTPException(status_code=500, detail="获取流量数据失败")

@app.get("/api/traffic/history")
async def get_traffic_history(
    interface: Optional[str] = None,
    hours: int = 24,
    current_user: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """获取历史流量数据（从数据库读取，支持最多30天）"""
    try:
        # 限制最多30天
        hours = min(hours, 24 * 30)
        
        # 计算时间范围
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=hours)
        
        # 从数据库查询
        query = db.query(TrafficHistory).filter(
            TrafficHistory.timestamp >= start_time,
            TrafficHistory.timestamp <= end_time
        )
        
        if interface:
            query = query.filter(TrafficHistory.interface == interface)
        
        # 按时间排序
        history_records = query.order_by(TrafficHistory.timestamp.asc()).all()
        
        # 转换为字典格式
        history_data = []
        for record in history_records:
            history_data.append({
                'timestamp': record.timestamp.timestamp() if isinstance(record.timestamp, datetime) else record.timestamp,
                'interface': record.interface,
                'bytes_sent': record.bytes_sent,
                'bytes_recv': record.bytes_recv,
                'packets_sent': record.packets_sent,
                'packets_recv': record.packets_recv,
                'bandwidth_sent': record.bandwidth_sent,
                'bandwidth_recv': record.bandwidth_recv,
                'src_ip': record.src_ip,
                'dst_ip': record.dst_ip,
                'protocol': record.protocol,
                'port': record.port
            })
        
        # 如果没有数据库记录，尝试从内存获取（向后兼容）
        if not history_data:
            cutoff_time = time.time() - (hours * 3600)
            filtered_history = [h for h in traffic_history if h['timestamp'] > cutoff_time]
            
            if interface:
                filtered_history = [h for h in filtered_history if h.get('interface') == interface]
            
            history_data = filtered_history
        
        return {
            "data": history_data,
            "count": len(history_data),
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat(),
                "hours": hours
            }
        }
        
    except Exception as e:
        logger.error(f"获取历史数据失败: {e}")
        raise HTTPException(status_code=500, detail="获取历史数据失败")

@app.get("/api/system/info")
async def get_system_info(current_user: str = Depends(verify_token)):
    """获取系统信息"""
    try:
        if is_windows and system_monitor:
            # Windows环境使用专门的监控器
            system_info = system_monitor.get_system_info()
        else:
            # Linux/Unix环境使用标准方法
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            memory_percent = memory.percent
            
            # 磁盘使用率（Windows使用C盘，Linux使用根目录）
            if is_windows:
                disk = psutil.disk_usage('C:')
            else:
                disk = psutil.disk_usage('/')
            disk_usage = (disk.used / disk.total) * 100
            
            # 网络接口列表
            try:
                network_interfaces = list(psutil.net_io_counters(pernic=True).keys())
            except Exception:
                network_interfaces = []
            
            system_info = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory_percent,
                "disk_usage": disk_usage,
                "network_interfaces": network_interfaces,
                "timestamp": time.time(),
                "platform": platform.system(),
                "simulation_mode": False
            }
        
        return system_info
        
    except Exception as e:
        logger.error(f"获取系统信息失败: {e}")
        raise HTTPException(status_code=500, detail="获取系统信息失败")

@app.get("/api/security/alerts")
async def get_security_alerts(current_user: str = Depends(verify_token)):
    """获取安全告警信息"""
    try:
        if is_windows and system_monitor:
            # Windows环境的安全告警
            alerts = security_monitor.alerts
        else:
            # Linux/Unix环境的安全告警
            active_alerts = security_monitor.get_active_alerts()
            alerts = []
            for alert in active_alerts:
                alerts.append({
                    "alert_id": alert.alert_id,
                    "type": alert.alert_type,
                    "severity": alert.severity,
                    "interface": alert.interface,
                    "description": alert.description,
                    "timestamp": alert.timestamp,
                    "source_ip": alert.source_ip,
                    "destination_ip": alert.destination_ip,
                    "port": alert.port,
                    "protocol": alert.protocol,
                    "bytes_transferred": alert.bytes_transferred,
                    "confidence": alert.confidence
                })
        
        return {"alerts": alerts, "count": len(alerts)}
        
    except Exception as e:
        logger.error(f"获取安全告警失败: {e}")
        raise HTTPException(status_code=500, detail="获取安全告警失败")

@app.get("/api/security/statistics")
async def get_security_statistics(current_user: str = Depends(verify_token)):
    """获取安全统计信息"""
    try:
        stats = security_monitor.get_alert_statistics()
        return stats
        
    except Exception as e:
        logger.error(f"获取安全统计失败: {e}")
        raise HTTPException(status_code=500, detail="获取安全统计失败")

@app.get("/api/windows/processes")
async def get_processes(current_user: str = Depends(verify_token)):
    """获取进程信息（Windows特有）"""
    if not is_windows or not system_monitor:
        raise HTTPException(status_code=404, detail="此功能仅在Windows环境下可用")
    
    try:
        processes = system_monitor.get_process_info()
        return {"processes": processes, "count": len(processes)}
    except Exception as e:
        logger.error(f"获取进程信息失败: {e}")
        raise HTTPException(status_code=500, detail="获取进程信息失败")

@app.get("/api/windows/connections")
async def get_network_connections(current_user: str = Depends(verify_token)):
    """获取网络连接信息（Windows特有）"""
    if not is_windows or not system_monitor:
        raise HTTPException(status_code=404, detail="此功能仅在Windows环境下可用")
    
    try:
        connections = system_monitor.get_network_connections()
        return {"connections": connections, "count": len(connections)}
    except Exception as e:
        logger.error(f"获取网络连接失败: {e}")
        raise HTTPException(status_code=500, detail="获取网络连接失败")

@app.get("/api/windows/disk_io")
async def get_disk_io(current_user: str = Depends(verify_token)):
    """获取磁盘IO信息（Windows特有）"""
    if not is_windows or not system_monitor:
        raise HTTPException(status_code=404, detail="此功能仅在Windows环境下可用")
    
    try:
        disk_io = system_monitor.get_disk_io()
        return disk_io
    except Exception as e:
        logger.error(f"获取磁盘IO失败: {e}")
        raise HTTPException(status_code=500, detail="获取磁盘IO失败")

@app.get("/api/windows/uptime")
async def get_system_uptime(current_user: str = Depends(verify_token)):
    """获取系统运行时间（Windows特有）"""
    if not is_windows or not system_monitor:
        raise HTTPException(status_code=404, detail="此功能仅在Windows环境下可用")
    
    try:
        uptime = system_monitor.get_system_uptime()
        return uptime
    except Exception as e:
        logger.error(f"获取系统运行时间失败: {e}")
        raise HTTPException(status_code=500, detail="获取系统运行时间失败")

@app.get("/api/windows/simulation/config")
async def get_simulation_config(current_user: str = Depends(verify_token)):
    """获取模拟配置（Windows特有）"""
    if not is_windows or not system_monitor:
        raise HTTPException(status_code=404, detail="此功能仅在Windows环境下可用")
    
    try:
        return {
            "enable_simulation": system_monitor.enable_simulation,
            "interfaces": system_monitor.simulation_data['interfaces'],
            "current_pattern": system_monitor.simulation_data['current_pattern'],
            "traffic_patterns": system_monitor.simulation_data['traffic_patterns']
        }
    except Exception as e:
        logger.error(f"获取模拟配置失败: {e}")
        raise HTTPException(status_code=500, detail="获取模拟配置失败")

@app.post("/api/windows/simulation/config")
async def update_simulation_config(
    config: dict,
    current_user: str = Depends(verify_token)
):
    """更新模拟配置（Windows特有）"""
    if not is_windows or not system_monitor:
        raise HTTPException(status_code=404, detail="此功能仅在Windows环境下可用")
    
    try:
        if 'enable_simulation' in config:
            system_monitor.enable_simulation = config['enable_simulation']
        
        if 'interfaces' in config:
            system_monitor.simulation_data['interfaces'] = config['interfaces']
        
        if 'current_pattern' in config:
            system_monitor.simulation_data['current_pattern'] = config['current_pattern']
        
        # 保存配置到文件
        system_monitor.save_simulation_config()
        
        return {"message": "模拟配置已更新"}
    except Exception as e:
        logger.error(f"更新模拟配置失败: {e}")
        raise HTTPException(status_code=500, detail="更新模拟配置失败")

@app.get("/api/wireshark/interfaces")
async def get_wireshark_interfaces(current_user: str = Depends(verify_token)):
    """获取Wireshark可用接口"""
    try:
        interfaces = wireshark_monitor.get_available_interfaces()
        return {"interfaces": interfaces, "count": len(interfaces)}
    except Exception as e:
        logger.error(f"获取Wireshark接口失败: {e}")
        raise HTTPException(status_code=500, detail="获取Wireshark接口失败")

@app.post("/api/wireshark/start_capture")
async def start_wireshark_capture(
    interface: str = None,
    current_user: str = Depends(verify_token)
):
    """开始Wireshark流量捕获"""
    try:
        # 如果没有指定接口，自动选择WLAN
        if not interface:
            interface = "WLAN"
        
        success = wireshark_monitor.start_capture(interface)
        if success:
            return {"message": f"已开始捕获接口 {interface} 的流量", "interface": interface}
        else:
            raise HTTPException(status_code=400, detail="开始捕获失败")
    except Exception as e:
        logger.error(f"开始Wireshark捕获失败: {e}")
        raise HTTPException(status_code=500, detail="开始捕获失败")

@app.post("/api/wireshark/stop_capture")
async def stop_wireshark_capture(current_user: str = Depends(verify_token)):
    """停止Wireshark流量捕获"""
    try:
        wireshark_monitor.stop_capture()
        return {"message": "流量捕获已停止"}
    except Exception as e:
        logger.error(f"停止Wireshark捕获失败: {e}")
        raise HTTPException(status_code=500, detail="停止捕获失败")

@app.get("/api/wireshark/packet_analysis")
async def get_packet_analysis(
    duration: int = 10,
    current_user: str = Depends(verify_token)
):
    """获取数据包分析"""
    try:
        analysis = wireshark_monitor.get_packet_analysis(duration)
        return analysis
    except Exception as e:
        logger.error(f"获取数据包分析失败: {e}")
        raise HTTPException(status_code=500, detail="获取数据包分析失败")

@app.get("/api/wireshark/connections")
async def get_wireshark_connections(current_user: str = Depends(verify_token)):
    """获取网络连接信息"""
    try:
        connections = wireshark_monitor.get_network_connections()
        return {"connections": connections, "count": len(connections)}
    except Exception as e:
        logger.error(f"获取网络连接失败: {e}")
        raise HTTPException(status_code=500, detail="获取网络连接失败")

@app.get("/api/wireshark/interface_status")
async def get_interface_status(current_user: str = Depends(verify_token)):
    """获取接口状态"""
    try:
        status = wireshark_monitor.get_interface_status()
        return status
    except Exception as e:
        logger.error(f"获取接口状态失败: {e}")
        raise HTTPException(status_code=500, detail="获取接口状态失败")

@app.get("/api/traffic/statistics")
async def get_traffic_statistics(current_user: str = Depends(verify_token)):
    """获取流量统计信息"""
    try:
        if use_wireshark:
            stats = traffic_analyzer.get_traffic_statistics()
        else:
            # 使用历史数据计算统计
            if not traffic_history:
                stats = {}
            else:
                recent_data = traffic_history[-100:] if len(traffic_history) > 100 else traffic_history
                
                total_bytes_sent = sum(d.get('bytes_sent', 0) for d in recent_data)
                total_bytes_recv = sum(d.get('bytes_recv', 0) for d in recent_data)
                total_packets_sent = sum(d.get('packets_sent', 0) for d in recent_data)
                total_packets_recv = sum(d.get('packets_recv', 0) for d in recent_data)
                
                avg_bandwidth_sent = sum(d.get('bandwidth_sent', 0) for d in recent_data) / len(recent_data) if recent_data else 0
                avg_bandwidth_recv = sum(d.get('bandwidth_recv', 0) for d in recent_data) / len(recent_data) if recent_data else 0
                
                stats = {
                    'total_bytes_sent': total_bytes_sent,
                    'total_bytes_recv': total_bytes_recv,
                    'total_packets_sent': total_packets_sent,
                    'total_packets_recv': total_packets_recv,
                    'avg_bandwidth_sent': avg_bandwidth_sent,
                    'avg_bandwidth_recv': avg_bandwidth_recv,
                    'data_points': len(recent_data)
                }
        
        return stats
    except Exception as e:
        logger.error(f"获取流量统计失败: {e}")
        raise HTTPException(status_code=500, detail="获取流量统计失败")

@app.get("/api/health")
async def health_check():
    """健康检查"""
    return {
        "status": "healthy", 
        "timestamp": time.time(),
        "platform": platform.system(),
        "wireshark_available": use_wireshark,
        "simulation_mode": is_windows and system_monitor and system_monitor.enable_simulation
    }

# ==================== 新模块API端点 ====================

@app.get("/api/situation/current")
async def get_current_situation(
    hours: int = 1,
    current_user: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """获取当前安全态势"""
    try:
        situation = situation_assessor.assess_current_situation(hours)
        return situation
    except Exception as e:
        logger.error(f"获取安全态势失败: {e}")
        raise HTTPException(status_code=500, detail="获取安全态势失败")

@app.get("/api/situation/trend")
async def get_situation_trend(
    days: int = 7,
    current_user: str = Depends(verify_token)
):
    """获取态势趋势分析"""
    try:
        trend = situation_assessor.get_trend_analysis(days)
        return trend
    except Exception as e:
        logger.error(f"获取趋势分析失败: {e}")
        raise HTTPException(status_code=500, detail="获取趋势分析失败")

@app.get("/api/events/analysis")
async def analyze_events(
    hours: int = 24,
    current_user: str = Depends(verify_token)
):
    """事件分析"""
    try:
        analysis = event_analyzer.analyze_events(hours)
        return analysis
    except Exception as e:
        logger.error(f"事件分析失败: {e}")
        raise HTTPException(status_code=500, detail="事件分析失败")

@app.get("/api/events/list")
async def list_events(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    risk_level: Optional[str] = None,
    event_type: Optional[str] = None,
    limit: int = 100,
    current_user: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """获取事件列表"""
    try:
        query = db.query(SecurityEvent)
        
        if start_time:
            query = query.filter(SecurityEvent.timestamp >= datetime.fromisoformat(start_time))
        if end_time:
            query = query.filter(SecurityEvent.timestamp <= datetime.fromisoformat(end_time))
        if risk_level:
            query = query.filter(SecurityEvent.risk_level == risk_level)
        if event_type:
            query = query.filter(SecurityEvent.event_type == event_type)
        
        events = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
        
        return {
            "events": [
                {
                    "id": e.id,
                    "event_type": e.event_type,
                    "src_ip": e.src_ip,
                    "dst_ip": e.dst_ip,
                    "timestamp": e.timestamp.isoformat() if e.timestamp else None,
                    "risk_level": e.risk_level,
                    "description": e.description,
                    "confidence": e.confidence
                }
                for e in events
            ],
            "count": len(events)
        }
    except Exception as e:
        logger.error(f"获取事件列表失败: {e}")
        raise HTTPException(status_code=500, detail="获取事件列表失败")

@app.get("/api/reports/daily")
async def generate_daily_report(
    date: Optional[str] = None,
    current_user: str = Depends(verify_token)
):
    """生成日报PDF"""
    try:
        target_date = datetime.fromisoformat(date) if date else datetime.utcnow()
        pdf_bytes = report_generator.generate_daily_report(target_date)
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=daily_report_{target_date.strftime('%Y%m%d')}.pdf"
            }
        )
    except Exception as e:
        logger.error(f"生成日报失败: {e}")
        raise HTTPException(status_code=500, detail="生成日报失败")

@app.get("/api/reports/weekly")
async def generate_weekly_report(
    date: Optional[str] = None,
    current_user: str = Depends(verify_token)
):
    """生成周报PDF"""
    try:
        target_date = datetime.fromisoformat(date) if date else datetime.utcnow()
        pdf_bytes = report_generator.generate_weekly_report(target_date)
        
        return Response(
            content=pdf_bytes,
            media_type="application/pdf",
            headers={
                "Content-Disposition": f"attachment; filename=weekly_report_{target_date.strftime('%Y%m%d')}.pdf"
            }
        )
    except Exception as e:
        logger.error(f"生成周报失败: {e}")
        raise HTTPException(status_code=500, detail="生成周报失败")

@app.post("/api/collector/start")
async def start_collection(
    interval: int = 5,
    current_user: str = Depends(verify_token)
):
    """启动数据采集"""
    try:
        data_collector.start_collection(interval)
        return {"message": f"数据采集已启动，间隔: {interval}秒"}
    except Exception as e:
        logger.error(f"启动数据采集失败: {e}")
        raise HTTPException(status_code=500, detail="启动数据采集失败")

@app.post("/api/collector/stop")
async def stop_collection(current_user: str = Depends(verify_token)):
    """停止数据采集"""
    try:
        data_collector.stop_collection()
        return {"message": "数据采集已停止"}
    except Exception as e:
        logger.error(f"停止数据采集失败: {e}")
        raise HTTPException(status_code=500, detail="停止数据采集失败")

@app.get("/api/audit/logs")
async def get_audit_logs(
    start_time: Optional[str] = None,
    end_time: Optional[str] = None,
    user_id: Optional[int] = None,
    action: Optional[str] = None,
    limit: int = 100,
    current_user: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """获取操作日志"""
    try:
        query = db.query(AuditLog)
        
        if start_time:
            query = query.filter(AuditLog.time >= datetime.fromisoformat(start_time))
        if end_time:
            query = query.filter(AuditLog.time <= datetime.fromisoformat(end_time))
        if user_id:
            query = query.filter(AuditLog.user_id == user_id)
        if action:
            query = query.filter(AuditLog.action == action)
        
        logs = query.order_by(AuditLog.time.desc()).limit(limit).all()
        
        return {
            "logs": [
                {
                    "id": l.id,
                    "user_id": l.user_id,
                    "action": l.action,
                    "time": l.time.isoformat() if l.time else None,
                    "details": l.details,
                    "ip_address": l.ip_address
                }
                for l in logs
            ],
            "count": len(logs)
        }
    except Exception as e:
        logger.error(f"获取操作日志失败: {e}")
        raise HTTPException(status_code=500, detail="获取操作日志失败")

@app.get("/api/risk/summary")
async def get_risk_summary(
    days: int = 7,
    current_user: str = Depends(verify_token),
    db: Session = Depends(get_db)
):
    """获取风险汇总"""
    try:
        end_date = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
        start_date = end_date - timedelta(days=days)
        
        summaries = db.query(RiskSummary).filter(
            RiskSummary.date >= start_date,
            RiskSummary.date < end_date
        ).order_by(RiskSummary.date.desc()).all()
        
        return {
            "summaries": [
                {
                    "date": s.date.isoformat(),
                    "critical": s.critical,
                    "high": s.high,
                    "medium": s.medium,
                    "low": s.low,
                    "total_score": s.total_score
                }
                for s in summaries
            ],
            "count": len(summaries)
        }
    except Exception as e:
        logger.error(f"获取风险汇总失败: {e}")
        raise HTTPException(status_code=500, detail="获取风险汇总失败")

# 启动时初始化
@app.on_event("startup")
async def startup_event():
    """应用启动时的初始化"""
    logger.info("校园网络安全态势可视化平台启动中...")
    
    # 初始化数据库
    try:
        init_db()
        logger.info("数据库初始化成功")
        
        # 创建默认用户（如果不存在）
        db = SessionLocal()
        try:
            default_users = [
                {"username": "admin", "password": "admin123", "role": "admin"},
                {"username": "monitor", "password": "monitor123", "role": "monitor"}
            ]
            
            for user_data in default_users:
                existing = db.query(User).filter(User.username == user_data["username"]).first()
                if not existing:
                    password_hash = hashlib.sha256(user_data["password"].encode()).hexdigest()
                    new_user = User(
                        username=user_data["username"],
                        password=password_hash,
                        role=user_data["role"]
                    )
                    db.add(new_user)
            
            db.commit()
            logger.info("默认用户创建完成")
        except Exception as e:
            logger.error(f"创建默认用户失败: {e}")
            db.rollback()
        finally:
            db.close()
            
    except Exception as e:
        logger.error(f"数据库初始化失败: {e}")
    
    # 启动数据采集（可选，默认启动）
    try:
        data_collector.start_collection(interval=5)
        logger.info("数据采集模块已启动")
    except Exception as e:
        logger.warning(f"数据采集模块启动失败: {e}")
    
    logger.info("系统已就绪，开始监控网络流量")

if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info"
    )
