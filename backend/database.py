"""
数据库连接和配置
"""

from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, relationship
from datetime import datetime
import os

# 数据库URL（支持环境变量配置）
DATABASE_URL = os.getenv(
    "DATABASE_URL",
    "postgresql://postgres:postgres@localhost:5432/security_monitor"
)

# 检查数据库是否可用
USE_DATABASE = True
engine = None

try:
    # 尝试创建数据库引擎并测试连接
    engine = create_engine(DATABASE_URL, echo=False, pool_pre_ping=True)
    # 测试连接
    with engine.connect() as conn:
        pass
except Exception as e:
    import logging
    logger = logging.getLogger(__name__)
    logger.warning(f"PostgreSQL数据库连接失败: {e}")
    logger.info("将使用SQLite文件数据库作为后备方案")
    USE_DATABASE = False
    # 使用SQLite文件数据库作为后备
    DATABASE_URL = "sqlite:///./security_monitor.db"
    try:
        engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})
        logger.info(f"SQLite数据库已初始化: {DATABASE_URL}")
    except Exception as e2:
        logger.error(f"SQLite数据库初始化也失败: {e2}")
        # 最后的后备：使用内存数据库
        DATABASE_URL = "sqlite:///:memory:"
        engine = create_engine(DATABASE_URL, echo=False, connect_args={"check_same_thread": False})

# 创建会话工厂
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# 声明基类
Base = declarative_base()


# 数据库模型
class User(Base):
    """用户表"""
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, index=True, nullable=False)
    password = Column(String(255), nullable=False)  # 存储哈希值
    role = Column(String(20), default="monitor", nullable=False)  # admin, monitor, viewer
    last_login = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    
    # 关系
    logs = relationship("AuditLog", back_populates="user")


class SecurityEvent(Base):
    """安全事件表"""
    __tablename__ = "events"
    
    id = Column(Integer, primary_key=True, index=True)
    event_type = Column(String(50), nullable=False, index=True)  # ddos, port_scan, data_exfiltration, etc.
    src_ip = Column(String(45), nullable=True, index=True)  # 支持IPv6
    dst_ip = Column(String(45), nullable=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    risk_level = Column(String(20), nullable=False, index=True)  # low, medium, high, critical
    description = Column(Text, nullable=True)
    interface = Column(String(100), nullable=True)
    protocol = Column(String(20), nullable=True)
    port = Column(Integer, nullable=True)
    bytes_transferred = Column(Integer, nullable=True)
    confidence = Column(Float, default=0.0)
    
    # 额外信息（JSON格式存储）
    extra_metadata = Column(Text, nullable=True)  # JSON字符串（metadata是SQLAlchemy保留字）


class RiskSummary(Base):
    """风险汇总表"""
    __tablename__ = "risk_summary"
    
    id = Column(Integer, primary_key=True, index=True)
    date = Column(DateTime, unique=True, index=True, nullable=False)
    high = Column(Integer, default=0, nullable=False)
    medium = Column(Integer, default=0, nullable=False)
    low = Column(Integer, default=0, nullable=False)
    critical = Column(Integer, default=0, nullable=False)
    total_score = Column(Float, default=0.0, nullable=False)  # 风险指数
    created_at = Column(DateTime, default=datetime.utcnow)


class AuditLog(Base):
    """操作日志表"""
    __tablename__ = "logs"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)  # login, logout, view_dashboard, etc.
    time = Column(DateTime, default=datetime.utcnow, index=True)
    details = Column(Text, nullable=True)  # JSON字符串或文本描述
    ip_address = Column(String(45), nullable=True)
    
    # 关系
    user = relationship("User", back_populates="logs")


class TrafficHistory(Base):
    """流量历史表（用于持久化存储历史流量数据）"""
    __tablename__ = "traffic_history"
    
    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    interface = Column(String(100), nullable=True, index=True)
    bytes_sent = Column(Integer, default=0, nullable=False)
    bytes_recv = Column(Integer, default=0, nullable=False)
    packets_sent = Column(Integer, default=0, nullable=False)
    packets_recv = Column(Integer, default=0, nullable=False)
    bandwidth_sent = Column(Float, default=0.0, nullable=False)  # bytes per second
    bandwidth_recv = Column(Float, default=0.0, nullable=False)  # bytes per second
    src_ip = Column(String(45), nullable=True)
    dst_ip = Column(String(45), nullable=True)
    protocol = Column(String(20), nullable=True)
    port = Column(Integer, nullable=True)


def init_db():
    """初始化数据库（创建表）"""
    Base.metadata.create_all(bind=engine)


def get_db():
    """获取数据库会话"""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

