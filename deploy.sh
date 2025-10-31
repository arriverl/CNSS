#!/bin/bash

# 实时流量监控系统一键部署脚本
# 支持Docker和Docker Compose部署

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# 打印函数
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# 检查Docker是否安装
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker未安装，请先安装Docker"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose未安装，请先安装Docker Compose"
        exit 1
    fi
    
    print_success "Docker环境检查通过"
}

# 检查系统权限
check_permissions() {
    if [ "$EUID" -eq 0 ]; then
        print_warning "检测到以root用户运行，建议使用普通用户运行此脚本"
    fi
}

# 创建必要的目录
create_directories() {
    print_info "创建必要的目录..."
    mkdir -p logs
    mkdir -p ssl
    print_success "目录创建完成"
}

# 构建和启动服务
deploy_services() {
    print_info "开始构建和部署服务..."
    
    # 停止现有容器
    print_info "停止现有容器..."
    docker-compose down 2>/dev/null || true
    
    # 构建镜像
    print_info "构建Docker镜像..."
    docker-compose build --no-cache
    
    # 启动服务
    print_info "启动服务..."
    docker-compose up -d
    
    print_success "服务部署完成"
}

# 检查服务状态
check_services() {
    print_info "检查服务状态..."
    
    # 等待服务启动
    sleep 10
    
    # 检查容器状态
    if docker-compose ps | grep -q "Up"; then
        print_success "服务启动成功"
    else
        print_error "服务启动失败"
        docker-compose logs
        exit 1
    fi
    
    # 检查健康状态
    print_info "检查服务健康状态..."
    for i in {1..30}; do
        if curl -s http://localhost:8000/api/health > /dev/null; then
            print_success "服务健康检查通过"
            break
        fi
        if [ $i -eq 30 ]; then
            print_error "服务健康检查失败"
            exit 1
        fi
        sleep 2
    done
}

# 显示访问信息
show_access_info() {
    print_success "部署完成！"
    echo ""
    echo "=========================================="
    echo "  实时流量监控系统部署成功"
    echo "=========================================="
    echo ""
    echo "访问地址："
    echo "  前端界面: http://localhost"
    echo "  API接口: http://localhost:8000"
    echo "  健康检查: http://localhost:8000/api/health"
    echo ""
    echo "默认登录账号："
    echo "  用户名: admin"
    echo "  密码: admin123"
    echo ""
    echo "或："
    echo "  用户名: monitor"
    echo "  密码: monitor123"
    echo ""
    echo "管理命令："
    echo "  查看日志: docker-compose logs -f"
    echo "  停止服务: docker-compose down"
    echo "  重启服务: docker-compose restart"
    echo "  更新服务: docker-compose pull && docker-compose up -d"
    echo ""
}

# 主函数
main() {
    echo "=========================================="
    echo "  实时流量监控系统一键部署脚本"
    echo "=========================================="
    echo ""
    
    # 检查环境
    check_docker
    check_permissions
    
    # 创建目录
    create_directories
    
    # 部署服务
    deploy_services
    
    # 检查服务
    check_services
    
    # 显示信息
    show_access_info
}

# 错误处理
trap 'print_error "部署过程中发生错误，请检查日志"; exit 1' ERR

# 执行主函数
main "$@"



