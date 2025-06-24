#!/bin/bash

# WireGuard安装配置脚本
# 适用于常见Linux发行版
# 需要root权限运行

# 检查是否有root权限
if [ "$(id -u)" -ne 0 ]; then
    echo "请使用root权限运行此脚本" >&2
    exit 1
fi

# 定义颜色输出
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}========== WireGuard 安装配置脚本 ==========${NC}"

# 检测发行版
echo -e "${YELLOW}[*] 检测操作系统发行版...${NC}"
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$NAME
    VER=$VERSION_ID
else
    echo -e "${RED}[!] 无法识别操作系统发行版${NC}"
    exit 1
fi

echo -e "${GREEN}[+] 检测到: ${OS} ${VER}${NC}"

# 安装前准备
echo -e "${YELLOW}[*] 准备系统环境...${NC}"
case $OS in
    "Ubuntu" | "Debian GNU/Linux")
        apt update
        apt install -y software-properties-common
        add-apt-repository -y ppa:wireguard/wireguard
        apt update
        ;;
    "CentOS Linux" | "Rocky Linux" | "AlmaLinux")
        yum install -y epel-release
        ;;
    "Fedora Linux")
        ;;
    *)
        echo -e "${RED}[!] 不支持的发行版: ${OS}${NC}"
        exit 1
        ;;
esac

# 安装WireGuard
echo -e "${YELLOW}[*] 正在安装WireGuard...${NC}"
case $OS in
    "Ubuntu" | "Debian GNU/Linux")
        apt install -y wireguard qrencode
        ;;
    "CentOS Linux" | "Rocky Linux" | "AlmaLinux")
        yum install -y elrepo-release
        yum install -y kmod-wireguard wireguard-tools qrencode
        ;;
    "Fedora Linux")
        dnf install -y wireguard-tools qrencode
        ;;
esac

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] WireGuard安装失败${NC}"
    exit 1
fi

echo -e "${GREEN}[+] WireGuard安装成功${NC}"

# 配置网络转发
echo -e "${YELLOW}[*] 配置网络转发...${NC}"
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/wg.conf
echo "net.ipv6.conf.all.forwarding = 1" >> /etc/sysctl.d/wg.conf
sysctl -p /etc/sysctl.d/wg.conf

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] 网络转发配置失败${NC}"
else
    echo -e "${GREEN}[+] 网络转发已启用${NC}"
fi

# 创建WireGuard配置
echo -e "${YELLOW}[*] 创建WireGuard配置...${NC}"
WG_DIR="/etc/wireguard"
WG_CONFIG="${WG_DIR}/wg0.conf"
mkdir -p $WG_DIR

# 生成密钥
echo -e "${YELLOW}[*] 生成WireGuard密钥...${NC}"
umask 077
PRIVATE_KEY=$(wg genkey)
PUBLIC_KEY=$(echo "$PRIVATE_KEY" | wg pubkey)
umask 022

# 获取服务器公网IP
echo -e "${YELLOW}[*] 获取服务器公网IP...${NC}"
SERVER_PUBLIC_IP=$(curl -s ifconfig.me)
if [ -z "$SERVER_PUBLIC_IP" ]; then
    echo -e "${RED}[!] 无法获取公网IP，请手动输入${NC}"
    read -p "请输入服务器公网IP: " SERVER_PUBLIC_IP
fi

# 配置端口
echo -e "${YELLOW}[*] 配置WireGuard端口...${NC}"
SERVER_PORT=51820
read -p "请输入WireGuard监听端口 [默认: 51820]: " input_port
if [ ! -z "$input_port" ]; then
    SERVER_PORT=$input_port
fi

# 配置客户端信息
echo -e "${YELLOW}[*] 配置客户端信息...${NC}"
CLIENT_NAME="client"
read -p "请输入客户端名称 [默认: client]: " input_client
if [ ! -z "$input_client" ]; then
    CLIENT_NAME=$input_client
fi

# 生成客户端密钥
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo "$CLIENT_PRIVATE_KEY" | wg pubkey)
CLIENT_IP="10.0.0.2/32"

# 创建服务器配置文件
cat > $WG_CONFIG << EOF
[Interface]
Address = 10.0.0.1/24
ListenPort = $SERVER_PORT
PrivateKey = $PRIVATE_KEY
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -j MASQUERADE; ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o $(ip -6 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -j MASQUERADE; ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o $(ip -6 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -j MASQUERADE

[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP
EOF

# 创建客户端配置文件
CLIENT_CONFIG="${WG_DIR}/${CLIENT_NAME}.conf"
cat > $CLIENT_CONFIG << EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = 8.8.8.8, 8.8.4.4

[Peer]
PublicKey = $PUBLIC_KEY
Endpoint = $SERVER_PUBLIC_IP:$SERVER_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

echo -e "${GREEN}[+] WireGuard配置完成${NC}"

# 配置防火墙
echo -e "${YELLOW}[*] 配置防火墙...${NC}"
FIREWALL_CONFIGURED=false

# 检查是否存在防火墙管理程序并优先使用
if command -v ufw &>/dev/null && systemctl is-active --quiet ufw; then
    echo -e "${YELLOW}[*] 发现ufw防火墙，使用ufw配置...${NC}"
    ufw allow $SERVER_PORT/udp
    ufw allow OpenSSH  # 确保SSH不被封锁
    ufw reload
    FIREWALL_CONFIGURED=true
    echo -e "${GREEN}[+] ufw防火墙配置完成${NC}"
elif command -v firewalld &>/dev/null && systemctl is-active --quiet firewalld; then
    echo -e "${YELLOW}[*] 发现firewalld，使用firewalld配置...${NC}"
    firewall-cmd --permanent --add-port=$SERVER_PORT/udp
    firewall-cmd --permanent --add-masquerade
    firewall-cmd --reload
    FIREWALL_CONFIGURED=true
    echo -e "${GREEN}[+] firewalld配置完成${NC}"
elif command -v nft &>/dev/null; then
    echo -e "${YELLOW}[*] 发现nftables，使用nftables配置...${NC}"
    # 检查是否有nftables规则文件
    if [ -f /etc/nftables.conf ]; then
        # 备份原文件
        cp /etc/nftables.conf /etc/nftables.conf.bak
        
        # 添加WireGuard规则
        if grep -q "table inet filter" /etc/nftables.conf; then
            # 如果已有filter表，添加到现有表中
            sed -i "/table inet filter/a \ \tchain input {\n\t\ttype filter hook input priority 0;\n\t\tudp dport $SERVER_PORT accept\n\t}" /etc/nftables.conf
        else
            # 否则创建新表
            cat >> /etc/nftables.conf << EOF

table inet filter {
    chain input {
        type filter hook input priority 0;
        udp dport $SERVER_PORT accept
    }
}
EOF
        fi
        
        # 重新加载nftables
        nft -f /etc/nftables.conf
        FIREWALL_CONFIGURED=true
        echo -e "${GREEN}[+] nftables配置完成${NC}"
    else
        echo -e "${YELLOW}[!] 未找到nftables配置文件，使用iptables配置...${NC}"
    fi
fi

# 如果没有防火墙管理程序，使用iptables
if [ "$FIREWALL_CONFIGURED" = false ]; then
    echo -e "${YELLOW}[*] 使用iptables配置防火墙...${NC}"
    iptables -A INPUT -p udp --dport $SERVER_PORT -j ACCEPT
    iptables -A FORWARD -i wg0 -j ACCEPT
    iptables -A FORWARD -o wg0 -j ACCEPT
    iptables -t nat -A POSTROUTING -o $(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1) -j MASQUERADE
    
    # 保存规则
    if [ -x "$(command -v netfilter-persistent)" ]; then
        netfilter-persistent save
    elif [ -x "$(command -v iptables-save)" ]; then
        iptables-save > /etc/iptables/rules.v4
        ip6tables-save > /etc/iptables/rules.v6
    else
        echo -e "${YELLOW}[!] 无法自动保存iptables规则，请手动保存${NC}"
    fi
    
    echo -e "${GREEN}[+] iptables配置完成${NC}"
fi

# 启用并启动WireGuard服务
echo -e "${YELLOW}[*] 启用并启动WireGuard服务...${NC}"
systemctl enable wg-quick@wg0
systemctl start wg-quick@wg0

if [ $? -ne 0 ]; then
    echo -e "${RED}[!] WireGuard服务启动失败${NC}"
    echo -e "${YELLOW}[*] 尝试重新加载模块...${NC}"
    modprobe wireguard
    systemctl start wg-quick@wg0
    
    if [ $? -ne 0 ]; then
        echo -e "${RED}[!] WireGuard服务仍然无法启动，请检查配置${NC}"
        exit 1
    fi
fi

echo -e "${GREEN}[+] WireGuard服务已启动${NC}"

#生成wgui监控服务
cd /etc/systemd/system/
cat << EOF > wgui.service
[Unit]
Description=Restart WireGuard
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart wg-quick@wg0.service

[Install]
RequiredBy=wgui.path
EOF

cat << EOF > wgui.path
[Unit]
Description=Watch /etc/wireguard/wg0.conf for changes

[Path]
PathModified=/etc/wireguard/wg0.conf

[Install]
WantedBy=multi-user.target
EOF

systemctl enable wgui.{path,service}
systemctl start wgui.{path,service}



# 显示配置信息
echo -e "${GREEN}========== WireGuard配置信息 ==========${NC}"
echo -e "${GREEN}[+] 服务器公钥:${NC} $PUBLIC_KEY"
echo -e "${GREEN}[+] 服务器监听端口:${NC} $SERVER_PORT"
echo -e "${GREEN}[+] 客户端配置文件:${NC} $CLIENT_CONFIG"
echo -e "${GREEN}[+] QR码:${NC}"
qrencode -t ansiutf8 < $CLIENT_CONFIG

echo -e "${GREEN}========== 安装完成 ==========${NC}"
echo -e "${GREEN}[+] WireGuard已成功安装并配置${NC}"
echo -e "${GREEN}[+] 客户端配置文件位置: ${CLIENT_CONFIG}${NC}"
echo -e "${GREEN}[+] 可以将此配置文件导入到WireGuard客户端应用中${NC}"
