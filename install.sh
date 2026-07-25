#!/bin/sh
set -eu
umask 077

REPO_RAW="${DM_REPO_RAW:-https://raw.githubusercontent.com/JohnMuyuan/Domain-Portfolio/main}"
APP_DIR="/opt/domain-manager"
DATA_DIR="/var/lib/domain-manager"
APP="$APP_DIR/domain_manager.py"
COMMAND="/usr/local/bin/domain-manager"
SERVICE="domain-manager"

require_root() {
    [ "$(id -u)" -eq 0 ] || { echo "请用 root 运行：sudo sh install.sh"; exit 1; }
}

installed() { [ -f "$APP" ] && [ -f "$DATA_DIR/config.json" ]; }
download() { curl -fLsS --retry 3 --connect-timeout 15 "$1" -o "$2"; }

prompt() {
    label=$1 default=$2
    printf "%s [%s]: " "$label" "$default" >/dev/tty
    IFS= read -r answer </dev/tty || answer=""
    [ -n "$answer" ] && printf '%s' "$answer" || printf '%s' "$default"
}

secret_prompt() {
    printf "%s（留空自动生成）: " "$1" >/dev/tty
    stty -echo </dev/tty
    IFS= read -r answer </dev/tty || answer=""
    stty echo </dev/tty
    printf '\n' >/dev/tty
    printf '%s' "$answer"
}

random_password() { openssl rand -base64 18 | tr -d '/+=' | cut -c1-18; }

install_packages() {
    command -v python3 >/dev/null 2>&1 && command -v curl >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1 && return
    echo "正在安装 Python 3、curl 和 openssl..."
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update
        DEBIAN_FRONTEND=noninteractive apt-get install -y python3 curl openssl ca-certificates
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y python3 curl openssl ca-certificates
    elif command -v yum >/dev/null 2>&1; then
        yum install -y python3 curl openssl ca-certificates
    elif command -v apk >/dev/null 2>&1; then
        apk add python3 curl openssl ca-certificates
    else
        echo "无法识别包管理器，请先手动安装 python3、curl、openssl。"
        exit 1
    fi
}

port_free() {
    python3 - "$1" <<'PY'
import socket, sys
s = socket.socket()
try:
    s.bind(("0.0.0.0", int(sys.argv[1])))
except OSError:
    raise SystemExit(1)
finally:
    s.close()
PY
}

open_firewall() {
    port=$1
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
        ufw allow "$port/tcp" >/dev/null
    elif command -v firewall-cmd >/dev/null 2>&1 && firewall-cmd --state >/dev/null 2>&1; then
        firewall-cmd --permanent --add-port="$port/tcp" >/dev/null
        firewall-cmd --reload >/dev/null
    fi
}

download_release() {
    temp=$(mktemp -d)
    if [ -f ./domain_manager.py ]; then
        cp ./domain_manager.py "$temp/domain_manager.py"
    else
        download "$REPO_RAW/domain_manager.py" "$temp/domain_manager.py"
    fi
    python3 -m py_compile "$temp/domain_manager.py"
    install -d -m 755 "$APP_DIR"
    install -m 755 "$temp/domain_manager.py" "$APP"
    if [ -f ./install.sh ]; then
        install -m 755 ./install.sh "$COMMAND"
    else
        download "$REPO_RAW/install.sh" "$temp/install.sh"
        install -m 755 "$temp/install.sh" "$COMMAND"
    fi
    rm -rf "$temp"
}

setup_service() {
    if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
        cat >/etc/systemd/system/domain-manager.service <<EOF
[Unit]
Description=Domain Manager web panel
After=network-online.target
Wants=network-online.target
[Service]
Type=simple
UMask=0077
ExecStart=/usr/bin/python3 $APP --data-dir $DATA_DIR serve
Restart=on-failure
RestartSec=5
[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable "$SERVICE" >/dev/null
        systemctl restart "$SERVICE"
    elif command -v rc-service >/dev/null 2>&1; then
        cat >/etc/init.d/domain-manager <<EOF
#!/sbin/openrc-run
name="Domain Manager"
command="/usr/bin/python3"
command_args="$APP --data-dir $DATA_DIR serve"
command_background=true
pidfile="/run/domain-manager.pid"
output_log="/var/log/domain-manager.log"
error_log="/var/log/domain-manager.log"
depend() { need net; }
EOF
        chmod 755 /etc/init.d/domain-manager
        rc-update add "$SERVICE" default >/dev/null
        rc-service "$SERVICE" restart || rc-service "$SERVICE" start
    else
        echo "未检测到 systemd/OpenRC，程序已安装但未创建服务。"
    fi
}

service_action() {
    action=$1
    if [ -f /etc/systemd/system/domain-manager.service ]; then
        systemctl "$action" "$SERVICE"
    elif command -v rc-service >/dev/null 2>&1 && [ -f /etc/init.d/domain-manager ]; then
        rc-service "$SERVICE" "$action"
    else
        echo "未找到服务"
        return 1
    fi
}

install_app() {
    require_root
    installed && { echo "已经安装，请运行 domain-manager update 更新。"; return; }
    install_packages
    username=${DM_PANEL_USER:-admin}
    password=${DM_PANEL_PASSWORD:-}
    port=${DM_PANEL_PORT:-8099}
    reverse_proxy=${DM_REVERSE_PROXY:-1}
    if [ "${DM_NONINTERACTIVE:-0}" != 1 ] && [ -t 0 ] && [ -r /dev/tty ]; then
        echo "Domain Manager 一键安装"
        username=$(prompt "面板用户名" "$username")
        password=$(secret_prompt "面板密码")
        port=$(prompt "面板端口" "$port")
        reverse_proxy=$(prompt "由 1Panel/Nginx 反向代理并管理 HTTPS？(Y/n)" "y")
    fi
    case "$reverse_proxy" in n|N|no|NO|0) host="0.0.0.0" ;; *) host="127.0.0.1" ;; esac
    [ -n "$password" ] || password=$(random_password)
    case "$port" in *[!0-9]*|"") echo "端口必须是数字"; exit 1 ;; esac
    [ "$port" -ge 1 ] && [ "$port" -le 65535 ] || { echo "端口必须在 1-65535 之间"; exit 1; }
    port_free "$port" || { echo "端口 $port 已被占用，请换一个。"; exit 1; }
    download_release
    python3 "$APP" --data-dir "$DATA_DIR" init --username "$username" --password "$password" --host "$host" --port "$port" --no-tls
    [ "$host" = "127.0.0.1" ] || open_firewall "$port"
    setup_service
    echo
    if [ "$host" = "127.0.0.1" ]; then
        echo "安装完成：请在 1Panel/Nginx 反向代理到 http://127.0.0.1:$port"
    else
        echo "安装完成：http://服务器IP:$port"
        echo "提示：公网使用建议套 1Panel/Nginx HTTPS。"
    fi
    echo "管理用户名：$username"
    echo "管理密码：$password"
    echo "以后运行 domain-manager 打开管理菜单。"
}

update_app() {
    require_root
    installed || { install_app; return; }
    install_packages
    download_release
    setup_service
    echo "更新完成。"
}

panel_info() {
    installed || { echo "尚未安装"; return; }
    values=$(python3 -c 'import json; c=json.load(open("/var/lib/domain-manager/config.json")); print(c.get("admin_username","admin")); print(c.get("listen_host","127.0.0.1")); print(c.get("listen_port",8099))')
    username=$(printf '%s\n' "$values" | sed -n '1p')
    host=$(printf '%s\n' "$values" | sed -n '2p')
    port=$(printf '%s\n' "$values" | sed -n '3p')
    [ "$host" = "127.0.0.1" ] && echo "反向代理地址：http://127.0.0.1:$port" || echo "面板地址：http://服务器IP:$port"
    echo "管理用户名：$username"
}

change_panel() {
    require_root
    installed || { echo "尚未安装"; return; }
    username=$(prompt "新管理用户名" "admin")
    password=$(secret_prompt "新管理密码")
    port=$(prompt "新面板端口" "8099")
    reverse_proxy=$(prompt "由 1Panel/Nginx 反向代理并管理 HTTPS？(Y/n)" "y")
    case "$reverse_proxy" in n|N|no|NO|0) host="0.0.0.0" ;; *) host="127.0.0.1" ;; esac
    [ -n "$password" ] || password=$(random_password)
    python3 "$APP" --data-dir "$DATA_DIR" init --username "$username" --password "$password" --host "$host" --port "$port" --no-tls
    [ "$host" = "127.0.0.1" ] || open_firewall "$port"
    service_action restart
    panel_info
    echo "新管理密码：$password"
}

uninstall_app() {
    require_root
    printf "确定卸载程序？域名数据默认保留 [y/N]: " >/dev/tty
    IFS= read -r answer </dev/tty || answer=n
    [ "$answer" = y ] || [ "$answer" = Y ] || { echo "已取消"; return; }
    service_action stop 2>/dev/null || true
    if [ -f /etc/systemd/system/domain-manager.service ]; then
        systemctl disable "$SERVICE" >/dev/null 2>&1 || true
        rm -f /etc/systemd/system/domain-manager.service
        systemctl daemon-reload
    fi
    command -v rc-update >/dev/null 2>&1 && rc-update del "$SERVICE" default >/dev/null 2>&1 || true
    rm -f /etc/init.d/domain-manager "$COMMAND"
    rm -rf "$APP_DIR"
    printf "同时删除面板配置和域名数据？[y/N]: " >/dev/tty
    IFS= read -r remove_data </dev/tty || remove_data=n
    if [ "$remove_data" = y ] || [ "$remove_data" = Y ]; then
        rm -rf "$DATA_DIR"
    fi
    echo "卸载完成。"
}

show_logs() {
    if [ -f /etc/systemd/system/domain-manager.service ]; then
        journalctl -u "$SERVICE" -n 100 --no-pager
    else
        tail -n 100 /var/log/domain-manager.log 2>/dev/null || true
    fi
}

menu() {
    require_root
    while :; do
        echo
        echo "Domain Manager 管理菜单"
        echo "1. 查看面板信息"
        echo "2. 查看服务状态"
        echo "3. 启动服务"
        echo "4. 停止服务"
        echo "5. 重启服务"
        echo "6. 修改用户名/密码/端口"
        echo "7. 更新程序"
        echo "8. 查看日志"
        echo "9. 卸载"
        echo "0. 退出"
        printf "请选择: " >/dev/tty
        IFS= read -r choice </dev/tty || return
        case "$choice" in
            1) panel_info ;;
            2) service_action status || true ;;
            3) service_action start ;;
            4) service_action stop ;;
            5) service_action restart ;;
            6) change_panel ;;
            7) update_app ;;
            8) show_logs ;;
            9) uninstall_app; return ;;
            0) return ;;
            *) echo "请输入菜单中的数字。" ;;
        esac
    done
}

case "${1:-}" in
    install) install_app ;;
    update) update_app ;;
    uninstall) uninstall_app ;;
    status|start|stop|restart) require_root; service_action "$1" ;;
    logs) require_root; show_logs ;;
    info) require_root; panel_info ;;
    "") if installed; then menu; else install_app; fi ;;
    *) echo "用法：domain-manager [install|update|uninstall|status|start|stop|restart|logs|info]"; exit 1 ;;
esac
