# 域名管理器

一个小白向的域名资产展示和续费提醒面板：前端卡片展示域名，后端用 Python 标准库提供 API，数据保存在本地 JSON 文件里。

## 功能

- 首页用卡片列出所有域名。
- 卡片显示到期时间、注册商、续费价格。
- 根据续费年费和剩余天数估算域名资产剩余价值。
- 按到期时间从近到远显示续费排名。
- 点击卡片进入详情页。
- 详情页可编辑域名信息、续费链接和资产备注。
- 详情页可打开续费链接。
- 支持日间、夜间和跟随系统主题。
- 支持 Telegram 和邮件到期提醒、自定义提前提醒天数。
- 设置页支持邮件预览和 SMTP 测试邮件。
- 带登录页，适合放到 1Panel/Nginx 后面反向代理。

说明：当前版本专注域名续费提醒和域名资产展示，不做 DNS 修改。

## 本地运行

```bash
python3 domain_manager.py --data-dir ./data init --username admin --password '请换成强密码' --host 127.0.0.1 --port 8099 --no-tls
python3 domain_manager.py --data-dir ./data serve
```

访问：

```text
http://127.0.0.1:8099
```

## 一键部署

在 Linux 服务器里，进入本项目目录后执行：

```bash
sudo sh install.sh
```

默认监听 `127.0.0.1:8099`，推荐用 1Panel/Nginx 创建反向代理，并在 1Panel/Nginx 里启用 HTTPS。

非交互安装示例：

```bash
DM_NONINTERACTIVE=1 \
DM_PANEL_USER=admin \
DM_PANEL_PASSWORD='请换成强密码' \
DM_PANEL_PORT=8099 \
DM_REVERSE_PROXY=1 \
sudo sh install.sh
```

安装后管理命令：

```bash
domain-manager info
domain-manager status
domain-manager restart
domain-manager logs
domain-manager update
```

## 数据位置

- 程序目录：`/opt/domain-manager`
- 数据目录：`/var/lib/domain-manager`
- 管理命令：`/usr/local/bin/domain-manager`

## 自检

```bash
python3 domain_manager.py --data-dir ./data self-test
```
