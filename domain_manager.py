#!/usr/bin/env python3
"""Small domain manager with a Chinese web panel and JSON storage."""

import argparse
import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import smtplib
import ssl
import sys
import threading
import time
import urllib.parse
import urllib.request
from datetime import date, datetime, timezone
from email.message import EmailMessage
from email.utils import formataddr
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote, urlparse

DEFAULTS = {
    "admin_username": "admin",
    "password_hash": "",
    "listen_host": "127.0.0.1",
    "listen_port": 8099,
    "session_secret": "",
    "tls_enabled": False,
    "tls_cert": "",
    "tls_key": "",
    "notify_enabled": False,
    "reminder_days": "30,7,1",
    "telegram_enabled": False,
    "telegram_bot_token": "",
    "telegram_chat_id": "",
    "email_enabled": False,
    "smtp_host": "",
    "smtp_port": 465,
    "smtp_security": "ssl",
    "smtp_username": "",
    "smtp_password": "",
    "mail_from": "",
    "mail_to": "",
    "notify_last_sent": {},
}
DOMAIN_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
SESSION_TTL = 12 * 60 * 60
sessions = {}
store_lock = threading.Lock()


def now_ts():
    return int(time.time())


def hash_password(password):
    salt = secrets.token_bytes(16)
    rounds = 200_000
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, rounds)
    return "pbkdf2_sha256${}${}${}".format(
        rounds,
        base64.b64encode(salt).decode(),
        base64.b64encode(digest).decode(),
    )


def verify_password(password, encoded):
    try:
        method, rounds, salt, digest = encoded.split("$", 3)
        if method != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), base64.b64decode(salt), int(rounds)
        )
        return hmac.compare_digest(actual, base64.b64decode(digest))
    except Exception:
        return False


def read_json(path, fallback):
    if not path.exists():
        return fallback
    with path.open("r", encoding="utf-8-sig") as source:
        return json.load(source)


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    with temp.open("w", encoding="utf-8") as target:
        json.dump(data, target, ensure_ascii=False, indent=2)
    try:
        os.chmod(temp, 0o600)
    except OSError:
        pass
    os.replace(temp, path)


def config_path(data_dir):
    return Path(data_dir) / "config.json"


def domains_path(data_dir):
    return Path(data_dir) / "domains.json"


def load_config(data_dir):
    config = dict(DEFAULTS)
    config.update(read_json(config_path(data_dir), {}))
    if not config["session_secret"]:
        config["session_secret"] = secrets.token_urlsafe(32)
        write_json(config_path(data_dir), config)
    return config


def load_store(data_dir):
    store = read_json(domains_path(data_dir), {"domains": sample_domains()})
    for domain in store.get("domains", []):
        domain.pop("dns_records", None)
    return store


def save_store(data_dir, store):
    write_json(domains_path(data_dir), store)


def parse_reminder_days(value):
    days = []
    for part in re.split(r"[,，\s]+", str(value or "")):
        if not part:
            continue
        try:
            day = int(part)
        except ValueError:
            continue
        if 0 <= day <= 3650 and day not in days:
            days.append(day)
    return days or [30, 7, 1]


def days_until(expires_at):
    if not expires_at:
        return None
    try:
        target = datetime.strptime(expires_at, "%Y-%m-%d").date()
    except ValueError:
        return None
    return (target - date.today()).days


def clean_settings(payload, current):
    config = dict(current)
    for key in ("notify_enabled", "telegram_enabled", "email_enabled"):
        config[key] = bool(payload.get(key))
    for key in ("telegram_chat_id", "smtp_host", "smtp_username", "mail_from", "mail_to"):
        config[key] = str(payload.get(key, "")).strip()
    for key in ("telegram_bot_token", "smtp_password"):
        value = str(payload.get(key, "")).strip()
        if value:
            config[key] = value
    config["reminder_days"] = ",".join(str(day) for day in parse_reminder_days(payload.get("reminder_days")))
    try:
        config["smtp_port"] = int(payload.get("smtp_port") or 465)
    except (TypeError, ValueError) as exc:
        raise ValueError("SMTP 端口必须是数字") from exc
    if config["smtp_port"] < 1 or config["smtp_port"] > 65535:
        raise ValueError("SMTP 端口必须在 1-65535 之间")
    security = str(payload.get("smtp_security", "ssl")).strip().lower()
    config["smtp_security"] = security if security in {"ssl", "starttls", "none"} else "ssl"
    return config


def settings_for_client(config):
    keys = (
        "notify_enabled", "reminder_days", "telegram_enabled", "telegram_chat_id",
        "email_enabled", "smtp_host", "smtp_port", "smtp_security", "smtp_username",
        "mail_from", "mail_to",
    )
    result = {key: config.get(key, DEFAULTS.get(key)) for key in keys}
    result["telegram_bot_configured"] = bool(config.get("telegram_bot_token"))
    result["smtp_password_configured"] = bool(config.get("smtp_password"))
    return result


def expiring_domains(domains, reminder_days):
    reminder_set = set(reminder_days)
    matches = []
    for domain in domains:
        left = days_until(domain.get("expires_at"))
        if left in reminder_set:
            item = dict(domain)
            item["days_left"] = left
            matches.append(item)
    return sorted(matches, key=lambda item: (item["days_left"], item["name"]))


def email_html(domains, config):
    rows = []
    for domain in domains:
        left = domain.get("days_left")
        if left is None:
            left_text = "未填写"
        elif left == 0:
            left_text = "今天到期"
        elif left < 0:
            left_text = f"已过期 {abs(left)} 天"
        else:
            left_text = f"还剩 {left} 天"
        rows.append(
            "<tr>"
            f"<td>{html.escape(domain.get('name', ''))}</td>"
            f"<td>{html.escape(domain.get('expires_at') or '未填写')}</td>"
            f"<td>{html.escape(left_text)}</td>"
            f"<td>{html.escape(domain.get('registrar') or '未填写')}</td>"
            f"<td>{html.escape(domain.get('renewal_price') or '未填写')}</td>"
            "</tr>"
        )
    if not rows:
        rows.append('<tr><td colspan="5" class="empty">当前没有命中提醒条件的域名。</td></tr>')
    return f"""<!doctype html><html><head><meta charset="utf-8"><style>
body{{margin:0;background:#f4f7fb;color:#172033;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}}
.wrap{{max-width:760px;margin:0 auto;padding:28px}}.card{{background:#fff;border:1px solid #dbe3ee;border-radius:12px;overflow:hidden;box-shadow:0 18px 45px #1d355714}}
.head{{background:#0f172a;color:#f8fafc;padding:22px 24px}}h1{{margin:0;font-size:24px}}.sub{{margin-top:7px;color:#b8c4d6}}
.body{{padding:22px 24px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:12px 10px;border-bottom:1px solid #e6edf5;text-align:left;font-size:14px}}th{{color:#657286;font-size:12px}}td:first-child{{font-weight:800}}.empty{{text-align:center;color:#657286}}.foot{{padding:16px 24px;color:#657286;font-size:12px;background:#f8fafc}}
</style></head><body><div class="wrap"><div class="card"><div class="head"><h1>域名续费提醒</h1><div class="sub">提醒规则：到期前 {html.escape(str(config.get('reminder_days', '30,7,1')))} 天</div></div><div class="body"><table><thead><tr><th>域名</th><th>到期时间</th><th>剩余时间</th><th>注册商</th><th>续费价格</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div><div class="foot">来自域名管理器。请及时到注册商后台确认续费状态。</div></div></div></body></html>"""


def email_text(domains):
    if not domains:
        return "当前没有命中提醒条件的域名。"
    lines = ["域名续费提醒："]
    for domain in domains:
        lines.append(f"- {domain.get('name')}：{domain.get('expires_at')}，还剩 {domain.get('days_left')} 天，{domain.get('renewal_price') or '未填写续费价'}")
    return "\n".join(lines)


def send_email(config, domains, subject="域名续费提醒"):
    if not config.get("email_enabled"):
        return
    if not config.get("smtp_host") or not config.get("mail_to"):
        raise ValueError("邮件通知缺少 SMTP 地址或收件人")
    message = EmailMessage()
    sender = config.get("mail_from") or config.get("smtp_username") or "domain-manager@localhost"
    message["From"] = formataddr(("域名管理器", sender))
    message["To"] = config["mail_to"]
    message["Subject"] = subject
    message.set_content(email_text(domains))
    message.add_alternative(email_html(domains, config), subtype="html")
    security = config.get("smtp_security", "ssl")
    if security == "ssl":
        smtp = smtplib.SMTP_SSL(config["smtp_host"], int(config.get("smtp_port") or 465), timeout=20)
    else:
        smtp = smtplib.SMTP(config["smtp_host"], int(config.get("smtp_port") or 25), timeout=20)
    try:
        if security == "starttls":
            smtp.starttls()
        if config.get("smtp_username"):
            smtp.login(config["smtp_username"], config.get("smtp_password", ""))
        smtp.send_message(message)
    finally:
        smtp.quit()


def send_telegram(config, domains):
    if not config.get("telegram_enabled"):
        return
    token = config.get("telegram_bot_token")
    chat_id = config.get("telegram_chat_id")
    if not token or not chat_id:
        raise ValueError("Telegram 通知缺少 Bot Token 或 Chat ID")
    lines = ["域名续费提醒"]
    for domain in domains:
        lines.append(f"{domain.get('name')}：{domain.get('expires_at')}，还剩 {domain.get('days_left')} 天")
    data = urllib.parse.urlencode({"chat_id": chat_id, "text": "\n".join(lines)}).encode()
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    with urllib.request.urlopen(url, data=data, timeout=20) as response:
        response.read()


def notification_loop(data_dir):
    while True:
        try:
            config = load_config(data_dir)
            if config.get("notify_enabled"):
                store = load_store(data_dir)
                matches = expiring_domains(store.get("domains", []), parse_reminder_days(config.get("reminder_days")))
                today = date.today().isoformat()
                due = []
                sent = dict(config.get("notify_last_sent") or {})
                for domain in matches:
                    key = f"{today}:{domain.get('id')}:{domain.get('days_left')}"
                    if sent.get(key):
                        continue
                    due.append(domain)
                if due:
                    send_email(config, due)
                    send_telegram(config, due)
                    for domain in due:
                        sent[f"{today}:{domain.get('id')}:{domain.get('days_left')}"] = True
                    config["notify_last_sent"] = dict(list(sent.items())[-500:])
                    write_json(config_path(data_dir), config)
        except Exception as exc:
            print(f"notification error: {exc}", file=sys.stderr)
        try:
            with store_lock:
                store = load_store(data_dir)
                if advance_auto_renewals(store.get("domains", [])):
                    save_store(data_dir, store)
        except Exception as exc:
            print(f"auto-renew update error: {exc}", file=sys.stderr)
        time.sleep(3600)


def advance_auto_renewals(domains, today=None):
    today = today or date.today()
    changed = 0
    for domain in domains:
        if not domain.get("auto_renew") or not domain.get("expires_at"):
            continue
        try:
            expires = date.fromisoformat(domain["expires_at"])
        except (TypeError, ValueError):
            continue
        original = expires
        while expires <= today:
            try:
                expires = expires.replace(year=expires.year + 1)
            except ValueError:
                expires = expires.replace(year=expires.year + 1, day=28)
        if expires != original:
            domain["expires_at"] = expires.isoformat()
            domain["updated_at"] = datetime.now(timezone.utc).isoformat()
            changed += 1
    return changed


def sample_domains():
    return [
        {
            "id": "demo-example",
            "name": "example.com",
            "expires_at": "2027-08-01",
            "registrar": "Namecheap",
            "renewal_price": "12.98 USD / 年",
            "renewal_url": "https://www.namecheap.com/domains/registration/results/?domain=example.com",
            "auto_renew": False,
            "notes": "示例域名，可以删除或直接改成自己的。",
        }
    ]


def clean_domain(payload, existing=None):
    existing = existing or {}
    name = str(payload.get("name", "")).strip().lower()
    if not DOMAIN_RE.match(name):
        raise ValueError("请输入正确的域名，例如 example.com")
    expires_at = str(payload.get("expires_at", "")).strip()
    if expires_at:
        try:
            datetime.strptime(expires_at, "%Y-%m-%d")
        except ValueError as exc:
            raise ValueError("到期时间格式应为 YYYY-MM-DD") from exc
    return {
        "id": existing.get("id") or secrets.token_hex(8),
        "name": name,
        "expires_at": expires_at,
        "registrar": str(payload.get("registrar", "")).strip(),
        "renewal_price": str(payload.get("renewal_price", "")).strip(),
        "renewal_url": str(payload.get("renewal_url", "")).strip(),
        "auto_renew": bool(payload.get("auto_renew")),
        "notes": str(payload.get("notes", "")).strip(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
    }


class DomainHandler(BaseHTTPRequestHandler):
    server_version = "DomainManager/1.0"

    @property
    def data_dir(self):
        return self.server.data_dir

    @property
    def config(self):
        return self.server.config

    def log_message(self, fmt, *args):
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def send_json(self, status, data):
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def read_body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length > 1024 * 1024:
            raise ValueError("请求内容太大")
        if not length:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def cookie_token(self):
        jar = cookies.SimpleCookie(self.headers.get("Cookie"))
        morsel = jar.get("dm_session")
        return morsel.value if morsel else ""

    def current_user(self):
        token = self.cookie_token()
        expires = sessions.get(token)
        if not expires or expires < now_ts():
            sessions.pop(token, None)
            return None
        sessions[token] = now_ts() + SESSION_TTL
        return self.config["admin_username"]

    def require_user(self):
        user = self.current_user()
        if not user:
            self.send_json(401, {"error": "请先登录"})
            return None
        return user

    def route_parts(self):
        path = urlparse(self.path).path
        return [unquote(part) for part in path.split("/") if part]

    def do_GET(self):
        parts = self.route_parts()
        if not parts or parts[0] != "api":
            return self.serve_index()
        if parts[1:] == ["me"]:
            user = self.current_user()
            return self.send_json(200, {"user": user} if user else {"user": None})
        if not self.require_user():
            return
        if parts[1:] == ["domains"]:
            with store_lock:
                domains = load_store(self.data_dir)["domains"]
            return self.send_json(200, {"domains": domains})
        if parts[1:] == ["settings"]:
            with store_lock:
                config = load_config(self.data_dir)
                self.server.config = config
            return self.send_json(200, {"settings": settings_for_client(config)})
        if parts[1:] == ["email-preview"]:
            with store_lock:
                config = load_config(self.data_dir)
                domains = load_store(self.data_dir).get("domains", [])
            preview_domains = []
            for domain in sorted(domains, key=lambda item: (item.get("expires_at") or "9999-12-31", item.get("name", "")))[:5]:
                item = dict(domain)
                item["days_left"] = days_until(item.get("expires_at"))
                preview_domains.append(item)
            return self.send_json(200, {"html": email_html(preview_domains, config)})
        if len(parts) == 3 and parts[1] == "domains":
            domain = self.find_domain(parts[2])
            return self.send_json(200, {"domain": domain} if domain else {"error": "域名不存在"})
        self.send_json(404, {"error": "接口不存在"})

    def do_POST(self):
        parts = self.route_parts()
        if parts[1:] == ["login"]:
            return self.login()
        if parts[1:] == ["logout"]:
            token = self.cookie_token()
            sessions.pop(token, None)
            self.send_response(204)
            self.send_header("Set-Cookie", "dm_session=; Max-Age=0; Path=/; SameSite=Lax; HttpOnly")
            self.end_headers()
            return
        if not self.require_user():
            return
        if parts[1:] == ["domains"]:
            return self.upsert_domain(None)
        if parts[1:] == ["email-test"]:
            return self.test_email()
        self.send_json(404, {"error": "接口不存在"})

    def do_PUT(self):
        parts = self.route_parts()
        if not self.require_user():
            return
        if len(parts) == 3 and parts[1] == "domains":
            return self.upsert_domain(parts[2])
        if parts[1:] == ["settings"]:
            return self.save_settings()
        self.send_json(404, {"error": "接口不存在"})

    def do_DELETE(self):
        parts = self.route_parts()
        if not self.require_user():
            return
        if len(parts) != 3 or parts[1] != "domains":
            return self.send_json(404, {"error": "接口不存在"})
        with store_lock:
            store = load_store(self.data_dir)
            before = len(store["domains"])
            store["domains"] = [item for item in store["domains"] if item["id"] != parts[2]]
            save_store(self.data_dir, store)
        self.send_json(200, {"deleted": before != len(store["domains"])})

    def login(self):
        try:
            body = self.read_body()
        except Exception:
            return self.send_json(400, {"error": "登录内容格式不正确"})
        username = str(body.get("username", ""))
        password = str(body.get("password", ""))
        if username != self.config["admin_username"] or not verify_password(password, self.config["password_hash"]):
            return self.send_json(403, {"error": "用户名或密码不对"})
        token = secrets.token_urlsafe(32)
        sessions[token] = now_ts() + SESSION_TTL
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Set-Cookie", f"dm_session={token}; Path=/; Max-Age={SESSION_TTL}; SameSite=Lax; HttpOnly")
        self.end_headers()
        self.wfile.write(json.dumps({"user": username}, ensure_ascii=False).encode("utf-8"))

    def find_domain(self, domain_id):
        with store_lock:
            for domain in load_store(self.data_dir)["domains"]:
                if domain["id"] == domain_id:
                    return domain
        return None

    def upsert_domain(self, domain_id):
        try:
            body = self.read_body()
            with store_lock:
                store = load_store(self.data_dir)
                existing = None
                for index, item in enumerate(store["domains"]):
                    if item["id"] == domain_id:
                        existing = item
                        break
                domain = clean_domain(body, existing)
                if any(item["id"] != domain["id"] and item["name"] == domain["name"] for item in store["domains"]):
                    raise ValueError("这个域名已经存在")
                if existing:
                    store["domains"][index] = domain
                else:
                    store["domains"].append(domain)
                store["domains"].sort(key=lambda item: (item.get("expires_at") or "9999-12-31", item["name"]))
                save_store(self.data_dir, store)
        except ValueError as exc:
            return self.send_json(400, {"error": str(exc)})
        except Exception:
            return self.send_json(400, {"error": "保存失败，请检查填写内容"})
        self.send_json(200, {"domain": domain})

    def save_settings(self):
        try:
            body = self.read_body()
            with store_lock:
                config = clean_settings(body, load_config(self.data_dir))
                write_json(config_path(self.data_dir), config)
                self.server.config = config
        except ValueError as exc:
            return self.send_json(400, {"error": str(exc)})
        except Exception:
            return self.send_json(400, {"error": "保存设置失败"})
        self.send_json(200, {"settings": settings_for_client(config)})

    def test_email(self):
        try:
            body = self.read_body()
            with store_lock:
                config = clean_settings(body, load_config(self.data_dir))
                domains = load_store(self.data_dir).get("domains", [])
            config["email_enabled"] = True
            preview = []
            for domain in sorted(domains, key=lambda item: (item.get("expires_at") or "9999-12-31", item.get("name", "")))[:5]:
                item = dict(domain)
                item["days_left"] = days_until(item.get("expires_at"))
                preview.append(item)
            send_email(config, preview, "域名管理器测试邮件")
        except ValueError as exc:
            return self.send_json(400, {"error": str(exc)})
        except Exception as exc:
            return self.send_json(502, {"error": f"测试邮件发送失败：{exc}"})
        self.send_json(200, {"message": f"测试邮件已发送到 {config['mail_to']}"})

    def serve_index(self):
        body = INDEX_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def init_app(args):
    data_dir = Path(args.data_dir)
    config = dict(DEFAULTS)
    if config_path(data_dir).exists():
        config.update(read_json(config_path(data_dir), {}))
    password = args.password or secrets.token_urlsafe(12)
    config.update(
        {
            "admin_username": args.username,
            "password_hash": hash_password(password),
            "listen_host": args.host,
            "listen_port": args.port,
            "session_secret": config.get("session_secret") or secrets.token_urlsafe(32),
            "tls_enabled": not args.no_tls,
            "tls_cert": args.cert,
            "tls_key": args.key,
        }
    )
    write_json(config_path(data_dir), config)
    if not domains_path(data_dir).exists():
        write_json(domains_path(data_dir), {"domains": sample_domains()})
    print(f"初始化完成：{args.host}:{args.port}")
    print(f"管理用户名：{args.username}")
    if not args.password:
        print(f"管理密码：{password}")


def serve(args):
    data_dir = Path(args.data_dir)
    config = load_config(data_dir)
    if not domains_path(data_dir).exists():
        write_json(domains_path(data_dir), {"domains": sample_domains()})
    server = ThreadingHTTPServer((config["listen_host"], int(config["listen_port"])), DomainHandler)
    server.data_dir = data_dir
    server.config = config
    threading.Thread(target=notification_loop, args=(data_dir,), daemon=True).start()
    if config.get("tls_enabled"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(config["tls_cert"], config["tls_key"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
    scheme = "https" if config.get("tls_enabled") else "http"
    print(f"Domain Manager listening on {scheme}://{config['listen_host']}:{config['listen_port']}")
    server.serve_forever()


def self_test():
    import tempfile

    with tempfile.TemporaryDirectory() as temp:
        class Args:
            data_dir = temp
            username = "admin"
            password = "password123"
            host = "127.0.0.1"
            port = 8099
            no_tls = True
            cert = ""
            key = ""

        init_app(Args)
        good = {
            "name": "my-domain.test",
            "expires_at": "2027-01-02",
            "registrar": "Cloudflare",
            "renewal_price": "10 USD / 年",
            "renewal_url": "https://dash.cloudflare.com",
        }
        domain = clean_domain(good)
        assert domain["name"] == "my-domain.test"
        try:
            clean_domain({"name": "bad name"})
        except ValueError:
            pass
        else:
            raise AssertionError("invalid domain accepted")
    print("self-test ok")


def main():
    parser = argparse.ArgumentParser(description="Domain Manager")
    parser.add_argument("--data-dir", default="./data")
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--username", default="admin")
    init.add_argument("--password", default="")
    init.add_argument("--host", default="127.0.0.1")
    init.add_argument("--port", type=int, default=8099)
    init.add_argument("--no-tls", action="store_true")
    init.add_argument("--cert", default="")
    init.add_argument("--key", default="")
    sub.add_parser("serve")
    sub.add_parser("self-test")
    args = parser.parse_args()
    if args.command == "init":
        init_app(args)
    elif args.command == "serve":
        serve(args)
    elif args.command == "self-test":
        self_test()


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>域名管理器</title>
<script>document.documentElement.dataset.theme=localStorage.getItem('dm_theme')||'auto'</script>
<style>
:root{color-scheme:light;--bg:#f4f7fb;--bg-soft:#eaf0f7;--fg:#172033;--muted:#657286;--card:#fffffff2;--card-solid:#fff;--border:#dbe3ee;--input:#f8fafc;--primary:#2563eb;--primary-hover:#1d4ed8;--primary-soft:#dbeafe;--accent:#0f766e;--success:#138a61;--success-soft:#dcfce7;--warning:#b7791f;--warning-soft:#fff1c2;--danger:#c2413b;--danger-soft:#fee2e2;--shadow:0 18px 45px #1d35570f;--shadow-hover:0 22px 55px #1d35571a;--ring:#2563eb35;--header:#0f172af2;--header-fg:#f8fafc;--header-muted:#b8c4d6;--header-border:#ffffff18;--header-hover:#ffffff12;--brand-tile:#172554}
html[data-theme=dark]{color-scheme:dark;--bg:#0c1320;--bg-soft:#111c30;--fg:#edf3ff;--muted:#9cabc0;--card:#131e30eb;--card-solid:#131e30;--border:#293750;--input:#0e1828;--primary:#6790ff;--primary-hover:#83a5ff;--primary-soft:#1c315d;--accent:#4fd1c5;--success:#47c79b;--success-soft:#153a35;--warning:#f0b45b;--warning-soft:#3d3020;--danger:#ff7281;--danger-soft:#401f29;--shadow:0 18px 55px #0006;--shadow-hover:0 24px 65px #0008;--ring:#7fa1ff44;--header:#09111ef2;--header-fg:#f5f8ff;--header-muted:#b9c5d8;--header-border:#ffffff12;--header-hover:#ffffff12;--brand-tile:#18294a}
@media(prefers-color-scheme:dark){html[data-theme=auto]{color-scheme:dark;--bg:#0c1320;--bg-soft:#111c30;--fg:#edf3ff;--muted:#9cabc0;--card:#131e30eb;--card-solid:#131e30;--border:#293750;--input:#0e1828;--primary:#6790ff;--primary-hover:#83a5ff;--primary-soft:#1c315d;--accent:#4fd1c5;--success:#47c79b;--success-soft:#153a35;--warning:#f0b45b;--warning-soft:#3d3020;--danger:#ff7281;--danger-soft:#401f29;--shadow:0 18px 55px #0006;--shadow-hover:0 24px 65px #0008;--ring:#7fa1ff44;--header:#09111ef2;--header-fg:#f5f8ff;--header-muted:#b9c5d8;--header-border:#ffffff12;--header-hover:#ffffff12;--brand-tile:#18294a}}
:root{--bg:#f6f7f9;--bg-soft:#eceff2;--fg:#1d232c;--muted:#69727d;--card:#fffffff2;--card-solid:#fff;--border:#dfe3e8;--input:#f8f9fb;--header:#15181df2;--brand-tile:#22272e}
html[data-theme=dark]{--bg:#101214;--bg-soft:#171a1e;--fg:#f2f4f7;--muted:#a3abb5;--card:#1b1f24ed;--card-solid:#1b1f24;--border:#30363d;--input:#15181c;--header:#0d0f11f2;--brand-tile:#20252b}
@media(prefers-color-scheme:dark){html[data-theme=auto]{--bg:#101214;--bg-soft:#171a1e;--fg:#f2f4f7;--muted:#a3abb5;--card:#1b1f24ed;--card-solid:#1b1f24;--border:#30363d;--input:#15181c;--header:#0d0f11f2;--brand-tile:#20252b}}
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:linear-gradient(180deg,var(--bg-soft),var(--bg) 280px);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI","Microsoft YaHei",sans-serif}button,input,textarea{font:inherit}button{cursor:pointer}a{color:var(--primary);text-decoration:none}.hidden{display:none!important}
.top{position:sticky;top:0;z-index:10;background:var(--header);color:var(--header-fg);border-bottom:1px solid var(--header-border);backdrop-filter:blur(16px);box-shadow:0 10px 30px #00000018}.nav{max-width:1180px;margin:auto;min-height:68px;padding:0 20px;display:flex;align-items:center;gap:16px}.brand{display:flex;gap:12px;align-items:center;font-weight:850;font-size:20px;margin-right:auto}.logo{width:38px;height:38px;border-radius:11px;background:linear-gradient(135deg,var(--primary),var(--accent));color:white;display:grid;place-items:center;font-weight:900;box-shadow:0 10px 24px #0002}.main{max-width:1180px;margin:0 auto;padding:30px 20px 64px}.toolbar{display:flex;justify-content:space-between;align-items:flex-end;gap:16px;margin-bottom:22px}.toolbar h1{font-size:32px;line-height:1.18;margin:0 0 7px}.muted{color:var(--muted)}.btn{border:1px solid var(--border);background:var(--card-solid);border-radius:8px;min-height:40px;padding:9px 14px;display:inline-flex;gap:8px;align-items:center;justify-content:center;color:var(--fg);text-decoration:none;box-shadow:0 2px 8px #00000008;transition:background .18s,border-color .18s,box-shadow .18s,transform .18s}.btn:hover{border-color:var(--primary);box-shadow:0 10px 24px #223a6a16;transform:translateY(-1px)}.btn.primary{background:var(--primary);border-color:var(--primary);color:white}.btn.primary:hover{background:var(--primary-hover)}.btn.danger{color:var(--danger);background:transparent}.theme-switch{display:flex;align-items:center;gap:2px;padding:3px;border:1px solid var(--header-border);border-radius:12px;background:var(--brand-tile);box-shadow:inset 0 1px 2px #00000010}.theme-option{width:32px;height:32px;min-height:32px;padding:7px;border:0;border-radius:9px;background:transparent;color:var(--header-muted);box-shadow:none}.theme-option svg{width:100%;height:100%}.theme-option:hover{background:var(--header-hover);color:var(--header-fg);transform:none;box-shadow:none}.theme-option.active{background:var(--card-solid);color:var(--primary);box-shadow:0 3px 10px #0002}.theme-switch.changed .theme-option.active{animation:theme-pop .24s ease}@keyframes theme-pop{50%{transform:scale(.82) rotate(-8deg)}}
.overview{display:grid;grid-template-columns:1.1fr .9fr;gap:18px;margin-bottom:18px}.metric-card,.rank-panel{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:18px;box-shadow:var(--shadow)}.metric-title,.rank-title{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:12px}.metric-title h2,.rank-title h2{margin:0;font-size:18px}.metric-value{font-size:30px;line-height:1.15;font-weight:900;overflow-wrap:anywhere}.metric-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:14px}.mini-metric{padding:11px;border:1px solid var(--border);border-radius:8px;background:var(--input)}.mini-metric b{display:block;font-size:18px}.rank-list{display:grid;gap:9px}.rank-item{display:grid;grid-template-columns:28px minmax(0,1fr) auto;gap:10px;align-items:center;padding:10px;border:1px solid var(--border);border-radius:8px;background:var(--input)}.rank-index{width:28px;height:28px;border-radius:8px;display:grid;place-items:center;background:var(--primary-soft);color:var(--primary);font-weight:850}.rank-name{font-weight:800;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.rank-meta{font-size:12px;color:var(--muted);margin-top:2px}.rank-days{font-weight:850;white-space:nowrap}.rank-days.danger{color:var(--danger)}.rank-days.warn{color:var(--warning)}.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(285px,1fr));gap:18px}.card{position:relative;overflow:hidden;background:var(--card);border:1px solid var(--border);border-radius:8px;padding:18px;text-align:left;min-height:198px;display:flex;flex-direction:column;gap:16px;box-shadow:var(--shadow);transition:transform .18s,border-color .18s,box-shadow .18s}.card:before{content:'';position:absolute;inset:0 0 auto;height:4px;background:var(--primary)}.card.warn:before{background:var(--warning)}.card.danger:before{background:var(--danger)}.card:hover{transform:translateY(-2px);border-color:var(--primary);box-shadow:var(--shadow-hover)}.card-top{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.domain{font-size:21px;line-height:1.28;font-weight:850;word-break:break-all}.tag{max-width:145px;border-radius:999px;background:var(--primary-soft);color:var(--primary);padding:5px 9px;font-size:12px;font-weight:750;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.meta{display:grid;gap:10px;margin-top:auto}.row{display:flex;justify-content:space-between;gap:14px;align-items:center}.label{color:var(--muted);font-size:13px}.value{font-weight:780;text-align:right;overflow-wrap:anywhere}.status{align-self:flex-start;border-radius:999px;padding:5px 10px;font-size:12px;font-weight:800;background:var(--success-soft);color:var(--success)}.status.warn{background:var(--warning-soft);color:var(--warning)}.status.danger{background:var(--danger-soft);color:var(--danger)}
.detail{max-width:780px}.settings-layout{display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,.9fr);gap:18px}.panel{background:var(--card);border:1px solid var(--border);border-radius:8px;padding:22px;box-shadow:var(--shadow)}.panel h2{font-size:20px;margin:0 0 17px}.form{display:grid;gap:14px}.field{display:grid;gap:7px}.field span{font-size:13px;color:var(--muted);font-weight:650}.check{display:flex;align-items:center;gap:9px;color:var(--fg);font-weight:700}.check input{width:auto}input,textarea,select{width:100%;border:1px solid var(--border);border-radius:8px;padding:11px 12px;background:var(--input);color:var(--fg);outline:none;transition:border-color .16s,box-shadow .16s}input:focus,textarea:focus,select:focus{border-color:var(--primary);box-shadow:0 0 0 4px var(--ring)}textarea{min-height:100px;resize:vertical}.preview-frame{width:100%;height:520px;border:1px solid var(--border);border-radius:8px;background:white}.empty{padding:38px;text-align:center;border:1px dashed var(--border);border-radius:8px;background:var(--card);color:var(--muted)}
.login{min-height:100vh;display:grid;place-items:center;padding:24px;background:linear-gradient(180deg,var(--bg-soft),var(--bg))}.login-box{position:relative;width:min(430px,100%);background:var(--card);border:1px solid var(--border);border-radius:8px;padding:26px;box-shadow:var(--shadow)}.login-box h1{margin:22px 0 16px;font-size:26px}.login .theme-switch{position:fixed;right:18px;top:18px;z-index:3;border-color:var(--border);background:var(--card-solid)}.login .theme-option{color:var(--muted)}.login .theme-option:hover{color:var(--fg);background:var(--primary-soft)}
@media(max-width:820px){.nav{padding:10px 14px;flex-wrap:wrap}.brand{font-size:18px}.theme-switch{order:3;margin-left:auto}.main{padding:22px 14px 44px}.toolbar{align-items:stretch;flex-direction:column}.toolbar h1{font-size:27px}.overview,.settings-layout{grid-template-columns:1fr}.metric-grid{grid-template-columns:1fr}.grid{grid-template-columns:1fr}.card{min-height:184px}.panel{padding:18px}.btn{width:100%}.top .btn{width:auto}}
body,.top,.card,.panel,input,textarea,select,.asset-band,.rank-section{transition:background-color .28s ease,border-color .28s ease,color .28s ease,box-shadow .28s ease}button:active,.btn:active{transform:translateY(1px) scale(.98)!important}.btn svg,.nav-btn svg{width:17px;height:17px;flex:0 0 auto}.nav{gap:9px}.nav-btn,.nav>#homeBtn,.nav>#settingsBtn,.nav>#logoutBtn{min-height:38px;padding:8px 12px;border:1px solid transparent;border-radius:8px;background:transparent;color:var(--header-muted);display:inline-flex;align-items:center;gap:7px;font:inherit;font-weight:700;box-shadow:none;transition:color .18s,background .18s,border-color .18s,transform .18s}.nav-btn:hover,.nav>#homeBtn:hover,.nav>#settingsBtn:hover,.nav>#logoutBtn:hover{color:var(--header-fg);background:var(--header-hover);border-color:transparent;box-shadow:none}.nav-btn.active,.nav>#homeBtn.active,.nav>#settingsBtn.active{color:var(--header-fg);background:var(--header-hover);border-color:var(--header-border)}.nav-divider{width:1px;height:26px;background:var(--header-border);margin:0 3px}.view-enter{animation:view-in .32s cubic-bezier(.2,.8,.2,1) both}@keyframes view-in{from{opacity:0;transform:translateY(9px)}to{opacity:1;transform:none}}
.toolbar{margin-bottom:24px}.toolbar h1{letter-spacing:0}.page-kicker{display:flex;align-items:center;gap:8px;color:var(--primary);font-size:12px;font-weight:850;text-transform:uppercase;margin-bottom:7px}.page-kicker:before{content:'';width:18px;height:2px;background:var(--primary)}.overview{grid-template-columns:minmax(0,1.15fr) minmax(320px,.85fr);gap:0;margin:0 0 30px;border-block:1px solid var(--border);background:transparent}.asset-band,.rank-section{padding:24px 0;background:transparent}.asset-band{padding-right:28px}.rank-section{padding-left:28px;border-left:1px solid var(--border)}.metric-title,.rank-title{margin-bottom:16px}.metric-title h2,.rank-title h2{font-size:15px;color:var(--muted)}.metric-value{font-size:38px}.metric-grid{display:flex;gap:0;margin-top:22px}.mini-metric{flex:1;padding:0 18px;border:0;border-left:1px solid var(--border);border-radius:0;background:transparent}.mini-metric:first-child{padding-left:0;border-left:0}.mini-metric b{font-size:21px;margin-top:4px}.rank-list{gap:0}.rank-item{padding:10px 0;border:0;border-top:1px solid var(--border);border-radius:0;background:transparent;transition:padding .18s,background .18s}.rank-item:hover{padding-left:8px;padding-right:8px;background:var(--input)}.rank-item:first-child{border-top:0}.rank-index{border-radius:7px}.section-bar{display:flex;align-items:end;justify-content:space-between;gap:12px;margin:0 0 14px}.section-bar h2{margin:0;font-size:18px}.section-count{color:var(--muted);font-size:13px}.grid{gap:16px}.card{min-height:210px;animation:card-in .36s cubic-bezier(.2,.8,.2,1) both;animation-delay:calc(var(--i,0)*45ms)}@keyframes card-in{from{opacity:0;transform:translateY(12px) scale(.985)}to{opacity:1;transform:none}}.card:hover{transform:translateY(-4px)}.card .status{transition:transform .18s}.card:hover .status{transform:translateY(-1px)}.card>*:not(.registrar-mark){position:relative;z-index:1}.card .meta .row:last-child{padding-right:52px}.tag-line{display:flex;align-items:center;gap:7px;flex-wrap:wrap}.auto-badge{border-radius:999px;padding:5px 9px;background:var(--success-soft);color:var(--success);font-size:12px;font-weight:800}.registrar-mark{position:absolute;right:12px;bottom:10px;z-index:0;width:44px;height:44px;display:grid;place-items:center;border-radius:14px;background:var(--registrar-color,#64748b);color:white;font-size:19px;font-weight:900;opacity:.48;box-shadow:inset 0 1px 0 #ffffff70;pointer-events:none}.registrar-mark.registrar-cloudflare{--registrar-color:#f48120}.registrar-mark.registrar-namecheap{--registrar-color:#de3723}.registrar-mark.registrar-godaddy{--registrar-color:#00a4a6}.registrar-mark.registrar-aliyun{--registrar-color:#ff6a00}.registrar-mark.registrar-tencent{--registrar-color:#006eff}.registrar-mark.registrar-namesilo{--registrar-color:#2667b1}.registrar-mark.registrar-porkbun{--registrar-color:#ef7878}.registrar-mark.registrar-dynadot{--registrar-color:#278fd2}
.detail{max-width:900px;margin:auto}.detail .panel{padding:26px}.detail-actions{display:flex;gap:9px;flex-wrap:wrap}.settings-layout{align-items:start}.settings-panel{padding:0;overflow:hidden}.settings-tabs{display:grid;grid-template-columns:repeat(3,1fr);border-bottom:1px solid var(--border);background:var(--input)}.settings-tab{position:relative;min-height:48px;border:0;border-right:1px solid var(--border);background:transparent;color:var(--muted);font:inherit;font-weight:750;cursor:pointer}.settings-tab:last-child{border-right:0}.settings-tab.active{color:var(--primary);background:var(--card-solid)}.settings-tab.active:after{content:'';position:absolute;left:22%;right:22%;bottom:-1px;height:2px;background:var(--primary)}.settings-pane{padding:22px;animation:view-in .24s both}.settings-pane[hidden]{display:none}.form-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.form-grid .wide{grid-column:1/-1}.switch-row{display:flex;align-items:center;justify-content:space-between;gap:18px;padding:13px 0;border-bottom:1px solid var(--border);font-weight:750}.switch-copy{display:grid;gap:4px}.switch-copy b{font-size:14px}.switch-copy small{color:var(--muted);font-size:12px;font-weight:500;line-height:1.5}.switch-row input{position:absolute;width:1px;height:1px;margin:0;opacity:0;pointer-events:none}.switch-track{position:relative;width:44px;height:24px;flex:0 0 auto;border-radius:99px;background:var(--border);transition:background .2s}.switch-track:after{content:'';position:absolute;left:3px;top:3px;width:18px;height:18px;border-radius:50%;background:white;box-shadow:0 2px 7px #0003;transition:transform .22s cubic-bezier(.2,.8,.2,1)}.switch-row input:checked+.switch-track{background:var(--primary)}.switch-row input:checked+.switch-track:after{transform:translateX(20px)}.switch-row:focus-within .switch-track{box-shadow:0 0 0 4px var(--ring)}.preview-panel{position:sticky;top:88px}.preview-head{display:flex;align-items:center;justify-content:space-between;gap:10px;margin-bottom:14px}.preview-head h2{margin:0}.preview-status{font-size:12px;color:var(--muted)}.preview-frame{height:580px;transition:opacity .2s}.preview-frame.loading{opacity:.35}.skeleton{position:relative;overflow:hidden;background:var(--input);border-radius:8px}.skeleton:after{content:'';position:absolute;inset:0;transform:translateX(-100%);background:linear-gradient(90deg,transparent,#ffffff18,transparent);animation:shimmer 1.2s infinite}@keyframes shimmer{to{transform:translateX(100%)}}.skeleton-card{height:210px;border:1px solid var(--border)}
.toast-stack{position:fixed;right:18px;top:86px;z-index:50;display:grid;gap:10px;width:min(360px,calc(100vw - 36px));pointer-events:none}.toast{display:grid;grid-template-columns:24px minmax(0,1fr);gap:10px;align-items:center;padding:13px 14px;border:1px solid var(--border);border-left:3px solid var(--success);border-radius:8px;background:var(--card-solid);color:var(--fg);box-shadow:0 18px 45px #0004;animation:toast-in .28s cubic-bezier(.2,.8,.2,1) both;pointer-events:auto}.toast.error{border-left-color:var(--danger)}.toast.out{animation:toast-out .2s ease both}@keyframes toast-in{from{opacity:0;transform:translateX(18px)}to{opacity:1;transform:none}}@keyframes toast-out{to{opacity:0;transform:translateX(18px)}}.toast-icon{width:24px;height:24px;display:grid;place-items:center;border-radius:50%;background:var(--success-soft);color:var(--success);font-weight:900}.toast.error .toast-icon{background:var(--danger-soft);color:var(--danger)}.btn.busy{pointer-events:none;opacity:.78}.btn.busy svg{animation:spin .7s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}
.skeleton-band{height:180px;margin:18px;border:1px solid var(--border)}
.login{padding:42px 22px;background:var(--bg)}.login-layout{position:relative;width:min(1000px,100%);min-height:620px;display:grid;grid-template-columns:minmax(0,1.08fr) minmax(360px,.82fr);overflow:hidden;border:1px solid var(--border);border-radius:8px;background:var(--card-solid);box-shadow:0 30px 90px #00000035;animation:login-rise .5s cubic-bezier(.2,.8,.2,1) both}.login-brand{position:relative;overflow:hidden;padding:54px;background:#21447f;color:white;display:flex;flex-direction:column;justify-content:center}.login-brand:after{content:'';position:absolute;width:330px;height:330px;border:1px solid #ffffff25;border-radius:50%;right:-185px;top:-140px;box-shadow:0 0 0 68px #ffffff0a,0 0 0 136px #ffffff08}.login-brand-mark{position:relative;z-index:1;width:54px;height:54px;display:grid;place-items:center;margin-bottom:34px;padding:13px;border:1px solid #ffffff38;border-radius:8px;background:#ffffff14}.login-brand-mark svg{width:100%;height:100%}.login-eyebrow{position:relative;z-index:1;color:#c7d7ff;font-size:12px;font-weight:850;text-transform:uppercase}.login-brand h1{position:relative;z-index:1;max-width:450px;margin:11px 0 18px;font-size:46px;line-height:1.06}.login-brand>p{position:relative;z-index:1;max-width:460px;margin:0;color:#dfebff;font-size:16px;line-height:1.7}.login-points{position:relative;z-index:1;display:grid;gap:14px;margin-top:40px}.login-point{display:grid;grid-template-columns:32px minmax(0,1fr);gap:11px;align-items:center;color:#edf4ff}.login-point>span{width:32px;height:32px;display:grid;place-items:center;border:1px solid #ffffff2f;border-radius:8px;background:#ffffff13;font-size:11px;font-weight:850}.login-point b{display:block;font-size:14px}.login-point small{display:block;color:#c7d7f4;margin-top:1px}.login-panel{padding:48px 44px;display:flex;flex-direction:column;justify-content:center;min-width:0}.login-panel h2{margin:0 0 7px;font-size:28px}.login-panel>.muted{margin:0 0 24px}.login-panel .field{margin-top:14px}.login-submit{width:100%;margin-top:24px}.login-message{margin-top:14px;padding:10px 12px;border:1px solid var(--danger);border-radius:8px;background:var(--danger-soft);color:var(--danger);font-size:13px;font-weight:700}.login-message:empty{display:none}.login-transport{display:flex;align-items:center;gap:8px;margin-top:20px;color:var(--muted);font-size:12px}.login-transport-dot{width:8px;height:8px;border-radius:50%;background:var(--success);box-shadow:0 0 0 4px var(--success-soft)}.login-transport.insecure .login-transport-dot{background:var(--warning);box-shadow:0 0 0 4px var(--warning-soft)}@keyframes login-rise{from{opacity:0;transform:translateY(16px) scale(.99)}to{opacity:1;transform:none}}
.pane-actions{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-top:20px;padding-top:18px;border-top:1px solid var(--border)}.pane-actions b,.pane-actions span{display:block}.pane-actions b{font-size:14px}.pane-actions span{margin-top:3px;color:var(--muted);font-size:12px}.pane-actions .btn{flex:0 0 auto}
@media(max-width:820px){.nav{display:grid;grid-template-columns:minmax(0,1fr) auto auto;gap:7px}.brand{grid-column:1;margin-right:0}.nav-btn,.nav>#homeBtn,.nav>#settingsBtn,.nav>#logoutBtn{font-size:0;width:40px;padding:8px;justify-content:center}.nav-btn svg{width:19px;height:19px}.nav-divider{display:none}.theme-switch{grid-column:1/3;grid-row:2;justify-self:start;margin:0;order:initial}.nav>#logoutBtn{grid-column:3;grid-row:2}.overview{grid-template-columns:1fr}.asset-band{padding:20px 0}.rank-section{padding:20px 0;border-left:0;border-top:1px solid var(--border)}.metric-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))}.mini-metric{padding:0 10px}.settings-layout{grid-template-columns:1fr}.preview-panel{position:static}.preview-frame{height:430px}.form-grid{grid-template-columns:1fr}.form-grid .wide{grid-column:auto}.detail-actions{display:grid;grid-template-columns:repeat(2,minmax(0,1fr))}.detail-actions .btn{width:100%}}
@media(max-width:820px){.nav>#homeBtn,.nav>#settingsBtn,.nav>#logoutBtn{width:auto;font-size:14px}}
@media(max-width:760px){.login{place-items:start center;padding:76px 14px 24px}.login-layout{min-height:0;grid-template-columns:1fr}.login-brand{padding:28px 25px}.login-brand-mark{width:46px;height:46px;margin-bottom:20px}.login-brand h1{font-size:31px;margin:9px 0 11px}.login-brand>p{font-size:14px}.login-points{display:none}.login-panel{padding:30px 25px 34px}.pane-actions{align-items:stretch;flex-direction:column}.pane-actions .btn{width:100%}}

/* Liquid glass theme */
:root{--glass:#ffffffa8;--glass-strong:#ffffffe0;--glass-border:#ffffffc9;--glass-highlight:#ffffffeb;--glass-shadow:0 18px 48px #47627c1c,0 3px 12px #47627c12;--glass-shadow-hover:0 24px 64px #3e57752b,0 6px 18px #3e57751a;--header:#ffffffa3;--header-fg:#1c2735;--header-muted:#5f6c7c;--header-border:#ffffffb8;--header-hover:#ffffffa8;--brand-tile:#ffffff70;--card:#ffffff9c;--card-solid:#ffffffe8;--input:#ffffff8f;--border:#8799ad4a;--shadow:var(--glass-shadow);--shadow-hover:var(--glass-shadow-hover)}
html[data-theme=dark]{--glass:#171b22b8;--glass-strong:#242a33e8;--glass-border:#ffffff24;--glass-highlight:#ffffff1f;--glass-shadow:0 22px 58px #00000059,0 4px 16px #00000038;--glass-shadow-hover:0 28px 72px #00000073,0 8px 22px #00000045;--header:#12161cb5;--header-fg:#f4f7fb;--header-muted:#aeb8c6;--header-border:#ffffff20;--header-hover:#ffffff14;--brand-tile:#ffffff0e;--card:#191e25b8;--card-solid:#242a33ed;--input:#ffffff0d;--border:#ffffff20;--shadow:var(--glass-shadow);--shadow-hover:var(--glass-shadow-hover)}
@media(prefers-color-scheme:dark){html[data-theme=auto]{--glass:#171b22b8;--glass-strong:#242a33e8;--glass-border:#ffffff24;--glass-highlight:#ffffff1f;--glass-shadow:0 22px 58px #00000059,0 4px 16px #00000038;--glass-shadow-hover:0 28px 72px #00000073,0 8px 22px #00000045;--header:#12161cb5;--header-fg:#f4f7fb;--header-muted:#aeb8c6;--header-border:#ffffff20;--header-hover:#ffffff14;--brand-tile:#ffffff0e;--card:#191e25b8;--card-solid:#242a33ed;--input:#ffffff0d;--border:#ffffff20;--shadow:var(--glass-shadow);--shadow-hover:var(--glass-shadow-hover)}}
body{background:linear-gradient(135deg,#e9f0fa 0%,#eef8f3 48%,#f5eff8 100%);background-attachment:fixed}html[data-theme=dark] body{background:linear-gradient(135deg,#0d141c 0%,#101c19 50%,#17131b 100%)}@media(prefers-color-scheme:dark){html[data-theme=auto] body{background:linear-gradient(135deg,#0d141c 0%,#101c19 50%,#17131b 100%)}}
.top{top:10px;margin:10px 14px 0;border:1px solid var(--glass-border);border-radius:22px;background:var(--header);box-shadow:inset 0 1px 0 var(--glass-highlight),0 14px 38px #26394d1d;-webkit-backdrop-filter:saturate(175%) blur(26px);backdrop-filter:saturate(175%) blur(26px)}.nav{min-height:64px}.logo{border-radius:15px;box-shadow:inset 0 1px 0 #ffffff78,0 9px 22px #245ad83b}.nav-btn,.nav>#homeBtn,.nav>#settingsBtn,.nav>#logoutBtn{border-radius:14px}.nav-btn.active,.nav>#homeBtn.active,.nav>#settingsBtn.active{background:var(--header-hover);border-color:var(--glass-border);box-shadow:inset 0 1px 0 var(--glass-highlight)}
.theme-switch{border-color:var(--glass-border);border-radius:18px;background:var(--brand-tile);box-shadow:inset 0 1px 0 var(--glass-highlight),0 7px 20px #00000014;-webkit-backdrop-filter:blur(18px);backdrop-filter:blur(18px)}.theme-option{border-radius:14px}.theme-option.active{background:var(--glass-strong);box-shadow:inset 0 1px 0 var(--glass-highlight),0 4px 12px #0000001f}
.card,.panel,.toast,.login-layout{border-color:var(--glass-border);background:var(--glass);box-shadow:inset 0 1px 0 var(--glass-highlight),var(--glass-shadow);-webkit-backdrop-filter:saturate(155%) blur(24px);backdrop-filter:saturate(155%) blur(24px)}.card{border-radius:22px}.panel{border-radius:22px}.card:hover{border-color:#ffffffdc;box-shadow:inset 0 1px 0 #fff,var(--glass-shadow-hover);transform:translateY(-5px)}html[data-theme=dark] .card:hover{border-color:#ffffff38}@media(prefers-color-scheme:dark){html[data-theme=auto] .card:hover{border-color:#ffffff38}}.card:before{height:3px}.tag,.status{box-shadow:inset 0 1px 0 #ffffff38}
.btn{border-color:var(--glass-border);border-radius:14px;background:var(--glass-strong);box-shadow:inset 0 1px 0 var(--glass-highlight),0 7px 20px #324b6514;-webkit-backdrop-filter:blur(16px);backdrop-filter:blur(16px)}.btn:hover{box-shadow:inset 0 1px 0 var(--glass-highlight),0 12px 28px #324b6524}.btn.primary{box-shadow:inset 0 1px 0 #ffffff57,0 10px 26px #2563eb3d}.btn.danger{background:color-mix(in srgb,var(--danger-soft) 58%,transparent)}
input,textarea,select{border-color:var(--glass-border);border-radius:14px;background:var(--input);box-shadow:inset 0 1px 0 var(--glass-highlight);-webkit-backdrop-filter:blur(14px);backdrop-filter:blur(14px)}input:hover,textarea:hover,select:hover{border-color:color-mix(in srgb,var(--primary) 40%,var(--glass-border))}.preview-frame,.empty,.skeleton{border-radius:18px}.settings-panel{border-radius:22px}.settings-tabs{background:#ffffff24}.settings-tab.active{background:var(--glass-strong)}.settings-tab:first-child{border-top-left-radius:21px}.settings-tab:last-child{border-top-right-radius:21px}.rank-item:hover{border-radius:13px;background:var(--glass)}.rank-index{border-radius:10px}.toast{border-radius:17px;background:var(--glass-strong)}
.login{background:transparent}.login-layout{border-radius:30px;background:var(--glass)}.login-brand{background:linear-gradient(145deg,#2456a5df,#21727ad9);-webkit-backdrop-filter:saturate(160%) blur(20px);backdrop-filter:saturate(160%) blur(20px)}.login-brand-mark,.login-point>span{border-radius:14px;box-shadow:inset 0 1px 0 #ffffff55}.login-panel{background:linear-gradient(145deg,#ffffff16,transparent)}
@media(max-width:820px){body{background-attachment:scroll}.top{top:7px;margin:7px 8px 0;border-radius:19px}.nav{padding:9px 11px}.main{padding:24px 14px 48px}.toolbar{gap:14px}.overview{margin-bottom:24px}.asset-band{padding-top:18px}.metric-value{font-size:34px}.card,.panel,.settings-panel{border-radius:18px}.card{min-height:190px;padding:17px}.settings-tab:first-child{border-top-left-radius:17px}.settings-tab:last-child{border-top-right-radius:17px}.preview-frame{height:400px;border-radius:15px}.toast-stack{top:124px;right:12px;width:calc(100vw - 24px)}.login-layout{border-radius:22px}.login-brand{border-radius:21px 21px 0 0}.login-panel{border-radius:0 0 21px 21px}}
@media(prefers-reduced-motion:reduce){*,*:before,*:after{animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
</style>
</head>
<body>
<div id="login" class="login hidden">
  <div class="theme-switch" role="group" aria-label="主题模式">
    <button type="button" class="theme-option" data-theme-value="auto" aria-label="跟随系统" title="跟随系统"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg></button>
    <button type="button" class="theme-option" data-theme-value="light" aria-label="日间模式" title="日间模式"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg></button>
    <button type="button" class="theme-option" data-theme-value="dark" aria-label="夜间模式" title="夜间模式"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z"/></svg></button>
  </div>
  <main class="login-layout"><section class="login-brand"><div class="login-brand-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M2 12h20M12 2a15.3 15.3 0 0 1 0 20M12 2a15.3 15.3 0 0 0 0 20"/></svg></div><span class="login-eyebrow">Domain Portfolio</span><h1>域名资产管理器</h1><p>集中掌握名下域名、续费成本与到期时间，让每一项数字资产都清晰可见。</p><div class="login-points"><div class="login-point"><span>DAY</span><div><b>到期时间</b><small>按续费紧急程度排列域名</small></div></div><div class="login-point"><span>¥</span><div><b>资产价值</b><small>根据年费与剩余时间自动估算</small></div></div><div class="login-point"><span>↗</span><div><b>续费入口</b><small>快速前往对应注册商完成续费</small></div></div></div></section><form class="login-panel" id="loginForm"><h2>欢迎回来</h2><p class="muted">登录后管理你的域名资产</p><label class="field"><span>用户名</span><input id="username" required autocomplete="username" value="admin" placeholder="请输入管理用户名"></label><label class="field"><span>密码</span><input id="password" required type="password" autocomplete="current-password" placeholder="请输入管理密码"></label><button class="btn primary login-submit" type="submit">登录面板</button><div id="loginMsg" class="login-message" role="alert"></div><div class="login-transport" id="loginTransport"><span class="login-transport-dot"></span><span id="loginTransportText">正在检查连接状态</span></div></form></main>
</div>
<div id="app" class="shell hidden">
  <header class="top"><nav class="nav"><div class="brand"><span class="logo">域</span><span>域名管理器</span></div><button class="btn" id="homeBtn">域名</button><button class="btn" id="settingsBtn">设置</button><div class="theme-switch" role="group" aria-label="主题模式"><button type="button" class="theme-option" data-theme-value="auto" aria-label="跟随系统" title="跟随系统"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect width="20" height="14" x="2" y="3" rx="2"/><line x1="8" x2="16" y1="21" y2="21"/><line x1="12" x2="12" y1="17" y2="21"/></svg></button><button type="button" class="theme-option" data-theme-value="light" aria-label="日间模式" title="日间模式"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.42 1.42M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg></button><button type="button" class="theme-option" data-theme-value="dark" aria-label="夜间模式" title="夜间模式"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 3a6 6 0 0 0 9 9 9 0 1 1-9-9Z"/></svg></button></div><button class="btn" id="logoutBtn" title="退出登录">退出</button></nav></header>
  <main class="main"><div id="listView"><div class="toolbar"><div><h1>我的域名</h1><div class="muted">集中查看域名资产、到期时间和续费入口。</div></div><button class="btn primary" id="addBtn">新增域名</button></div><div id="overview" class="overview"></div><div id="cards" class="grid"></div></div><div id="detailView" class="hidden"></div><div id="settingsView" class="hidden"></div></main>
</div>
<script>
const $=s=>document.querySelector(s);let domains=[],current=null,settings=null,settingsTab='rules';
const ICONS={spinner:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12a9 9 0 1 1-6.2-8.56"/></svg>',check:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m5 12 4 4L19 6"/></svg>',back:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m15 18-6-6 6-6"/></svg>',send:'<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/></svg>'};
const toastStack=document.createElement('div');toastStack.className='toast-stack';toastStack.setAttribute('aria-live','polite');document.body.appendChild(toastStack);
function toast(message,type='success'){const el=document.createElement('div');el.className=`toast ${type==='error'?'error':''}`;el.innerHTML=`<span class="toast-icon">${type==='error'?'!':'✓'}</span><span>${escapeHtml(message)}</span>`;toastStack.appendChild(el);setTimeout(()=>{el.classList.add('out');setTimeout(()=>el.remove(),220)},2800)}
function setBusy(button,busy,label){if(!button)return;if(busy){button.dataset.label=button.innerHTML;button.classList.add('busy');button.disabled=true;button.innerHTML=`${ICONS.spinner}${label||'处理中'}`}else{button.classList.remove('busy');button.disabled=false;button.innerHTML=button.dataset.label||label||button.innerHTML}}
function activateNav(view){homeBtn.classList.toggle('active',view==='home');settingsBtn.classList.toggle('active',view==='settings')}
function enterView(view){window.scrollTo({top:0,behavior:'auto'});view.classList.remove('view-enter');void view.offsetWidth;view.classList.add('view-enter')}
const themeButtons=[...document.querySelectorAll('[data-theme-value]')];
function setTheme(t,feedback=false){document.documentElement.dataset.theme=t;localStorage.setItem('dm_theme',t);themeButtons.forEach(b=>{const active=b.dataset.themeValue===t;b.classList.toggle('active',active);b.setAttribute('aria-pressed',String(active))});if(feedback){document.querySelectorAll('.theme-switch').forEach(sw=>{sw.classList.remove('changed');void sw.offsetWidth;sw.classList.add('changed');setTimeout(()=>sw.classList.remove('changed'),260)})}}
themeButtons.forEach(b=>b.onclick=()=>setTheme(b.dataset.themeValue,true));setTheme(document.documentElement.dataset.theme||'auto');
async function api(path,opts={}){const r=await fetch(path,{headers:{'Content-Type':'application/json'},...opts});if(r.status===401){showLogin();throw new Error('请先登录')}const t=await r.text();const data=t?JSON.parse(t):{};if(!r.ok)throw new Error(data.error||'请求失败');return data}
function showLogin(){login.classList.remove('hidden');app.classList.add('hidden')}function showApp(){login.classList.add('hidden');app.classList.remove('hidden')}
function daysLeft(d){if(!d)return '';return Math.ceil((new Date(d+'T00:00:00')-new Date())/86400000)}
function expiryText(d){const n=daysLeft(d);if(n==='')return '未填写';if(n<0)return `已过期 ${Math.abs(n)} 天`;if(n<=30)return `${d}（还剩 ${n} 天）`;return d}
function statusInfo(d){const n=daysLeft(d);if(n==='')return ['unknown','未填写到期'];if(n<0)return ['danger','已过期'];if(n<=30)return ['danger','马上续费'];if(n<=90)return ['warn','需要关注'];return ['ok','状态正常']}
function priceInfo(text){const raw=String(text||'');const match=raw.replace(/,/g,'').match(/\d+(?:\.\d+)?/);if(!match)return null;let symbol='';if(/usd|\$/i.test(raw))symbol='$';else if(/cny|rmb|¥|元/i.test(raw))symbol='¥';return {amount:Number(match[0]),symbol}}
function remainingValue(d){const price=priceInfo(d.renewal_price),days=daysLeft(d.expires_at);if(!price||days===''||days<=0)return null;return {amount:price.amount*days/365,symbol:price.symbol}}
function money(value,symbol=''){const fixed=value>=100?value.toFixed(0):value.toFixed(2);return symbol?`${symbol}${fixed}`:fixed}
function totalRemaining(){const totals={};for(const d of domains){const v=remainingValue(d);if(v)totals[v.symbol]=(totals[v.symbol]||0)+v.amount}const parts=Object.entries(totals).map(([symbol,total])=>money(total,symbol));return parts.length?parts.join(' + '):'暂无可估算价值'}
function renderOverview(){const expiring=domains.filter(d=>{const n=daysLeft(d.expires_at);return n!==''&&n>=0&&n<=90}).length;const expired=domains.filter(d=>{const n=daysLeft(d.expires_at);return n!==''&&n<0}).length;overview.innerHTML=`<section class="asset-band"><div class="metric-title"><h2>当前域名资产剩余价值</h2><span class="muted">按年费和剩余天数估算</span></div><div class="metric-value">${escapeHtml(totalRemaining())}</div><div class="metric-grid"><div class="mini-metric"><span class="label">域名总数</span><b>${domains.length}</b></div><div class="mini-metric"><span class="label">90 天内续费</span><b>${expiring}</b></div><div class="mini-metric"><span class="label">已过期</span><b>${expired}</b></div></div></section><section class="rank-section"><div class="rank-title"><h2>续费排名</h2><span class="muted">从近到远</span></div><div class="rank-list">${renderRank()}</div></section>`}
function renderRank(){const sorted=[...domains].sort((a,b)=>{const da=daysLeft(a.expires_at),db=daysLeft(b.expires_at);return (da===''?Infinity:da)-(db===''?Infinity:db)}).slice(0,8);if(!sorted.length)return '<div class="empty">暂无域名</div>';return sorted.map((d,i)=>{const n=daysLeft(d.expires_at),cls=n!==''&&n<=30?'danger':n!==''&&n<=90?'warn':'';const dayText=n===''?'未填写':n<0?`过期 ${Math.abs(n)} 天`:`${n} 天`;return `<div class="rank-item"><span class="rank-index">${i+1}</span><div><div class="rank-name">${escapeHtml(d.name)}</div><div class="rank-meta">${escapeHtml(d.expires_at||'未填写到期时间')} · ${escapeHtml(d.renewal_price||'未填写续费价')}</div></div><strong class="rank-days ${cls}">${dayText}</strong></div>`}).join('')}
async function loadDomains(){showApp();showList(false);overview.innerHTML='<div class="skeleton skeleton-band"></div><div class="skeleton skeleton-band"></div>';cards.innerHTML='<div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div>';try{const data=await api('/api/domains');domains=data.domains;renderList();enterView(listView)}catch(e){toast(e.message,'error')}}
function showList(animate=true){settingsView.classList.add('hidden');detailView.classList.add('hidden');listView.classList.remove('hidden');activateNav('home');if(animate)enterView(listView)}
function registrarMark(registrar){const raw=String(registrar||'').trim(),name=raw.toLowerCase();const known=[['cloudflare','cloudflare','☁'],['namecheap','namecheap','N'],['godaddy','godaddy','G'],['阿里','aliyun','A'],['aliyun','aliyun','A'],['alibaba','aliyun','A'],['腾讯','tencent','T'],['tencent','tencent','T'],['namesilo','namesilo','NS'],['porkbun','porkbun','P'],['dynadot','dynadot','D']];for(const [key,kind,label] of known)if(name.includes(key))return{kind,label};return{kind:'generic',label:raw?[...raw][0].toUpperCase():'◎'}}
function renderList(){showList(false);renderOverview();let bar=document.getElementById('sectionBar');if(!bar){bar=document.createElement('div');bar.id='sectionBar';bar.className='section-bar';cards.before(bar)}bar.innerHTML=`<h2>域名资产</h2><span class="section-count">${domains.length} 个域名</span>`;cards.innerHTML='';if(!domains.length){cards.innerHTML='<div class="empty">还没有域名，点右上角新增。</div>';return}domains.forEach((d,i)=>{const [state,label]=statusInfo(d.expires_at);const remaining=remainingValue(d),mark=registrarMark(d.registrar);const b=document.createElement('button');b.className=`card ${state==='danger'?'danger':state==='warn'?'warn':''}`;b.style.setProperty('--i',i);b.innerHTML=`<div class="registrar-mark registrar-${mark.kind}" aria-hidden="true">${escapeHtml(mark.label)}</div><div class="card-top"><span class="domain">${escapeHtml(d.name)}</span><span class="status ${state==='danger'?'danger':state==='warn'?'warn':''}">${label}</span></div><div class="tag-line"><span class="tag">${escapeHtml(d.registrar||'未填写注册商')}</span>${d.auto_renew?'<span class="auto-badge">自动续费</span>':''}</div><div class="meta"><div class="row"><span class="label">到期时间</span><strong class="value">${escapeHtml(expiryText(d.expires_at))}</strong></div><div class="row"><span class="label">续费价格</span><strong class="value">${escapeHtml(d.renewal_price||'未填写')}</strong></div><div class="row"><span class="label">剩余价值</span><strong class="value">${escapeHtml(remaining?money(remaining.amount,remaining.symbol):'无法估算')}</strong></div></div>`;b.onclick=()=>openDetail(d.id);cards.appendChild(b)})}
function blank(){return{id:null,name:'',expires_at:'',registrar:'',renewal_price:'',renewal_url:'',auto_renew:false,notes:''}}
function openDetail(id){current=id?domains.find(d=>d.id===id):blank();settingsView.classList.add('hidden');listView.classList.add('hidden');detailView.classList.remove('hidden');activateNav('home');renderDetail();enterView(detailView)}
function renderDetail(){const d=current;detailView.innerHTML=`<div class="toolbar"><div><div class="page-kicker">${d.id?'Asset detail':'New asset'}</div><h1>${d.id?escapeHtml(d.name):'新增域名'}</h1></div><div class="detail-actions"><button class="btn" id="backBtn">${ICONS.back}返回</button><button class="btn danger ${d.id?'':'hidden'}" id="deleteBtn">删除</button><a class="btn ${d.renewal_url?'':'hidden'}" href="${escapeAttr(d.renewal_url)}" target="_blank" rel="noopener">去续费</a><button class="btn primary" id="saveBtn">保存</button></div></div><div class="detail"><section class="panel"><h2>域名信息</h2><div class="form form-grid"><label class="field"><span>域名</span><input id="fName" value="${escapeAttr(d.name)}" placeholder="example.com"></label><label class="field"><span>到期时间</span><input id="fExpires" type="date" value="${escapeAttr(d.expires_at||'')}"></label><label class="field"><span>注册商</span><input id="fRegistrar" value="${escapeAttr(d.registrar||'')}" placeholder="阿里云 / Cloudflare / Namecheap"></label><label class="field"><span>续费价格</span><input id="fPrice" value="${escapeAttr(d.renewal_price||'')}" placeholder="例如 69 元 / 年"></label><label class="field wide"><span>续费链接</span><input id="fUrl" value="${escapeAttr(d.renewal_url||'')}" placeholder="https://..."></label><label class="switch-row wide"><span class="switch-copy"><b>注册商已开启自动续费</b><small>到期后面板自动顺延 1 年，不会代替注册商扣费；临近到期仍会照常提醒。</small></span><input id="fAutoRenew" type="checkbox" ${d.auto_renew?'checked':''}><span class="switch-track"></span></label><label class="field wide"><span>备注</span><textarea id="fNotes">${escapeHtml(d.notes||'')}</textarea></label></div></section></div>`;backBtn.onclick=loadDomains;saveBtn.onclick=saveCurrent;if(d.id)deleteBtn.onclick=deleteCurrent}
function collect(){return{name:fName.value,expires_at:fExpires.value,registrar:fRegistrar.value,renewal_price:fPrice.value,renewal_url:fUrl.value,auto_renew:fAutoRenew.checked,notes:fNotes.value}}
async function openSettings(){showApp();listView.classList.add('hidden');detailView.classList.add('hidden');settingsView.classList.remove('hidden');activateNav('settings');settingsView.innerHTML='<div class="skeleton skeleton-band"></div><div class="settings-layout"><div class="skeleton skeleton-card"></div><div class="skeleton skeleton-card"></div></div>';try{const data=await api('/api/settings');settings=data.settings;renderSettings();addEmailTestButton();enterView(settingsView);await loadEmailPreview()}catch(e){toast(e.message,'error')}}
function renderSettings(){const s=settings;settingsView.innerHTML=`<div class="toolbar"><div><div class="page-kicker">Notifications</div><h1>通知设置</h1><div class="muted">管理域名到期提醒渠道。</div></div><button class="btn primary" id="saveSettingsBtn">保存设置</button></div><div class="settings-layout"><section class="panel settings-panel"><div class="settings-tabs" role="tablist"><button class="settings-tab" data-settings-tab="rules">提醒规则</button><button class="settings-tab" data-settings-tab="telegram">Telegram</button><button class="settings-tab" data-settings-tab="email">邮件</button></div><div class="settings-pane" data-settings-pane="rules"><label class="switch-row"><span>启用到期提醒</span><input id="nEnabled" type="checkbox" ${s.notify_enabled?'checked':''}><span class="switch-track"></span></label><div class="form" style="margin-top:18px"><label class="field"><span>提前提醒天数</span><input id="nDays" value="${escapeAttr(s.reminder_days||'30,7,1')}" placeholder="例如 30,7,1"></label></div></div><div class="settings-pane" data-settings-pane="telegram" hidden><label class="switch-row"><span>启用 TG 机器人通知</span><input id="tgEnabled" type="checkbox" ${s.telegram_enabled?'checked':''}><span class="switch-track"></span></label><div class="form" style="margin-top:18px"><label class="field"><span>Bot Token${s.telegram_bot_configured?'（已保存，留空不修改）':''}</span><input id="tgToken" type="password" autocomplete="new-password" placeholder="123456:ABC..."></label><label class="field"><span>Chat ID</span><input id="tgChat" value="${escapeAttr(s.telegram_chat_id||'')}" placeholder="个人或群组 Chat ID"></label></div></div><div class="settings-pane" data-settings-pane="email" hidden><label class="switch-row"><span>启用邮件通知</span><input id="mailEnabled" type="checkbox" ${s.email_enabled?'checked':''}><span class="switch-track"></span></label><div class="form-grid" style="margin-top:18px"><label class="field wide"><span>SMTP 主机</span><input id="smtpHost" value="${escapeAttr(s.smtp_host||'')}" placeholder="smtp.example.com"></label><label class="field"><span>SMTP 端口</span><input id="smtpPort" type="number" min="1" max="65535" value="${escapeAttr(s.smtp_port||465)}"></label><label class="field"><span>连接方式</span><select id="smtpSecurity"><option value="ssl" ${s.smtp_security==='ssl'?'selected':''}>SSL</option><option value="starttls" ${s.smtp_security==='starttls'?'selected':''}>STARTTLS</option><option value="none" ${s.smtp_security==='none'?'selected':''}>不加密</option></select></label><label class="field wide"><span>SMTP 用户名</span><input id="smtpUser" value="${escapeAttr(s.smtp_username||'')}" autocomplete="username"></label><label class="field wide"><span>SMTP 密码${s.smtp_password_configured?'（已保存，留空不修改）':''}</span><input id="smtpPass" type="password" autocomplete="new-password"></label><label class="field"><span>发件人</span><input id="mailFrom" value="${escapeAttr(s.mail_from||'')}" placeholder="notice@example.com"></label><label class="field"><span>收件人</span><input id="mailTo" value="${escapeAttr(s.mail_to||'')}" placeholder="you@example.com"></label></div></div></section><section class="panel preview-panel"><div class="preview-head"><h2>邮件预览</h2><span id="previewStatus" class="preview-status">加载中</span></div><iframe id="emailPreview" class="preview-frame loading" title="邮件预览"></iframe></section></div>`;document.querySelectorAll('[data-settings-tab]').forEach(button=>button.onclick=()=>{settingsTab=button.dataset.settingsTab;applySettingsTab()});saveSettingsBtn.onclick=saveSettings;settingsView.oninput=()=>saveSettingsBtn.classList.add('dirty');applySettingsTab()}
function applySettingsTab(){document.querySelectorAll('[data-settings-tab]').forEach(button=>button.classList.toggle('active',button.dataset.settingsTab===settingsTab));document.querySelectorAll('[data-settings-pane]').forEach(pane=>pane.hidden=pane.dataset.settingsPane!==settingsTab)}
function collectSettings(){return{notify_enabled:nEnabled.checked,reminder_days:nDays.value,telegram_enabled:tgEnabled.checked,telegram_bot_token:tgToken.value,telegram_chat_id:tgChat.value,email_enabled:mailEnabled.checked,smtp_host:smtpHost.value,smtp_port:smtpPort.value,smtp_security:smtpSecurity.value,smtp_username:smtpUser.value,smtp_password:smtpPass.value,mail_from:mailFrom.value,mail_to:mailTo.value}}
function addEmailTestButton(){const pane=$('[data-settings-pane=email]');if(!pane||$('#testEmailBtn'))return;pane.insertAdjacentHTML('beforeend',`<div class="pane-actions"><div><b>验证邮件配置</b><span>使用当前填写的配置发送，不会自动保存。</span></div><button class="btn" id="testEmailBtn" type="button">${ICONS.send}发送测试邮件</button></div>`);testEmailBtn.onclick=testEmail}
async function testEmail(){const button=testEmailBtn;setBusy(button,true,'发送中');try{const data=await api('/api/email-test',{method:'POST',body:JSON.stringify(collectSettings())});toast(data.message)}catch(e){toast(e.message,'error')}finally{setBusy(button,false)}}
async function saveSettings(){const button=saveSettingsBtn;setBusy(button,true,'保存中');try{const data=await api('/api/settings',{method:'PUT',body:JSON.stringify(collectSettings())});settings=data.settings;renderSettings();addEmailTestButton();await loadEmailPreview();toast('通知设置已保存')}catch(e){toast(e.message,'error')}finally{setBusy(button,false)}}
async function loadEmailPreview(){const frame=$('#emailPreview'),status=$('#previewStatus');if(!frame)return;frame.classList.add('loading');status.textContent='加载中';try{const data=await api('/api/email-preview');frame.onload=()=>{frame.classList.remove('loading');status.textContent='预览已更新'};frame.srcdoc=data.html}catch(e){frame.classList.remove('loading');status.textContent='预览加载失败';toast(e.message,'error')}}
async function saveCurrent(){const button=saveBtn;setBusy(button,true,'保存中');try{const method=current.id?'PUT':'POST',url=current.id?`/api/domains/${current.id}`:'/api/domains';const data=await api(url,{method,body:JSON.stringify(collect())});current=data.domain;await loadDomains();openDetail(current.id);toast('域名信息已保存')}catch(e){toast(e.message,'error')}finally{setBusy(button,false)}}
async function deleteCurrent(){if(!confirm('确定删除这个域名？'))return;const button=deleteBtn;setBusy(button,true,'删除中');try{await api(`/api/domains/${current.id}`,{method:'DELETE'});await loadDomains();toast('域名已删除')}catch(e){toast(e.message,'error');setBusy(button,false)}}
function escapeHtml(s){return String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}function escapeAttr(s){return escapeHtml(s)}
const localConnection=['localhost','127.0.0.1','::1'].includes(location.hostname);if(location.protocol==='https:')loginTransportText.textContent='当前连接已启用 HTTPS';else{loginTransport.classList.add('insecure');loginTransportText.textContent=localConnection?'当前为本地 HTTP 连接':'当前连接未启用 HTTPS'}
loginForm.onsubmit=async e=>{e.preventDefault();const button=loginForm.querySelector('button[type=submit]');loginMsg.textContent='';setBusy(button,true,'登录中');try{await api('/api/login',{method:'POST',body:JSON.stringify({username:username.value,password:password.value})});await loadDomains();toast('登录成功')}catch(err){loginMsg.textContent=err.message}finally{setBusy(button,false)}};logoutBtn.onclick=async()=>{await api('/api/logout',{method:'POST'}).catch(()=>{});showLogin()};homeBtn.onclick=loadDomains;settingsBtn.onclick=openSettings;addBtn.onclick=()=>openDetail(null);
(async()=>{const me=await api('/api/me').catch(()=>({user:null}));me.user?loadDomains():showLogin()})();
</script>
</body></html>"""


if __name__ == "__main__":
    main()
