import tempfile

import domain_manager


def test_domain_validation():
    payload = {
        "name": "Example.COM",
        "expires_at": "2027-01-02",
        "registrar": "Cloudflare",
        "renewal_price": "10 USD / 年",
    }

    domain = domain_manager.clean_domain(payload)

    assert domain["name"] == "example.com"


def test_rdap_normalization_extracts_asset_record():
    payload = {
        "events": [
            {"eventAction": "registration", "eventDate": "2020-01-02T03:04:05Z"},
            {"eventAction": "expiration", "eventDate": "2027-01-02T00:00:00Z"},
            {"eventAction": "last changed", "eventDate": "2026-06-01T00:00:00Z"},
        ],
        "status": ["client transfer prohibited", "server hold"],
        "entities": [{
            "roles": ["registrar"],
            "handle": "fallback",
            "vcardArray": ["vcard", [["fn", {}, "text", "Cloudflare, Inc."]]],
        }],
        "nameservers": [{"ldhName": "NS2.EXAMPLE.COM"}, {"ldhName": "NS1.EXAMPLE.COM"}],
        "secureDNS": {"delegationSigned": True},
    }

    record = domain_manager.normalize_rdap(payload)

    assert record["created_at"] == "2020-01-02"
    assert record["expires_at"] == "2027-01-02"
    assert record["updated_at"] == "2026-06-01"
    assert record["registrar"] == "Cloudflare, Inc."
    assert record["nameservers"] == ["ns1.example.com", "ns2.example.com"]
    assert record["secure_dns"] is True
    assert record["healthy"] is False


def test_exchange_rates_are_normalized_with_fallbacks():
    rates = domain_manager.normalize_exchange_rates({"rates": {"CNY": 7.25, "EUR": "0.84", "JPY": -1}})

    assert rates["USD"] == 1
    assert rates["CNY"] == 7.25
    assert rates["EUR"] == 0.84
    assert rates["JPY"] == domain_manager.FALLBACK_EXCHANGE_RATES["JPY"]


def test_init_writes_config_and_sample_domain():
    class Args:
        username = "admin"
        password = "password123"
        host = "127.0.0.1"
        port = 8099
        no_tls = True
        cert = ""
        key = ""

    with tempfile.TemporaryDirectory() as temp:
        Args.data_dir = temp
        domain_manager.init_app(Args)
        config = domain_manager.load_config(temp)
        store = domain_manager.load_store(temp)

    assert config["admin_username"] == "admin"
    assert domain_manager.verify_password("password123", config["password_hash"])
    assert store["domains"][0]["name"] == "example.com"


def test_notification_helpers_build_preview():
    domains = [
        {"id": "a", "name": "soon.test", "expires_at": "2099-01-08", "registrar": "Cloudflare", "renewal_price": "10 USD / 年"}
    ]
    days = domain_manager.parse_reminder_days("30, 7, 1")

    assert days == [30, 7, 1]

    domains[0]["expires_at"] = domain_manager.date.today().replace(
        day=min(domain_manager.date.today().day, 20)
    ).isoformat()
    domains[0]["days_left"] = domain_manager.days_until(domains[0]["expires_at"])
    html = domain_manager.email_html(domains, {"reminder_days": "30,7,1"})

    assert "soon.test" in html
    assert "域名续费提醒" in html


def test_email_sender_uses_test_subject():
    sent = []

    class FakeSMTP:
        def __init__(self, *args, **kwargs):
            pass

        def login(self, username, password):
            pass

        def send_message(self, message):
            sent.append(message)

        def quit(self):
            pass

    original = domain_manager.smtplib.SMTP_SSL
    domain_manager.smtplib.SMTP_SSL = FakeSMTP
    try:
        domain_manager.send_email({
            "email_enabled": True,
            "smtp_host": "smtp.example.com",
            "smtp_port": 465,
            "smtp_security": "ssl",
            "smtp_username": "notice@example.com",
            "smtp_password": "secret",
            "mail_to": "owner@example.com",
            "reminder_days": "30,7,1",
        }, [], "域名管理器测试邮件")
    finally:
        domain_manager.smtplib.SMTP_SSL = original

    assert sent[0]["Subject"] == "域名管理器测试邮件"
    assert sent[0]["To"] == "owner@example.com"


def test_auto_renewals_advance_only_enabled_domains():
    domains = [
        {"name": "due.test", "expires_at": "2026-07-26", "auto_renew": True},
        {"name": "old.test", "expires_at": "2020-01-01", "auto_renew": True},
        {"name": "leap.test", "expires_at": "2024-02-29", "auto_renew": True},
        {"name": "manual.test", "expires_at": "2026-07-26", "auto_renew": False},
    ]

    changed = domain_manager.advance_auto_renewals(domains, domain_manager.date(2026, 7, 26))

    assert changed == 3
    assert domains[0]["expires_at"] == "2027-07-26"
    assert domains[1]["expires_at"] == "2027-01-01"
    assert domains[2]["expires_at"] == "2027-02-28"
    assert domains[3]["expires_at"] == "2026-07-26"
