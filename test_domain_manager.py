import tempfile

import domain_manager


def test_domain_validation():
    payload = {
        "name": "Example.COM",
        "expires_at": "2027-01-02",
        "registrar": "Cloudflare",
        "renewal_amount": "129.90",
        "renewal_currency": "USD",
        "renewal_years": 2,
    }

    domain = domain_manager.clean_domain(payload)

    assert domain["name"] == "example.com"
    assert domain["renewal_amount"] == "129.9"
    assert domain["renewal_price"] == "129.9 USD / 2 年"


def test_legacy_renewal_price_is_migrated_and_invalid_amount_rejected():
    domain = domain_manager.clean_domain({"name": "legacy.test", "renewal_price": "10 USD / 年"})

    assert (domain["renewal_amount"], domain["renewal_currency"], domain["renewal_years"]) == ("10", "USD", 1)
    try:
        domain_manager.clean_domain({"name": "bad.test", "renewal_amount": "12.345", "renewal_currency": "CNY", "renewal_years": 1})
    except ValueError:
        pass
    else:
        raise AssertionError("invalid renewal amount accepted")


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


def test_rdap_normalization_reads_li_registrar_org():
    record = domain_manager.normalize_rdap(
        {
            "status": ["active"],
            "secureDNS": {"delegationSigned": False},
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": [
                        "vcard",
                        [["org", {}, "text", "Hosting Concepts B.V. d/b/a Registrar.eu "]],
                    ],
                    "url": "https://www.openprovider.com",
                }
            ],
        }
    )
    assert record["registrar"] == "Hosting Concepts B.V. d/b/a Registrar.eu"
    assert record["statuses"] == ["active"]
    assert record["secure_dns"] is False


def test_registration_lookup_falls_back_to_registry_whois():
    whois_text = """domain: yp.mk
registrar: MARCOM-REG
registered: 22.06.2026 18:35:07
expire: 22.06.2027
nserver: maleah.ns.cloudflare.com
nserver: marty.ns.cloudflare.com
"""
    original_rdap = domain_manager.fetch_rdap
    original_referral = getattr(domain_manager, "whois_referral", None)
    original_whois = getattr(domain_manager, "fetch_whois_text", None)

    def rdap_unavailable(_name):
        raise ValueError("RDAP unavailable")

    domain_manager.fetch_rdap = rdap_unavailable
    domain_manager.whois_referral = lambda _tld: "whois.marnet.mk"
    domain_manager.fetch_whois_text = lambda _host, _name: whois_text
    try:
        record = domain_manager.fetch_registration("yp.mk")
    finally:
        domain_manager.fetch_rdap = original_rdap
        if original_referral is None:
            del domain_manager.whois_referral
        else:
            domain_manager.whois_referral = original_referral
        if original_whois is None:
            del domain_manager.fetch_whois_text
        else:
            domain_manager.fetch_whois_text = original_whois

    assert record["source"] == "WHOIS"
    assert record["created_at"] == "2026-06-22"
    assert record["expires_at"] == "2027-06-22"
    assert record["registrar"] == "MARCOM-REG"
    assert record["nameservers"] == ["maleah.ns.cloudflare.com", "marty.ns.cloudflare.com"]


def test_registration_lookup_uses_registered_parent_for_subdomain():
    original_rdap = domain_manager.fetch_rdap

    def parent_only(name):
        if name != "dpdns.org":
            raise ValueError("not registered")
        return {"expires_at": "2029-03-13", "registrar": "Gandi SAS"}

    domain_manager.fetch_rdap = parent_only
    try:
        record = domain_manager.fetch_registration("muyno.dpdns.org")
    finally:
        domain_manager.fetch_rdap = original_rdap

    assert record["queried_name"] == "dpdns.org"
    assert record["is_parent"] is True
    assert record["expires_at"] == "2029-03-13"


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
