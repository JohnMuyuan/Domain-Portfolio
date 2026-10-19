# Domain Manager

A beginner-friendly domain portfolio and renewal reminder dashboard. Domain cards are displayed in the frontend, a Python standard-library backend serves the API, and data is stored in local JSON files.

## Features

- Domain cards with expiry dates, registrars, and renewal prices.
- Remaining portfolio value estimated from annual renewal fees and days remaining.
- Renewal ranking ordered by expiry date.
- Detail pages for editing domain information, renewal links, and portfolio notes, and opening renewal links.
- Light, dark, and system themes.
- Telegram and email expiry reminders with configurable lead time.
- Email previews and SMTP test emails in Settings.
- A login page suitable for deployment behind a 1Panel or Nginx reverse proxy.

The current version focuses on portfolio display and renewal reminders; it does not modify DNS records.

## Run locally

```bash
python3 domain_manager.py --data-dir ./data init --username admin --password 'replace-with-a-strong-password' --host 127.0.0.1 --port 8099 --no-tls
python3 domain_manager.py --data-dir ./data serve
```

Open `http://127.0.0.1:8099`.

## Deploy

Run on a Linux server:

```bash
curl -fLsS https://raw.githubusercontent.com/JohnMuyuan/Domain-Portfolio/main/install.sh -o install.sh
sudo sh install.sh
```

If you have already downloaded the source, run `sudo sh install.sh` from the project directory.

The default listener is `127.0.0.1:8099`. Configure a reverse proxy and HTTPS in 1Panel or Nginx.

Leaving the dashboard password blank generates a strong random password, displayed after installation. Noninteractive installation also generates one when `DM_PANEL_PASSWORD` is unset.

Noninteractive example:

```bash
DM_NONINTERACTIVE=1 \
DM_PANEL_USER=admin \
DM_PANEL_PASSWORD='replace-with-a-strong-password' \
DM_PANEL_PORT=8099 \
DM_REVERSE_PROXY=1 \
sudo sh install.sh
```

Management commands:

```bash
domain-manager info
domain-manager status
domain-manager restart
domain-manager logs
domain-manager update
```

## Data locations

- Application: `/opt/domain-manager`
- Data: `/var/lib/domain-manager`
- Management command: `/usr/local/bin/domain-manager`

## Self-test

```bash
python3 domain_manager.py --data-dir ./data self-test
```
