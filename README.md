<!-- ---------------------------------------------------------------------------
     Author  : Kyle <kyle@hacking-linux.com>
     Version : 20260206v1
     License : MIT
     --------------------------------------------------------------------------- -->

# Password Manager

A self-hosted web-based password manager with admin-managed user accounts and AES-256-GCM vault encryption.  Built with **FastAPI** (Python) on the backend and plain **HTML / CSS / JavaScript** on the frontend - no React, Vue, or other frameworks.

## Author & License

- **Author**: Kyle
- **Email**: kyle@hacking-linux.com
- **Version**: 20260206v1
- **License**: MIT License (see LICENSE file)

---

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Screenshots](#screenshots)
- [Quick Start](#quick-start)
- [Usage Guide](#usage-guide)
- [Permission Model](#permission-model)
- [Security](#security-boundaries-current-prototype)
- [API Reference](#api-reference-summary)

---

## Features

### Core Capabilities
- [*] **Secure Password Storage** - AES-256-GCM encryption with individual IVs per entry
- [*] **Multi-User System** - Admin-managed user accounts with role-based access
- [*] **Multiple Entry Types** - Login credentials, SSH keys, API credentials, Database connections, Secure notes
- [*] **Password Generator** - Built-in generator with Random, Memorable, and PIN modes
- [*] **Import/Export** - Bulk operations via Excel files (.xlsx)
- [*] **Audit Logging** - Track all admin actions and sensitive operations
- [*] **Single-Page Architecture** - Fast, responsive interface without page reloads

### Entry Categories
- **Login** - Website credentials with username/password/URL
- **SSH Key** - Public/private key pairs with optional passphrases
- **API Credentials** - API keys and secrets for service integrations
- **Database** - Connection strings, hosts, ports, and credentials
- **Secure Note** - Encrypted text notes for any sensitive information

---

## Architecture

### Technology Stack

```
+-------------------------------------------------------------+
|                        Frontend Layer                        |
|  * Vanilla JavaScript (ES6+)                                 |
|  * HTML5 + CSS3 (Dark Theme)                                 |
|  * No frameworks - lightweight & fast                        |
+---------------------+---------------------------------------+
                      | HTTPS / REST API
+---------------------v---------------------------------------+
|                       Backend Layer                          |
|  * FastAPI (Python 3.10+)                                    |
|  * Uvicorn ASGI Server                                       |
|  * JWT Authentication                                        |
|  * PBKDF2-SHA256 (600k rounds) for login passwords          |
|  * AES-256-GCM for vault encryption                          |
+---------------------+---------------------------------------+
                      | SQLAlchemy ORM
+---------------------v---------------------------------------+
|                      Database Layer                          |
|  * MySQL 8.0 (InnoDB, utf8mb4)                               |
|  * Tables: users, vault_items, audit_logs                    |
|  * Alembic migrations                                        |
+-------------------------------------------------------------+
```

### Data Flow

```
+----------------+
|    Browser     |
| (SessionStorage|  <-- JWT Token stored client-side
+-------+--------+
        |
        | 1. Login Request (email + password)
        v
+------------------------------------------+
|    FastAPI Auth Router                   |
|  * Validate credentials (PBKDF2)         |
|  * Generate JWT token (30min expiry)     |
+-------+----------------------------------+
        |
        | 2. API Requests (Authorization: Bearer <token>)
        v
+------------------------------------------+
|    FastAPI Vault Router                  |
|  * Verify JWT & user ownership           |
|  * Encrypt/Decrypt vault data            |
|  * CRUD operations                        |
+-------+----------------------------------+
        |
        | 3. Database Operations
        v
+------------------------------------------+
|         MySQL Database                   |
|  * Users (hashed passwords)              |
|  * Vault Items (encrypted fields)        |
|  * Audit Logs (admin actions)            |
+------------------------------------------+
```

### Security Architecture

| Layer | Protection Mechanism |
|-------|---------------------|
| **Transport** | HTTPS recommended (TLS 1.2+) |
| **Authentication** | JWT tokens (HS256), 30-minute expiry |
| **Login Passwords** | PBKDF2-SHA256 with 600,000 iterations |
| **Vault Encryption** | AES-256-GCM with unique IV per entry |
| **Authorization** | User ID verification on every vault operation |
| **Secrets** | Master key stored in environment variable only |

---

## Screenshots

### 1. Login Page
![Login Page](docs/screenshots/1-login.png)

The login interface with email/password authentication. First-time users are prompted to change their temporary password.

### 2. Vault Dashboard
![Vault Dashboard](docs/screenshots/2-vault-dashboard.png)

Main vault interface showing the sidebar with entry list and the detail/edit panel on the right.

### 3. Password Generator
![Password Generator](docs/screenshots/3-password-generator.png)

Built-in password generator with Random, Memorable, and PIN modes.

### 4. Entry Details
![Entry Details](docs/screenshots/4-entry-details.png)

Vault entry detail view showing all fields for a login credential with reveal and copy options.

### 5. Admin - User Management
![Admin User Management](docs/screenshots/5-admin-users.png)

Admin panel for creating and managing user accounts, resetting passwords, and changing roles.

### 6. Admin - Audit Logs
![Admin Audit Logs](docs/screenshots/6-admin-audit.png)

Audit log view showing all administrative actions and vault operations for compliance tracking.

---

## Quick Start

### Prerequisites

| Software | Minimum version |
|---|---|
| Python | 3.10 |
| MySQL | 8.0 (InnoDB, utf8mb4) |
| pip | latest |

### 1.  Install dependencies

```bash
cd pasmgr
pip install -r requirements.txt
```

### 2.  Create the config file

Copy the template below into `pasmgr/etc/app.conf` and fill in real values.  **This file must never be committed to version control.**

```bash
# MySQL connection string
database_url=mysql+pymysql://root:yourpassword@localhost:3306/pasmgr

# JWT signing secret - at least 64 random hex characters
# Generate: python3 -c "import secrets; print(secrets.token_hex(32))"
secret_key=your-secret-key-here

# AES-256 master encryption key - base64-encoded 32 random bytes
# Generate: python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
master_encryption_key=your-base64-key-here

# JWT token expiration (optional, default: 10080 minutes = 7 days)
access_token_expire_minutes=30

# Seed admin (used only by bin/seed_admin.py - inert afterward)
first_admin_email=admin@yourcompany.com
first_admin_password=TemporaryAdmin123!
```

### 3.  Create the MySQL database

```sql
CREATE DATABASE pasmgr CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### 4.  Run the database migration

```bash
cd pasmgr
alembic -c etc/alembic.ini upgrade head
```

This creates the `users` and `vault_items` tables.

### 5.  Seed the first admin account

```bash
python bin/seed_admin.py
```

The admin account starts with `force_password_change = true`.  The operator must set a permanent password on first login.

### 6.  Start the server

```bash
bin/start.sh
```

The server serves **both** the API and the frontend static files.  Open your browser to:

```
http://localhost:8001/login.html
```

To stop the server gracefully:

```bash
bin/stop.sh
```

---

## Usage Guide

### For Administrators

#### Creating a New User

1. **Login** as admin at `http://localhost:8001/login.html`
2. Navigate to **Admin Panel** from the top navigation
3. Click **"Users"** tab
4. Fill in the new user form:
   - Email address (used for login)
   - Role (admin or user)
   - System generates a temporary password
5. Click **"Create User"**
6. Share the email and temporary password with the new user
7. User must change password on first login

#### Managing Users

- **Reset Password**: Click [Reset] icon to generate a new temporary password
- **Change Role**: Toggle between admin and user roles
- **Disable User**: Click [Lock] to soft-disable (prevents login)
- **View Audit Logs**: Switch to "Audit" tab to see all admin actions

### For Regular Users

#### First Login

1. Navigate to `http://localhost:8001/login.html`
2. Enter your email and temporary password (provided by admin)
3. You'll be prompted to set a new password immediately
4. Choose a strong password (minimum requirements apply)

#### Managing Your Vault

##### Creating an Entry

1. Click **"+ New"** button in the sidebar
2. Select entry **Category**:
   - **Login**: Website credentials
   - **SSH Key**: Server access keys
   - **API Credentials**: API keys and secrets
   - **Database**: Database connection info
   - **Secure Note**: Any sensitive text
3. Fill in required fields (varies by category)
4. Click **"Save"**

##### Using the Password Generator

1. When creating/editing an entry, click **[Gen] Generate** next to the password field
2. Choose generation mode:
   - **Random**: Strong random password (configurable length 6-32)
     - Always includes uppercase + lowercase
     - Optional: digits, symbols
   - **Memorable**: Easy-to-type format (e.g., `brave-oak-47`)
   - **PIN**: Numeric only (4-8 digits)
3. Adjust options and click **"Generate"**
4. Password is auto-filled (you can edit before saving)

##### Viewing Stored Passwords

1. Click on any entry in the sidebar
2. Passwords are hidden by default (shows `********`)
3. Click **[Eye] Reveal** to decrypt and display plaintext
4. Click **[Copy] Copy** to copy to clipboard
5. Click **[Lock] Hide** to hide again

##### Searching Entries

- Use the search box in the sidebar
- Searches across title, username, and URL fields
- Results update in real-time as you type

##### Organizing Entries

- Entries are grouped by category (icons in sidebar)
- Click category icons to filter view
- Edit entry to change category

##### Exporting & Importing

**Export (Backup)**
1. Click **Export** button in sidebar
2. Downloads Excel file with all your vault entries
3. Passwords are decrypted in export (keep file secure!)

**Import (Restore)**
1. Click **Import** button in sidebar
2. Select Excel file (must match export format)
3. System validates and imports entries
4. Duplicates are skipped automatically

#### Changing Your Password

1. Click your email in top-right corner
2. Select **"Change Password"**
3. Enter current password
4. Enter new password (twice)
5. Click **"Save"**

### Category-Specific Fields

| Category | Required Fields | Optional Fields |
|----------|----------------|-----------------|
| **Login** | Title, Password | Username, URL, Notes |
| **SSH Key** | Title, Private Key | Public Key, Password (for key), Notes |
| **API Credentials** | Title | API Key, API Secret, Endpoint URL, Notes |
| **Database** | Title | Username, Password, Host/URL, Port, Notes |
| **Secure Note** | Title, Notes | - |

### Best Practices

#### Password Security
- [+] Use the password generator for strong passwords
- [+] Use unique passwords for each service
- [+] Choose "Random" mode for maximum security
- [+] Enable symbols and digits for stronger passwords
- [-] Don't reuse passwords across entries
- [-] Don't share your vault password with anyone

#### Vault Management
- [+] Export your vault regularly for backup
- [+] Store exports in a secure location (encrypted drive)
- [+] Use descriptive titles for easy searching
- [+] Add notes to document special requirements
- [+] Review and update old credentials periodically
- [-] Don't export to shared/cloud folders without encryption

#### Admin Operations
- [+] Review audit logs regularly
- [+] Disable unused accounts promptly
- [+] Use strong passwords for admin accounts
- [+] Limit number of admin users
- [-] Don't share admin credentials
- [-] Don't create accounts without user knowledge

---

## Permission Model

| Role | Capabilities |
|---|---|
| **admin** | Create users * Reset any user's password * Change user roles * Disable users * Manage own vault |
| **user** | Log in * Change own password * Manage own vault entries |

* **No self-registration.**  All accounts are created by an admin via the Admin Panel.
* New accounts have `force_password_change = true`.  The user must set their own password before accessing the vault.
* Each user can only read, create, update, or delete their **own** vault entries.  Server-side ownership checks prevent cross-user access even if item IDs are guessed.

---

## Password Generator & Vault Integration

The password generator is available directly inside the "New Entry" / "Edit Entry" form on the Vault page.

### How it works

1. Click the **[Gen] Generate** button next to the password field.  A small options panel appears.
2. Choose a mode:

   | Mode | Description |
   |---|---|
   | **Random** | Upper + lower case letters (mandatory), optionally digits and/or symbols.  Configurable length 6-32. |
   | **Memorable** | `adjective-noun-NN` pattern (e.g. `brave-oak-47`).  Easy to type manually. |
   | **PIN** | Digits only, length 4-8. |

3. Click **Generate**.  The password is filled into the input field.
4. You may manually edit the generated password before saving.

### Primary vs. fallback

* **Primary path:** the browser calls `GET /vault/generate-password` on the backend.  The server uses Python's `secrets` module (OS CSPRNG) to generate the password.
* **Fallback:** if the network call fails, the same logic runs in the browser using the Web Crypto API (`crypto.getRandomValues`).  No security is lost either way.

---

## Security Boundaries (current prototype)

| Layer | What is protected | How |
|---|---|---|
| Login passwords | Never stored in plaintext | PBKDF2-SHA256 (600 000 rounds) via passlib - pure Python, no glibc constraints |
| Vault passwords | Never stored in plaintext | AES-256-GCM encryption with a per-record 12-byte nonce |
| Master encryption key | Never written to the database or logs | Loaded exclusively from the `MASTER_ENCRYPTION_KEY` environment variable at runtime |
| Cross-user access | Each vault query is filtered by `user_id` from the JWT | Server rejects any request where the item's owner != the authenticated user |
| Token lifetime | JWTs expire after 30 minutes | No refresh token in this prototype; re-login is required after expiry |
| User enumeration | Login endpoint returns the same error message for unknown email and wrong password | Prevents attackers from discovering valid emails |

### What needs hardening before production

| Area | Recommendation |
|---|---|
| Token storage | Replace `sessionStorage` with an **httpOnly, Secure, SameSite=Strict** cookie set by a dedicated backend endpoint |
| HTTPS | All traffic **must** use TLS.  Set `Secure` flag on cookies |
| Rate limiting | Add rate limiting on `POST /auth/login` (e.g. `slowapi` - 5 attempts / minute per IP) |
| Refresh tokens | Add a long-lived refresh token (httpOnly cookie) backed by a server-side `sessions` table so the user is not forced to re-login every 30 minutes |
| CORS | Lock `allow_origins` to the exact production domain - never use `*` |
| Secrets management | Replace `etc/app.conf` with a secrets manager (AWS Secrets Manager, HashiCorp Vault, etc.) |
| CSP headers | Add `Content-Security-Policy` headers restricting `script-src` to `'self'` only |
| AES key rotation | Add a `key_version` column to `vault_items`.  When the master key rotates, re-encrypt all items in a background job |
| PBKDF2 rounds | Consider increasing rounds beyond 600 000 as hardware speeds up (accept slower login) |
| Database account | Use a dedicated MySQL service account with only `INSERT / SELECT / UPDATE / DELETE` on the `pasmgr` schema - no `GRANT`, no `DROP` |
| Logging | Never log request bodies or token values.  Use structured logging with request-ID correlation |

---

## Project Structure

```
pasmgr/
+-- bin/
|   +-- start.sh                   # launch uvicorn (auto-detects venv, tees to log/)
|   +-- stop.sh                    # graceful SIGTERM -> SIGKILL shutdown
|   +-- seed_admin.py              # one-shot admin bootstrap
+-- etc/
|   +-- app.conf                   # secrets & connection strings - NEVER commit
|   +-- logging.conf               # Python logging INI (rotation, format, handlers)
|   +-- alembic.ini                # Alembic config -> run as: alembic -c etc/alembic.ini ...
|   +-- pasmgr.service             # systemd unit file (RHEL / CentOS)
+-- tools/
|   +-- init.sh                    # create virtual environment (python3 -m venv .)
|   +-- clean.sh                   # remove virtual environment and __pycache__
|   +-- changewp.sh                # fix venv paths after moving project directory
|   +-- gen_requirements.sh        # generate requirements.txt from installed packages
|   +-- download_offline_pkgs.sh   # download dependencies for offline installation
|   +-- install_offline_pkg.sh     # install from offline packages
|   +-- clean_installed_pkg.sh     # uninstall all packages from venv
|   +-- initdb.sh                  # initialize MySQL database
|   +-- pasmgr.ddl.sql             # database creation SQL
+-- log/
|   +-- app.log                    # rotating application log (gitignored)
|   +-- uvicorn.log                # uvicorn stdout/stderr (gitignored)
+-- backend/
|   +-- main.py                    # FastAPI app, CORS, request-log middleware, router mounts
|   +-- database.py                # SQLAlchemy engine & session
|   +-- core/
|   |   +-- config.py              # pydantic Settings (reads etc/app.conf)
|   |   +-- logger.py              # loads etc/logging.conf, exposes logger
|   |   +-- security.py            # PBKDF2-SHA256 * AES-256-GCM * JWT * auth guards
|   +-- models/
|   |   +-- user.py                # User ORM
|   |   +-- vault_item.py          # VaultItem ORM (CASCADE delete)
|   +-- auth/                      # POST /auth/login * PUT /auth/change-password * GET /auth/me
|   +-- admin/                     # POST /admin/users * GET /admin/users * reset-password * change-role * disable
|   +-- vault/                     # CRUD /vault/items * decrypt * export * import * generate-password
|   +-- migrations/                # Alembic env + initial migration
+-- frontend/
|   +-- index.html                 # meta-refresh redirect -> login.html
|   +-- login.html                 # Login page + forced password-change modal
|   +-- vault.html                 # Vault sidebar + detail/edit form + generator
|   +-- admin.html                 # Create User page
|   +-- admin-users.html           # User Management page (table + reset / role / disable modals)
|   +-- styles.css                 # Dark-theme global stylesheet + nav dropdown
|   +-- app.js                     # Token mgmt * Fetch wrapper * page logic * local password generator
+-- requirements.txt
+-- .gitignore
+-- README.md
```

---

## API Reference (summary)

All endpoints that require authentication expect an `Authorization: Bearer <token>` header.

| Method | Path | Auth | Description |
|---|---|---|---|
| POST | `/auth/login` | - | Authenticate; returns JWT |
| PUT | `/auth/change-password` | user | Change own password |
| GET | `/auth/me` | user | Current user info |
| POST | `/admin/users` | admin | Create a user |
| GET | `/admin/users` | admin | List all users |
| PUT | `/admin/users/{id}/reset-password` | admin | Reset a user's password |
| PUT | `/admin/users/{id}/change-role` | admin | Change a user's role (admin <-> user) |
| PUT | `/admin/users/{id}/disable` | admin | Soft-disable a user |
| GET | `/vault/items` | user | List own vault entries |
| POST | `/vault/items` | user | Create a vault entry |
| GET | `/vault/items/{id}` | user | Get one entry (encrypted) |
| GET | `/vault/items/{id}/decrypt` | user | Reveal plaintext password |
| PUT | `/vault/items/{id}` | user | Update an entry |
| DELETE | `/vault/items/{id}` | user | Delete an entry |
| GET | `/vault/export` | user | Export all entries as .xlsx |
| POST | `/vault/import` | user | Bulk-import entries from .xlsx |
| GET | `/vault/generate-password` | user | Server-side password generation |
| GET | `/health` | - | Liveness check |

---

## Development Tools

The `tools/` directory contains utility scripts to help with development, deployment, and maintenance tasks.

### Virtual Environment Management

**Create virtual environment:**
```bash
./tools/init.sh
```
Creates a Python virtual environment in the project root (equivalent to `python3 -m venv .`).

**Clean virtual environment:**
```bash
./tools/clean.sh
```
Removes the virtual environment and all `__pycache__` directories.

**Fix virtual environment paths:**
```bash
./tools/changewp.sh
```
Updates activate scripts and Python shebangs after moving the project to a different directory. Run this after cloning or moving the project.

### Dependency Management

**Generate requirements.txt:**
```bash
./tools/gen_requirements.sh
```
Generates `requirements.txt` from currently installed packages in the virtual environment.

**Download packages for offline installation:**
```bash
./tools/download_offline_pkgs.sh
```
Downloads all dependencies to `packages/` directory for offline installation (useful for air-gapped environments).

**Install from offline packages:**
```bash
./tools/install_offline_pkg.sh
```
Installs dependencies from the `packages/` directory without internet access.

**Clean installed packages:**
```bash
./tools/clean_installed_pkg.sh
```
Uninstalls all packages from the virtual environment (useful for testing fresh installs).

### Database Initialization

**Initialize database:**
```bash
./tools/initdb.sh
```
Drops and recreates the `pasmgr` database. **Warning**: This will delete all existing data!

Default connection settings in `initdb.sh`:
- Host: 127.0.0.1
- User: root
- Password: pass

Edit the script if your MySQL credentials differ.

---

## Deployment Guide

### Prerequisites

- **Python**: 3.10 or higher
- **MySQL**: 8.0 or higher
- **Operating System**: Linux, macOS, or Windows with WSL
- **Reverse Proxy**: Nginx or Apache (for production)
- **SSL Certificate**: Let's Encrypt or commercial CA (for production)

### Development Deployment

#### 1. Clone Repository

```bash
git clone https://github.com/yourusername/pasmgr.git
cd pasmgr
```

#### 2. Set Up Python Virtual Environment

```bash
python3 -m venv .
source bin/activate
pip install -r requirements.txt
```

#### 3. Configure Database

```bash
# Create MySQL database
mysql -u root -p
```

```sql
CREATE DATABASE pasmgr CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
CREATE USER 'pasmgr_user'@'localhost' IDENTIFIED BY 'your_strong_password';
GRANT ALL PRIVILEGES ON pasmgr.* TO 'pasmgr_user'@'localhost';
FLUSH PRIVILEGES;
EXIT;
```

#### 4. Configure Application

```bash
# Copy template and edit
cp etc/app.conf.example etc/app.conf
vim etc/app.conf
```

Generate security keys:

```bash
# Generate SECRET_KEY (any random string, min 32 chars)
python3 -c "import secrets; print(secrets.token_hex(32))"

# Generate MASTER_ENCRYPTION_KEY (base64-encoded 32 bytes)
python3 -c "import base64, os; print(base64.urlsafe_b64encode(os.urandom(32)).decode())"
```

Update `etc/app.conf` with your values:

```bash
# Database
database_url=mysql+pymysql://pasmgr_user:your_strong_password@localhost:3306/pasmgr

# Security
secret_key=your_generated_secret_key_here
master_encryption_key=your_generated_master_key_here
access_token_expire_minutes=30

# First Admin
first_admin_email=admin@yourdomain.com
first_admin_password=YourSecurePassword123!
```

#### 5. Run Database Migrations

```bash
cd backend
alembic -c ../etc/alembic.ini upgrade head
```

#### 6. Create First Admin User

```bash
cd ..
python3 bin/seed_admin.py
```

#### 7. Start Development Server

```bash
cd backend
uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

Access the application at: `http://localhost:8000/login.html`

---

### Production Deployment

#### 1. System Preparation

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Install dependencies
sudo apt install -y python3 python3-pip python3-venv mysql-server nginx certbot python3-certbot-nginx

# Create application user
sudo useradd -m -s /bin/bash pasmgr
sudo su - pasmgr
```

#### 2. Application Setup

```bash
# Clone repository
git clone https://github.com/yourusername/pasmgr.git
cd pasmgr

# Set up virtual environment
python3 -m venv .
source bin/activate
pip install -r requirements.txt gunicorn

# Configure application (same as development step 4)
cp etc/app.conf.example etc/app.conf
vim etc/app.conf  # Update with production values

# Run migrations and seed admin
cd backend
alembic -c ../etc/alembic.ini upgrade head
cd ..
python3 bin/seed_admin.py
```

#### 3. Create Systemd Service

```bash
# Exit to root user
exit

# Create service file
sudo vim /etc/systemd/system/pasmgr.service
```

Add the following content:

```ini
[Unit]
Description=Password Manager Application
After=network.target mysql.service

[Service]
Type=notify
User=pasmgr
Group=pasmgr
WorkingDirectory=/home/pasmgr/pasmgr/backend
Environment="PATH=/home/pasmgr/pasmgr/bin"
ExecStart=/home/pasmgr/pasmgr/bin/gunicorn main:app \
    --workers 4 \
    --worker-class uvicorn.workers.UvicornWorker \
    --bind 127.0.0.1:8000 \
    --access-logfile /home/pasmgr/pasmgr/log/access.log \
    --error-logfile /home/pasmgr/pasmgr/log/error.log \
    --log-level info

Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
# Enable and start service
sudo systemctl daemon-reload
sudo systemctl enable pasmgr
sudo systemctl start pasmgr
sudo systemctl status pasmgr
```

#### 4. Configure Nginx Reverse Proxy

```bash
sudo vim /etc/nginx/sites-available/pasmgr
```

Add the following configuration:

```nginx
server {
    listen 80;
    server_name pasmgr.yourdomain.com;

    # Redirect HTTP to HTTPS
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name pasmgr.yourdomain.com;

    # SSL Configuration (certificates will be added by certbot)
    ssl_certificate /etc/letsencrypt/live/pasmgr.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/pasmgr.yourdomain.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;

    # Proxy settings
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket support (if needed)
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";

        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }

    # File upload size limit
    client_max_body_size 10M;

    # Logging
    access_log /var/log/nginx/pasmgr_access.log;
    error_log /var/log/nginx/pasmgr_error.log;
}
```

```bash
# Enable site and test configuration
sudo ln -s /etc/nginx/sites-available/pasmgr /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx
```

#### 5. Obtain SSL Certificate

```bash
sudo certbot --nginx -d pasmgr.yourdomain.com
```

#### 6. Configure Firewall

```bash
sudo ufw allow 'Nginx Full'
sudo ufw allow OpenSSH
sudo ufw enable
sudo ufw status
```

#### 7. Set Up Log Rotation

```bash
sudo vim /etc/logrotate.d/pasmgr
```

Add the following:

```
/home/pasmgr/pasmgr/log/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 pasmgr pasmgr
    sharedscripts
    postrotate
        systemctl reload pasmgr > /dev/null 2>&1 || true
    endscript
}
```

#### 8. Set Up Database Backups

```bash
sudo vim /home/pasmgr/backup.sh
```

Add the following script:

```bash
#!/bin/bash
# Database backup script

BACKUP_DIR="/home/pasmgr/backups"
DATE=$(date +%Y%m%d_%H%M%S)
DB_NAME="pasmgr"
DB_USER="pasmgr_user"
DB_PASS="your_strong_password"

mkdir -p $BACKUP_DIR

# Create backup
mysqldump -u $DB_USER -p$DB_PASS $DB_NAME | gzip > $BACKUP_DIR/pasmgr_$DATE.sql.gz

# Keep only last 30 days of backups
find $BACKUP_DIR -name "pasmgr_*.sql.gz" -mtime +30 -delete

echo "Backup completed: pasmgr_$DATE.sql.gz"
```

```bash
# Make executable and set up cron
sudo chmod +x /home/pasmgr/backup.sh
sudo chown pasmgr:pasmgr /home/pasmgr/backup.sh

# Add to crontab (daily at 2 AM)
sudo crontab -e -u pasmgr
# Add line: 0 2 * * * /home/pasmgr/backup.sh >> /home/pasmgr/pasmgr/log/backup.log 2>&1
```

---

### Security Checklist for Production

- [ ] Change all default passwords in `etc/app.conf`
- [ ] Use strong, randomly generated SECRET_KEY and MASTER_ENCRYPTION_KEY
- [ ] Enable HTTPS with valid SSL certificate
- [ ] Configure firewall to allow only necessary ports (80, 443, 22)
- [ ] Set up database backups with encryption
- [ ] Enable database SSL connections
- [ ] Implement rate limiting (e.g., using nginx limit_req)
- [ ] Set up monitoring and alerting (e.g., Prometheus + Grafana)
- [ ] Configure log aggregation (e.g., ELK stack)
- [ ] Regularly update dependencies: `pip list --outdated`
- [ ] Set up automatic security updates
- [ ] Restrict database user privileges (no SUPER, FILE, PROCESS)
- [ ] Use environment-specific app.conf files (never commit to git)
- [ ] Implement IP whitelisting for admin panel (optional)
- [ ] Set up fail2ban for brute-force protection

---

### Maintenance

#### Update Application

```bash
# Switch to application user
sudo su - pasmgr
cd pasmgr

# Pull latest changes
git pull origin main

# Activate virtual environment
source bin/activate

# Update dependencies
pip install -r requirements.txt --upgrade

# Run migrations
cd backend
alembic upgrade head

# Exit to root and restart service
exit
sudo systemctl restart pasmgr
```

#### Monitor Application

```bash
# Check application status
sudo systemctl status pasmgr

# View recent logs
sudo journalctl -u pasmgr -n 100 --no-pager

# Monitor real-time logs
sudo journalctl -u pasmgr -f

# Check Nginx logs
sudo tail -f /var/log/nginx/pasmgr_access.log
sudo tail -f /var/log/nginx/pasmgr_error.log
```

#### Restore from Backup

```bash
# Decompress backup
gunzip /home/pasmgr/backups/pasmgr_YYYYMMDD_HHMMSS.sql.gz

# Restore database
mysql -u pasmgr_user -p pasmgr < /home/pasmgr/backups/pasmgr_YYYYMMDD_HHMMSS.sql
```

---
