# ⚡ PhishGuard - Phishing Detection System

A full-stack phishing/malicious URL detector built with Flask, MySQL, and Google Safe Browsing API.

---

## 🛠 Tech Stack

| Layer     | Technology                          |
|-----------|-------------------------------------|
| Frontend  | HTML5, CSS3, Vanilla JavaScript     |
| Backend   | Python 3 + Flask                    |
| Database  | MySQL (via flask-mysqldb)           |
| API       | Google Safe Browsing API v4         |
| Env       | Python Virtual Environment (venv)   |

---

## 📁 Project Structure

```
phishing_detector/
├── app.py                  # Main Flask app
├── requirements.txt        # Python dependencies
├── schema.sql              # MySQL database schema
├── setup.sh                # Auto-setup script
├── .env.example            # Environment variable template
├── .gitignore
├── static/
│   ├── css/style.css       # Cyberpunk-themed stylesheet
│   └── js/main.js          # Scan logic & UI interactions
└── templates/
    ├── base.html            # Base layout with navbar
    ├── index.html           # Homepage / URL scanner
    ├── history.html         # Scan history page
    └── dashboard.html       # Stats dashboard
```

---

## ⚙️ Setup Instructions

### Step 1 — Clone / create project
```bash
cd phishing_detector
```

### Step 2 — Create virtual environment
```bash
python3 -m venv venv
```

### Step 3 — Activate virtual environment
```bash
# Linux / macOS
source venv/bin/activate

# Windows
venv\Scripts\activate
```

### Step 4 — Install dependencies
```bash
pip install -r requirements.txt
```

### Step 5 — Configure environment
```bash
cp .env.example .env
# Edit .env with your credentials
```

Required `.env` values:
```env
SECRET_KEY=your_secret_key
GOOGLE_SAFE_BROWSING_API_KEY=YOUR_GOOGLE_API_KEY
MYSQL_HOST=localhost
MYSQL_USER=root
MYSQL_PASSWORD=your_password
MYSQL_DB=phishing_detector
```

### Step 6 — Setup MySQL Database
```bash
mysql -u root -p < schema.sql
```

### Step 7 — Run the app
```bash
python app.py
```

Open browser → **http://localhost:5000**

---

## 🔑 Getting Google Safe Browsing API Key

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or use existing)
3. Navigate to **APIs & Services → Library**
4. Search for **"Safe Browsing API"** and enable it
5. Go to **APIs & Services → Credentials**
6. Click **"Create Credentials" → "API Key"**
7. Copy the key into your `.env` file

---

## 🌐 Pages

| Route        | Description                          |
|--------------|--------------------------------------|
| `/`          | URL scanner with results             |
| `/history`   | Paginated scan history from MySQL    |
| `/dashboard` | Stats cards + Chart.js activity chart|
| `/scan`      | POST API endpoint for scanning       |
| `/api/history` | JSON history endpoint              |
| `/api/stats` | JSON stats endpoint                  |

---

## 📊 Database Tables

- **scan_history** — Every URL scan with result, threat type, timestamp
- **threat_stats** — Daily aggregated scan statistics
- **url_whitelist** — Trusted domains (bypass API check)

---

## 🔒 Threat Types Detected

- `SOCIAL_ENGINEERING` → Phishing pages
- `MALWARE` → Malware distribution
- `UNWANTED_SOFTWARE` → PUPs
- `POTENTIALLY_HARMFUL_APPLICATION` → Android threats

---

## 📦 Dependencies

```
flask==3.0.3
flask-mysqldb==2.0.0
requests==2.32.3
python-dotenv==1.0.1
flask-cors==4.0.1
mysqlclient==2.2.4
```

> **Note on mysqlclient (Linux):** You may need `sudo apt install libmysqlclient-dev python3-dev` before pip install.
