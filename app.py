"""
Phishing Detector - Flask Application
Uses Google Safe Browsing API + MySQL + Heuristic Engine
"""

import os
import re
import math
import json
import socket
import requests
from datetime import datetime, date
from urllib.parse import urlparse, unquote
from flask import Flask, render_template, request, jsonify, redirect, url_for
import pymysql.cursors
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

# ---- Config ----
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key')
app.config['MYSQL_HOST'] = os.getenv('MYSQL_HOST', 'localhost')
app.config['MYSQL_PORT'] = int(os.getenv('MYSQL_PORT', 3306))
app.config['MYSQL_USER'] = os.getenv('MYSQL_USER', 'root')
app.config['MYSQL_PASSWORD'] = os.getenv('MYSQL_PASSWORD', '')
app.config['MYSQL_DB'] = os.getenv('MYSQL_DB', 'phishing_detector')
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

GOOGLE_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY', '')
SAFE_BROWSING_URL = (
    f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
)

# Simple MySQL wrapper using PyMySQL
class MySQL:
    def __init__(self, app):
        self.app = app
        self._conn = None

    @property
    def connection(self):
        if self._conn is None or not self._conn.open:
            self._conn = pymysql.connect(
                host=self.app.config['MYSQL_HOST'],
                port=self.app.config['MYSQL_PORT'],
                user=self.app.config['MYSQL_USER'],
                password=self.app.config['MYSQL_PASSWORD'],
                database=self.app.config['MYSQL_DB'],
                cursorclass=pymysql.cursors.DictCursor,
                autocommit=True
            )
        return self._conn

mysql = MySQL(app)


# =============================================================
# HEURISTIC ENGINE
# =============================================================

# Legitimate brands that phishers commonly impersonate
BRAND_KEYWORDS = [
    "paypal", "paytm", "phonepe", "gpay", "googlepay",
    "amazon", "flipkart", "snapdeal", "meesho",
    "netflix", "hotstar", "jiocinema",
    "sbi", "hdfc", "icici", "axis", "kotak", "pnb", "bankofbaroda",
    "ubi", "rbl", "yesbank", "federalbank",
    "google", "facebook", "instagram", "whatsapp", "twitter",
    "apple", "microsoft", "outlook", "office365",
    "irctc", "uidai", "incometax", "epfo", "aadhaar",
    "upi", "bhim", "npci",
    "wellsfargo", "chase", "citibank", "barclays",
    "dhl", "fedex", "bluedart", "indiapost",
]

# Dangerous TLDs commonly used in phishing
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",   # Free Freenom TLDs
    ".xyz", ".top", ".click", ".link",
    ".download", ".zip", ".review",
    ".country", ".kim", ".stream",
    ".gdn", ".men", ".loan", ".win",
    ".bid", ".trade", ".date", ".faith",
}

# Legitimate TLDs for brand domains (not suspicious by themselves)
TRUSTED_TLDS = {".com", ".org", ".net", ".gov", ".edu", ".in", ".co.in", ".gov.in"}

# URL shortener domains — hide the real destination
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly",
    "short.link", "rebrand.ly", "cutt.ly", "is.gd",
    "buff.ly", "adf.ly", "bc.vc", "tiny.cc",
}

# Phishing keyword signals in path/query
PHISHING_KEYWORDS = [
    "login", "signin", "sign-in", "log-in",
    "verify", "verification", "validate", "confirm",
    "update", "update-account", "account-update",
    "secure", "security", "secure-login",
    "banking", "netbanking", "e-banking",
    "password", "passwd", "credentials",
    "otp", "two-factor", "2fa",
    "suspend", "suspended", "locked", "unlock",
    "urgent", "alert", "warning", "notice",
    "prize", "winner", "congratulations", "reward",
    "kyc", "pan", "aadhar", "aadhaar",
    "refund", "cashback", "offer", "free",
    "click-here", "act-now", "limited-time",
]

# Known phishing/malware domain patterns (regex)
KNOWN_PHISH_PATTERNS = [
    r'paypal[^.]*\.(?!com\b)',          # paypal-something.xyz
    r'amazon[^.]*-(?:login|signin)',    # amazon-login.net
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}',  # Raw IP address as host
    r'(?:bank|secure|account)[^.]*\.(?:xyz|top|tk|ml)',
    r'(?:verify|update|confirm)[^.]*\.(?:xyz|top|tk|ml|ga)',
    r'(?:free|prize|winner|reward)[^.]*\.(com|net|xyz)',
    r'(?:support|helpdesk|customer)[^.]*(?:paypal|amazon|apple|google)',
]


def shannon_entropy(string: str) -> float:
    """
    Calculate Shannon entropy of a string.
    High entropy (>3.5) in subdomains = likely randomly generated = phishing.
    """
    if not string:
        return 0.0
    freq = {}
    for ch in string:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(string)
    entropy = -sum((c / length) * math.log2(c / length) for c in freq.values())
    return round(entropy, 4)


def count_special_chars(url: str) -> dict:
    """Count special characters that inflate URL complexity."""
    return {
        "hyphens":     url.count("-"),
        "dots":        url.count("."),
        "at_signs":    url.count("@"),
        "double_slash":url.count("//") - 1,   # subtract the protocol //
        "percent":     url.count("%"),
        "equals":      url.count("="),
        "ampersand":   url.count("&"),
        "tildes":      url.count("~"),
        "underscores": url.count("_"),
    }


def has_ip_host(parsed) -> bool:
    """Check if the host is a raw IP address (huge phishing signal)."""
    host = parsed.hostname or ""
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')
    return bool(ip_pattern.match(host))


def check_typosquatting(domain: str) -> tuple[bool, str]:
    """
    Detect typosquatting — slight misspellings of trusted brands.
    e.g. paypa1.com, arnazon.com, g00gle.com
    """
    # Leet-speak normalisation
    leet_map = str.maketrans("013456789", "oieasbgpq")
    normalised = domain.lower().translate(leet_map)

    for brand in BRAND_KEYWORDS:
        # Exact brand in domain is handled elsewhere — skip
        if brand in normalised:
            continue
        # Levenshtein-lite: check if domain is within edit distance 2
        if _edit_distance(normalised.split(".")[0], brand) <= 2 and len(brand) > 4:
            return True, brand
    return False, ""


def _edit_distance(s1: str, s2: str) -> int:
    """Simple Levenshtein distance for typosquatting detection."""
    if abs(len(s1) - len(s2)) > 3:
        return 99
    m, n = len(s1), len(s2)
    dp = list(range(n + 1))
    for i in range(1, m + 1):
        prev = dp[:]
        dp[0] = i
        for j in range(1, n + 1):
            cost = 0 if s1[i-1] == s2[j-1] else 1
            dp[j] = min(dp[j] + 1, dp[j-1] + 1, prev[j-1] + cost)
    return dp[n]


def brand_in_subdomain(parsed) -> tuple[bool, str]:
    """
    Detect brand name used in subdomain to look legitimate.
    e.g. paypal.com.evilsite.tk  →  paypal is subdomain, real domain is evilsite.tk
    """
    host = parsed.hostname or ""
    parts = host.split(".")
    # The real domain is last 2 parts (or 3 for co.in etc)
    if len(parts) > 2:
        subdomains = ".".join(parts[:-2]).lower()
        for brand in BRAND_KEYWORDS:
            if brand in subdomains:
                return True, brand
    return False, ""


def analyze_heuristics(url: str) -> dict:
    """
    Full heuristic analysis of a URL.
    Returns a scored risk report with individual signals.
    """
    signals   = []   # list of { name, severity, description }
    score     = 0    # 0-100 risk score
    parsed    = urlparse(url)
    domain    = parsed.hostname or ""
    full_path = parsed.path + "?" + parsed.query if parsed.query else parsed.path
    url_lower = url.lower()

    # ── 1. Raw IP address as host ──────────────────────────────
    if has_ip_host(parsed):
        score += 30
        signals.append({
            "name": "IP Address as Host",
            "severity": "CRITICAL",
            "description": f"URL uses a raw IP ({domain}) instead of a domain name. "
                           "Legitimate sites never do this."
        })

    # ── 2. No HTTPS ────────────────────────────────────────────
    if parsed.scheme != "https":
        score += 15
        signals.append({
            "name": "No HTTPS",
            "severity": "HIGH",
            "description": "URL uses HTTP instead of HTTPS. All legitimate banking/payment sites use HTTPS."
        })

    # ── 3. Suspicious TLD ──────────────────────────────────────
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 20
            signals.append({
                "name": "Suspicious TLD",
                "severity": "HIGH",
                "description": f"Domain uses '{tld}' — a free/disposable TLD heavily associated with phishing."
            })
            break

    # ── 4. URL shortener ───────────────────────────────────────
    if domain in URL_SHORTENERS:
        score += 20
        signals.append({
            "name": "URL Shortener",
            "severity": "HIGH",
            "description": f"'{domain}' is a URL shortener that hides the real destination."
        })

    # ── 5. Brand in subdomain (brand hijacking) ────────────────
    brand_sub, brand_name = brand_in_subdomain(parsed)
    if brand_sub:
        score += 35
        signals.append({
            "name": "Brand Hijacking in Subdomain",
            "severity": "CRITICAL",
            "description": f"'{brand_name}' appears in the subdomain to look legitimate, "
                           f"but the real domain is '{domain}'. Classic phishing trick."
        })

    # ── 6. Brand keyword in domain (not the real brand domain) ─
    parts = domain.split(".")
    apex  = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    for brand in BRAND_KEYWORDS:
        if brand in apex and brand not in apex.split(".")[0]:
            # brand is in the TLD portion weirdly
            pass
        elif brand in domain and domain != f"{brand}.com" and domain != f"{brand}.in":
            score += 25
            signals.append({
                "name": "Brand Impersonation",
                "severity": "CRITICAL",
                "description": f"Domain contains '{brand}' but is NOT the official {brand} website. "
                               f"Real domain: '{domain}'"
            })
            break

    # ── 7. Typosquatting ───────────────────────────────────────
    is_typo, typo_brand = check_typosquatting(domain)
    if is_typo:
        score += 25
        signals.append({
            "name": "Typosquatting Detected",
            "severity": "HIGH",
            "description": f"Domain '{domain}' looks like a misspelling of '{typo_brand}'. "
                           "Attackers register near-identical domains to trick users."
        })

    # ── 8. Phishing keywords in path/query ─────────────────────
    matched_keywords = [kw for kw in PHISHING_KEYWORDS if kw in url_lower]
    if matched_keywords:
        kw_score = min(len(matched_keywords) * 8, 30)
        score += kw_score
        signals.append({
            "name": "Phishing Keywords in URL",
            "severity": "MEDIUM" if kw_score < 20 else "HIGH",
            "description": f"URL contains suspicious keywords: {', '.join(matched_keywords[:5])}. "
                           "These are commonly used to craft convincing phishing pages."
        })

    # ── 9. Excessive subdomains ────────────────────────────────
    subdomain_count = len(parts) - 2
    if subdomain_count >= 3:
        score += 15
        signals.append({
            "name": "Excessive Subdomains",
            "severity": "MEDIUM",
            "description": f"URL has {subdomain_count} subdomains. "
                           "Phishers use deep subdomains to hide the real domain."
        })

    # ── 10. URL length ─────────────────────────────────────────
    url_length = len(url)
    if url_length > 100:
        bonus = min((url_length - 100) // 20 * 5, 15)
        score += bonus
        signals.append({
            "name": "Abnormally Long URL",
            "severity": "LOW",
            "description": f"URL is {url_length} characters long. "
                           "Long URLs are used to hide the real domain in the path."
        })

    # ── 11. @ symbol in URL ────────────────────────────────────
    if "@" in url:
        score += 20
        signals.append({
            "name": "@ Symbol in URL",
            "severity": "HIGH",
            "description": "Browser ignores everything before '@' in a URL. "
                           "e.g. https://paypal.com@evil.com  →  goes to evil.com"
        })

    # ── 12. Double slash in path ───────────────────────────────
    if "//" in parsed.path:
        score += 10
        signals.append({
            "name": "Double Slash in Path",
            "severity": "LOW",
            "description": "Double slashes in the path are used to confuse security scanners."
        })

    # ── 13. High entropy subdomain ─────────────────────────────
    if len(parts) > 2:
        subdomain_str = ".".join(parts[:-2])
        entropy = shannon_entropy(subdomain_str)
        if entropy > 3.5:
            score += 20
            signals.append({
                "name": "High Entropy Subdomain",
                "severity": "HIGH",
                "description": f"Subdomain '{subdomain_str}' has Shannon entropy of {entropy} (>3.5). "
                               "Randomly generated subdomains indicate DGA (Domain Generation Algorithm) malware."
            })

    # ── 14. Known phishing regex patterns ──────────────────────
    for pattern in KNOWN_PHISH_PATTERNS:
        if re.search(pattern, url_lower):
            score += 25
            signals.append({
                "name": "Known Phishing Pattern",
                "severity": "CRITICAL",
                "description": f"URL matches a known phishing URL pattern (regex: {pattern[:40]}...)."
            })
            break

    # ── 15. Hex / percent encoding in domain ──────────────────
    if "%" in domain:
        score += 15
        signals.append({
            "name": "Encoded Characters in Domain",
            "severity": "HIGH",
            "description": "Hex-encoded characters in the domain hide the real destination from users."
        })

    # ── 16. Multiple redirects indicator ──────────────────────
    special = count_special_chars(url)
    if special["equals"] >= 2 and "url=" in url_lower:
        score += 15
        signals.append({
            "name": "Open Redirect Indicator",
            "severity": "HIGH",
            "description": "URL contains redirect parameters (url=, redirect=, next=) "
                           "which may chain through multiple sites to hide the final destination."
        })

    # ── 17. Punycode / IDN homograph attack ───────────────────
    if "xn--" in domain:
        score += 25
        signals.append({
            "name": "Punycode / IDN Homograph Attack",
            "severity": "CRITICAL",
            "description": f"Domain uses Punycode (xn--). Attackers use lookalike Unicode characters "
                           f"(e.g. 'pаypal.com' with Cyrillic 'а') that are visually identical to real domains."
        })

    # Cap score at 100
    score = min(score, 100)

    # Determine final heuristic verdict
    if score >= 60:
        verdict = "phishing"
    elif score >= 30:
        verdict = "suspicious"
    else:
        verdict = "safe"

    return {
        "heuristic_score":   score,
        "heuristic_verdict": verdict,
        "signals":           signals,
        "signal_count":      len(signals),
        "special_chars":     count_special_chars(url),
        "url_length":        len(url),
        "entropy":           shannon_entropy(domain),
    }


# =============================================================
# COMBINED VERDICT
# =============================================================

def combine_verdicts(gsb_result: dict, heuristic: dict) -> dict:
    """
    Merge Google Safe Browsing result with heuristic analysis.
    GSB finding always wins. If GSB says safe but heuristics
    score high, we escalate appropriately.
    """
    gsb_status   = gsb_result.get("status", "error")
    h_verdict    = heuristic["heuristic_verdict"]
    h_score      = heuristic["heuristic_score"]

    # GSB found a real threat — trust it
    if gsb_status in ("phishing", "suspicious"):
        final_status  = gsb_status
        final_message = f"[Google Safe Browsing] {gsb_result.get('message', '')}. " \
                        f"Heuristic risk score: {h_score}/100."
        final_source  = "google_safe_browsing"

    # GSB says safe/error but heuristics flagged high
    elif h_verdict == "phishing":
        final_status  = "phishing"
        final_message = (
            f"Google Safe Browsing: {gsb_status}. "
            f"However, heuristic analysis detected {heuristic['signal_count']} phishing signals "
            f"with a risk score of {h_score}/100."
        )
        final_source  = "heuristic"

    elif h_verdict == "suspicious":
        final_status  = "suspicious"
        final_message = (
            f"Google Safe Browsing: {gsb_status}. "
            f"Heuristic analysis found {heuristic['signal_count']} suspicious patterns "
            f"(risk score: {h_score}/100). Proceed with caution."
        )
        final_source  = "heuristic"

    else:
        final_status  = "safe"
        final_message = (
            f"Google Safe Browsing: No threats detected. "
            f"Heuristic risk score: {h_score}/100. URL appears safe."
        )
        final_source  = "both"

    return {
        "status":          final_status,
        "message":         final_message,
        "source":          final_source,
        "threat_type":     gsb_result.get("threat_type"),
        "platform":        gsb_result.get("platform"),
        "threat_entry_type": gsb_result.get("threat_entry_type"),
        "heuristic":       heuristic,
    }


# =============================================================
# Helpers (same as before)
# =============================================================

def extract_domain(url: str) -> str:
    pattern = r'(?:https?://)?(?:www\.)?([^/?\s]+)'
    match = re.search(pattern, url.lower())
    return match.group(1) if match else url.lower()


def is_whitelisted(url: str) -> bool:
    domain = extract_domain(url)
    try:
        cur = mysql.connection.cursor()
        cur.execute(
            "SELECT id FROM url_whitelist WHERE %s LIKE CONCAT('%%', domain)",
            (domain,)
        )
        result = cur.fetchone()
        cur.close()
        return result is not None
    except Exception:
        return False


def check_safe_browsing(url: str) -> dict:
    if not GOOGLE_API_KEY or GOOGLE_API_KEY in ('', 'YOUR_GOOGLE_API_KEY_HERE'):
        return {
            'status': 'error',
            'message': 'Google Safe Browsing API key not configured',
            'threat_type': None, 'platform': None, 'threat_entry_type': None
        }

    payload = {
        "client": {"clientId": "phishing-detector-app", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": [
                "MALWARE", "SOCIAL_ENGINEERING",
                "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"
            ],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        resp = requests.post(SAFE_BROWSING_URL, json=payload, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        if 'matches' in data and data['matches']:
            match = data['matches'][0]
            threat_type = match.get('threatType', 'UNKNOWN')
            status = 'phishing' if threat_type in ('SOCIAL_ENGINEERING', 'MALWARE') else 'suspicious'
            return {
                'status': status,
                'message': f'Threat detected: {threat_type}',
                'threat_type': threat_type,
                'platform': match.get('platformType', 'UNKNOWN'),
                'threat_entry_type': match.get('threatEntryType', 'UNKNOWN')
            }
        return {
            'status': 'safe',
            'message': 'No threats found by Google Safe Browsing',
            'threat_type': None, 'platform': None, 'threat_entry_type': None
        }

    except requests.exceptions.Timeout:
        return {'status': 'error', 'message': 'API request timed out',
                'threat_type': None, 'platform': None, 'threat_entry_type': None}
    except requests.exceptions.RequestException as e:
        return {'status': 'error', 'message': f'API request failed: {str(e)}',
                'threat_type': None, 'platform': None, 'threat_entry_type': None}


def save_scan(url, result_data, ip=None, ua=None):
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            INSERT INTO scan_history
                (url, result, threat_type, platform, threat_entry_type, ip_address, user_agent)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
        """, (
            url,
            result_data['status'],
            result_data.get('threat_type'),
            result_data.get('platform'),
            result_data.get('threat_entry_type'),
            ip, ua
        ))
        mysql.connection.commit()
        cur.close()

        today     = date.today()
        status    = result_data['status']
        count_col = {'safe': 'safe_count', 'phishing': 'phishing_count',
                     'suspicious': 'suspicious_count'}.get(status)

        if count_col:
            cur2 = mysql.connection.cursor()
            cur2.execute(f"""
                INSERT INTO threat_stats (stat_date, total_scans, {count_col})
                VALUES (%s, 1, 1)
                ON DUPLICATE KEY UPDATE
                    total_scans = total_scans + 1,
                    {count_col} = {count_col} + 1
            """, (today,))
            mysql.connection.commit()
            cur2.close()

    except Exception as e:
        print(f"[DB ERROR] save_scan: {e}")


# =============================================================
# Routes
# =============================================================

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url  = (data.get('url') or '').strip()

    if not url:
        return jsonify({'status': 'error', 'message': 'URL is required'}), 400

    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url

    url_pattern = re.compile(
        r'^https?://'
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'
        r'localhost|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
        r'(?::\d+)?(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    if not url_pattern.match(url):
        return jsonify({'status': 'error', 'message': 'Invalid URL format'}), 400

    # Whitelist check — skip analysis entirely
    if is_whitelisted(url):
        result = {
            'status': 'safe',
            'message': 'URL is in the trusted whitelist',
            'threat_type': None, 'platform': None, 'threat_entry_type': None,
            'url': url, 'whitelisted': True,
            'heuristic': None, 'source': 'whitelist'
        }
        save_scan(url, result, request.remote_addr, request.user_agent.string)
        return jsonify(result)

    # ── Run both engines in parallel (sequential here, fast enough) ──
    gsb_result = check_safe_browsing(url)
    heuristic  = analyze_heuristics(url)
    combined   = combine_verdicts(gsb_result, heuristic)

    combined['url']         = url
    combined['whitelisted'] = False
    combined['scanned_at']  = datetime.utcnow().isoformat() + 'Z'

    save_scan(url, combined, request.remote_addr, request.user_agent.string)
    return jsonify(combined)


@app.route('/history')
def history():
    return render_template('history.html')


@app.route('/api/history')
def api_history():
    page          = int(request.args.get('page', 1))
    per_page      = int(request.args.get('per_page', 20))
    filter_result = request.args.get('filter', 'all')
    offset        = (page - 1) * per_page

    try:
        cur    = mysql.connection.cursor()
        where  = ""
        params = []
        if filter_result != 'all':
            where  = "WHERE result = %s"
            params = [filter_result]

        cur.execute(f"SELECT COUNT(*) as total FROM scan_history {where}", params)
        total = cur.fetchone()['total']

        cur.execute(f"""
            SELECT id, url, result, threat_type, platform, scanned_at
            FROM scan_history {where}
            ORDER BY scanned_at DESC
            LIMIT %s OFFSET %s
        """, params + [per_page, offset])
        rows = cur.fetchall()
        cur.close()

        for row in rows:
            if row.get('scanned_at'):
                row['scanned_at'] = row['scanned_at'].strftime('%Y-%m-%d %H:%M:%S')

        return jsonify({'data': rows, 'total': total, 'page': page, 'per_page': per_page})
    except Exception as e:
        print(f"[API ERROR] /api/history: {e}")
        return jsonify({'error': str(e), 'data': [], 'total': 0}), 500


@app.route('/api/stats')
def api_stats():
    try:
        cur = mysql.connection.cursor()
        cur.execute("""
            SELECT
                COUNT(*) AS total_scans,
                SUM(result = 'phishing')  AS phishing_count,
                SUM(result = 'safe')      AS safe_count,
                SUM(result = 'suspicious') AS suspicious_count
            FROM scan_history
        """)
        stats = cur.fetchone()

        cur.execute("""
            SELECT stat_date, total_scans, phishing_count, safe_count
            FROM threat_stats
            ORDER BY stat_date DESC LIMIT 7
        """)
        chart_data = cur.fetchall()
        cur.close()

        for row in chart_data:
            if row.get('stat_date'):
                row['stat_date'] = str(row['stat_date'])

        return jsonify({'stats': stats, 'chart': chart_data})
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')


if __name__ == '__main__':
    debug = os.getenv('FLASK_DEBUG', 'True').lower() == 'true'
    app.run(debug=debug, host='0.0.0.0', port=5000)
