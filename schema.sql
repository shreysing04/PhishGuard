-- =============================================
-- Phishing Detector - MySQL Database Schema
-- =============================================

CREATE DATABASE IF NOT EXISTS phishing_detector;
USE phishing_detector;

-- ---- Scan history table ----
CREATE TABLE IF NOT EXISTS scan_history (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url TEXT NOT NULL,
    result ENUM('safe', 'phishing', 'suspicious', 'error') NOT NULL,
    threat_type VARCHAR(100) DEFAULT NULL,
    platform VARCHAR(100) DEFAULT NULL,
    threat_entry_type VARCHAR(100) DEFAULT NULL,
    scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45) DEFAULT NULL,
    user_agent TEXT DEFAULT NULL
);

-- ---- Threat stats summary table ----
CREATE TABLE IF NOT EXISTS threat_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    stat_date DATE NOT NULL,
    total_scans INT DEFAULT 0,
    phishing_count INT DEFAULT 0,
    safe_count INT DEFAULT 0,
    suspicious_count INT DEFAULT 0,
    UNIQUE KEY unique_date (stat_date)
);

-- ---- Whitelist table ----
CREATE TABLE IF NOT EXISTS url_whitelist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    domain VARCHAR(255) NOT NULL UNIQUE,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reason VARCHAR(255) DEFAULT NULL
);

-- ---- Insert some trusted domains ----
INSERT IGNORE INTO url_whitelist (domain, reason) VALUES
('google.com', 'Major search engine'),
('github.com', 'Developer platform'),
('stackoverflow.com', 'Developer Q&A'),
('wikipedia.org', 'Encyclopedia'),
('youtube.com', 'Video platform');

-- ---- View: recent threats ----
CREATE OR REPLACE VIEW recent_threats AS
SELECT url, result, threat_type, scanned_at
FROM scan_history
WHERE result IN ('phishing', 'suspicious')
ORDER BY scanned_at DESC
LIMIT 50;
