/**
 * PhishGuard - Main JavaScript
 * Handles URL scanning & result rendering
 */

async function scanURL() {
    const input = document.getElementById('urlInput');
    const scanBtn = document.getElementById('scanBtn');
    const btnText = document.getElementById('btnText');
    const btnLoader = document.getElementById('btnLoader');
    const scannerCard = document.getElementById('scannerCard');
    const resultCard = document.getElementById('resultCard');

    const url = input.value.trim();
    if (!url) {
        shakeInput(input);
        return;
    }

    // Loading state
    scanBtn.disabled = true;
    btnText.textContent = 'SCANNING';
    btnLoader.classList.remove('hidden');

    try {
        const res = await fetch('/scan', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ url })
        });

        const data = await res.json();
        saveToLocalStorage(data);
        renderResult(data, resultCard, scannerCard);
    } catch (err) {
        renderResult({
            status: 'error',
            message: 'Network error. Is the Flask server running?',
            url: url
        }, resultCard, scannerCard);
    } finally {
        scanBtn.disabled = false;
        btnText.textContent = 'SCAN NOW';
        btnLoader.classList.add('hidden');
    }
}

function renderResult(data, resultCard, scannerCard) {
    const icons = {
        safe: '✅',
        phishing: '🚨',
        suspicious: '⚠️',
        error: '❌'
    };

    const labels = {
        safe: 'SAFE',
        phishing: 'PHISHING DETECTED',
        suspicious: 'SUSPICIOUS',
        error: 'ERROR'
    };

    // Build detail tags
    let detailsHTML = '';

    // 1. Show Heuristic Score
    if (data.heuristic && data.heuristic.heuristic_score !== undefined) {
        const score = data.heuristic.heuristic_score;
        let scoreClass = score >= 60 ? 'score-high' : (score >= 30 ? 'score-med' : 'score-low');
        detailsHTML += `<span class="detail-tag ${scoreClass}">RISK SCORE: ${score}/100</span>`;
    }

    // 2. Show Source
    if (data.source) {
        const sourceName = data.source === 'google_safe_browsing' ? 'GOOGLE API' : (data.source === 'heuristic' ? 'HEURISTIC ENGINE' : 'HYBRID SCAN');
        detailsHTML += `<span class="detail-tag source-tag">${sourceName}</span>`;
    }

    // 3. Show Google Threat Type
    if (data.threat_type) {
        detailsHTML += `<span class="detail-tag threat-tag">THREAT: ${data.threat_type}</span>`;
    }

    // 4. Show Individual Heuristic Signals
    if (data.heuristic && data.heuristic.signals) {
        data.heuristic.signals.forEach(sig => {
            detailsHTML += `<span class="detail-tag signal-tag" title="${sig.description}">${sig.name}</span>`;
        });
    }

    if (data.whitelisted) {
        detailsHTML += `<span class="detail-tag whitelist-tag">✓ WHITELISTED DOMAIN</span>`;
    }

    // Populate
    document.getElementById('resultIcon').textContent = icons[data.status] || '❓';
    document.getElementById('resultLabel').textContent = labels[data.status] || data.status.toUpperCase();
    document.getElementById('resultURL').textContent = data.url || '';
    document.getElementById('resultMessage').textContent = data.message || '';
    document.getElementById('resultDetails').innerHTML = detailsHTML;

    // Style the card
    resultCard.className = `result-card result-${data.status}`;
    resultCard.classList.remove('hidden');

    // Set card result class for color
    resultCard.classList.add(`res-${data.status}`);

    // Hide scanner, show result
    if (scannerCard) scannerCard.classList.add('hidden');

    resultCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
}

function resetScanner() {
    const scannerCard = document.getElementById('scannerCard');
    const resultCard = document.getElementById('resultCard');
    const input = document.getElementById('urlInput');

    if (resultCard) resultCard.classList.add('hidden');
    if (scannerCard) scannerCard.classList.remove('hidden');
    const input = document.getElementById('urlInput');
    if (input) input.focus();
}

function saveToLocalStorage(data) {
    if (!data || data.status === 'error') return;
    
    let history = JSON.parse(localStorage.getItem('phishguard_history') || '[]');
    
    const newEntry = {
        url: data.url,
        result: data.status,
        threat_type: data.threat_type || 'N/A',
        platform: data.platform || 'N/A',
        scanned_at: new Date().toLocaleString(),
        score: data.heuristic ? data.heuristic.heuristic_score : 0
    };
    
    // Add to start, avoid duplicates if same URL scanned twice in a row
    if (history.length > 0 && history[0].url === newEntry.url) {
        history[0] = newEntry; // update timestamp
    } else {
        history.unshift(newEntry);
    }
    
    if (history.length > 50) history = history.slice(0, 50);
    localStorage.setItem('phishguard_history', JSON.stringify(history));
}

function shakeInput(el) {
    el.style.animation = 'none';
    el.offsetHeight; // reflow
    el.style.animation = 'shake 0.4s ease';
    el.addEventListener('animationend', () => { el.style.animation = ''; }, { once: true });
}

// Add shake keyframe
const style = document.createElement('style');
style.textContent = `
@keyframes shake {
    0%, 100% { transform: translateX(0); }
    20% { transform: translateX(-8px); }
    40% { transform: translateX(8px); }
    60% { transform: translateX(-4px); }
    80% { transform: translateX(4px); }
}`;
document.head.appendChild(style);
