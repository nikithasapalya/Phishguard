# PhishGuard v3 — What's New

## 🛡 Hybrid Detection Engine
The scanner now uses a **3-layer pipeline** instead of relying only on the ML model:

1. **Allowlist** (~150 trusted apex domains: Google, YouTube, GitHub, SBI, HDFC, PayPal, Microsoft, Amazon, etc.)
   → instant **2% risk / CLEAN**
2. **Blocklist** (raw IP host, `@` obfuscation, punycode, brand-spoof in subdomain, suspicious TLD + login keywords)
   → instant **97% risk / HIGH**
3. **ML model** (Random Forest, 21 features, trained on 5,000 phishing + 5,000 legit URLs)
   → calibrated **0–100% risk score**

## 🎚 Calibrated Risk Bands
- **0–30%** → Safe (green)
- **30–55%** → Low Risk
- **55–80%** → Suspicious
- **80–100%** → High Risk (red)

## 🆕 New `/bulk_scan` endpoint
POST `{"urls": ["...", "..."]}` → batch-scan up to 50 URLs with summary counts.

## 🏫 Yenepoya University Portals Added to Allowlist
The following institutional URLs are now trusted (instant CLEAN, 2% risk):
- `yenepoya.edu.in` — Main university website
- `student.yenepoya.edu.in` — Student portal
- `ytincubator.com` — YT Incubator (startup cell)
- `yengage.yenepoya.edu.in` — YEngage portal
- `vidyen.yenepoya.in` — VidYen learning platform
- `ydc.yenepoya.edu.in` — Yenepoya Dental College portal

## 📈 Bigger Training Set
Legit URL corpus expanded from ~80 → **150+ diverse real-world URLs** with paths, subdomains, search queries.

## 🔍 Dashboard already supports
- WHOIS lookup
- Full security report (`/report` returns ML + features + WHOIS + indicators + recommendations)
- 7-day trend chart, threat logs, smooth scrolling sidebar nav
