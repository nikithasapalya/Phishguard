"""
PhishGuard Flask API + Dashboard.

Run from anywhere:
    python api/app.py
or:
    cd api && python app.py
"""
import os
import sys
import sqlite3
import socket
from datetime import datetime, timedelta

import joblib
from flask import Flask, request, jsonify, render_template, g
from flask_cors import CORS

# ── Paths (anchor everything to this file, not CWD) ──────────────────────────
HERE      = os.path.dirname(os.path.abspath(__file__))
ROOT      = os.path.dirname(HERE)
MODEL_DIR = os.path.join(ROOT, "model")
sys.path.insert(0, MODEL_DIR)

from feature_extractor import features_to_list, extract_features  # noqa: E402
from trust_lists import (                                          # noqa: E402
    is_allowlisted, hard_phishing_signals, risk_band,
)

MODEL_PATH  = os.path.join(MODEL_DIR, "phishing_model.pkl")
SCALER_PATH = os.path.join(MODEL_DIR, "scaler.pkl")
DB_PATH     = os.path.join(HERE, "detections.db")

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# ── Always return JSON errors, never HTML ────────────────────────────────────
@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Endpoint not found", "status": 404}), 404

@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({"error": "Method not allowed", "status": 405}), 405

@app.errorhandler(500)
def internal_error(e):
    return jsonify({"error": "Internal server error", "status": 500}), 500

# ── Ensure JSON content-type on all API responses ────────────────────────────
@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"]  = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type,Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET,POST,OPTIONS"
    return response

# ── Load model ───────────────────────────────────────────────────────────────
model = scaler = None
try:
    model  = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    print("[OK] Model + scaler loaded.")
except Exception as e:
    print(f"[!] Could not load model artifacts: {e}")
    print("    Run: python model/train_model.py")

# ── DB helpers ───────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(_):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS detections (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            url        TEXT NOT NULL,
            prediction TEXT NOT NULL,
            confidence REAL NOT NULL,
            risk_score REAL NOT NULL DEFAULT 0,
            timestamp  TEXT NOT NULL,
            source     TEXT DEFAULT 'api'
        )
    """)
    cols = [r[1] for r in conn.execute("PRAGMA table_info(detections)").fetchall()]
    if "risk_score" not in cols:
        conn.execute("ALTER TABLE detections ADD COLUMN risk_score REAL NOT NULL DEFAULT 0")
    conn.commit()
    conn.close()

init_db()

# ── Routes ───────────────────────────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/predict", methods=["POST", "OPTIONS"])
def predict():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    if model is None or scaler is None:
        return jsonify({"error": "Model not loaded. Run train_model.py first."}), 503
    try:
        data   = request.get_json(silent=True) or {}
        url    = (data.get("url") or "").strip()
        source = (data.get("source") or "api").strip()
        if not url:
            return jsonify({"error": "Missing URL"}), 400

        # ── Hybrid layer 1: trusted-domain allowlist ────────────────────────
        decision_source = "ml"
        if is_allowlisted(url):
            risk_score      = 0.02
            decision_source = "allowlist"
        else:
            hard = hard_phishing_signals(url)
            if hard:
                risk_score      = 0.97
                decision_source = "blocklist"
            else:
                feats      = features_to_list(url, is_training=False)
                X          = scaler.transform([feats])
                probs      = model.predict_proba(X)[0]
                risk_score = float(probs[1])

        is_phishing = risk_score >= 0.55
        confidence  = risk_score if is_phishing else (1.0 - risk_score)
        severity, verdict = risk_band(risk_score)

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO detections (url, prediction, confidence, risk_score, timestamp, source)"
                " VALUES (?,?,?,?,?,?)",
                (
                    url,
                    "phishing" if is_phishing else "legitimate",
                    round(confidence, 4),
                    round(risk_score, 4),
                    datetime.utcnow().isoformat(),
                    source,
                ),
            )
            conn.commit()
        except Exception as e:
            print(f"[!] DB insert failed: {e}")

        return jsonify({
            "url":             url,
            "prediction":      "phishing" if is_phishing else "legitimate",
            "is_phishing":     bool(is_phishing),
            "risk_score":      round(risk_score, 4),
            "risk_percent":    round(risk_score * 100, 1),
            "confidence":      round(confidence, 4),
            "severity":        severity,
            "verdict":         verdict,
            "decision_source": decision_source,
        })
    except Exception as e:
        print(f"[!] /predict error: {e}")
        return jsonify({"error": "Internal server error", "details": str(e)}), 500


@app.route("/stats", methods=["GET", "OPTIONS"])
def stats():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    try:
        conn  = get_db()
        total = conn.execute("SELECT COUNT(*) FROM detections").fetchone()[0]
        phish = conn.execute(
            "SELECT COUNT(*) FROM detections WHERE prediction='phishing'"
        ).fetchone()[0]
        legit = conn.execute(
            "SELECT COUNT(*) FROM detections WHERE prediction='legitimate'"
        ).fetchone()[0]
        avg_conf_row = conn.execute("SELECT AVG(confidence) FROM detections").fetchone()[0]
        avg_conf = float(avg_conf_row) if avg_conf_row is not None else 0.0
        rate     = round((phish / total) * 100, 1) if total else 0.0

        trend = []
        today = datetime.utcnow().date()
        for i in range(6, -1, -1):
            day     = today - timedelta(days=i)
            day_iso = day.isoformat()
            n = conn.execute(
                "SELECT COUNT(*) FROM detections "
                "WHERE prediction='phishing' AND substr(timestamp,1,10)=?",
                (day_iso,),
            ).fetchone()[0]
            trend.append({"date": day.strftime("%b %d"), "phishing": n})

        return jsonify({
            "total_scanned":  total,
            "phishing_found": phish,
            "legitimate":     legit,
            "avg_confidence": round(avg_conf, 4),
            "phishing_rate":  rate,
            "trend":          trend,
        })
    except Exception as e:
        print(f"[!] /stats error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/logs", methods=["GET", "OPTIONS"])
def logs():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    try:
        limit = int(request.args.get("limit", 50))
        ftype = request.args.get("type", "all").lower()
        q      = "SELECT url, prediction, confidence, risk_score, timestamp, source FROM detections"
        params: tuple = ()
        if ftype in ("phishing", "legitimate"):
            q     += " WHERE prediction = ?"
            params = (ftype,)
        q     += " ORDER BY id DESC LIMIT ?"
        params = params + (limit,)
        rows   = get_db().execute(q, params).fetchall()
        return jsonify({"logs": [dict(r) for r in rows]})
    except Exception as e:
        print(f"[!] /logs error: {e}")
        return jsonify({"error": str(e), "logs": []}), 500


# ── WHOIS — with robust fallback, never returns HTML ────────────────────────
@app.route("/whois", methods=["POST", "OPTIONS"])
def whois_lookup():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    try:
        data   = request.get_json(silent=True) or {}
        url    = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "Missing URL"}), 400

        domain = url.split("//")[-1].split("/")[0].split(":")[0].lower().strip()
        if not domain:
            return jsonify({"error": "Invalid URL"}), 400

        # ── Try python-whois ──────────────────────────────────────────────
        try:
            import whois as whois_lib  # type: ignore
        except ImportError:
            return jsonify({
                "domain":  domain,
                "error":   "python-whois not installed",
                "install": "Run: pip install python-whois",
                "registrar":       None,
                "creation_date":   None,
                "expiration_date": None,
                "updated_date":    None,
                "age_days":        None,
                "country":         None,
                "org":             None,
                "name_servers":    [],
                "status":          [],
                "emails":          [],
            }), 200

        socket.setdefaulttimeout(10)
        try:
            w = whois_lib.whois(domain)
        except Exception as exc:
            return jsonify({
                "domain":          domain,
                "error":           f"WHOIS lookup failed: {exc}",
                "registrar":       None,
                "creation_date":   None,
                "expiration_date": None,
                "updated_date":    None,
                "age_days":        None,
                "country":         None,
                "org":             None,
                "name_servers":    [],
                "status":          [],
                "emails":          [],
            }), 200

        def _norm(v):
            if isinstance(v, list): v = v[0] if v else None
            if isinstance(v, datetime): return v.isoformat()
            return str(v) if v is not None else None

        creation   = _norm(w.creation_date)
        expiration = _norm(w.expiration_date)
        updated    = _norm(w.updated_date)

        age_days = None
        if creation:
            try:
                age_days = (datetime.utcnow() - datetime.fromisoformat(
                    creation.split("T")[0])).days
            except Exception:
                age_days = None

        name_servers = []
        if w.name_servers:
            try:
                name_servers = list({n.lower() for n in w.name_servers if n})
            except Exception:
                name_servers = []

        statuses = []
        if w.status:
            statuses = w.status if isinstance(w.status, list) else [w.status]

        emails = []
        if w.emails:
            emails = w.emails if isinstance(w.emails, list) else [w.emails]

        return jsonify({
            "domain":          domain,
            "registrar":       _norm(w.registrar),
            "creation_date":   creation,
            "expiration_date": expiration,
            "updated_date":    updated,
            "age_days":        age_days,
            "country":         _norm(w.country),
            "org":             _norm(w.org),
            "name_servers":    name_servers,
            "status":          statuses,
            "emails":          emails,
        })
    except Exception as e:
        print(f"[!] /whois error: {e}")
        # Always return JSON, never let Flask return HTML
        return jsonify({"error": str(e), "domain": ""}), 200


# ── Full report ──────────────────────────────────────────────────────────────
@app.route("/report", methods=["POST", "OPTIONS"])
def full_report():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    if model is None or scaler is None:
        return jsonify({"error": "Model not loaded. Run train_model.py first."}), 503
    try:
        data = request.get_json(silent=True) or {}
        url  = (data.get("url") or "").strip()
        if not url:
            return jsonify({"error": "Missing URL"}), 400

        feat_dict    = extract_features(url, is_training=False)
        feat_list    = [float(v) for v in feat_dict.values()]

        decision_source = "ml"
        hard_signals    = []
        if is_allowlisted(url):
            risk_score      = 0.02
            decision_source = "allowlist"
        else:
            hard_signals = hard_phishing_signals(url)
            if hard_signals:
                risk_score      = 0.97
                decision_source = "blocklist"
            else:
                X          = scaler.transform([feat_list])
                probs      = model.predict_proba(X)[0]
                risk_score = float(probs[1])

        is_phishing = risk_score >= 0.55
        confidence  = risk_score if is_phishing else (1.0 - risk_score)

        domain     = url.split("//")[-1].split("/")[0].split(":")[0].lower()
        whois_info = {"domain": domain}
        try:
            import whois as whois_lib  # type: ignore
            socket.setdefaulttimeout(8)
            w = whois_lib.whois(domain)

            def _norm(v):
                if isinstance(v, list): v = v[0] if v else None
                if isinstance(v, datetime): return v.isoformat()
                return str(v) if v is not None else None

            creation = _norm(w.creation_date)
            age_days = None
            if creation:
                try:
                    age_days = (datetime.utcnow() - datetime.fromisoformat(
                        creation.split("T")[0])).days
                except Exception:
                    age_days = None
            whois_info.update({
                "registrar":       _norm(w.registrar),
                "creation_date":   creation,
                "expiration_date": _norm(w.expiration_date),
                "age_days":        age_days,
                "country":         _norm(w.country),
                "org":             _norm(w.org),
            })
        except Exception as e:
            whois_info["error"] = str(e)

        indicators = []
        if feat_dict["has_ip_address"]:        indicators.append("URL uses a raw IP address instead of a domain")
        if feat_dict["uses_https"] == 0:       indicators.append("Does not use HTTPS")
        if feat_dict["is_url_shortener"]:      indicators.append("Uses a URL shortener")
        if feat_dict["brand_in_subdomain"]:    indicators.append("Brand name appears in subdomain (spoofing)")
        if feat_dict["suspicious_keywords"]>0: indicators.append(
            f"Contains {int(feat_dict['suspicious_keywords'])} suspicious keyword(s) (login/verify/secure/...)")
        if feat_dict["num_at_symbols"] > 0:    indicators.append("Contains '@' symbol (URL obfuscation)")
        if feat_dict["subdomain_depth"] > 3:   indicators.append(f"Unusually deep subdomain ({int(feat_dict['subdomain_depth'])} levels)")
        if feat_dict["url_length"] > 75:       indicators.append(f"Very long URL ({int(feat_dict['url_length'])} chars)")
        if feat_dict["num_hyphens"] > 4:       indicators.append(f"Excessive hyphens ({int(feat_dict['num_hyphens'])})")
        if feat_dict["num_digits"] > 10:       indicators.append(f"Excessive digits ({int(feat_dict['num_digits'])})")
        if whois_info.get("age_days") is not None and whois_info["age_days"] < 90:
            indicators.append(f"Domain is very new ({whois_info['age_days']} days old)")

        for s in hard_signals:
            if s not in indicators:
                indicators.insert(0, s)
        if decision_source == "allowlist":
            indicators = ["Domain is on PhishGuard's verified trusted-domain allowlist."]

        severity, verdict = risk_band(risk_score)

        recommendations = []
        if is_phishing:
            recommendations += [
                "Do NOT enter any credentials or personal data.",
                "Do NOT download files from this site.",
                "Report the URL to your IT/security team.",
            ]
        else:
            recommendations += [
                "URL appears safe based on lexical + host signals.",
                "Still verify the certificate and domain spelling before logging in.",
            ]
        if not feat_dict["uses_https"]:
            recommendations.append("Avoid submitting any data over plain HTTP.")
        if whois_info.get("age_days") is not None and whois_info["age_days"] < 30:
            recommendations.append("Domain registered in the last 30 days — extra caution advised.")

        return jsonify({
            "url":          url,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "ml": {
                "prediction":      "phishing" if is_phishing else "legitimate",
                "is_phishing":     bool(is_phishing),
                "risk_score":      round(risk_score, 4),
                "risk_percent":    round(risk_score * 100, 1),
                "confidence":      round(confidence, 4),
                "verdict":         verdict,
                "severity":        severity,
                "decision_source": decision_source,
            },
            "features":        feat_dict,
            "indicators":      indicators,
            "whois":           whois_info,
            "recommendations": recommendations,
        })
    except Exception as e:
        print(f"[!] /report error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/bulk_scan", methods=["POST", "OPTIONS"])
def bulk_scan():
    if request.method == "OPTIONS":
        return jsonify({}), 200
    if model is None or scaler is None:
        return jsonify({"error": "Model not loaded."}), 503
    try:
        data = request.get_json(silent=True) or {}
        urls = data.get("urls") or []
        if not isinstance(urls, list):
            return jsonify({"error": "urls must be a list"}), 400
        urls = [str(u).strip() for u in urls if str(u).strip()][:50]

        results = []
        for url in urls:
            try:
                if is_allowlisted(url):
                    rs, src = 0.02, "allowlist"
                elif hard_phishing_signals(url):
                    rs, src = 0.97, "blocklist"
                else:
                    feats = features_to_list(url, is_training=False)
                    X     = scaler.transform([feats])
                    rs    = float(model.predict_proba(X)[0][1])
                    src   = "ml"
                sev, verdict = risk_band(rs)
                results.append({
                    "url":             url,
                    "risk_percent":    round(rs * 100, 1),
                    "severity":        sev,
                    "verdict":         verdict,
                    "is_phishing":     rs >= 0.55,
                    "decision_source": src,
                })
            except Exception as e:
                results.append({"url": url, "error": str(e)})

        summary = {
            "total":  len(results),
            "high":   sum(1 for r in results if r.get("severity") == "high"),
            "medium": sum(1 for r in results if r.get("severity") == "medium"),
            "low":    sum(1 for r in results if r.get("severity") == "low"),
            "safe":   sum(1 for r in results if r.get("severity") == "safe"),
        }
        return jsonify({"results": results, "summary": summary})
    except Exception as e:
        print(f"[!] /bulk_scan error: {e}")
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"ok": True, "model_loaded": model is not None})


if __name__ == "__main__":
    import os
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_ENV") != "production"
    print(f"\n[OK] PhishGuard API online at http://0.0.0.0:{port}\n")
    app.run(debug=debug, host="0.0.0.0", port=port)