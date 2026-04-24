const API = "https://phishguard-6z54.onrender.com";

async function showCurrentPage() {
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  const tab = tabs[0];
  if (!tab || !tab.url || !tab.url.startsWith("http")) {
    document.getElementById("loading").textContent = "Open a webpage to scan it.";
    return;
  }

  document.getElementById("loading").style.display = "none";
  document.getElementById("status-section").style.display = "block";
  document.getElementById("url-text").textContent = tab.url;

  const stored = await chrome.storage.local.get("lastCheck");
  const last = stored.lastCheck;

  if (last && last.url === tab.url) {
    renderResult(last);
  } else {
    renderResult(null);
    chrome.runtime.sendMessage(
      { type: "CHECK_URL", url: tab.url },
      (response) => {
        if (response && response.success) renderResult(response.data);
        else renderError();
      }
    );
  }
}

function renderResult(data) {
  const card  = document.getElementById("status-card");
  const icon  = document.getElementById("status-icon");
  const label = document.getElementById("status-label");
  const fill  = document.getElementById("risk-fill");
  const pct   = document.getElementById("risk-pct");

  if (!data) {
    label.textContent = "Scanning...";
    return;
  }

  const risk = data.risk_score || 0;
  pct.textContent = (risk * 100).toFixed(0) + "%";
  fill.style.width = (risk * 100) + "%";

  if (data.is_phishing) {
    card.className    = "status-card danger";
    icon.textContent  = "🚨";
    label.textContent = "PHISHING DETECTED";
    label.className   = "status-label danger";
    fill.style.background = "#e53935";
  } else {
    card.className    = "status-card safe";
    icon.textContent  = "✅";
    label.textContent = "Safe";
    label.className   = "status-label safe";
    fill.style.background = "#43a047";
  }
}

function renderError() {
  const label = document.getElementById("status-label");
  label.textContent = "API Offline — Start Flask server";
  label.className   = "status-label neutral";
}

async function checkManual() {
  const input = document.getElementById("manual-url").value.trim();
  if (!input) return;

  const btn = document.getElementById("check-btn");
  const resultDiv = document.getElementById("manual-result");

  btn.disabled = true;
  btn.textContent = "Checking...";
  resultDiv.textContent = "";

  try {
    const res = await fetch(`${API}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: input, source: "popup_manual" })
    });
    const data = await res.json();

    if (data.is_phishing) {
      resultDiv.innerHTML = `<span style="color:#c62828">🚨 Phishing — ${(data.risk_score*100).toFixed(0)}% risk</span>`;
    } else {
      resultDiv.innerHTML = `<span style="color:#2e7d32">✅ Legitimate — ${(data.confidence*100).toFixed(0)}% confident</span>`;
    }
  } catch (e) {
    resultDiv.innerHTML = `<span style="color:#e65100">⚠ Could not reach API. Is Flask running?</span>`;
  }

  btn.disabled = false;
  btn.textContent = "Analyse URL";
}

document.addEventListener("DOMContentLoaded", () => {
  showCurrentPage();
  document.getElementById("manual-url").addEventListener("keydown", (e) => {
    if (e.key === "Enter") checkManual();
  });
  document.getElementById("check-btn").addEventListener("click", checkManual);
});
