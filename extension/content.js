// content.js — Injected into every page
// Shows a warning banner when phishing is detected

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === "PHISHING_WARNING") {
    showWarningBanner(message.data);
  }
});

function showWarningBanner(data) {
  // Don't show duplicate banners
  if (document.getElementById("phishguard-banner")) return;

  const risk = Math.round((data.risk_score || 0) * 100);

  const banner = document.createElement("div");
  banner.id = "phishguard-banner";
  banner.innerHTML = `
    <div style="
      position: fixed;
      top: 0; left: 0; right: 0;
      z-index: 2147483647;
      background: linear-gradient(135deg, #b71c1c, #c62828);
      color: #fff;
      padding: 12px 20px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      font-size: 14px;
      box-shadow: 0 3px 10px rgba(0,0,0,.3);
    ">
      <div style="display:flex;align-items:center;gap:12px;">
        <span style="font-size:22px;">🚨</span>
        <div>
          <div style="font-weight:700;font-size:15px;">Phishing Warning — ${risk}% Risk</div>
          <div style="font-size:12px;opacity:.85;margin-top:2px;">
            Our ML model flagged this URL as a potential phishing site. Proceed with extreme caution.
          </div>
        </div>
      </div>
      <button onclick="document.getElementById('phishguard-banner').remove()" style="
        background: rgba(255,255,255,.2);
        border: none;
        color: #fff;
        padding: 6px 14px;
        border-radius: 6px;
        cursor: pointer;
        font-size: 13px;
        white-space: nowrap;
        margin-left: 16px;
      ">Dismiss</button>
    </div>
  `;

  document.body.prepend(banner);

  // Auto-dismiss after 12 seconds
  setTimeout(() => {
    const b = document.getElementById("phishguard-banner");
    if (b) b.remove();
  }, 12000);
}
