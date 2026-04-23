// background.js — Service Worker
// Checks every URL the user navigates to against the ML API

const API_URL = "http://127.0.0.1:5000";
const RISK_THRESHOLD = 0.7;  // Flag URLs with phishing risk > 70%

// Skip these domains (whitelisted)
const WHITELIST = [
  "google.com", "youtube.com", "github.com",
  "stackoverflow.com", "wikipedia.org", "chrome://",
  "localhost", "127.0.0.1",
  // Yenepoya University & affiliated portals
  "yenepoya.edu.in", "student.yenepoya.edu.in", "ytincubator.com",
  "yengage.yenepoya.edu.in", "vidyen.yenepoya.in", "ydc.yenepoya.edu.in"
];

// ── Listen for tab navigation ─────────────────────────────────────────────────
chrome.webNavigation.onCompleted.addListener(async (details) => {
  if (details.frameId !== 0) return;           // Main frame only
  const url = details.url;
  if (!url.startsWith("http")) return;         // Skip chrome:// etc.
  if (isWhitelisted(url)) return;

  try {
    const result = await checkUrl(url);
    if (result && result.risk_score >= RISK_THRESHOLD) {
      // Store result for popup to read
      await chrome.storage.local.set({
        lastCheck: {
          url,
          ...result,
          tabId: details.tabId,
          timestamp: new Date().toISOString()
        }
      });

      // Update badge to warn user
      chrome.action.setBadgeText({ text: "⚠", tabId: details.tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#E53935" });

      // Send message to content script to show warning banner
      chrome.tabs.sendMessage(details.tabId, {
        type: "PHISHING_WARNING",
        data: result
      }).catch(() => {}); // Tab may not have content script yet

    } else {
      chrome.action.setBadgeText({ text: "✓", tabId: details.tabId });
      chrome.action.setBadgeBackgroundColor({ color: "#43A047" });

      await chrome.storage.local.set({
        lastCheck: { url, ...result, tabId: details.tabId }
      });
    }
  } catch (err) {
    console.error("[PhishGuard] API error:", err);
    chrome.action.setBadgeText({ text: "?", tabId: details.tabId });
    chrome.action.setBadgeBackgroundColor({ color: "#888" });
  }
}, { url: [{ schemes: ["http", "https"] }] });


// ── API call ──────────────────────────────────────────────────────────────────
async function checkUrl(url) {
  const response = await fetch(`${API_URL}/predict`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, source: "extension" })
  });
  if (!response.ok) throw new Error(`API returned ${response.status}`);
  return response.json();
}


// ── Whitelist check ───────────────────────────────────────────────────────────
function isWhitelisted(url) {
  return WHITELIST.some(domain => url.includes(domain));
}


// ── Listen for messages from popup ───────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "CHECK_URL") {
    checkUrl(message.url)
      .then(result => sendResponse({ success: true, data: result }))
      .catch(err  => sendResponse({ success: false, error: err.message }));
    return true; // Keep channel open for async response
  }
});
