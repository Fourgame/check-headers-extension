let appliedHeaders = {};

// Intercept response headers
chrome.webRequest.onHeadersReceived.addListener(
  function (details) {
    console.log("Intercepting headers for:", details.url);

    const existingHeaderNames = new Set(
      details.responseHeaders.map(h => h.name.toLowerCase())
    );

    const updatedHeaders = details.responseHeaders.filter(h => {
      return !appliedHeaders.hasOwnProperty(h.name.toLowerCase());
    });

    for (const [key, value] of Object.entries(appliedHeaders)) {
      updatedHeaders.push({ name: key, value: value });
      if (!existingHeaderNames.has(key)) {
        console.log(`Adding new header: ${key}: ${value}`);
      } else {
        console.log(`✏ Overriding header: ${key}`);
      }
    }

    return { responseHeaders: updatedHeaders };
  },
  { urls: ["<all_urls>"], types: ["main_frame"] },
  ["blocking", "responseHeaders", "extraHeaders"]

);

// Listener for Apply from popup.js
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "apply-multiple-headers") {
    console.log("Applying headers from popup:", message.headers);

    appliedHeaders = {}; 
    const headers = message.headers;

    for (const [name, value] of Object.entries(headers)) {
      appliedHeaders[name.toLowerCase()] = value;
    }

    chrome.storage.local.set({ appliedHeaders }, () => {
      sendResponse({ success: true });
    });

    return true;
  }

  if (message.type === "apply-header") {
    const name = message.header.toLowerCase();
    appliedHeaders[name] = message.value;

    chrome.storage.local.set({ appliedHeaders }, () => {
      sendResponse({ success: true });
    });

    return true;
  }

  if (message.type === "apply-csp-mode") {
    const cspName = "content-security-policy";
    appliedHeaders[cspName] = message.value;

    chrome.storage.local.set({ appliedHeaders }, () => {
      sendResponse({ success: true });
    });

    return true;
  }
});

// Load applied headers from storage
chrome.storage.local.get("appliedHeaders", (data) => {
  appliedHeaders = data.appliedHeaders || {};
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "get-latest-headers") {
    chrome.storage.local.get("lastHeaders", (data) => {
      sendResponse({ headers: data.lastHeaders || {} });
    });
    return true;
  }
});
chrome.webRequest.onHeadersReceived.addListener(
  (details) => {
    const headersObj = {};
    for (const h of details.responseHeaders || []) {
      headersObj[h.name.toLowerCase()] = h.value;
    }

    chrome.storage.local.set({ lastHeaders: headersObj });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);
