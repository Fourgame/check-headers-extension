chrome.webRequest.onHeadersReceived.addListener(
  function (details) {
    const headers = {};
    details.responseHeaders.forEach(h => {
      headers[h.name.toLowerCase()] = h.value;
    });
    chrome.storage.local.set({ lastHeaders: headers });
  },
  { urls: ["<all_urls>"] },
  ["responseHeaders"]
);