const headersList = [
  "strict-transport-security", "x-frame-options", "x-content-type-options",
  "content-security-policy", "x-permitted-cross-domain-policies", "referrer-policy",
  "clear-site-data", "cross-origin-embedder-policy", "cross-origin-opener-policy",
  "cross-origin-resource-policy", "cache-control", "permissions-policy",
  "expect-ct", "public-key-pins", "x-xss-protection", "pragma"
];

const headerInfo = {
  "strict-transport-security": {
    description: "Forces browsers to use HTTPS by setting a long enough max-age value (≥15768000 seconds).",
    status: "Active",
    example: "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
  },
  "x-frame-options": {
    description: "Protects against clickjacking by controlling iframe embedding.",
    status: "Active (Deprecated by CSP frame-ancestors)",
    example: "X-Frame-Options: DENY",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
  },
  "x-content-type-options": {
    description: "Prevents MIME-sniffing and enforces declared Content-Type.",
    status: "Active",
    example: "X-Content-Type-Options: nosniff",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
  },
  "content-security-policy": {
    description: "Restricts content sources to mitigate XSS and code injection attacks.",
    status: "Active",
    example: "Content-Security-Policy: default-src 'self'; script-src 'self'",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
  },
  "x-permitted-cross-domain-policies": {
    description: "Restricts Adobe Flash/Acrobat cross-domain data loading policies.",
    status: "Active",
    example: "X-Permitted-Cross-Domain-Policies: none",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Permitted-Cross-Domain-Policies"
  },
  "referrer-policy": {
    description: "Controls how much referrer information is sent with requests.",
    status: "Active",
    example: "Referrer-Policy: strict-origin-when-cross-origin",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
  },
  "clear-site-data": {
    description: "Clears cookies, storage, and cache on the client when invoked.",
    status: "Active",
    example: 'Clear-Site-Data: "cache", "cookies", "storage"',
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Clear-Site-Data"
  },
  "cross-origin-embedder-policy": {
    description: "Isolates context by preventing loading of cross-origin resources unless they grant permission.",
    status: "Active",
    example: "Cross-Origin-Embedder-Policy: require-corp",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy"
  },
  "cross-origin-opener-policy": {
    description: "Protects from cross-origin attacks by isolating top-level documents.",
    status: "Active",
    example: "Cross-Origin-Opener-Policy: same-origin",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy"
  },
  "cross-origin-resource-policy": {
    description: "Controls who can load the resource (same-origin, same-site, or cross-origin).",
    status: "Active",
    example: "Cross-Origin-Resource-Policy: same-origin",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy"
  },
  "cache-control": {
    description: "Directs how resources are cached by the browser or intermediaries.",
    status: "Almost Deprecated (still widely used)",
    example: "Cache-Control: no-store, max-age=0",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control"
  },
  "permissions-policy": {
    description: "Controls access to powerful browser features and APIs like camera and geolocation.",
    status: "Active (Working Draft)",
    example: "Permissions-Policy: camera=(), geolocation=(self)",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
  },
  "expect-ct": {
    description: "Deprecated. Was used to enforce Certificate Transparency requirements.",
    status: "Deprecated",
    example: 'Expect-CT: max-age=86400, enforce, report-uri="https://example.com/report"',
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect-CT"
  },
  "public-key-pins": {
    description: "Deprecated. Previously used to pin public keys for HTTPS connections.",
    status: "Deprecated",
    example: 'Public-Key-Pins: pin-sha256="..."; max-age=10000; includeSubDomains',
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Public-Key-Pins"
  },
  "x-xss-protection": {
    description: "Deprecated. Used to activate browser's XSS filtering.",
    status: "Deprecated",
    example: "X-XSS-Protection: 0",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
  },
  "pragma": {
    description: "Deprecated. Used for HTTP/1.0 caching control (use Cache-Control instead).",
    status: "Deprecated",
    example: "Pragma: no-cache",
    mdn: "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Pragma"
  }
};


function getHeaderStatus(name, value) {
  if (value === undefined) return { status: "not-have", reason: "Header not present." };
  const val = value.trim().toLowerCase();

  switch (name) {
    case "strict-transport-security":
      if (/max-age=(\d+)/i.test(value)) {
        const maxAge = parseInt(value.match(/max-age=(\d+)/i)[1]);
        if (maxAge >= 15768000) return { status: "correct", reason: "HTTPS enforced with proper max-age." };
        return { status: "uncorrect", reason: "max-age too short." };
      }
      return { status: "uncorrect", reason: "max-age not specified." };

    case "x-frame-options":
      if (["deny", "sameorigin"].includes(val)) return { status: "correct", reason: "Proper clickjacking protection." };
      return { status: "uncorrect", reason: "Not supported by modern browsers." };

    case "x-content-type-options":
      if (val === "nosniff") return { status: "correct", reason: "MIME sniffing protection active." };
      return { status: "uncorrect", reason: "Only 'nosniff' is valid." };

    case "content-security-policy":
      if (/default-src/i.test(value)) {
        if (/unsafe-inline/.test(value)) return { status: "uncorrect", reason: "Unsafe directive weakens CSP." };
        return { status: "correct", reason: "Defines secure content restrictions." };
      }
      return { status: "uncorrect", reason: "Missing default-src directive." };

    case "x-permitted-cross-domain-policies":
      if (["none", "master-only"].includes(val)) return { status: "correct", reason: "Cross-domain policy restricted." };
      return { status: "uncorrect", reason: "Permissive policy may expose Flash vulnerabilities." };

    case "referrer-policy":
      if (["no-referrer", "strict-origin", "strict-origin-when-cross-origin"].includes(val)) return { status: "correct", reason: "Privacy-safe referrer policy." };
      if (["unsafe-url", "origin"].includes(val)) return { status: "uncorrect", reason: "May expose referrer data." };
      return { status: "uncorrect", reason: "Unknown or missing policy." };

    case "clear-site-data":
      return { status: "correct", reason: "Triggers data clearing on request." };

    case "cross-origin-embedder-policy":
      if (val === "require-corp") return { status: "correct", reason: "Isolates context for better security." };
      return { status: "uncorrect", reason: "Insufficient isolation." };

    case "cross-origin-opener-policy":
      if (val === "same-origin") return { status: "correct", reason: "Browsing context properly isolated." };
      if (val === "same-origin-allow-popups") return { status: "uncorrect", reason: "Allows popups to share context." };
      return { status: "not-have", reason: "No protection from cross-origin interactions." };

    case "cross-origin-resource-policy":
      if (["same-origin", "same-site"].includes(val)) return { status: "correct", reason: "Restricts external resource access." };
      if (val === "cross-origin") return { status: "uncorrect", reason: "Too permissive." };
      return { status: "not-have", reason: "CORP not set." };

    case "cache-control":
      if (/no-store|no-cache/i.test(val)) return { status: "correct", reason: "Prevents sensitive data caching." };
      if (/public/i.test(val)) return { status: "uncorrect", reason: "Caching may leak information." };
      return { status: "not-have", reason: "No cache policy defined." };

    case "permissions-policy":
      if (/=\(\)/.test(value)) {
        return { status: "correct", reason: "All features explicitly disabled." };
      }
      if (/\*=\*/.test(value) || /=\(\*\)/.test(value)) {
        return { status: "uncorrect", reason: "Wildcard '*' used — overexposes features." };
      }
      if (/=\(self(?: [^)]*)?\)/.test(value) || /=\("self"(?: [^)]*)?\)/.test(value)) {
        return { status: "correct", reason: "Features limited to same-origin — acceptable." };
      }
      return { status: "uncorrect", reason: "May allow cross-origin feature access." };

    case "expect-ct":
    case "public-key-pins":
    case "x-xss-protection":
    case "pragma":
      return { status: "uncorrect", reason: "Deprecated no longer effective." };

    default:
      return { status: "correct", reason: "Header is present." };
  }
}

function renderHeaders(headers) {
  const container = document.getElementById("result");
  container.innerHTML = "<tr><th>Header</th><th>Status</th></tr>";

  headersList.forEach(name => {
    const value = headers[name];
    const { status, reason } = getHeaderStatus(name, value);

    const mainRow = document.createElement("tr");
    mainRow.className = "main-row";
    mainRow.innerHTML = `<td class="${status}">${name}</td><td class="${status}">${status}</td>`;

    const detailRow = document.createElement("tr");
    detailRow.className = "detail-row";
    detailRow.style.display = "none";
    const info = headerInfo[name];
    detailRow.innerHTML = `<td colspan="2" style="font-size: 0.85em; color: #555;">
      <b>Current Value:</b> <code>${value !== undefined ? value : "Not Have"}</code><br>
      <b>Status:</b> ${reason}<br><br>
      ${info?.description || "No description"}<br>
      <a href="${info?.mdn}" target="_blank">MDN Reference</a>
    </td>`;

    mainRow.onclick = () => {
      detailRow.style.display = detailRow.style.display === "none" ? "table-row" : "none";
    };

    container.appendChild(mainRow);
    container.appendChild(detailRow);

    

  });
  const score = calculateSecurityScore(headers);
  document.getElementById("score").innerText = `Security Score: ${score}/100`;
}

// โหลด header ทันทีเมื่อเปิด popup
chrome.storage.local.get("lastHeaders", data => {
  renderHeaders(data.lastHeaders || {});
});


function calculateSecurityScore(headers) {
  let score = 0;
  headersList.forEach(name => {
    const value = headers[name];
    const { status } = getHeaderStatus(name, value);

    if (status === "correct") {
      score += 6.25;
    } else if (status === "uncorrect") {
      score += 3;
    }
    // not-have or deprecated = 0
  });
  return Math.round(score);
}


// โหลด key ตอนเปิด popup
chrome.storage.local.get("geminiKey", data => {
  if (data.geminiKey) {
    document.getElementById("apiKey").value = data.geminiKey;
  }
});

// Save Key
document.getElementById("saveKey").onclick = () => {
  const key = document.getElementById("apiKey").value;
  chrome.storage.local.set({ geminiKey: key }, () => {
    alert("Gemini API Key saved.");
  });
};

// โหลด headers แล้วแสดงผล
chrome.storage.local.get("lastHeaders", data => {
  renderHeaders(data.lastHeaders || {});
});

// ปุ่ม Analyze ด้วย Gemini
document.getElementById("analyzeWithAI").onclick = () => {
  const apiKey = document.getElementById("apiKey").value;
  if (!apiKey) {
    alert("Please enter your Gemini API Key.");
    return;
  }

  chrome.storage.local.get("lastHeaders", async (data) => {
    const headers = data.lastHeaders || {};
    const body = { apiKey, headers };

    try {
      const res = await fetch("http://localhost:5000/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body)
      });

      const json = await res.json();
      if (json.result) {
        document.getElementById("aiResult").innerText = json.result;

        // บันทึกผล Gemini โดยใช้ domain เป็น key
        chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
          const url = new URL(tabs[0].url);
          const domain = url.hostname;

          chrome.storage.local.get("geminiAnalysis", (data) => {
            const analysis = data.geminiAnalysis || {};
            analysis[domain] = json.result;
            chrome.storage.local.set({ geminiAnalysis: analysis });
          });
        });

      } else {
        document.getElementById("aiResult").innerText = "Error: " + (json.error || "No response");
      }
    } catch (e) {
      document.getElementById("aiResult").innerText = "Backend error: " + e.message;
    }
  });
};