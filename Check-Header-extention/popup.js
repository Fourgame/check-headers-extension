const headersList = [
  "strict-transport-security", "x-frame-options", "x-content-type-options",
  "content-security-policy", "x-permitted-cross-domain-policies", "referrer-policy",
  "clear-site-data", "cross-origin-embedder-policy", "cross-origin-opener-policy",
  "cross-origin-resource-policy", "cache-control", "permissions-policy",
  "expect-ct", "public-key-pins", "x-xss-protection", "pragma"
];

const headerInfo = {
  "strict-transport-security": {
    description: "Forces browsers to use HTTPS by setting a long enough max-age value (more then 15768000 seconds).",
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


function normalizeHeaderKey(domHeaderName) {
  return domHeaderName.toLowerCase();
}


function getHeaderStatus(header, value , lastHeaders = {}) {
  const v = (value || '').trim().toLowerCase();
  if (!v) return { status: "missing", reason: "Header not present." };
  if (v === 'timeout') return { status: "timeout", reason: "Request timed out while fetching header." };

  switch (header) {
    case 'content-security-policy': {
      const issues = [];
      if (v.includes('unsafe-inline') || v.includes('unsafe-eval') || v.includes('*')) issues.push('insecure');
      if (!v.includes('default-src')) issues.push('no-default-src');
      return issues.length
        ? { status: issues.join(', '), reason: "CSP contains weak or missing directives." }
        : { status: "valid", reason: "CSP policy is strict and complete." };
    }

    case 'x-frame-options':
      return ['deny', 'sameorigin'].includes(v)
        ? { status: "valid", reason: "Protects against clickjacking." }
        : { status: "invalid", reason: "Invalid value for X-Frame-Options." };

    case 'referrer-policy': {
      const valid = [
        'no-referrer', 'no-referrer-when-downgrade', 'origin',
        'origin-when-cross-origin', 'same-origin', 'strict-origin',
        'strict-origin-when-cross-origin', 'unsafe-url'
      ];
      return valid.includes(v)
        ? { status: "valid", reason: "Referrer-Policy is appropriate." }
        : { status: "invalid", reason: "Unsupported referrer policy value." };
    }

    case 'permissions-policy':
      return /\s=\s\*/.test(v)
        ? { status: "invalid", reason: "Wildcard (*) permissions are not allowed." }
        : { status: "valid", reason: "Permissions policy properly restricted." };

    case 'x-xss-protection':
      if (v === '0') return { status: "deprecated", reason: "XSS protection disabled (deprecated)." };
      if (v.includes('mode=enable')) return { status: "invalid", reason: "Deprecated and misconfigured." };
      return { status: "deprecated", reason: "Legacy XSS protection enabled." };

    case 'public-key-pins':
      return v.includes('pin-sha256') && v.includes('max-age')
        ? { status: "deprecated", reason: "HPKP set (deprecated)." }
        : { status: "malformed", reason: "Missing pin or max-age in HPKP." };

    case 'pragma': {
      const cc = (lastHeaders['cache-control'] || '').toLowerCase();
      if (v.includes('no-cache')) {
        if (!cc || !cc.includes('no-store')) {
          return { status: "insecure", reason: "Pragma used without matching Cache-Control." };
        }
        return { status: "valid", reason: "Pragma and Cache-Control are consistent." };
      }
      return { status: "other", reason: "Pragma present but no known security impact." };
    }

    case 'x-content-type-options':
      return v === 'nosniff'
        ? { status: "valid", reason: "Content type sniffing is prevented." }
        : { status: "invalid", reason: "nosniff not specified." };

    case 'cross-origin-embedder-policy':
      return ['require-corp', 'credentialless'].includes(v)
        ? { status: "valid", reason: "COEP policy enforced properly." }
        : { status: "invalid", reason: "Improper COEP value." };

    case 'cross-origin-opener-policy':
      if (v === 'unsafe-none') return { status: "insecure", reason: "Top-level isolation is not enforced." };
      return ['same-origin', 'same-origin-allow-popups'].includes(v)
        ? { status: "valid", reason: "Proper isolation via COOP." }
        : { status: "invalid", reason: "Unrecognized COOP value." };

    case 'cross-origin-resource-policy':
      return ['same-origin', 'same-site', 'cross-origin'].includes(v)
        ? { status: "valid", reason: "CORP value is recognized." }
        : { status: "invalid", reason: "Invalid CORP directive." };

    case 'clear-site-data':
      return v.includes('"cache"') && v.includes('"cookies"')
        ? { status: "valid", reason: "Clears cache and cookies on request." }
        : { status: "invalid", reason: "Missing cache or cookie clearing directive." };

    case 'cache-control': {
      const directives = v.split(',').map(d => d.trim());
      if (directives.includes('public') && directives.includes('no-store'))
        return { status: "conflict", reason: "Conflicting caching instructions (public + no-store)." };
      if ((v.match(/max-age=\d+/g) || []).length > 1)
        return { status: "conflict", reason: "Multiple max-age directives found." };
      if (directives.includes('no-cache') && !directives.includes('no-store') && !directives.includes('must-revalidate'))
        return { status: "incomplete", reason: "no-store or must-revalidate missing." };
      return { status: "valid", reason: "Cache-Control is well-formed." };
    }

    case 'expect-ct':
      if (v.includes('enforce') && !v.includes('max-age'))
        return { status: "malformed", reason: "Missing max-age for enforce mode." };
      if (v.includes('report-only') && !v.includes('report-uri'))
        return { status: "malformed", reason: "No report-uri for report-only mode." };
      return { status: "deprecated", reason: "Expect-CT is deprecated." };

    case 'feature-policy':
      return v !== ''
        ? { status: "deprecated", reason: "Feature-Policy is deprecated." }
        : { status: "missing", reason: "Header not present." };

    case 'x-permitted-cross-domain-policies':
      return ['none', 'master-only', 'by-content-type', 'all'].includes(v)
        ? { status: "valid", reason: "Cross-domain policy is acceptable." }
        : { status: "invalid", reason: "Unknown value for cross-domain policy." };

    default:
      return { status: "valid", reason: "No issue detected." };
  }
}

const statusPriority = {
  valid: 1,
  ok: 1,
  present: 1,
  "not-needed": 2,
  "partial": 3,
  required: 4,
  recommend: 5,
  insecure: 6,
  invalid: 7,
  incomplete: 8,
  conflict: 9,
  deprecated: 10,
  malformed: 11,
  timeout: 12,
  missing: 13,
  other: 14
};



function renderHeaders(headers, sortField = 'header', asc = true) {
  const container = document.getElementById("result");
  container.innerHTML = `
    <tr>
      <th id="sort-header">Header</th>
      <th id="sort-status">Status</th>
      <th>Detail</th>
    </tr>
  `;

  const rows = headersList.map(name => {
    const value = headers[name];
    const { status, reason } = getHeaderStatus(name, value, headers);
    return {
      name,
      value,
      status,
      reason,
      info: headerInfo[name]
    };
  });

  rows.sort((a, b) => {
    if (sortField === 'status') {
      // แยก status หลักตัวแรกเท่านั้น เช่น "insecure, no-default-src" → "insecure"
      const statusA = a.status.split(',')[0].trim().toLowerCase();
      const statusB = b.status.split(',')[0].trim().toLowerCase();
  
      const priorityA = statusPriority[statusA] || 99;
      const priorityB = statusPriority[statusB] || 99;
  
      return asc ? priorityA - priorityB : priorityB - priorityA;
    } else {
      const valA = a.name;
      const valB = b.name;
      return asc ? valA.localeCompare(valB) : valB.localeCompare(valA);
    }
  });
  

  for (const row of rows) {
    const mainRow = document.createElement("tr");
    mainRow.className = "main-row";
    mainRow.innerHTML = `
      <td class="${row.status}">${row.name}</td>
      <td class="${row.status}">${row.status}</td>
      <td style="font-size: 12px; color: #666;">${row.reason}</td>
    `;

    const detailRow = document.createElement("tr");
    detailRow.className = "detail-row";
    detailRow.style.display = "none";
    detailRow.innerHTML = `
      <td colspan="3" style="font-size: 0.85em; color: #555;">
        <b>Current Value:</b> <code>${row.value !== undefined ? row.value : "Not Have"}</code><br>
        <b>Status:</b> ${row.reason}<br><br>
        <b>Description:</b> ${row.info?.description || "No description"}<br><br>
        <b>Example:</b><br>
        <div style="background: #f0f0f0; padding: 10px; border-radius: 4px; margin-top: 4px; margin-bottom: 8px; font-family: monospace; font-size: 13px; width: 100%; box-sizing: border-box;">
          ${row.info?.example || "No example available"}
        </div>
        <a href="${row.info?.mdn}" target="_blank">🔗 MDN Reference</a>
      </td>
    `;

    mainRow.onclick = () => {
      detailRow.style.display = detailRow.style.display === "none" ? "table-row" : "none";
    };

    container.appendChild(mainRow);
    container.appendChild(detailRow);
  }

  const score = calculateSecurityScore(headers);
  document.getElementById("score").innerText = `Security Score: ${score}/100`;

  // Add click to sort
  document.getElementById("sort-status").onclick = () => {
    const nextSort = currentSortField === 'status' ? !sortAsc : true;
    currentSortField = 'status';
    sortAsc = nextSort;
    renderHeaders(headers, currentSortField, sortAsc);
  };
}


// โหลด header ทันทีเมื่อเปิด popup
fetchHeadersLive();




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
        document.getElementById("aiResult").innerHTML = renderSimpleMarkdown(json.result);

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

document.getElementById("runDomAnalysis").onclick = renderDomAnalysisLive;
renderDomAnalysisLive();
function renderDomAnalysisLive() {
  chrome.tabs.query({ active: true, currentWindow: true }, tabs => {
    const tabId = tabs[0].id;

    // inject content.js
    chrome.scripting.executeScript({
      target: { tabId: tabId },
      files: ["content.js"]
    }, () => {
      console.log("content.js injected");

      // รอฟังผลจาก content.js
      chrome.runtime.onMessage.addListener(function listener(msg, sender, sendResponse) {
        if (msg.type === "dom-analysis-result") {
          chrome.runtime.onMessage.removeListener(listener);
          chrome.storage.local.get("lastHeaders", data => {
            displayDomAnalysis(msg.data, data.lastHeaders || {});
          });
        }
      });
    });
  });
}



document.getElementById("showCurrentHeaders").onclick = () => {
  chrome.runtime.sendMessage({ type: "get-latest-headers" }, (response) => {
    const headers = response.headers || {};
    const formatted = Object.entries(headers)
      .map(([key, value]) => `${key}: ${value}`)
      .join("\n");

    const pre = document.getElementById("currentHeadersDisplay");
    pre.innerText = formatted || "No headers found.";
    pre.style.display = "block";
  });
};



document.getElementById("runDomAnalysis").onclick = renderDomAnalysisLive;
renderDomAnalysisLive(); // เมื่อเปิด popup ก็โหลด DOM สดทันที



document.addEventListener('DOMContentLoaded', () => {
  const tabButtons = document.querySelectorAll('.tab-btn');
  const tabContents = document.querySelectorAll('.tab-content');

  tabButtons.forEach(btn => {
    btn.addEventListener('click', () => {
      tabButtons.forEach(b => b.classList.remove('active'));
      btn.classList.add('active');

      const target = btn.getAttribute('data-tab');
      tabContents.forEach(tab => {
        tab.classList.remove('active');
        if (tab.id === target) tab.classList.add('active');
      });
    });
  });
});
chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  if (tabs.length > 0) {
    try {
      const url = new URL(tabs[0].url);
      document.getElementById("currentDomain").value = url.hostname;
    } catch (e) {
      document.getElementById("currentDomain").value = "Invalid URL";
    }
  }
});


document.getElementById("generateHeaderFromDOM").onclick = () => {
  chrome.storage.local.get("domAnalysis", data => {
    const dom = data.domAnalysis || {};
    const headers = [];

    if (dom["Content-Security-Policy"]?.status === "insecure") {
      headers.push("Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'");
    }
    if (dom["X-Frame-Options"]?.status === "required") {
      headers.push("X-Frame-Options: DENY");
    }
    if (dom["Cross-Origin-Resource-Policy"]?.status === "recommend") {
      headers.push("Cross-Origin-Resource-Policy: same-origin");
    }
    if (dom["Permissions-Policy"]?.status === "recommend") {
      headers.push("Permissions-Policy: camera=(), microphone=(), geolocation=()");
    }
    if (dom["Referrer-Policy"]?.status === "recommend") {
      headers.push("Referrer-Policy: strict-origin-when-cross-origin");
    }
    if (dom["Clear-Site-Data"]?.status === "missing") {
      headers.push('Clear-Site-Data: "cache", "cookies", "storage"');
    }
    if (dom["Cache-Control"]?.status === "missing") {
      headers.push("Cache-Control: no-store, max-age=0");
    }
    if (dom["Pragma"]?.status === "missing") {
      headers.push("Pragma: no-cache");
    }

    const output = headers.length === 0
      ? "No security issues found in DOM."
      : headers.join("\n");

    // เปลี่ยนตรงนี้ให้มาแสดงใน currentHeadersDisplay แทน
    const pre = document.getElementById("currentHeadersDisplay");
    pre.innerText = output;
    pre.style.display = "block";
  });
};

function applyHeader(headerName, headerValue) {
  chrome.runtime.sendMessage({
    type: "apply-header",
    header: headerName,
    value: headerValue
  }, response => {
    if (response && response.success) {
      alert(`Applied header: ${headerName}`);
    } else {
      alert(`Failed to apply header: ${headerName}`);
    }
  });
}




function displayDomAnalysis(dom, headers){
  const container = document.getElementById("domResult");
  container.innerHTML = "<table id='domTable'><tr><th>Header</th></tr>";
  

  Object.entries(dom).forEach(([name, info]) => {
    const status = (info.status || "").toLowerCase();
    let statusClass = "uncorrect";
    if (["secure", "ok", "not-needed", "present"].includes(status)) statusClass = "correct";
    else if (["recommend", "legacy-relevant", "partial", "required"].includes(status)) statusClass = "uncorrect";
    else if (["missing"].includes(status)) statusClass = "not-have";

    const defaultCode = {
      "Content-Security-Policy": "Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self';",
      "X-Frame-Options": "X-Frame-Options: DENY",
      "Cross-Origin-Resource-Policy": "Cross-Origin-Resource-Policy: same-origin",
      "Permissions-Policy": "Permissions-Policy: camera=(), microphone=(), geolocation=()",
      "Referrer-Policy": "Referrer-Policy: strict-origin-when-cross-origin",
      "Clear-Site-Data": 'Clear-Site-Data: "cache", "cookies", "storage"',
      "Cache-Control": "Cache-Control: no-store, max-age=0",
      "Pragma": "Pragma: no-cache"
    };
    const normalizedKey = normalizeHeaderKey(name);
    const headerValue = headers[normalizedKey];

    const suggestedValue = defaultCode[name] || "";
    const domHeaderCode =
        info.metaContent
          ? info.metaContent
          : (headerValue
              ? `${name}: ${headerValue}`
              : "No meta tag or header value found");

    const safeId = name.replace(/[^a-z0-9]/gi, '');
    const mainRow = document.createElement("tr");
    mainRow.className = "main-row";
    mainRow.innerHTML = `<td class="${statusClass}">${name}</td>`;


    const detailRow = document.createElement("tr");
    detailRow.className = "detail-row";
    detailRow.style.display = "none";

    detailRow.innerHTML = `
        <td colspan="2" style="font-size: 13px; color: #444;">
          <b>Details:</b><br>${info.recommendation || (info.issues || []).join(", ") || "No details."}<br><br>

          <b>DOM present:</b><br>
          <textarea readonly rows="3" style="width:100%; font-family: monospace; font-size:13px; background:#f5f5f5; border:1px dashed #ccc; color:#333;">${domHeaderCode}</textarea><br><br>

          <label for="code-${safeId}"><b>🛠 Suggest Code:</b></label><br>
          <textarea id="code-${safeId}" rows="2" style="width:100%; font-family: monospace; font-size:13px;">${suggestedValue}</textarea>

          
        </td>
      `;


    mainRow.onclick = () => {
      detailRow.style.display = detailRow.style.display === "none" ? "table-row" : "none";
    };

    container.querySelector("table").appendChild(mainRow);
    container.querySelector("table").appendChild(detailRow);
  });
  
}



// Export text
document.getElementById("exportText").onclick = () => {
  const blob = new Blob([document.getElementById("finalHeaderBox").value], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "headers.txt";
  a.click();
  URL.revokeObjectURL(url);
};

// Export JSON
document.getElementById("exportJSON").onclick = () => {
  const lines = document.getElementById("finalHeaderBox").value.split('\n');
  const headers = {};
  lines.forEach(line => {
    const [name, ...rest] = line.split(":");
    if (name && rest.length > 0) headers[name.trim()] = rest.join(":").trim();
  });

  const blob = new Blob([JSON.stringify(headers, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "headers.json";
  a.click();
  URL.revokeObjectURL(url);
};

document.getElementById("headerModeSelect").onchange = () => {
  const mode = document.getElementById("headerModeSelect").value;

  chrome.storage.local.get("lastHeaders", data => {
    const websiteHeaders = data.lastHeaders || {};
    const userHeaders = {};

    // ดึงจาก finalHeaderBox (user-defined headers)
    const userInput = document.getElementById("finalHeaderBox").value.trim().split("\n");
    userInput.forEach(line => {
      const [name, ...rest] = line.split(":");
      if (name && rest.length > 0) {
        userHeaders[name.trim().toLowerCase()] = rest.join(":").trim();
      }
    });

    const merged = {};
    const allKeys = new Set([
      ...Object.keys(websiteHeaders),
      ...Object.keys(userHeaders)
    ]);

    allKeys.forEach(key => {
      const websiteVal = websiteHeaders[key] || "";
      const userVal = userHeaders[key] || "";

      if (mode === "website") {
        if (websiteVal) merged[key] = websiteVal;
      } else if (mode === "user") {
        if (userVal) merged[key] = userVal;
      } else if (mode === "combine_strict") {
        // เอา user ถ้ามี, ถ้าไม่มีก็ใช้ website, แล้วลบ unsafe ของ CSP
        let val = userVal || websiteVal;
        if (key === "content-security-policy") {
          val = val.replace(/'unsafe-inline'|'unsafe-eval'/g, "").replace(/\s+/g, " ");
        }
        if (val) merged[key] = val.trim();
      } else if (mode === "combine_loose") {
        // รวมทั้งสอง ถ้ามีทั้งคู่ (เฉพาะ CSP จะ merge), อย่างอื่นเลือก user > website
        if (key === "content-security-policy" && websiteVal && userVal) {
          merged[key] = `${websiteVal}; ${userVal}`;
        } else {
          merged[key] = userVal || websiteVal;
        }
      }
    });

    const formatted = Object.entries(merged)
      .map(([k, v]) => `${k}: ${v}`)
      .join("\n");

    document.getElementById("combinedHeaderOutput").value = formatted || "No headers found.";
  });
};

document.getElementById("applyAllHeaders").addEventListener("click", () => {
  const headerText = document.getElementById("combinedHeaderOutput").value;
  const headerLines = headerText.split("\n");

  const headersToApply = {};
  headerLines.forEach(line => {
    const [key, ...valueParts] = line.split(":");
    if (key && valueParts.length > 0) {
      headersToApply[key.trim().toLowerCase()] = valueParts.join(":").trim();
    }
  });

  console.log("Sending apply-multiple-headers:", headersToApply);

  chrome.runtime.sendMessage({
    type: "apply-multiple-headers",
    headers: headersToApply
  }, (response) => {
    if (response && response.success) {
      alert("Headers applied successfully.");
      chrome.tabs.reload(); // reload tab เพื่อให้ header มีผล
    } else {
      alert("Failed to apply headers.");
    }
  });
  
});
function fetchHeadersLive() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs.length === 0) return;

    chrome.scripting.executeScript({
      target: { tabId: tabs[0].id },
      func: () => {
        // ทำ HTTP GET ไปยัง URL ปัจจุบันเพื่อ trigger onHeadersReceived
        fetch(window.location.href, { method: 'GET', credentials: 'include' });

      }
    }, () => {
      // รอหน่อยแล้วดึง headers ใหม่
      setTimeout(() => {
        chrome.storage.local.get("lastHeaders", data => {
          renderHeaders(data.lastHeaders || {}, 'status', true); 
        });
      }, 1500);
    });
  });
}

function renderSimpleMarkdown(text) {
  let html = text
    .replace(/^### (.*$)/gim, '<h4>$1</h4>')
    .replace(/^## (.*$)/gim, '<h3>$1</h3>')
    .replace(/^# (.*$)/gim, '<h2>$1</h2>')
    .replace(/\*\*(.*?)\*\*/gim, '<b>$1</b>')
    .replace(/\*(.*?)\*/gim, '<li>$1</li>')
    .replace(/\n-{3,}/g, '<hr>')
    .replace(/\n/g, '<br>');

  // ถ้ามี <li> แต่ไม่มี <ul> → wrap
  if (html.includes('<li>')) {
    html = html.replace(/(<br>)*(<li>.*<\/li>)+/g, match => {
      const items = match.replace(/<br>/g, '');
      return `<ul>${items}</ul>`;
    });
  }

  return html;
}

document.getElementById("headerModeSelect").dispatchEvent(new Event("change"));
