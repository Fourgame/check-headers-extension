// content.js (ไม่มี import แล้ว)
function analyzeDomFindings(findings) {
  const results = {};

  // 1. Content-Security-Policy (CSP)
  const cspIssues = [];
  if (findings.inlineScript > 0) cspIssues.push("unsafe-inline script");
  if (findings.inlineStyle > 0) cspIssues.push("unsafe-inline style");
  if (findings.eventHandlers > 0) cspIssues.push("inline event handlers");
  if (findings.evalUsage) cspIssues.push("eval usage");

  results["Content-Security-Policy"] = cspIssues.length > 0 ? {
    status: "insecure",
    issues: cspIssues
  } : {
    status: "secure",
    issues: []
  };

  // 2. X-Frame-Options (iframe detection)
  results["X-Frame-Options"] = findings.iframes.length > 0 ? {
    status: "required",
    recommendation: "DENY or SAMEORIGIN recommended due to iframe presence"
  } : {
    status: "not-needed",
    recommendation: "No iframe detected"
  };

  // 3. Cross-Origin-Resource-Policy
  const hasThirdPartyScripts = findings.externalScripts.some(src => {
    try {
      const url = new URL(src);
      return location.hostname !== url.hostname;
    } catch (e) {
      return false;
    }
  });

  results["Cross-Origin-Resource-Policy"] = hasThirdPartyScripts ? {
    status: "recommend",
    recommendation: "Consider same-site or same-origin policy due to external script domains"
  } : {
    status: "ok",
    recommendation: "No cross-origin scripts detected"
  };

  // 4. Permissions-Policy
  results["Permissions-Policy"] = {
    status: "recommend",
    recommendation: "Define permissions-policy to limit browser features like camera, microphone"
  };

  // 5. Referrer-Policy
  const anchorWithTarget = document.querySelectorAll("a[target='_blank']").length;
  results["Referrer-Policy"] = anchorWithTarget > 0 ? {
    status: "recommend",
    recommendation: "Consider using 'noopener noreferrer' with target=_blank or define Referrer-Policy header"
  } : {
    status: "ok",
    recommendation: "No high-risk external anchors found"
  };


  // 6. Clear-Site-Data
  results["Clear-Site-Data"] = findings.clearSiteDataMeta ? {
    status: "present",
    recommendation: "Meta tag for Clear-Site-Data found. Use response header instead for full effect.",
    metaContent: `Clear-Site-Data: ${findings.clearSiteDataContent}`
  } : {
    status: "missing",
    recommendation: "No Clear-Site-Data meta tag found. Prefer header to clear caches."
  };


  // 7. Cache-Control
  results["Cache-Control"] = findings.cacheControlMeta ? {
    status: "present",
    recommendation: "Meta Cache-Control tag found. Headers provide stronger caching control.",
    metaContent: `Cache-Control: ${findings.cacheControlContent}`
  } : {
    status: "missing",
    recommendation: "No cache control detected in meta. Use HTTP headers for cache policy."
  };

  return results;
}

  
  (function () {
    console.log("content.js loaded");
  
    const findings = {
      inlineScript: document.querySelectorAll('script:not([src])').length,
      inlineStyle: document.querySelectorAll('[style]').length,
      eventHandlers: document.querySelectorAll('*[onclick], *[onload], *[onerror]').length,
      evalUsage: typeof window.eval === 'function' && window.eval.toString().includes('[native code]'),
      iframes: [...document.querySelectorAll('iframe')].map(f => ({ sandbox: f.hasAttribute('sandbox') })),
      externalScripts: [...document.querySelectorAll('script[src]')].map(s => s.src),
    
      clearSiteDataMeta: !!document.querySelector('meta[http-equiv="Clear-Site-Data"]'),
      clearSiteDataContent: document.querySelector('meta[http-equiv="Clear-Site-Data"]')?.getAttribute('content') || null,
    
      pragmaMeta: !!document.querySelector('meta[http-equiv="Pragma"]'),
      pragmaContent: document.querySelector('meta[http-equiv="Pragma"]')?.getAttribute('content') || null,
    
      cacheControlMeta: !!document.querySelector('meta[http-equiv="Cache-Control"]'),
      cacheControlContent: document.querySelector('meta[http-equiv="Cache-Control"]')?.getAttribute('content') || null
    };
    
  
    const domResult = analyzeDomFindings(findings);
    console.log("DOM Analysis Result:", domResult);
    
      chrome.storage.local.set({ domAnalysis: domResult }, () => {
        chrome.runtime.sendMessage({
          type: "dom-analysis-result",
          data: domResult
        });
      });

  })();
  
  (function() {
    const inlineScripts = document.querySelectorAll("script:not([src])");
  
    inlineScripts.forEach((script, index) => {
      const oldCode = script.textContent;
  
      // 🔧 แก้ script ได้ตรงนี้
      const newCode = `
        console.log("Script ${index} was intercepted and modified.");
        try {
          ${oldCode}
        } catch (e) {
          console.error("Original script error:", e);
        }
      `;
  
      // แทนที่ script เดิม
      const newScript = document.createElement("script");
      newScript.textContent = newCode;
      script.replaceWith(newScript);
    });
  
    console.log("Modified inline scripts:", inlineScripts.length);
  })();
  
// ส่ง DOM สดไปให้ popup โดยตรง
chrome.runtime.sendMessage({
  type: "dom-analysis-result",
  data: domResult
});

