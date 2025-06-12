export function analyzeDomFindings(findings) {
    const results = {};
  
    // 1. Content-Security-Policy (CSP) analysis
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
  
    // 2. X-Frame-Options (XFO)
    results["X-Frame-Options"] = findings.iframes.length > 0 ? {
      status: "required",
      recommendation: "DENY or SAMEORIGIN recommended due to iframe presence"
    } : {
      status: "not-needed",
      recommendation: "No iframe detected"
    };
  
    // 3. Cross-Origin-Resource-Policy (CORP)
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
  
    // 6. X-XSS-Protection
    results["X-XSS-Protection"] = findings.inlineScript > 0 || findings.eventHandlers > 0 ? {
      status: "legacy-relevant",
      recommendation: "Inline scripts/event handlers were used. X-XSS-Protection is deprecated, prefer CSP"
    } : {
      status: "not-needed",
      recommendation: "No legacy XSS patterns detected"
    };
  
    // 7. Feature-Policy (via iframe sandbox)
    const sandboxedIframes = findings.iframes.filter(f => f.sandbox).length;
    results["Feature-Policy"] = sandboxedIframes > 0 ? {
      status: "partial",
      recommendation: "Some iframes use sandbox. Consider modern Permissions-Policy instead."
    } : {
      status: "missing",
      recommendation: "No iframe sandbox detected. Feature-Policy deprecated, use Permissions-Policy"
    };
  
    // 8. Clear-Site-Data (detect meta tag)
    results["Clear-Site-Data"] = findings.clearSiteDataMeta ? {
      status: "present",
      recommendation: "Meta tag for Clear-Site-Data found. Use response header instead for full effect."
    } : {
      status: "missing",
      recommendation: "No Clear-Site-Data meta tag found. Prefer header to clear caches."
    };
  
    // 9. Pragma
    results["Pragma"] = findings.pragmaMeta ? {
      status: "present",
      recommendation: "Pragma meta tag detected. Consider combining with Cache-Control."
    } : {
      status: "missing",
      recommendation: "No pragma meta tag found. Consider using headers for no-cache control."
    };
  
    // 10. Cache-Control
    results["Cache-Control"] = findings.cacheControlMeta ? {
      status: "present",
      recommendation: "Meta Cache-Control tag found. Headers provide stronger caching control."
    } : {
      status: "missing",
      recommendation: "No cache control detected in meta. Use HTTP headers for cache policy."
    };
  
    return results;
  }
  