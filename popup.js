const importantHeaders = [
  "strict-transport-security",
  "x-frame-options",
  "x-content-type-options",
  "content-security-policy",
  "x-permitted-cross-domain-policies",
  "referrer-policy",
  "clear-site-data",
  "cross-origin-embedder-policy",
  "cross-origin-opener-policy",
  "cross-origin-resource-policy",
  "cache-control",
  "permissions-policy",
  // Deprecated
  "expect-ct",
  "public-key-pins",
  "x-xss-protection",
  "pragma"
];

function validateHeader(header, value) {
  if (value === undefined) return ['not have', 'Header is missing'];

  value = value.trim();
  switch (header) {
    case 'strict-transport-security':
      try {
        const match = value.match(/max-age=(\d+)/i);
        const maxAge = parseInt(match?.[1] || '0');
        return maxAge >= 15768000
          ? ['correct', 'Valid max-age set']
          : ['uncorrect', 'max-age is too short (< 6 months)'];
      } catch {
        return ['uncorrect', 'Invalid or missing max-age directive'];
      }

    case 'x-frame-options':
      return ['DENY', 'SAMEORIGIN'].includes(value.toUpperCase())
        ? ['correct', 'Valid X-Frame-Options value']
        : ['uncorrect', 'Value should be DENY or SAMEORIGIN'];

    case 'x-content-type-options':
      return value.toLowerCase() === 'nosniff'
        ? ['correct', 'Correctly prevents MIME-sniffing']
        : ['uncorrect', 'Should be exactly "nosniff"'];

    case 'content-security-policy':
    case 'clear-site-data':
    case 'permissions-policy':
      return value
        ? ['correct', `${header} is defined`]
        : ['uncorrect', 'Header is present but empty'];

    case 'x-permitted-cross-domain-policies':
      return value.toLowerCase() === 'none'
        ? ['correct', 'Blocks all Flash cross-domain policies']
        : ['uncorrect', 'Should be "none"'];

    case 'referrer-policy':
      return ['strict-origin-when-cross-origin', 'no-referrer', 'same-origin'].includes(value)
        ? ['correct', 'Secure referrer policy in place']
        : ['uncorrect', 'Weak or outdated referrer policy'];

    case 'cross-origin-embedder-policy':
      return value.toLowerCase() === 'require-corp'
        ? ['correct', 'Cross-Origin Embedding is restricted']
        : ['uncorrect', 'Should be "require-corp"'];

    case 'cross-origin-opener-policy':
      return value.toLowerCase() === 'same-origin'
        ? ['correct', 'Ensures top-level document isolation']
        : ['uncorrect', 'Should be "same-origin"'];

    case 'cross-origin-resource-policy':
      return ['same-origin', 'same-site'].includes(value.toLowerCase())
        ? ['correct', 'CORP policy is restrictive']
        : ['uncorrect', 'Should be "same-origin" or "same-site"'];

    case 'cache-control':
      return value.toLowerCase().includes('no-store') || value.toLowerCase().includes('no-cache')
        ? ['correct', 'Prevents caching of sensitive content']
        : ['uncorrect', 'Missing "no-store" or "no-cache" directive'];

    // Deprecated headers
    case 'expect-ct':
      return value.toLowerCase().includes('enforce')
        ? ['correct', 'Expect-CT is enforced (though deprecated)']
        : ['uncorrect', 'Missing enforce directive'];

    case 'public-key-pins':
      return ['uncorrect', 'Deprecated and should not be used'];

    case 'x-xss-protection':
      return ['uncorrect', 'Deprecated in modern browsers — avoid use'];

    case 'pragma':
      return ['uncorrect', 'Deprecated — use Cache-Control instead'];

    default:
      return ['uncorrect', 'Header not recognized'];
  }
}

chrome.storage.local.get("lastHeaders", data => {
  const headers = data.lastHeaders || {};
  const container = document.getElementById("result");
  container.innerHTML = "";

  importantHeaders.forEach(name => {
    const [status, reason] = validateHeader(name, headers[name]);
    const div = document.createElement("div");
    div.className = "header";
    const statusClass = status.replace(' ', '-');  // แปลง "not have" → "not-have"
    div.innerHTML = `<b>${name}</b>: <span class="${statusClass}">${status}</span><br><small>${reason}</small>`;
    container.appendChild(div);

  });
});
